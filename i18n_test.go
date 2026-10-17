package main

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// Anahtar kümeleri ve her anahtarın yer tutucuları iki dilde birebir aynı olmalı.
func TestLocaleParity(t *testing.T) {
	ph := regexp.MustCompile(`\{[a-z_]+\}`)
	en, tr := catalogs["en"], catalogs["tr"]
	if len(en) == 0 || len(tr) == 0 {
		t.Fatal("katalog boş")
	}
	for k, v := range en {
		w, ok := tr[k]
		if !ok {
			t.Errorf("tr.json eksik: %s", k)
			continue
		}
		a, b := ph.FindAllString(v, -1), ph.FindAllString(w, -1)
		slices.Sort(a)
		slices.Sort(b)
		if !slices.Equal(a, b) {
			t.Errorf("%s: yer tutucular farklı: en=%v tr=%v", k, a, b)
		}
	}
	for k := range tr {
		if _, ok := en[k]; !ok {
			t.Errorf("en.json eksik: %s", k)
		}
	}
	if got := slices.Sorted(maps.Keys(catalogs)); !slices.Equal(got, []string{"en", "tr"}) {
		t.Errorf("diller: %v", got)
	}
}

func TestNormLang(t *testing.T) {
	for in, want := range map[string]string{"tr": "tr", "TR-tr": "tr", "en_US": "en", " en ": "en", "de": "", "": ""} {
		if got := normLang(in); got != want {
			t.Errorf("normLang(%q) = %q, beklenen %q", in, got, want)
		}
	}
}

func TestTranslate(t *testing.T) {
	cases := []struct {
		lang, key string
		params    map[string]any
		want      string
	}{
		{"tr", "login.submit", nil, "Giriş yap"},
		{"en", "login.submit", nil, "Sign in"},
		{"tr-TR", "login.submit", nil, "Giriş yap"},
		{"de", "login.submit", nil, "Sign in"}, // desteklenmeyen dil → en
		{"", "login.submit", nil, "Sign in"},
		{"en", "time.ago_d", map[string]any{"n": 1}, "1 day ago"},
		{"en", "time.ago_d", map[string]any{"n": 3}, "3 days ago"},
		{"tr", "time.ago_d", map[string]any{"n": 3}, "3 gün önce"},
		{"tr", "status.who_viewer", map[string]any{"user": "ayse"}, "ayse · izleyici"},
		{"en", "err.http", nil, "HTTP {status}"}, // eksik parametre olduğu gibi kalır
		{"tr", "yok.boyle.anahtar", nil, "yok.boyle.anahtar"},
	}
	for _, c := range cases {
		if got := T(c.lang, c.key, c.params); got != c.want {
			t.Errorf("T(%q, %q) = %q, beklenen %q", c.lang, c.key, got, c.want)
		}
	}
}

func TestCodedErrorResponse(t *testing.T) {
	_, h := v5App(t)

	// X-Kut başlığı yok → secure() reddeder
	r := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	var body struct {
		Code  string `json:"code"`
		Error string `json:"error"`
	}
	if rec.Code != 403 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Code != "forbidden" || body.Error != "Forbidden request." {
		t.Fatalf("forbidden: %d %s", rec.Code, rec.Body)
	}

	rec = post(h, "/api/login", `{"password":"yanlis-parola-123"}`, nil)
	if rec.Code != 401 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Code != "bad_password" {
		t.Fatalf("bad_password: %d %s", rec.Code, rec.Body)
	}
	rec = post(h, "/api/login", `{"username":"admin","password":"yanlis-parola-123"}`, nil)
	if json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Code != "bad_credentials" {
		t.Fatalf("bad_credentials: %s", rec.Body)
	}
	rec = post(h, "/api/login", `{"bilinmeyen":1}`, nil)
	if rec.Code != 400 || json.Unmarshal(rec.Body.Bytes(), &body) != nil || body.Code != "bad_request" {
		t.Fatalf("bad_request: %d %s", rec.Code, rec.Body)
	}
}

func TestCodedErrType(t *testing.T) {
	err := ue("save_failed", map[string]any{"msg": "disk dolu"})
	var ce *codedErr
	if !errors.As(err, &ce) || ce.Code != "save_failed" || err.Error() != "Could not save: disk dolu" {
		t.Fatalf("codedErr: %#v %q", err, err)
	}
}

func put(h http.Handler, path, body string, c *http.Cookie) *httptest.ResponseRecorder {
	return rq(h, "PUT", path, []byte(body), c)
}

func TestLanguagePreferences(t *testing.T) {
	a, h, c := maintApp(t)

	if got := a.srvLang(); got != "tr" {
		t.Fatalf("boş sunucu dili tr sayılmalı: %q", got)
	}
	if r := put(h, "/api/settings/lang", `{"lang":"de"}`, c); r.Code != 400 || !strings.Contains(r.Body.String(), `"code":"bad_lang"`) {
		t.Fatalf("desteklenmeyen sunucu dili: %d %s", r.Code, r.Body)
	}
	if r := put(h, "/api/settings/lang", `{"lang":"en"}`, c); r.Code != 200 {
		t.Fatalf("sunucu dili: %d %s", r.Code, r.Body)
	}
	if a.srvLang() != "en" {
		t.Fatal("sunucu dili bellekte güncellenmedi")
	}
	var srv Server
	if err := loadJSON(serverPath(a.dataDir), &srv); err != nil || srv.cfg().Lang != "en" {
		t.Fatalf("server.json'a yazılmadı: %v %+v", err, srv.Settings)
	}

	if r := put(h, "/api/me/lang", `{"lang":"en-GB"}`, c); r.Code != 200 || !strings.Contains(r.Body.String(), `"lang":"en"`) {
		t.Fatalf("hesap dili: %d %s", r.Code, r.Body)
	}
	if a.getAdmin().Lang != "en" {
		t.Fatal("hesap dili kaydedilmedi")
	}
	var me map[string]any
	r := rq(h, "GET", "/api/me", nil, c)
	if json.Unmarshal(r.Body.Bytes(), &me) != nil || me["lang"] != "en" || me["server_lang"] != "en" {
		t.Fatalf("/api/me: %s", r.Body)
	}
	if r := put(h, "/api/me/lang", `{"lang":"xx"}`, c); r.Code != 400 {
		t.Fatalf("geçersiz hesap dili kabul edildi: %d", r.Code)
	}
	if r := put(h, "/api/me/lang", `{"lang":""}`, c); r.Code != 200 || a.getAdmin().Lang != "" {
		t.Fatalf("hesap dili temizlenemedi: %d", r.Code)
	}

	r = rq(h, "GET", "/api/login-info", nil, &http.Cookie{Name: "x", Value: "y"})
	if !strings.Contains(r.Body.String(), `"server_lang":"en"`) {
		t.Fatalf("login-info: %s", r.Body)
	}
	// Ayarlar ekranının sunucu dili seçicisi değeri /api/settings'ten okur
	var st map[string]any
	r = rq(h, "GET", "/api/settings", nil, c)
	if json.Unmarshal(r.Body.Bytes(), &st) != nil || st["server_lang"] != "en" {
		t.Fatalf("/api/settings server_lang: %s", r.Body)
	}
	if !viewerMayWrite("/api/me/lang") {
		t.Fatal("izleyici kendi dilini değiştirebilmeli")
	}
}

// Ayarlar formu kaydedilince sunucu dili silinmemeli.
func TestPutSettingsKeepsLang(t *testing.T) {
	a, h, c := maintApp(t)
	if r := put(h, "/api/settings/lang", `{"lang":"en"}`, c); r.Code != 200 {
		t.Fatalf("sunucu dili: %d", r.Code)
	}
	body := `{"endpoint":"203.0.113.10","port":51820,"dns":"1.1.1.1","mtu":0,"keepalive":25,"block_private":true,"update_check":false,"ipv6":false}`
	if r := put(h, "/api/settings", body, c); r.Code != 200 {
		t.Fatalf("ayarlar: %d %s", r.Code, r.Body)
	}
	if a.srvLang() != "en" {
		t.Fatalf("ayar kaydı dili sildi: %q", a.srvLang())
	}
}

// Parola değişince (web, kut passwd, yönetici sıfırlaması) hesabın 2FA'sı ve dil tercihi korunmalı.
func TestPasswordChangeKeepsPrefs(t *testing.T) {
	rec, err := newAdmin("yeni-parola-12345")
	if err != nil {
		t.Fatal(err)
	}
	old := adminRecord{TOTPSecret: "S", TOTPLast: 7, Recovery: []string{"r"}, Lang: "en"}
	got := rec.withPrefsFrom(old)
	if got.Lang != "en" || got.TOTPSecret != "S" || got.TOTPLast != 7 || len(got.Recovery) != 1 || got.Hash != rec.Hash {
		t.Fatalf("tercihler korunmadı ya da parola değişmedi: %+v", got)
	}
}

// Kataloglar bölüm başına dosyalardan (web/locales/<dil>/*.json) birleştirilir; aynı anahtar iki dosyada olamaz.
func TestLoadCatalogsMergesParts(t *testing.T) {
	fsys := fstest.MapFS{
		"web/locales/en/a.json": {Data: []byte(`{"x":{"one":"1"}}`)},
		"web/locales/en/b.json": {Data: []byte(`{"y":"2"}`)},
		"web/locales/tr/a.json": {Data: []byte(`{"x":{"one":"bir"}}`)},
		"web/locales/tr/b.json": {Data: []byte(`{"y":"iki"}`)},
	}
	c, err := loadCatalogs(fsys)
	if err != nil || c["en"]["x.one"] != "1" || c["tr"]["y"] != "iki" {
		t.Fatalf("birleştirme: %v %v", err, c)
	}
	fsys["web/locales/en/c.json"] = &fstest.MapFile{Data: []byte(`{"x":{"one":"tekrar"}}`)}
	if _, err := loadCatalogs(fsys); err == nil || !strings.Contains(err.Error(), "x.one") {
		t.Fatalf("yinelenen anahtar kabul edildi: %v", err)
	}
}

// Tarayıcı birleşik kataloğu tek adresten alır; desteklenmeyen dil 404.
func TestServeLocale(t *testing.T) {
	_, h := v5App(t)
	r := httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/locales/tr.json", nil))
	var m map[string]string
	if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &m) != nil || m["login.submit"] != "Giriş yap" {
		t.Fatalf("katalog: %d %s", r.Code, r.Body.String()[:min(200, r.Body.Len())])
	}
	r = httptest.NewRecorder()
	h.ServeHTTP(r, httptest.NewRequest("GET", "/locales/de.json", nil))
	if r.Code != 404 {
		t.Fatalf("desteklenmeyen dil: %d", r.Code)
	}
}

func TestErrOf(t *testing.T) {
	r := httptest.NewRecorder()
	errOf(r, 400, ue("bad_lang", nil))
	if !strings.Contains(r.Body.String(), `"code":"bad_lang"`) {
		t.Fatalf("kodlu hata: %s", r.Body)
	}
	r = httptest.NewRecorder()
	errOf(r, 400, errors.New("düz metin"))
	if strings.Contains(r.Body.String(), `"code"`) || !strings.Contains(r.Body.String(), "düz metin") {
		t.Fatalf("düz hata: %s", r.Body)
	}
}

func TestReqLangAndCLILang(t *testing.T) {
	a, _ := v5App(t)
	r := httptest.NewRequest("GET", "/", nil)
	if a.reqLang(r) != "tr" { // başlık yok, hesap yok, sunucu dili boş → tr
		t.Fatalf("varsayılan: %q", a.reqLang(r))
	}
	r.Header.Set("X-Kut-Lang", "en-GB")
	if a.reqLang(r) != "en" {
		t.Fatalf("başlık: %q", a.reqLang(r))
	}
	for _, k := range []string{"KUT_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(k, "")
	}
	t.Setenv("LANG", "C.UTF-8")
	if got := cliLang(""); got != "tr" {
		t.Fatalf("C yerel ayarı tr'ye düşmeli: %q", got)
	}
	t.Setenv("LANG", "en_US.UTF-8")
	if got := cliLang(""); got != "en" {
		t.Fatalf("LANG: %q", got)
	}
	t.Setenv("KUT_LANG", "tr")
	if got := cliLang(""); got != "tr" {
		t.Fatalf("KUT_LANG öncelikli olmalı: %q", got)
	}
}

func TestLogReqTStoresCode(t *testing.T) {
	a, _ := v5App(t)
	a.logEventT("1.2.3.4", "test", "login.submit", map[string]any{"x": 1})
	evs := a.act.list(1)
	if len(evs) != 1 || evs[0].Code != "login.submit" || evs[0].Text != "Giriş yap" || evs[0].Params["x"] != 1 {
		t.Fatalf("olay: %+v", evs)
	}
	if got := fmtTime("en", time.Date(2026, 10, 16, 9, 5, 0, 0, time.UTC), true); got != "2026-10-16 09:05" {
		t.Fatalf("fmtTime en: %q", got)
	}
}
