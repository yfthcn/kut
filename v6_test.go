package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func at(day time.Weekday, hh, mm int) time.Time {
	// 2026-10-11 Pazar; day gün kaydırır
	return time.Date(2026, 10, 11+int(day), hh, mm, 0, 0, time.Local)
}

func TestScheduleWindows(t *testing.T) {
	work := &Schedule{Days: []int{1, 2, 3, 4, 5}, From: "08:00", To: "18:00", Scope: "tunnel"}
	cases := []struct {
		now  time.Time
		want bool
	}{
		{at(time.Monday, 9, 0), true}, {at(time.Monday, 7, 59), false}, {at(time.Monday, 18, 0), false},
		{at(time.Saturday, 12, 0), false}, {at(time.Friday, 17, 59), true},
	}
	for _, c := range cases {
		if got := work.allows(c.now); got != c.want {
			t.Errorf("iş saati %v: %v", c.now, got)
		}
	}
	// gece yarısını aşan: Cuma 22:00 – 06:00; Cumartesi 03:00 hâlâ Cuma penceresinde
	night := &Schedule{Days: []int{5}, From: "22:00", To: "06:00", Scope: "internet"}
	for _, c := range []struct {
		now  time.Time
		want bool
	}{
		{at(time.Friday, 23, 0), true}, {at(time.Saturday, 3, 0), true}, {at(time.Saturday, 6, 0), false},
		{at(time.Friday, 3, 0), false}, {at(time.Saturday, 23, 0), false}, {at(time.Sunday, 3, 0), false},
	} {
		if got := night.allows(c.now); got != c.want {
			t.Errorf("gece %v: %v", c.now, got)
		}
	}
	var nilS *Schedule
	if !nilS.allows(time.Now()) {
		t.Error("zamanlama yoksa hep serbest")
	}
}

func TestScheduleScopes(t *testing.T) {
	out := at(time.Saturday, 12, 0)
	tun := Peer{Enabled: true, Internet: true, Schedule: &Schedule{Days: []int{1}, From: "08:00", To: "09:00", Scope: "tunnel"}}
	if tun.active(out) {
		t.Error("tünel kapsamı dışında peer kapalı olmalı")
	}
	in := Peer{Enabled: true, Internet: true, Schedule: &Schedule{Days: []int{1}, From: "08:00", To: "09:00", Scope: "internet"}}
	if !in.active(out) || in.inetOn(out) {
		t.Error("internet kapsamı: tünel açık, internet kapalı olmalı")
	}
	if !in.inetOn(at(time.Monday, 8, 30)) {
		t.Error("pencere içinde internet açık olmalı")
	}
}

func TestNormalizeScheduleRejects(t *testing.T) {
	bad := []*Schedule{
		{Days: nil, From: "08:00", To: "09:00", Scope: "tunnel"},
		{Days: []int{7}, From: "08:00", To: "09:00", Scope: "tunnel"},
		{Days: []int{1}, From: "8:00", To: "09:00", Scope: "tunnel"},
		{Days: []int{1}, From: "08:00", To: "08:00", Scope: "tunnel"},
		{Days: []int{1}, From: "08:00", To: "09:00", Scope: "x"},
	}
	for i, b := range bad {
		if _, err := normalizeSchedule(b); err == nil {
			t.Errorf("#%d reddedilmeli", i)
		}
	}
}

// Zamanlama penceresi değişince izleyici cihazı sunucudan kaldırmalı/geri eklemeli.
func TestTickAppliesScheduleFlip(t *testing.T) {
	a := testApp(t)
	now := time.Now()
	// şu an pencerenin DIŞINDA kalacak bir zamanlama: bugünü içermeyen gün
	other := (int(now.Weekday()) + 3) % 7
	sch := &Schedule{Days: []int{other}, From: "00:00", To: "23:59", Scope: "tunnel"}
	a.peers = []Peer{{ID: "1", Name: "cocuk", PublicKey: "A", PSK: "P", IP: "10.77.0.2", Enabled: true, Schedule: sch}}
	a.act = &activity{}
	a.tick() // ilk tur: yalnızca durumu öğrenir
	a.peers[0].Schedule = &Schedule{Days: []int{int(now.Weekday())}, From: "00:00", To: "23:59", Scope: "tunnel"}
	// bugünü içine alan pencere (23:59 hariç) → içeri girdi
	if now.Hour() == 23 && now.Minute() == 59 {
		t.Skip("gün sonu")
	}
	a.tick()
	conf := readConf(t, a)
	if !strings.Contains(conf, "# cocuk") {
		t.Fatalf("pencere başlayınca peer eklenmeliydi:\n%s", conf)
	}
	found := false
	for _, e := range a.act.list(10) {
		if e.Kind == "schedule" {
			found = true
		}
	}
	if !found {
		t.Error("zamanlama olayı günlüğe yazılmadı")
	}
}

func TestBulkActions(t *testing.T) {
	a, h := v5App(t)
	c := sessionOf(post(h, "/api/login", `{"password":"correct-horse-battery"}`, nil))
	for _, n := range []string{"a", "b", "c"} {
		if r := post(h, "/api/peers", `{"name":"`+n+`"}`, c); r.Code != 200 {
			t.Fatalf("%s: %d %s", n, r.Code, r.Body)
		}
	}
	ids := `["` + a.peers[0].ID + `","` + a.peers[1].ID + `"]`
	do := func(body string) *httptest.ResponseRecorder { return post(h, "/api/peers/bulk", body, c) }
	if r := do(`{"ids":` + ids + `,"action":"group","group":"Aile"}`); r.Code != 200 {
		t.Fatalf("group %d %s", r.Code, r.Body)
	}
	if a.peers[0].Group != "Aile" || a.peers[1].Group != "Aile" || a.peers[2].Group != "" {
		t.Fatal("grup yalnızca seçililere yazılmalı")
	}
	if r := do(`{"ids":` + ids + `,"action":"group","group":"<script>"}`); r.Code != 400 {
		t.Fatal("geçersiz grup adı reddedilmeli")
	}
	do(`{"ids":` + ids + `,"action":"disable"}`)
	if a.peers[0].Enabled || a.peers[1].Enabled || !a.peers[2].Enabled {
		t.Fatal("toplu kapatma yanlış")
	}
	do(`{"ids":` + ids + `,"action":"enable"}`)
	do(`{"ids":` + ids + `,"action":"internet","internet":true}`)
	if !a.peers[0].Internet || a.peers[2].Internet {
		t.Fatal("toplu internet izni yanlış")
	}
	do(`{"ids":` + ids + `,"action":"expires","expires_minutes":60}`)
	if a.peers[0].ExpiresAt == nil || a.peers[2].ExpiresAt != nil {
		t.Fatal("toplu süre yanlış")
	}
	do(`{"ids":` + ids + `,"action":"schedule","schedule":{"days":[1,2],"from":"08:00","to":"09:00","scope":"internet"}}`)
	if a.peers[0].Schedule == nil || a.peers[2].Schedule != nil {
		t.Fatal("toplu zamanlama yanlış")
	}
	if r := do(`{"ids":["yok"],"action":"disable"}`); r.Code != 404 {
		t.Fatalf("bilinmeyen kimlik 404 olmalı: %d", r.Code)
	}
	if r := do(`{"ids":[],"action":"disable"}`); r.Code != 400 {
		t.Fatal("boş seçim reddedilmeli")
	}
	// hepsi-ya-da-hiçbiri: bilinmeyen kimlik varken geçerli olanlar da değişmemeli
	before := a.peers[2].Enabled
	do(`{"ids":["` + a.peers[2].ID + `","yok"],"action":"disable"}`)
	if a.peers[2].Enabled != before {
		t.Fatal("kısmi uygulama olmamalı")
	}
	do(`{"ids":` + ids + `,"action":"delete"}`)
	if len(a.peers) != 1 || a.peers[0].Name != "c" {
		t.Fatalf("toplu silme yanlış: %d", len(a.peers))
	}
}

func TestPeerHistoryRings(t *testing.T) {
	h := &peerHistory{}
	for i := 0; i < 300; i++ {
		h.add("K", sample{T: int64(1000 + i*15), Rx: uint64(i), Tx: uint64(i)})
	}
	if n := len(h.list("K", 0)); n != tiers[0].keep {
		t.Fatalf("ince halka %d", n)
	}
	if n := len(h.list("K", 1)); n < 14 || n > 16 {
		t.Fatalf("kaba halka %d (4500 sn / 300 ≈ 15)", n)
	}
	if n := len(h.list("K", 2)); n < 2 || n > 4 {
		t.Fatalf("hafta halkası %d (4500 sn / 1800 ≈ 3)", n)
	}
	h.prune(map[string]bool{})
	if h.list("K", 0) != nil {
		t.Fatal("silinen cihazın geçmişi temizlenmeli")
	}
}

func TestLogExportCSVInjection(t *testing.T) {
	a, h := v5App(t)
	c := sessionOf(post(h, "/api/login", `{"password":"correct-horse-battery"}`, nil))
	// Metin doğrudan act.add ile: geri yüklenen activity.jsonl'deki olaylar katalogdan geçmez, Text ham kalır.
	a.act.add(Event{T: time.Now().Unix(), IP: "1.2.3.4", Kind: "x", Text: `=HYPERLINK("http://e.example")`})
	a.act.add(Event{T: time.Now().Unix(), IP: "1.2.3.4", Kind: "@SUM(1+1)", Text: "olay türü yedekten gelebilir"}) // activity.jsonl geri yüklenebilir: Kind da dışarıdan gelir
	req := httptest.NewRequest("GET", "/api/activity/export", nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	body := rec.Body.String()
	if rec.Code != 200 || !strings.HasPrefix(body, "zaman,") || strings.Contains(body, ",=HYPERLINK") || !strings.Contains(body, "'=HYPERLINK") ||
		strings.Contains(body, ",@SUM") {
		t.Fatalf("CSV güvenli değil: %d\n%s", rec.Code, body)
	}
	req = httptest.NewRequest("GET", "/api/activity/export?format=json", nil)
	req.AddCookie(c)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[") {
		t.Fatal("JSON dizi olmalı")
	}
}

func readConf(t *testing.T, a *App) string {
	t.Helper()
	b, err := os.ReadFile(a.srv.ConfPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func login(h http.Handler, user, pw string) *http.Cookie {
	body := `{"password":"` + pw + `"}`
	if user != "" {
		body = `{"username":"` + user + `","password":"` + pw + `"}`
	}
	return sessionOf(post(h, "/api/login", body, nil))
}

func TestMultiUserRolesAndIsolation(t *testing.T) {
	a, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	if owner == nil {
		t.Fatal("sahip girişi")
	}
	if r := post(h, "/api/users", `{"name":"ayse","password":"ayse-long-password","role":"viewer"}`, owner); r.Code != 200 {
		t.Fatalf("kullanıcı ekle: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/users", `{"name":"ayse","password":"ayse-long-password","role":"viewer"}`, owner); r.Code != 409 {
		t.Fatal("aynı ad ikinci kez eklenmemeli")
	}
	if r := post(h, "/api/users", `{"name":"admin","password":"ayse-long-password","role":"admin"}`, owner); r.Code != 400 {
		t.Fatal("ayrılmış ad reddedilmeli")
	}
	if r := post(h, "/api/users", `{"name":"x y","password":"ayse-long-password","role":"admin"}`, owner); r.Code != 400 {
		t.Fatal("geçersiz ad reddedilmeli")
	}
	if login(h, "ayse", "yanlis-parola-xyz") != nil {
		t.Fatal("yanlış parola geçti")
	}
	if login(h, "yok", "ayse-long-password") != nil {
		t.Fatal("olmayan hesap geçti")
	}
	v := login(h, "ayse", "ayse-long-password")
	if v == nil {
		t.Fatal("izleyici girişi")
	}
	// izleyici okuyabilir, yazamaz, kullanıcı listesini göremez
	get := func(path string, c *http.Cookie) int {
		req := httptest.NewRequest("GET", path, nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if get("/api/notify", v) != 403 {
		t.Fatal("izleyici bildirim ayarını görmemeli")
	}
	if get("/api/status", v) != 200 || get("/api/users", v) != 403 {
		t.Fatal("izleyici yetkisi yanlış")
	}
	if r := post(h, "/api/peers", `{"name":"x"}`, v); r.Code != 403 {
		t.Fatalf("izleyici cihaz ekleyememeli: %d", r.Code)
	}
	if r := post(h, "/api/peers/bulk", `{"ids":["a"],"action":"delete"}`, v); r.Code != 403 {
		t.Fatal("izleyici toplu işlem yapamamalı")
	}
	// izleyici kendi parolasını değiştirebilir; sahibinkini değil
	if r := post(h, "/api/password", `{"current":"ayse-long-password","new":"ayse-new-password-1"}`, v); r.Code != 200 {
		t.Fatalf("kendi parolası: %d %s", r.Code, r.Body)
	}
	if login(h, "", "correct-horse-battery") == nil {
		t.Fatal("sahibin parolası değişmemeli")
	}
	if login(h, "ayse", "ayse-new-password-1") == nil {
		t.Fatal("yeni parola çalışmalı")
	}
	// disk: users.json yazıldı, admin.json'da ayşe yok
	us, _ := loadUsers(a.dataDir)
	if len(us) != 1 || us[0].Name != "ayse" {
		t.Fatalf("users.json: %+v", us)
	}
	// günlükte kullanıcı adı
	found := false
	for _, e := range a.act.list(50) {
		if e.Kind == "user_create" && e.User == "admin" {
			found = true
		}
	}
	if !found {
		t.Error("günlük işlemi yapan hesabı yazmalı")
	}
	// rol değiştirince oturum düşer
	v2 := login(h, "ayse", "ayse-new-password-1")
	if r := post(h, "/api/users", `{}`, v2); r.Code != 403 {
		t.Fatal("izleyici hesap yönetemez")
	}
	req := httptest.NewRequest("PATCH", "/api/users/ayse", strings.NewReader(`{"role":"admin"}`))
	req.Header.Set("X-Kut", "1")
	req.AddCookie(owner)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || get("/api/status", v2) != 401 {
		t.Fatalf("rol değişince eski oturum düşmeli: %d / %d", rec.Code, get("/api/status", v2))
	}
	// silinen hesabın oturumu ve girişi biter; sahip ve kendini silemez
	adm := login(h, "ayse", "ayse-new-password-1")
	req = httptest.NewRequest("DELETE", "/api/users/admin", nil)
	req.Header.Set("X-Kut", "1")
	req.AddCookie(adm)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatal("sahip silinemez")
	}
	req = httptest.NewRequest("DELETE", "/api/users/ayse", nil)
	req.Header.Set("X-Kut", "1")
	req.AddCookie(owner)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || get("/api/status", adm) != 401 || login(h, "ayse", "ayse-new-password-1") != nil {
		t.Fatal("silinen hesap girememeli")
	}
}

func TestPerUserTwoFactor(t *testing.T) {
	a, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	post(h, "/api/users", `{"name":"bob","password":"bob-long-password","role":"admin"}`, owner)
	bob := login(h, "bob", "bob-long-password")
	rec := post(h, "/api/totp/setup", `{}`, bob)
	var setup struct{ Secret string }
	json.Unmarshal(rec.Body.Bytes(), &setup)
	code, _ := totpAt(setup.Secret, time.Now().Unix()/30)
	if r := post(h, "/api/totp/enable", `{"code":"`+code+`","password":"bob-long-password"}`, bob); r.Code != 200 {
		t.Fatalf("bob 2FA: %d %s", r.Code, r.Body)
	}
	if a.getAdmin().TOTPSecret != "" {
		t.Fatal("bob'un 2FA'sı sahibe yazılmamalı")
	}
	if r := post(h, "/api/login", `{"username":"bob","password":"bob-long-password"}`, nil); !strings.Contains(r.Body.String(), "totp_required") {
		t.Fatalf("bob kod istemeli: %s", r.Body)
	}
	if login(h, "", "correct-horse-battery") == nil {
		t.Fatal("sahip 2FA'sız girebilmeli")
	}
	// yerel kurtarma
	lh := a.handler(true)
	if r := post(lh, "/api/local/2fa-off", `{"user":"bob"}`, nil); r.Code != 200 {
		t.Fatalf("local off: %d %s", r.Code, r.Body)
	}
	if login(h, "bob", "bob-long-password") == nil {
		t.Fatal("2FA kapanınca parolayla girilmeli")
	}
}

func TestFilterEvents(t *testing.T) {
	now := time.Now()
	evs := []Event{
		{T: now.Add(-10 * time.Second).Unix(), Kind: "login_fail", Text: "hatalı parola", IP: "1.2.3.4"},
		{T: now.Add(-2 * time.Hour).Unix(), Kind: "peer_create", Text: "telefon eklendi", IP: "10.10.0.2", User: "ali"},
		{T: now.Add(-3 * 24 * time.Hour).Unix(), Kind: "login", Text: "giriş", IP: "10.10.0.3", User: "admin"},
	}
	get := func(s string) ([]Event, map[string]int) {
		q, _ := url.ParseQuery(s)
		return filterEvents(evs, q, now)
	}
	if r, c := get("g=guvenlik"); len(r) != 1 || c["cihaz"] != 1 || c["giris"] != 1 {
		t.Fatalf("grup: %v %v", r, c)
	}
	if r, _ := get("q=TELEFON"); len(r) != 1 {
		t.Fatalf("q: %v", r)
	}
	if r, _ := get("u=ali"); len(r) != 1 {
		t.Fatalf("u: %v", r)
	}
	if r, _ := get("since=3600"); len(r) != 1 {
		t.Fatalf("since: %v", r)
	}
	if r, _ := get(""); len(r) != 3 {
		t.Fatalf("hepsi: %v", r)
	}
}

func TestPeerKind(t *testing.T) {
	_, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	if r := post(h, "/api/peers", `{"name":"tel","kind":"phone"}`, c); r.Code != 200 || !strings.Contains(r.Body.String(), `"kind":"phone"`) && !strings.Contains(r.Body.String(), "tel") {
		t.Fatalf("ekleme: %d %s", r.Code, r.Body.String())
	}
	if r := post(h, "/api/peers", `{"name":"x","kind":"toaster"}`, c); r.Code != 400 {
		t.Fatalf("bilinmeyen tür 400 olmalı: %d", r.Code)
	}
	req := httptest.NewRequest("GET", "/api/status", nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), `"kind":"phone"`) {
		t.Fatalf("durumda tür yok: %s", rec.Body.String())
	}
}
