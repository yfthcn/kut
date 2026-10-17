package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func v5App(t *testing.T) (*App, http.Handler) {
	t.Helper()
	a := testApp(t)
	a.sess, a.lim, a.hist, a.act = newSessions(), newLimiter(), &history{}, &activity{}
	adm, err := newAdmin("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	a.setAdmin(adm)
	return a, a.handler(false)
}

func post(h http.Handler, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("X-Kut", "1")
	req.RemoteAddr = "198.51.100.7:4000"
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func sessionOf(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == cookieName && c.Value != "" {
			return c
		}
	}
	return nil
}

// RFC 6238 Ek B: SHA-1, gizli "12345678901234567890", T=59 → 94287082 (son 6 hane 287082).
func TestTOTPRFCVector(t *testing.T) {
	sec := b32.EncodeToString([]byte("12345678901234567890"))
	got, err := totpAt(sec, 59/30)
	if err != nil || got != "287082" {
		t.Fatalf("got %q err %v", got, err)
	}
	now := time.Unix(59, 0)
	step, ok := totpVerify(sec, "287082", now, 0)
	if !ok || step != 1 {
		t.Fatalf("doğrulanamadı: %d %v", step, ok)
	}
	if _, ok := totpVerify(sec, "287082", now, step); ok {
		t.Fatal("aynı adım ikinci kez kabul edilmemeli")
	}
	if _, ok := totpVerify(sec, "000000", now, 0); ok {
		t.Fatal("yanlış kod kabul edildi")
	}
}

func TestTwoFactorLoginFlow(t *testing.T) {
	a, h := v5App(t)
	pw := `{"password":"correct-horse-battery"}`
	c := sessionOf(post(h, "/api/login", pw, nil))
	if c == nil {
		t.Fatal("2FA kapalıyken giriş olmalı")
	}
	// kur
	rec := post(h, "/api/totp/setup", `{}`, c)
	var setup struct{ Secret string }
	json.Unmarshal(rec.Body.Bytes(), &setup)
	if rec.Code != 200 || setup.Secret == "" {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	step := time.Now().Unix() / 30
	code, _ := totpAt(setup.Secret, step)
	rec = post(h, "/api/totp/enable", `{"code":"`+code+`","password":"correct-horse-battery"}`, c)
	var en struct {
		Recovery []string
	}
	json.Unmarshal(rec.Body.Bytes(), &en)
	if rec.Code != 200 || len(en.Recovery) != recoveryN {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	// parola tek başına oturum vermez
	rec = post(h, "/api/login", pw, nil)
	if sessionOf(rec) != nil || !strings.Contains(rec.Body.String(), "totp_required") {
		t.Fatalf("kod istenmeli: %s", rec.Body)
	}
	// enable'da kullanılan adım tekrar kullanılamaz (yeniden oynatma)
	rec = post(h, "/api/login", `{"password":"correct-horse-battery","code":"`+code+`"}`, nil)
	if sessionOf(rec) != nil {
		t.Fatal("kullanılmış kod kabul edildi")
	}
	// bir sonraki adımın kodu geçerli (±1 tolerans)
	next, _ := totpAt(setup.Secret, step+1)
	rec = post(h, "/api/login", `{"password":"correct-horse-battery","code":"`+next+`"}`, nil)
	if sessionOf(rec) == nil {
		t.Fatalf("geçerli kod reddedildi: %s", rec.Body)
	}
	// yanlış parola + doğru kod olmaz
	rec = post(h, "/api/login", `{"password":"yanlis-parola-xx","code":"`+next+`"}`, nil)
	if sessionOf(rec) != nil {
		t.Fatal("yanlış parola geçti")
	}
	// kurtarma kodu bir kez çalışır
	rc := en.Recovery[0]
	rec = post(h, "/api/login", `{"password":"correct-horse-battery","code":"`+rc+`"}`, nil)
	if sessionOf(rec) == nil {
		t.Fatalf("kurtarma kodu reddedildi: %s", rec.Body)
	}
	rec = post(h, "/api/login", `{"password":"correct-horse-battery","code":"`+rc+`"}`, nil)
	if sessionOf(rec) != nil {
		t.Fatal("kurtarma kodu ikinci kez çalıştı")
	}
	// kalıcılık: diskteki kayıtta sır var, kullanılan kod yok
	var onDisk adminRecord
	if err := loadJSON(adminPath(a.dataDir), &onDisk); err != nil || onDisk.TOTPSecret == "" || len(onDisk.Recovery) != recoveryN-1 {
		t.Fatalf("disk kaydı yanlış: %v %d", err, len(onDisk.Recovery))
	}
	// parola değişince 2FA korunur
	if got := (adminRecord{}); got.TOTPSecret != "" {
		t.Fatal("sıfır değer")
	}
	nrec, _ := newAdmin("another-long-password")
	if nrec = nrec.withPrefsFrom(a.getAdmin()); nrec.TOTPSecret == "" || len(nrec.Recovery) != recoveryN-1 {
		t.Fatal("parola değişiminde 2FA kayboldu")
	}
}

func TestLocal2FAOff(t *testing.T) {
	a, _ := v5App(t)
	h := a.handler(true)
	adm := a.getAdmin()
	adm.TOTPSecret = newSecretForTest(t)
	a.setAdmin(adm)
	req := httptest.NewRequest("POST", "/api/local/2fa-off", strings.NewReader(`{}`))
	req.Header.Set("X-Kut", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || a.getAdmin().TOTPSecret != "" {
		t.Fatalf("kapanmadı: %d %s", rec.Code, rec.Body)
	}
}

func newSecretForTest(t *testing.T) string {
	s, err := newTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSaveJSONKeepsBak(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	if err := saveJSON(p, map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(p, map[string]int{"a": 2}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p + ".bak")
	if err != nil || !strings.Contains(string(b), "1") {
		t.Fatalf(".bak eski içeriği tutmalı: %v %q", err, b)
	}
}

func TestRecovererTurnsPanicInto500(t *testing.T) {
	h := recoverer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 500 {
		t.Fatalf("kod %d", rec.Code)
	}
}

func TestBackupRestoreRoundTrip(t *testing.T) {
	src := t.TempDir()
	spriv, spub, _ := mustKeys(t)
	os.WriteFile(filepath.Join(src, "server.json"), []byte(`{"private_key":"`+spriv+`","public_key":"`+spub+`","endpoint":"203.0.113.10","port":51820,"subnet":"10.77.0.0/24","iface":"wg0","conf_path":"/etc/wireguard/wg0.conf","server.json":1}`), 0o600)
	os.WriteFile(filepath.Join(src, "admin.json"), []byte(`{}`), 0o600)
	os.WriteFile(filepath.Join(src, "peers.json"), []byte(`[]`), 0o600)
	out := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := cmdBackup([]string{"-data", src, "-o", out}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(out); st == nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("yedek 0600 olmalı: %v", st)
	}
	f, _ := os.Open(out)
	gz, _ := gzip.NewReader(f)
	tr := tar.NewReader(gz)
	n := 0
	for {
		if _, err := tr.Next(); err != nil {
			break
		}
		n++
	}
	f.Close()
	if n != 3 {
		t.Fatalf("arşivde %d dosya", n)
	}
	dst := t.TempDir()
	os.WriteFile(filepath.Join(dst, "peers.json"), []byte(`old`), 0o600)
	if err := cmdRestore([]string{"-data", dst, "-f", out}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dst, "server.json"))
	if !strings.Contains(string(b), "server.json") {
		t.Fatalf("geri yüklenmedi: %q", b)
	}
	if old, _ := os.ReadFile(filepath.Join(dst, "peers.json.bak")); string(old) != "old" {
		t.Fatalf("eski dosya .bak olmalı: %q", old)
	}
}

// ---- süreli / misafir cihaz ----

func TestExpiredPeerNotActiveAndTickDisables(t *testing.T) {
	a := testApp(t)
	past := time.Now().Add(-time.Minute)
	future := time.Now().Add(time.Hour)
	a.peers = []Peer{
		{ID: "1", Name: "misafir", PublicKey: "A", PSK: "P", IP: "10.77.0.2", Enabled: true, ExpiresAt: &past},
		{ID: "2", Name: "gelecek", PublicKey: "B", PSK: "P", IP: "10.77.0.3", Enabled: true, ExpiresAt: &future},
	}
	if a.peers[0].active(time.Now()) || !a.peers[1].active(time.Now()) {
		t.Fatal("active() süreyi dikkate almalı")
	}
	a.tick()
	if a.peers[0].Enabled {
		t.Fatal("süresi dolan cihaz kapanmadı")
	}
	if !a.peers[1].Enabled {
		t.Fatal("süresi dolmayan cihaz kapandı")
	}
	conf, _ := os.ReadFile(a.srv.ConfPath)
	if strings.Contains(string(conf), "# misafir") || !strings.Contains(string(conf), "# gelecek") {
		t.Fatalf("conf yanlış:\n%s", conf)
	}
	var saved []Peer
	if err := loadJSON(peersPath(a.dataDir), &saved); err != nil || saved[0].Enabled {
		t.Fatalf("peers.json güncellenmedi: %v", err)
	}
}

func TestGuestCreateEditToggle(t *testing.T) {
	a, h := v5App(t)
	c := sessionOf(post(h, "/api/login", `{"password":"correct-horse-battery"}`, nil))
	rec := post(h, "/api/peers", `{"name":"konuk","expires_minutes":60}`, c)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if a.peers[0].ExpiresAt == nil || time.Until(*a.peers[0].ExpiresAt) < 59*time.Minute {
		t.Fatal("bitiş zamanı yazılmadı")
	}
	if post(h, "/api/peers", `{"name":"kotu","expires_minutes":99999999}`, c).Code != 400 {
		t.Fatal("aşırı süre reddedilmeli")
	}
	// süresini geçir → durum "expired"
	past := time.Now().Add(-time.Second)
	a.peers[0].ExpiresAt = &past
	st := a.buildStatus()
	pv := st["peers"].([]peerView)
	if pv[0].State != "expired" || pv[0].ExpiresAt == 0 {
		t.Fatalf("durum: %+v", pv[0])
	}
	// elle açmak süre sınırını kaldırır
	id := a.peers[0].ID
	if r := post(h, "/api/peers/"+id+"/toggle", `{}`, c); r.Code != 200 {
		t.Fatalf("toggle %d %s", r.Code, r.Body)
	}
	if !a.peers[0].Enabled || a.peers[0].ExpiresAt != nil {
		t.Fatalf("elle açma süresiz yapmalı: %+v", a.peers[0])
	}
	// PATCH ile yeni süre
	req := httptest.NewRequest("PATCH", "/api/peers/"+id, strings.NewReader(`{"name":"konuk","note":"","expires_minutes":120}`))
	req.Header.Set("X-Kut", "1")
	req.AddCookie(c)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || a.peers[0].ExpiresAt == nil {
		t.Fatalf("patch %d %s", rr.Code, rr.Body)
	}
}

func TestParseSpan(t *testing.T) {
	for in, want := range map[string]int{"90m": 90, "8h": 480, "3d": 4320, "2w": 20160} {
		if got, err := parseSpan(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "h", "0h", "-3d", "5x", "400d"} {
		if _, err := parseSpan(bad); err == nil {
			t.Errorf("%q hata vermeli", bad)
		}
	}
}
