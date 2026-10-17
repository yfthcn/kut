package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHistoryPersistRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "history.json.gz")
	h, ph := &history{}, &peerHistory{}
	now := time.Now().Unix()
	for i := 0; i < 50; i++ {
		x := sample{T: now - int64(50-i)*15, Rx: uint64(i * 100), Tx: uint64(i * 200)}
		h.add(x)
		ph.add("PUB", x)
	}
	// çok eski bir örnek yüklenirken atılmalı
	ph.add("PUB", sample{T: now - 90*24*3600, Rx: 1, Tx: 1})
	if err := saveHistory(p, h, ph); err != nil {
		t.Fatal(err)
	}
	h2, ph2 := &history{}, &peerHistory{}
	loadHistory(p, h2, ph2, now)
	if got := h2.list(0); len(got) != 50 || got[49].Tx != 49*200 {
		t.Fatalf("genel geçmiş: %d", len(got))
	}
	l := ph2.list("PUB", 0)
	if len(l) == 0 || l[0].T < now-3600-100 {
		t.Fatalf("eski örnek temizlenmeliydi: %+v", l[:1])
	}
	// bozuk dosya sessizce yok sayılır
	os.WriteFile(p, []byte("bozuk"), 0o600)
	loadHistory(p, &history{}, &peerHistory{}, now)
}

func TestLogCompactArchivesByMonth(t *testing.T) {
	dir := t.TempDir()
	l := loadActivity(filepath.Join(dir, "activity.jsonl"))
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.Local)
	l.add(Event{T: now.AddDate(0, -5, 0).Unix(), Kind: "k", Text: "eski-1"})
	l.add(Event{T: now.AddDate(0, -4, 0).Unix(), Kind: "k", Text: "eski-2"})
	l.add(Event{T: now.AddDate(0, 0, -3).Unix(), Kind: "k", Text: "yeni"})
	arch := filepath.Join(dir, "logs")
	n, err := l.compact(now.AddDate(0, 0, -90).Unix(), arch, true)
	if err != nil || n != 2 {
		t.Fatalf("compact: %d %v", n, err)
	}
	if tot, _ := l.stats(); tot != 1 {
		t.Fatalf("günlükte 1 olay kalmalı: %d", tot)
	}
	ents, _ := os.ReadDir(arch)
	if len(ents) != 2 {
		t.Fatalf("iki aylık arşiv beklenir: %d", len(ents))
	}
	// ikinci çalıştırmada aynı aya eklenir ve gzip akışı okunabilir kalır
	l.add(Event{T: now.AddDate(0, -5, 0).Unix(), Kind: "k", Text: "eski-3"})
	if n, _ := l.compact(now.AddDate(0, 0, -90).Unix(), arch, true); n != 1 {
		t.Fatal("ikinci compact")
	}
	f, _ := os.Open(filepath.Join(arch, "activity-"+now.AddDate(0, -5, 0).Format("2006-01")+".jsonl.gz"))
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(gz)
	if !strings.Contains(string(b), "eski-1") || !strings.Contains(string(b), "eski-3") {
		t.Fatalf("arşiv içeriği: %s", b)
	}
	// diskteki dosya yeniden yüklenince yalnızca kalan olay gelir
	if re := loadActivity(l.path); len(re.evs) != 1 || re.evs[0].Text != "yeni" {
		t.Fatalf("yeniden yükleme: %+v", re.evs)
	}
	// arşiv saklama: 3 aydan eski aylar silinir
	if k := pruneArchives(arch, 3, now); k != 2 {
		t.Fatalf("arşiv budama: %d", k)
	}
	// arşiv kapalıysa silinir, dosya oluşmaz
	l2 := &activity{}
	l2.add(Event{T: 1, Text: "x"})
	if n, _ := l2.compact(100, filepath.Join(dir, "yok"), false); n != 1 {
		t.Fatal("arşivsiz silme")
	}
	if _, err := os.Stat(filepath.Join(dir, "yok")); err == nil {
		t.Fatal("arşiv kapalıyken dizin oluşmamalı")
	}
}

func TestBackupSlots(t *testing.T) {
	loc := time.Local
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, loc) // Perşembe
	d := BackupCfg{Freq: "daily", Time: "03:30"}
	if got := lastSlot(d, now); !got.Equal(time.Date(2026, 10, 15, 3, 30, 0, 0, loc)) {
		t.Fatalf("günlük: %v", got)
	}
	if got := lastSlot(d, time.Date(2026, 10, 15, 2, 0, 0, 0, loc)); !got.Equal(time.Date(2026, 10, 14, 3, 30, 0, 0, loc)) {
		t.Fatalf("günlük (saatten önce): %v", got)
	}
	w := BackupCfg{Freq: "weekly", Time: "04:00", Weekday: 1} // Pazartesi
	if got := lastSlot(w, now); !got.Equal(time.Date(2026, 10, 12, 4, 0, 0, 0, loc)) {
		t.Fatalf("haftalık: %v", got)
	}
	m := BackupCfg{Freq: "monthly", Time: "05:00"}
	if got := lastSlot(m, now); !got.Equal(time.Date(2026, 10, 1, 5, 0, 0, 0, loc)) {
		t.Fatalf("aylık: %v", got)
	}
	if got := nextSlot(m, now); !got.Equal(time.Date(2026, 11, 1, 5, 0, 0, 0, loc)) {
		t.Fatalf("aylık sonraki: %v", got)
	}
}

func maintApp(t *testing.T) (*App, http.Handler, *http.Cookie) {
	a, h := v5App(t)
	// gerçek bir veri dizini: server.json + admin.json yedeğe girer
	a.mt = newMaint("")
	// geri yükleme validateState'ten geçmeli: gerçek anahtarlar ve tam arayüz/yol
	spriv, spub, _ := mustKeys(t)
	_, ppub, ppsk := mustKeys(t)
	srv, _ := json.Marshal(Server{PrivateKey: spriv, PublicKey: spub, Endpoint: "1.2.3.4", Port: 51820, Subnet: "10.77.0.0/24", Iface: "wg0", ConfPath: "/etc/wireguard/wg0.conf", Schema: currentSchema})
	adm, _ := json.Marshal(a.admin)
	os.WriteFile(filepath.Join(a.dataDir, "server.json"), srv, 0o600)
	os.WriteFile(filepath.Join(a.dataDir, "admin.json"), adm, 0o600)
	os.WriteFile(filepath.Join(a.dataDir, "peers.json"), []byte(`[{"id":"p1","name":"ilk","public_key":"`+ppub+`","psk":"`+ppsk+`","ip":"10.77.0.2","enabled":true}]`), 0o600)
	return a, h, login(h, "", "correct-horse-battery")
}

func TestScheduledBackupAndRetention(t *testing.T) {
	a, _, _ := maintApp(t)
	a.act = &activity{}
	a.mt.update(func(c *MaintCfg) { c.Backup.Keep = 2; c.Backup.Time = "00:00" })
	now := time.Now()
	a.maintTick(now)
	if n := len(a.listBackups()); n != 1 {
		t.Fatalf("ilk tur yedek almalı: %d", n)
	}
	a.maintTick(now.Add(time.Minute)) // aynı slot: tekrar almaz
	if n := len(a.listBackups()); n != 1 {
		t.Fatalf("aynı slotta ikinci yedek: %d", n)
	}
	// eski oto yedekleri doldur; yalnızca en yeni 2 kalmalı, elle alınan korunmalı
	for _, n := range []string{"kut-oto-20200101-000001.tar.gz", "kut-oto-20200102-000001.tar.gz", "kut-elle-20200101-000001.tar.gz"} {
		os.WriteFile(filepath.Join(a.backupDir(), n), []byte("x"), 0o600)
	}
	a.pruneBackups(2)
	var oto, elle int
	for _, b := range a.listBackups() {
		switch b.Kind {
		case "oto":
			oto++
		case "elle":
			elle++
		}
	}
	if oto != 2 || elle != 1 {
		t.Fatalf("budama: oto=%d elle=%d", oto, elle)
	}
}

func TestBackupAPIAndRestore(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	restarted := make(chan struct{}, 1)
	a.restartF = func() { restarted <- struct{}{} }
	restartDelay = 10 * time.Millisecond

	rec := post(h, "/api/backups", `{"owner_password":"correct-horse-battery"}`, c)
	if rec.Code != 200 {
		t.Fatalf("elle yedek: %d %s", rec.Code, rec.Body.String())
	}
	var nm struct{ Name string }
	json.Unmarshal(rec.Body.Bytes(), &nm)
	if !backupNameRe.MatchString(nm.Name) {
		t.Fatalf("ad: %q", nm.Name)
	}
	// indirme
	req := httptest.NewRequest(http.MethodGet, "/api/backups/"+nm.Name, nil)
	req.AddCookie(c)
	req.Header.Set("X-Kut-Owner-Pass", "correct-horse-battery")
	r2 := httptest.NewRecorder()
	h.ServeHTTP(r2, req)
	if r2.Code != 200 || r2.Header().Get("Content-Disposition") == "" || len(r2.Body.Bytes()) < 50 {
		t.Fatalf("indirme: %d", r2.Code)
	}
	// yol gezinmesi reddedilir
	for _, bad := range []string{"..%2Fserver.json", "kut-elle-1-2.tar.gz", "x.tar.gz"} {
		rq := httptest.NewRequest(http.MethodGet, "/api/backups/"+bad, nil)
		rq.AddCookie(c)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, rq)
		if rr.Code == 200 {
			t.Fatalf("geçersiz ad kabul edildi: %s", bad)
		}
	}
	// yedekten sonra cihaz listesini boz, geri yükle → eski içerik gelmeli
	os.WriteFile(filepath.Join(a.dataDir, "peers.json"), []byte(`[]`), 0o600)
	rr := post(h, "/api/backups/"+nm.Name+"/restore", `{"owner_password":"correct-horse-battery"}`, c)
	if rr.Code != 200 {
		t.Fatalf("geri yükleme: %d %s", rr.Code, rr.Body.String())
	}
	select {
	case <-restarted:
	case <-time.After(2 * time.Second):
		t.Fatal("yeniden başlatma çağrılmadı")
	}
	b, _ := os.ReadFile(filepath.Join(a.dataDir, "peers.json"))
	if !strings.Contains(string(b), `"ilk"`) {
		t.Fatalf("peers.json geri gelmedi: %s", b)
	}
	// geri yükleme öncesi yedek alınmış olmalı
	var once int
	for _, bi := range a.listBackups() {
		if bi.Kind == "oncesi" {
			once++
		}
	}
	if once != 1 {
		t.Fatalf("oncesi yedeği: %d", once)
	}
	// çöp dosya yüklenemez, veri değişmez
	before, _ := os.ReadFile(filepath.Join(a.dataDir, "server.json"))
	bad := uploadForm(h, c, fileField([]byte("bu bir yedek degil")), textField("owner_password", "correct-horse-battery"))
	if bad.Code != 400 {
		t.Fatalf("çöp dosya: %d", bad.Code)
	}
	after, _ := os.ReadFile(filepath.Join(a.dataDir, "server.json"))
	if string(before) != string(after) {
		t.Fatal("başarısız geri yüklemede veri değişti")
	}
	// ayar doğrulaması
	put := func(body string) int {
		rq := httptest.NewRequest(http.MethodPut, "/api/maint", strings.NewReader(body))
		rq.Header.Set("X-Kut", "1")
		rq.AddCookie(c)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		return rc.Code
	}
	if put(`{"enabled":true,"freq":"hourly","time":"03:30","keep":7}`) != 400 || put(`{"enabled":true,"freq":"daily","time":"3:30","keep":7}`) != 400 ||
		put(`{"enabled":true,"freq":"daily","time":"03:30","keep":0}`) != 400 || put(`{"enabled":true,"freq":"daily","time":"03:30","keep":7,"log_days":3}`) != 400 {
		t.Fatal("geçersiz ayar kabul edildi")
	}
	if put(`{"enabled":true,"freq":"weekly","time":"04:00","weekday":2,"keep":5,"log_days":30,"log_archive":true,"archive_months":6}`) != 200 {
		t.Fatal("geçerli ayar reddedildi")
	}
	if g := a.mt.get(); g.Backup.Freq != "weekly" || g.LogDays != 30 || g.Backup.Keep != 5 {
		t.Fatalf("kaydedilmedi: %+v", g)
	}
}

func TestBackupViewerForbidden(t *testing.T) {
	a, h, owner := maintApp(t)
	if r := post(h, "/api/users", `{"name":"ayse","password":"ayse-long-password","role":"viewer"}`, owner); r.Code != 200 {
		t.Fatalf("kullanıcı: %d %s", r.Code, r.Body.String())
	}
	v := login(h, "ayse", "ayse-long-password")
	for _, p := range []string{"/api/maint", "/api/backups/kut-elle-20200101-000001.tar.gz"} {
		rq := httptest.NewRequest(http.MethodGet, p, nil)
		rq.AddCookie(v)
		rc := httptest.NewRecorder()
		h.ServeHTTP(rc, rq)
		if rc.Code != 403 {
			t.Fatalf("%s izleyiciye açık: %d", p, rc.Code)
		}
	}
	_ = a
}

func TestCompactLogsFailureBacksOffRetry(t *testing.T) {
	a, _, _ := maintApp(t)
	a.act = &activity{evs: []Event{{T: 1, Kind: "login", Text: "çok eski"}}}
	a.mt.update(func(c *MaintCfg) { c.LogDays, c.LogArchive, c.LastCompact = 30, true, 0 })
	// arşiv dizini yerine düz dosya: MkdirAll başarısız olur
	if err := os.WriteFile(a.archiveDir(), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a.compactLogs(now)
	want := now.Add(-23 * time.Hour).Unix()
	if got := a.mt.get().LastCompact; got != want {
		t.Fatalf("hata sonrası LastCompact=%d, beklenen %d (bir saat sonra yeniden denenmeli)", got, want)
	}
	if now.Unix()-a.mt.get().LastCompact >= 24*3600 {
		t.Fatal("sonraki turda hemen yeniden denenecek")
	}
}

func TestMaintUpdateConcurrentWritesStaySerialized(t *testing.T) {
	m := newMaint(filepath.Join(t.TempDir(), "maint.json"))
	var wg sync.WaitGroup
	for i := 1; i <= 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.update(func(c *MaintCfg) { c.LogDays = i }); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	// diskteki son durum bellektekiyle aynı olmalı (yazmalar sıralı)
	var disk MaintCfg
	b, _ := os.ReadFile(m.path)
	if err := json.Unmarshal(b, &disk); err != nil {
		t.Fatal(err)
	}
	if disk.LogDays != m.get().LogDays {
		t.Fatalf("disk=%d bellek=%d: eski yazma yenisini ezdi", disk.LogDays, m.get().LogDays)
	}
}

func TestReportPermsCoverMaintJSONAndBackups(t *testing.T) {
	a, _, _ := maintApp(t)
	perms := func() Check {
		for _, c := range a.buildReport(refLang).Checks {
			if c.ID == "perms" {
				return c
			}
		}
		t.Fatal("perms denetimi yok")
		return Check{}
	}
	os.Chmod(a.dataDir, 0o700)
	os.WriteFile(filepath.Join(a.dataDir, "maint.json"), []byte("{}"), 0o600)
	os.MkdirAll(a.backupDir(), 0o700)
	if c := perms(); c.Level != "ok" {
		t.Fatalf("sıkı izinlerde ok beklenir: %s %s", c.Level, c.Detail)
	}
	os.Chmod(filepath.Join(a.dataDir, "maint.json"), 0o644)
	os.Chmod(a.backupDir(), 0o755)
	c := perms()
	if c.Level != "warn" || !strings.Contains(c.Detail, "maint.json") || !strings.Contains(c.Detail, "backups") {
		t.Fatalf("gevşek maint.json ve backups yakalanmalı: %s %s", c.Level, c.Detail)
	}
}

func TestApplyBackupFilesMovesAbsentToBak(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.json"), []byte("eski-sunucu"), 0o600)
	os.WriteFile(filepath.Join(dir, "users.json"), []byte("eski-kullanicilar"), 0o600)
	if err := applyBackupFiles(dir, map[string][]byte{"server.json": []byte("yeni-sunucu")}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "server.json")); string(b) != "yeni-sunucu" {
		t.Fatalf("server.json: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "server.json.bak")); string(b) != "eski-sunucu" {
		t.Fatalf("server.json.bak: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "users.json")); !os.IsNotExist(err) {
		t.Fatalf("yedekte olmayan users.json yerinde kaldı: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "users.json.bak")); string(b) != "eski-kullanicilar" {
		t.Fatalf("users.json.bak: %q", b)
	}
}

func TestApplyBackupFilesRollsBackOnWriteError(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.json"), []byte("eski-sunucu"), 0o600)
	os.WriteFile(filepath.Join(dir, "admin.json"), []byte("eski-yonetici"), 0o600)
	os.WriteFile(filepath.Join(dir, "users.json"), []byte("eski-kullanicilar"), 0o600)
	// peers.json dolu bir dizin: üzerine rename başarısız olur (server.json'dan sonra, admin.json'dan önce yazılır)
	if err := os.MkdirAll(filepath.Join(dir, "peers.json", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := map[string][]byte{"server.json": []byte("yeni-sunucu"), "peers.json": []byte("[]"), "admin.json": []byte("yeni-yonetici")}
	if err := applyBackupFiles(dir, got); err == nil {
		t.Fatal("yazma hatası bekleniyordu")
	}
	for name, want := range map[string]string{"server.json": "eski-sunucu", "admin.json": "eski-yonetici", "users.json": "eski-kullanicilar"} {
		if b, _ := os.ReadFile(filepath.Join(dir, name)); string(b) != want {
			t.Fatalf("%s geri alınmadı: %q", name, b)
		}
	}
}

func TestRestoreWebWriteErrorIs500(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	a.restartF = func() { t.Error("başarısız geri yüklemede yeniden başlatılmamalı") }
	rec := post(h, "/api/backups", `{"owner_password":"correct-horse-battery"}`, c)
	var nm struct{ Name string }
	json.Unmarshal(rec.Body.Bytes(), &nm)
	// veri dizini salt okunur olunca geçici dosya oluşturulamaz (yedekler alt dizinde, yazılabilir kalır)
	if err := os.Chmod(a.dataDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(a.dataDir, 0o700) })
	rr := post(h, "/api/backups/"+nm.Name+"/restore", `{"owner_password":"correct-horse-battery"}`, c)
	if rr.Code != 500 {
		t.Fatalf("disk hatası 500 olmalı: %d %s", rr.Code, rr.Body.String())
	}
}

// Yedek listesi türden bağımsız olarak yeniden eskiye sıralanır (ad türle başladığı için ada göre sıralamak yanlış).
func TestListBackupsNewestFirst(t *testing.T) {
	a, _, _ := maintApp(t)
	dir := filepath.Join(a.dataDir, "backups")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-time.Hour)
	for i, n := range []string{"kut-oto-20260101-000000.tar.gz", "kut-elle-20260101-000000.tar.gz", "kut-oncesi-20260101-000000.tar.gz"} {
		p := filepath.Join(dir, n)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		mt := base.Add(time.Duration(i) * time.Minute) // oto en eski, oncesi en yeni
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, b := range a.listBackups() {
		got = append(got, b.Kind)
	}
	if strings.Join(got, ",") != "oncesi,elle,oto" {
		t.Fatalf("sıra %v, beklenen oncesi,elle,oto", got)
	}
}

// ---- Yedek yükleme (multipart) ----

// formPart: multipart gövdesinin bir alanı; file=true ise dosya alanı olarak yazılır.
type formPart struct {
	name, value string
	file        bool
}

func fileField(b []byte) formPart       { return formPart{name: "file", value: string(b), file: true} }
func textField(name, v string) formPart { return formPart{name: name, value: v} }

// uploadForm: /api/backups/upload'a multipart/form-data gövdesiyle istek atar (sözleşme 7).
func uploadForm(h http.Handler, c *http.Cookie, parts ...formPart) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for _, p := range parts {
		if p.file {
			fw, _ := mw.CreateFormFile(p.name, "kut-yedek.tar.gz")
			_, _ = fw.Write([]byte(p.value))
		} else {
			_ = mw.WriteField(p.name, p.value)
		}
	}
	_ = mw.Close()
	return sendAs(h, "POST", "/api/backups/upload", buf.String(), c, map[string]string{"Content-Type": mw.FormDataContentType()})
}

// errBody: kodlu hata yanıtının gövdesi.
type errBody struct {
	Code     string         `json:"code"`
	Params   map[string]any `json:"params"`
	Error    string         `json:"error"`
	NeedPass bool           `json:"need_pass"`
}

func bodyOf(t *testing.T, r *httptest.ResponseRecorder) errBody {
	t.Helper()
	var b errBody
	if err := json.Unmarshal(r.Body.Bytes(), &b); err != nil {
		t.Fatalf("yanıt JSON değil: %v %s", err, r.Body)
	}
	return b
}

// Yükleme gövdesi multipart: alanlar file, passphrase, endpoint, owner_password, owner_code, inspect.
// Eksik dosya, bilinmeyen ya da yinelenen alan, multipart olmayan gövde reddedilir; hiçbir şey yazılmaz.
func TestBackupUploadMultipartFields(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	a.restartF = func() {}
	restartDelay = 10 * time.Millisecond
	blob, _, err := buildBackup(a.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	const pw = "correct-horse-battery"
	before, _ := os.ReadFile(filepath.Join(a.dataDir, "server.json"))
	for _, tc := range []struct {
		label  string
		parts  []formPart
		status int
		code   string
	}{
		{"dosyasız", []formPart{textField("owner_password", pw)}, 400, "backup.upload_no_file"},
		{"bilinmeyen alan", []formPart{fileField(blob), textField("owner_password", pw), textField("restore_all", "1")}, 400, "backup.upload_unknown_field"},
		{"yinelenen alan", []formPart{fileField(blob), textField("owner_password", pw), textField("owner_password", pw)}, 400, "backup.upload_duplicate_field"},
		{"iki dosya", []formPart{fileField(blob), fileField(blob), textField("owner_password", pw)}, 400, "backup.upload_duplicate_field"},
		{"geçersiz inspect", []formPart{fileField(blob), textField("inspect", "evet")}, 400, "backup.upload_bad_form"},
		{"sahip parolası yanlış", []formPart{fileField(blob), textField("owner_password", "yanlis-parola-xyz")}, 403, "backup.owner_bad_password"},
		{"sahip parolasız", []formPart{fileField(blob)}, 403, "backup.owner_bad_password"},
		{"çöp dosya", []formPart{fileField([]byte("bu bir yedek degil")), textField("owner_password", pw)}, 400, "backup.unreadable"},
	} {
		r := uploadForm(h, c, tc.parts...)
		if b := bodyOf(t, r); r.Code != tc.status || b.Code != tc.code {
			t.Errorf("%s: %d %q, beklenen %d %q (%s)", tc.label, r.Code, b.Code, tc.status, tc.code, r.Body)
		}
	}
	// multipart olmayan gövde (eski istemci: ham dosya + başlıklar) reddedilir
	raw := sendAs(h, "POST", "/api/backups/upload", string(blob), c, map[string]string{"X-Kut-Owner-Pass": pw})
	if b := bodyOf(t, raw); raw.Code != 400 || b.Code != "backup.upload_bad_form" {
		t.Errorf("ham gövde: %d %s", raw.Code, raw.Body)
	}
	// sahip parolası artık başlıktan okunmaz: başlıkta doğru parola, formda yok → 403
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "kut.tar.gz")
	_, _ = fw.Write(blob)
	_ = mw.Close()
	hdr := sendAs(h, "POST", "/api/backups/upload", buf.String(), c, map[string]string{"Content-Type": mw.FormDataContentType(), "X-Kut-Owner-Pass": pw})
	if hdr.Code != 403 {
		t.Errorf("başlıktaki sahip parolası okunmamalı: %d %s", hdr.Code, hdr.Body)
	}
	if after, _ := os.ReadFile(filepath.Join(a.dataDir, "server.json")); !bytes.Equal(before, after) {
		t.Fatal("reddedilen yükleme veriyi değiştirdi")
	}
	// önizleme: sahip parolası istemez, hiçbir şey yazmaz
	pv := uploadForm(h, c, fileField(blob), textField("inspect", "1"))
	var p backupPreview
	if json.Unmarshal(pv.Body.Bytes(), &p) != nil || pv.Code != 200 || p.Devices != 1 || p.Subnet != "10.77.0.0/24" {
		t.Fatalf("önizleme: %d %s", pv.Code, pv.Body)
	}
	if len(a.listBackups()) != 0 {
		t.Fatal("önizleme yedek almamalı")
	}
	// boş inspect = geri yükleme; tüm alanlar bir kez
	ok := uploadForm(h, c, fileField(blob), textField("inspect", ""), textField("passphrase", ""), textField("endpoint", ""), textField("owner_password", pw), textField("owner_code", ""))
	if ok.Code != 200 || !strings.Contains(ok.Body.String(), `"ok":true`) {
		t.Fatalf("geri yükleme: %d %s", ok.Code, ok.Body)
	}
}

// Boyut sınırı mevcutla aynı (64 MB, gövdenin tamamı): aşan yükleme 413 ve kodlu hata.
func TestBackupUploadTooLarge(t *testing.T) {
	_, h, c := maintApp(t)
	r := uploadForm(h, c, fileField(make([]byte, 64<<20+1)), textField("owner_password", "correct-horse-battery"))
	if b := bodyOf(t, r); r.Code != http.StatusRequestEntityTooLarge || b.Code != "backup.too_large" {
		t.Fatalf("büyük dosya: %d %s", r.Code, r.Body)
	}
}

// Geri yüklemede yedek önce açılır ve doğrulanır, sonra sahip doğrulanır: yanlış yedek parolası 2FA
// kodunu (burada tek kullanımlık kurtarma kodunu) harcamamalı. Hem adla geri yükleme hem yükleme.
func TestRestoreBadPassphraseKeepsOwnerCode(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	a.restartF = func() {}
	restartDelay = 10 * time.Millisecond
	_, rcv := enableOwnerTOTP(t, h, c)
	const bpass = "yedek-parolasi-1"
	a.mt.update(func(m *MaintCfg) { m.Backup.Pass = bpass })
	name, err := a.makeBackup("elle", false)
	if err != nil || !strings.HasSuffix(name, ".enc") {
		t.Fatalf("şifreli yedek: %q %v", name, err)
	}
	raw, _ := os.ReadFile(filepath.Join(a.backupDir(), name))
	a.mt.update(func(m *MaintCfg) { m.Backup.Pass = "" }) // kayıtlı parola yok: istekteki parola tek kaynak

	body := func(pass, code string) string {
		return `{"passphrase":"` + pass + `","owner_password":"correct-horse-battery","owner_code":"` + code + `"}`
	}
	r := post(h, "/api/backups/"+name+"/restore", body("yanlis-parola-9", rcv[0]), c)
	if r.Code != http.StatusUnprocessableEntity || !bodyOf(t, r).NeedPass {
		t.Fatalf("yanlış yedek parolası: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/backups/"+name+"/restore", body(bpass, rcv[0]), c); r.Code != 200 {
		t.Fatalf("aynı kurtarma kodu geçerli kalmalıydı: %d %s", r.Code, r.Body)
	}

	up := func(pass, code string) *httptest.ResponseRecorder {
		return uploadForm(h, c, fileField(raw), textField("passphrase", pass), textField("owner_password", "correct-horse-battery"), textField("owner_code", code))
	}
	if r := up("yanlis-parola-9", rcv[1]); r.Code != http.StatusUnprocessableEntity {
		t.Fatalf("yükleme, yanlış yedek parolası: %d %s", r.Code, r.Body)
	}
	if r := up(bpass, rcv[1]); r.Code != 200 {
		t.Fatalf("yükleme, aynı kurtarma kodu geçerli kalmalıydı: %d %s", r.Code, r.Body)
	}
}

// Bakım/bildirim/günlük katmanının kaynakta andığı her katalog anahtarı iki dilde de var olmalı (yazım hatası
// T'de sessizce anahtarın kendisine düşerdi). ue("x") / errCode(w, s, "x") → err.x; "log.…", "notify.…" doğrudan.
func TestMaintCatalogKeysExist(t *testing.T) {
	codeRe := regexp.MustCompile(`(?:\bue\(|\berrCode\(w, [^,]+, )"([a-z_.]+)"`)
	keyRe := regexp.MustCompile(`"((?:log|notify|logexport)\.[a-z_]+(?:\.[a-z_]+)*)"`)
	has := func(lang, k string) bool {
		_, one := catalogs[lang][k]
		_, many := catalogs[lang][k+".other"]
		return one || many
	}
	n := 0
	for _, f := range []string{"maint.go", "backup.go", "notify.go", "export.go", "monitor.go", "about.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, m := range codeRe.FindAllStringSubmatch(string(src), -1) {
			keys = append(keys, "err."+m[1])
		}
		rest := codeRe.ReplaceAllString(string(src), "") // ue("notify.x") bir hata kodudur, "notify.x" anahtarı değil
		for _, m := range keyRe.FindAllStringSubmatch(rest, -1) {
			if strings.HasSuffix(m[1], ".json") { // dosya adı (notify.json), anahtar değil
				continue
			}
			keys = append(keys, m[1])
		}
		for _, k := range keys {
			n++
			for _, l := range langs {
				if !has(l, k) {
					t.Errorf("%s: %s kataloğunda %q yok", f, l, k)
				}
			}
		}
	}
	if n < 40 {
		t.Fatalf("tarama çok az anahtar buldu (%d): desen kodla uyuşmuyor", n)
	}
}

// Bakım/yedek olayları katalog anahtarıyla yazılır (sözleşme 4).
func TestMaintLogEventsCoded(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	if r := sendAs(h, "PUT", "/api/maint", `{"enabled":true,"freq":"daily","time":"03:30","keep":7,"log_days":90,"new_pass":"yeni-yedek-parolasi","owner_password":"correct-horse-battery"}`, c, nil); r.Code != 200 {
		t.Fatalf("ayar: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/backups", `{"owner_password":"correct-horse-battery"}`, c); r.Code != 200 {
		t.Fatalf("yedek: %d %s", r.Code, r.Body)
	}
	var codes []string
	for _, e := range a.act.list(10) {
		if e.Code == "" || e.Text == "" || e.Text == e.Code {
			t.Errorf("kodsuz ya da çevrilmemiş olay: %+v", e)
		}
		codes = append(codes, e.Code)
	}
	want := []string{"log.backup.manual", "log.settings.maint_changed", "log.settings.backup_pass_set"}
	if !slices.Equal(codes, want) {
		t.Fatalf("olay kodları %v, beklenen %v", codes, want)
	}
	if e := a.act.list(1)[0]; !strings.HasPrefix(fmt.Sprint(e.Params["name"]), "kut-elle-") {
		t.Fatalf("yedek adı parametrede olmalı: %+v", e)
	}
}

// Dışa aktarılan CSV'nin başlık satırı sunucu dilinde (olay metinleri gibi).
func TestLogExportHeaderFollowsServerLang(t *testing.T) {
	a, h, c := maintApp(t)
	s := a.getSrv()
	cfg := s.cfg()
	cfg.Lang = "en"
	s.Settings = &cfg
	a.setSrv(s)
	rq := httptest.NewRequest(http.MethodGet, "/api/activity/export", nil)
	rq.AddCookie(c)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rq)
	want := strings.Join([]string{T("en", "logexport.col.time", nil), T("en", "logexport.col.source", nil), T("en", "logexport.col.user", nil), T("en", "logexport.col.event", nil), T("en", "logexport.col.text", nil)}, ",")
	if rr.Code != 200 || !strings.HasPrefix(rr.Body.String(), want+"\n") || strings.HasPrefix(want, "logexport") {
		t.Fatalf("başlık: %d %q, beklenen %q", rr.Code, rr.Body.String(), want)
	}
}

// Bakım ve yedek uç noktalarının hataları kodludur (sözleşme 1): istemci metni kendi dilinde yazar.
func TestMaintErrorsAreCoded(t *testing.T) {
	_, h, c := maintApp(t)
	put := func(body string) *httptest.ResponseRecorder {
		return sendAs(h, "PUT", "/api/maint", body, c, nil)
	}
	for _, tc := range []struct{ body, code string }{
		{`{"enabled":true,"freq":"hourly","time":"03:30","keep":7}`, "maint.bad_freq"},
		{`{"enabled":true,"freq":"daily","time":"3:30","keep":7}`, "maint.bad_time"},
		{`{"enabled":true,"freq":"daily","time":"03:30","keep":0}`, "maint.bad_keep"},
		{`{"enabled":true,"freq":"daily","time":"03:30","keep":7,"log_days":3}`, "maint.bad_log_days"},
	} {
		if r := put(tc.body); r.Code != 400 || bodyOf(t, r).Code != tc.code {
			t.Errorf("%s: %d %s, beklenen %s", tc.body, r.Code, r.Body, tc.code)
		}
	}
	if r := sendAs(h, "DELETE", "/api/backups/kut-elle-20200101-000001.tar.gz", "", c, nil); r.Code != 404 || bodyOf(t, r).Code != "backup.not_found" {
		t.Errorf("olmayan yedek: %d %s", r.Code, r.Body)
	}
	if r := sendAs(h, "DELETE", "/api/backups/x.tar.gz", "", c, nil); r.Code != 400 || bodyOf(t, r).Code != "backup.bad_name" {
		t.Errorf("geçersiz ad: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/backups", `{"owner_password":"yanlis-parola-xyz"}`, c); r.Code != 403 || bodyOf(t, r).Code != "backup.owner_bad_password" {
		t.Errorf("yanlış sahip parolası: %d %s", r.Code, r.Body)
	}
}

// Yedekteki kayıt adı saldırgan denetimindedir: `kut restore -f` terminale yazarken kaçış dizileri
// çalışmamalı (Quote ile kaçışlanır).
func TestParseBackupEscapesEntryName(t *testing.T) {
	evil := "x\x1b]0;T\a\r\nY"
	_, err := parseBackup(tarGz(t, []tarEntry{{name: evil, data: []byte("x")}}))
	if err == nil {
		t.Fatal("beklenmeyen kayıt reddedilmeliydi")
	}
	for _, lang := range []string{"tr", "en"} {
		out := cliErrText(lang, err)
		for _, bad := range []string{"\x1b", "\a", "\r", "\n"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: çıktıda ham %q baytı var: %q", lang, bad, out)
			}
		}
		if !strings.Contains(out, `\x1b`) {
			t.Errorf("%s: kaçışlı \\x1b yok: %q", lang, out)
		}
	}
}
