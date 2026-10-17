package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEncryptRoundTrip(t *testing.T) {
	plain := bytes.Repeat([]byte("kut yedek içeriği "), 500)
	enc, err := encryptBackup(plain, "doğru-parola-1")
	if err != nil {
		t.Fatal(err)
	}
	if !isEncrypted(enc) || bytes.Contains(enc, []byte("kut yedek")) {
		t.Fatal("şifreli çıktı düz metin sızdırıyor")
	}
	got, err := decryptBackup(enc, "doğru-parola-1")
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("çözme: %v", err)
	}
	if _, err := decryptBackup(enc, "yanlış-parola-1"); err != errBadPass {
		t.Fatalf("yanlış parola: %v", err)
	}
	// iki şifreleme aynı çıktıyı vermemeli (tuz/nonce rastgele)
	enc2, _ := encryptBackup(plain, "doğru-parola-1")
	if bytes.Equal(enc, enc2) {
		t.Fatal("tuz/nonce rastgele değil")
	}
	// başlık oynanırsa (AAD) ya da veri bozulursa çözülemez
	for _, pos := range []int{len(encMagic) + 6, encHeaderLen + 10, len(enc) - 1} {
		bad := append([]byte(nil), enc...)
		bad[pos] ^= 0x01
		if _, err := decryptBackup(bad, "doğru-parola-1"); err == nil {
			t.Fatalf("bozuk veri kabul edildi (konum %d)", pos)
		}
	}
	// aşırı yineleme sayısı CPU'yu tüketmesin
	huge := append([]byte(nil), enc...)
	huge[len(encMagic)] = 0xff
	if _, err := decryptBackup(huge, "x"); err == nil || err == errBadPass {
		t.Fatalf("aşırı yineleme reddedilmeli: %v", err)
	}
	if _, err := decryptBackup(enc[:20], "x"); err == nil {
		t.Fatal("kesik dosya reddedilmeli")
	}
	for _, p := range []string{"kısa", strings.Repeat("a", 201), "iki\nsatır-parola"} {
		if checkPass(p) == nil {
			t.Fatalf("parola kabul edildi: %q", p)
		}
	}
	if checkPass("yeterince-uzun") != nil {
		t.Fatal("geçerli parola reddedildi")
	}
}

func rq(h http.Handler, method, path string, body []byte, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("X-Kut", "1")
	r.RemoteAddr = "198.51.100.7:4000"
	r.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestEncryptedBackupAPI(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	restarted := make(chan struct{}, 4)
	a.restartF = func() { restarted <- struct{}{} }
	restartDelay = 10 * time.Millisecond
	const pass = "şifre-Çok-güçlü-1"

	base := `{"enabled":true,"freq":"daily","time":"03:30","weekday":1,"keep":7,"log_days":90,"log_archive":true,"archive_months":12,"owner_password":"correct-horse-battery"`
	put := func(extra string) *httptest.ResponseRecorder {
		return rq(h, "PUT", "/api/maint", []byte(base+extra+`}`), c)
	}
	if r := put(`,"new_pass":"kısa"`); r.Code != 400 {
		t.Fatalf("kısa parola: %d", r.Code)
	}
	r := put(`,"new_pass":"` + pass + `"`)
	if r.Code != 200 {
		t.Fatalf("parola ayarı: %d %s", r.Code, r.Body)
	}
	if strings.Contains(r.Body.String(), pass) || !strings.Contains(r.Body.String(), `"has_pass":true`) {
		t.Fatalf("parola yanıtta sızdı ya da has_pass yok: %s", r.Body)
	}
	if g := rq(h, "GET", "/api/maint", nil, c); strings.Contains(g.Body.String(), pass) {
		t.Fatal("GET /api/maint parolayı döndürüyor")
	}
	if fi, err := os.Stat(filepath.Join(a.dataDir, "maint.json")); err == nil && fi.Mode().Perm() != 0o600 {
		t.Fatalf("maint.json izni: %v", fi.Mode().Perm())
	}

	// elle yedek şifreli üretilir
	br := rq(h, "POST", "/api/backups", []byte(`{"owner_password":"correct-horse-battery"}`), c)
	var nm struct{ Name string }
	json.Unmarshal(br.Body.Bytes(), &nm)
	if !strings.HasSuffix(nm.Name, ".enc") || !backupNameRe.MatchString(nm.Name) {
		t.Fatalf("ad: %q", nm.Name)
	}
	raw, _ := os.ReadFile(filepath.Join(a.backupDir(), nm.Name))
	if !isEncrypted(raw) || bytes.Contains(raw, []byte("private_key")) {
		t.Fatal("yedek diskte şifresiz")
	}
	if l := a.listBackups(); len(l) != 1 || !l[0].Enc || l[0].Kind != "elle" {
		t.Fatalf("liste: %+v", l)
	}

	// kayıtlı parolayla önizleme (parola yazmadan)
	pv := rq(h, "POST", "/api/backups/"+nm.Name+"/restore", []byte(`{"inspect":true}`), c)
	if pv.Code != 200 {
		t.Fatalf("önizleme: %d %s", pv.Code, pv.Body)
	}
	var p backupPreview
	json.Unmarshal(pv.Body.Bytes(), &p)
	if !p.Encrypted || p.Devices != 1 || p.Subnet == "" || p.Endpoint != "1.2.3.4" || strings.Contains(p.ThisEndpoint, ":") {
		t.Fatalf("önizleme içeriği: %+v", p)
	}

	// parolayı sunucudan sil: artık parola istenmeli
	if r := put(`,"clear_pass":true`); r.Code != 200 || !strings.Contains(r.Body.String(), `"has_pass":false`) {
		t.Fatalf("parola silme: %d %s", r.Code, r.Body)
	}
	for _, body := range []string{`{"inspect":true}`, `{"inspect":true,"passphrase":"yanlis-parola-9"}`} {
		r := rq(h, "POST", "/api/backups/"+nm.Name+"/restore", []byte(body), c)
		if r.Code != 422 || !strings.Contains(r.Body.String(), `"need_pass":true`) {
			t.Fatalf("parola istenmeli (%s): %d %s", body, r.Code, r.Body)
		}
	}
	// yeni yedek artık düz
	br = rq(h, "POST", "/api/backups", []byte(`{"owner_password":"correct-horse-battery"}`), c)
	var nm2 struct{ Name string }
	json.Unmarshal(br.Body.Bytes(), &nm2)
	if strings.HasSuffix(nm2.Name, ".enc") {
		t.Fatal("parola silindikten sonra yedek şifreli")
	}

	// dosyadan yükleme: Türkçe parola multipart alanında (kodlama gerekmez); önizleme hiçbir şey yazmaz
	before, _ := os.ReadFile(filepath.Join(a.dataDir, "server.json"))
	if r := uploadForm(h, c, fileField(raw), textField("passphrase", pass), textField("inspect", "1")); r.Code != 200 {
		t.Fatalf("yükleme önizleme: %d %s", r.Code, r.Body)
	}
	if r := uploadForm(h, c, fileField(raw), textField("inspect", "1")); r.Code != 422 {
		t.Fatalf("parolasız yükleme: %d", r.Code)
	}
	// geçersiz uç nokta reddedilir, veri değişmez
	if r := uploadForm(h, c, fileField(raw), textField("passphrase", pass), textField("endpoint", "kötü host!"), textField("owner_password", "correct-horse-battery")); r.Code != 400 {
		t.Fatalf("geçersiz uç nokta: %d %s", r.Code, r.Body)
	}
	if after, _ := os.ReadFile(filepath.Join(a.dataDir, "server.json")); !bytes.Equal(before, after) {
		t.Fatal("önizleme/başarısız istek veriyi değiştirdi")
	}

	// uç nokta değiştirerek geri yükleme (sunucu taşıma)
	rr := rq(h, "POST", "/api/backups/"+nm.Name+"/restore", []byte(`{"passphrase":"`+pass+`","endpoint":"203.0.113.9","owner_password":"correct-horse-battery"}`), c)
	if rr.Code != 200 {
		t.Fatalf("geri yükleme: %d %s", rr.Code, rr.Body)
	}
	select {
	case <-restarted:
	case <-time.After(2 * time.Second):
		t.Fatal("yeniden başlatma çağrılmadı")
	}
	var srv Server
	b, _ := os.ReadFile(filepath.Join(a.dataDir, "server.json"))
	if json.Unmarshal(b, &srv) != nil || srv.Endpoint != "203.0.113.9" || srv.PrivateKey == "" {
		t.Fatalf("uç nokta/anahtar: %+v", srv)
	}
	var was Server
	json.Unmarshal(before, &was)
	if srv.PrivateKey != was.PrivateKey || srv.Port != was.Port || srv.Subnet != was.Subnet {
		t.Fatal("uç nokta dışındaki alanlar değişmemeliydi")
	}
}

func TestPreviewSameServer(t *testing.T) {
	a, _, _ := maintApp(t)
	b, _, _ := buildBackup(a.dataDir)
	got, err := parseBackup(b)
	if err != nil {
		t.Fatal(err)
	}
	var s Server
	json.Unmarshal(got["server.json"], &s)
	a.srv.PrivateKey = s.PrivateKey
	if !a.previewOf(got, false).SameServer {
		t.Fatal("aynı anahtar: same_server true olmalı")
	}
	a.srv.PrivateKey = "baska"
	if a.previewOf(got, false).SameServer {
		t.Fatal("farklı anahtar: same_server false olmalı")
	}
}

func TestCLIEncryptedBackupRestoreEndpoint(t *testing.T) {
	src := t.TempDir()
	spriv, spub, _ := mustKeys(t)
	os.WriteFile(filepath.Join(src, "server.json"), []byte(`{"private_key":"`+spriv+`","public_key":"`+spub+`","subnet":"10.77.0.0/24","endpoint":"1.2.3.4","port":51820,"iface":"wg0","conf_path":"/etc/wireguard/wg0.conf"}`), 0o600)
	os.WriteFile(filepath.Join(src, "admin.json"), []byte(`{}`), 0o600)
	t.Setenv("KUT_BACKUP_PASSWORD", "cli-parola-123")
	out := filepath.Join(t.TempDir(), "b.tar.gz.enc")
	if err := cmdBackup([]string{"-data", src, "-o", out, "-encrypt"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	if !isEncrypted(raw) {
		t.Fatal("CLI yedeği şifreli değil")
	}
	// yanlış parola
	dst := t.TempDir()
	t.Setenv("KUT_BACKUP_PASSWORD", "yanlis-parola-1")
	if err := cmdRestore([]string{"-data", dst, "-f", out}); err == nil {
		t.Fatal("yanlış parolayla geri yüklendi")
	}
	if _, err := os.Stat(filepath.Join(dst, "server.json")); err == nil {
		t.Fatal("başarısız geri yüklemede dosya yazıldı")
	}
	t.Setenv("KUT_BACKUP_PASSWORD", "cli-parola-123")
	if err := cmdRestore([]string{"-data", dst, "-f", out, "-endpoint", "vpn.example.com"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dst, "server.json"))
	var s Server
	json.Unmarshal(b, &s)
	if s.Endpoint != "vpn.example.com" || s.PrivateKey != spriv {
		t.Fatalf("%+v", s)
	}
	// geçersiz uç nokta: hiçbir şey yazılmaz
	dst2 := t.TempDir()
	if err := cmdRestore([]string{"-data", dst2, "-f", out, "-endpoint", "a b"}); err == nil {
		t.Fatal("geçersiz uç nokta kabul edildi")
	}
}

// encryptCheap: encryptBackup'ın dosya biçimi, ama başlığın kabul ettiği en düşük yinelemeyle (testte çok sayıda
// çözme denemesi PBKDF2'nin 600 bin turunu beklemesin). Çözme yolu üretimdekiyle aynıdır.
func encryptCheap(t *testing.T, plain []byte, pass string) []byte {
	t.Helper()
	const iters = 1000
	salt, nonce := make([]byte, encSaltLen), make([]byte, 12)
	rand.Read(salt)
	rand.Read(nonce)
	key, err := deriveKey(pass, salt, iters)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(blk)
	hdr := binary.BigEndian.AppendUint32([]byte(encMagic), iters)
	hdr = append(append(hdr, salt...), nonce...)
	return gcm.Seal(hdr, nonce, plain, hdr[:encHeaderLen-12])
}

// Yedek parolası denemeleri (adla geri yükleme, önizleme, yükleme) IP başına hız sınırına girer: kovası dolunca
// doğru parola da 429 alır; doğru parola kovayı sıfırlar. Yükleme aynı kovayı paylaşır.
func TestBackupPassphraseIsRateLimited(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	plain, _, err := buildBackup(a.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	const good, bad = "dogru-yedek-parolasi", "yanlis-yedek-parolasi"
	enc := encryptCheap(t, plain, good)
	if _, err := decryptBackup(enc, good); err != nil {
		t.Fatalf("test yedeği çözülemiyor: %v", err)
	}
	name := "kut-elle-20260101-000000.tar.gz.enc"
	os.MkdirAll(a.backupDir(), 0o700)
	if err := os.WriteFile(filepath.Join(a.backupDir(), name), enc, 0o600); err != nil {
		t.Fatal(err)
	}
	try := func(pass string) int {
		b, _ := json.Marshal(map[string]any{"inspect": true, "passphrase": pass})
		return rq(h, "POST", "/api/backups/"+name+"/restore", b, c).Code
	}
	for i := range maxFails - 1 {
		if got := try(bad); got != http.StatusUnprocessableEntity {
			t.Fatalf("%d. yanlış parola: %d", i+1, got)
		}
	}
	if got := try(good); got != http.StatusOK {
		t.Fatalf("sınır dolmadan doğru parola: %d", got)
	}
	var codes []int
	for range maxFails + 1 {
		codes = append(codes, try(bad))
	}
	if codes[maxFails-1] != http.StatusUnprocessableEntity || codes[maxFails] != http.StatusTooManyRequests {
		t.Fatalf("kodlar %v: doğru parola sıfırlamalı; ilk %d yanlış deneme 422, sonrası 429 olmalı", codes, maxFails)
	}
	if got := try(good); got != http.StatusTooManyRequests {
		t.Fatalf("kova doluyken doğru parola da beklemeli: %d", got)
	}
	up := uploadForm(h, c, fileField(enc), textField("passphrase", good), textField("inspect", "1"))
	if up.Code != http.StatusTooManyRequests || bodyOf(t, up).Code != "too_many_attempts" {
		t.Fatalf("yükleme aynı kovayı paylaşmalı: %d %s", up.Code, up.Body)
	}
	// parola gerekmeyen (şifresiz) yedek sınırdan etkilenmez
	if up := uploadForm(h, c, fileField(plain), textField("inspect", "1")); up.Code != http.StatusOK {
		t.Fatalf("şifresiz yedek önizlemesi: %d %s", up.Code, up.Body)
	}
}
