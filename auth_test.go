package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func getCode(h http.Handler, path string, c *http.Cookie) int {
	req := httptest.NewRequest("GET", path, nil)
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func patch(h http.Handler, path, body string, c *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("PATCH", path, strings.NewReader(body))
	req.Header.Set("X-Kut", "1")
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Eşzamanlı yanlış parolalar sınırı aşmamalı: sayım doğrulamadan önce yapılır.
func TestLoginLimitHoldsUnderConcurrency(t *testing.T) {
	_, h := v5App(t)
	const n = 20
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = post(h, "/api/login", `{"password":"yanlis-parola-xyz"}`, nil).Code
		}()
	}
	wg.Wait()
	var unauth, limited int
	for _, c := range codes {
		switch c {
		case http.StatusUnauthorized:
			unauth++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("beklenmeyen kod %d", c)
		}
	}
	if unauth > maxFails || limited != n-unauth {
		t.Fatalf("401=%d 429=%d; en çok %d deneme doğrulanmalı", unauth, limited, maxFails)
	}
}

// Denetim senaryosu: aynı IP'den sahibe 4 yanlış parola + izleyicinin 1 doğru girişi, 3 tur. İzleyicinin başarısı
// sahibe yönelik denemelerin sayacını sıfırlamamalı: sahip için 6. denemeden itibaren 429.
func TestViewerLoginDoesNotResetOwnerFailures(t *testing.T) {
	_, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	if r := post(h, "/api/users", `{"name":"ayse","password":"ayse-long-password","role":"viewer"}`, owner); r.Code != 200 {
		t.Fatalf("kullanıcı ekle: %d %s", r.Code, r.Body)
	}
	var codes []int
	for range 3 {
		for range 4 {
			codes = append(codes, post(h, "/api/login", `{"password":"yanlis-parola-xyz"}`, nil).Code)
		}
		if r := post(h, "/api/login", `{"username":"ayse","password":"ayse-long-password"}`, nil); r.Code != 200 {
			t.Fatalf("izleyici girişi: %d %s", r.Code, r.Body)
		}
	}
	for i, c := range codes {
		want := http.StatusUnauthorized
		if i >= maxFails {
			want = http.StatusTooManyRequests
		}
		if c != want {
			t.Fatalf("sahibe %d. deneme: %d, beklenen %d (tüm kodlar %v)", i+1, c, want, codes)
		}
	}
}

// Hesap başına küresel kova: farklı IP'lerden aynı hesaba yapılan denemeler de sınırlanır.
func TestLimiterAccountBucketAcrossIPs(t *testing.T) {
	l := newLimiter()
	ok := 0
	for i := range 50 {
		if l.allow(fmt.Sprintf("192.0.2.%d", i), ownerName) {
			ok++
		}
	}
	if ok != maxFails*4 {
		t.Fatalf("farklı IP'lerden %d deneme geçti, hesap başına %d olmalı", ok, maxFails*4)
	}
	if !l.allow("192.0.2.1", "ayse") {
		t.Fatal("başka hesap etkilenmemeli")
	}
}

// IP başına toplam kova: kullanıcı adını değiştirerek aynı IP'den sınırsız (PBKDF2'li) deneme yapılamaz.
func TestLimiterIPBucketAcrossNames(t *testing.T) {
	l := newLimiter()
	ok := 0
	for i := range 50 {
		if l.allow("198.51.100.7", fmt.Sprintf("yok%d", i)) {
			ok++
		}
	}
	if ok != maxFails*4 {
		t.Fatalf("aynı IP'den farklı adlarla %d deneme geçti, en çok %d olmalı", ok, maxFails*4)
	}
	// başarı yalnızca kendi ip|kullanıcı kovasını sıfırlar
	l2 := newLimiter()
	for range maxFails {
		l2.allow("198.51.100.7", ownerName)
	}
	l2.allow("198.51.100.7", "ayse")
	l2.succeed("198.51.100.7", "ayse")
	if l2.allow("198.51.100.7", ownerName) {
		t.Fatal("izleyicinin başarısı sahibin kovasını sıfırladı")
	}
	// başarılı girişler IP kovasını doldurmaz (aynı NAT arkasındaki meşru kullanıcılar kilitlenmesin)
	l3 := newLimiter()
	for i := range maxFails * 6 {
		u := fmt.Sprintf("kisi%d", i%3)
		if !l3.allow("198.51.100.7", u) {
			t.Fatalf("%d. başarılı girişte IP kovası doldu", i+1)
		}
		l3.succeed("198.51.100.7", u)
	}
}

// sendAs: yöntem, gövde ve ek başlıklarla oturumlu istek.
func sendAs(h http.Handler, method, path, body string, c *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Kut", "1")
	req.RemoteAddr = "198.51.100.7:4000"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Yedek tüm hesapların parola özetlerini ve sunucunun özel anahtarını taşır; geri yükleme sahibin parolasını
// değiştirebilir. Bu yüzden yedek işlemleri ve bakım ayarı yalnızca sahibe açık, geri yükleme sahibin parolasını ister.
func TestBackupOwnerOnly(t *testing.T) {
	a, h, owner := maintApp(t)
	a.act = &activity{}
	a.restartF = func() {}
	if r := post(h, "/api/users", `{"name":"can","password":"can-long-password","role":"admin"}`, owner); r.Code != 200 {
		t.Fatalf("kullanıcı ekle: %d %s", r.Code, r.Body)
	}
	can := login(h, "can", "can-long-password")
	blob, _, err := buildBackup(a.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	name, err := a.makeBackup("elle", false)
	if err != nil {
		t.Fatal(err)
	}
	if c := getCode(h, "/api/maint", can); c != 200 {
		t.Fatalf("yedek listesi sahip olmayan yöneticiye de açık kalmalı: %d", c)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/backups/upload", string(blob)},
		{"POST", "/api/backups/upload?inspect=1", string(blob)},
		{"POST", "/api/backups", `{}`},
		{"GET", "/api/backups/" + name, ""},
		{"DELETE", "/api/backups/" + name, ""},
		{"POST", "/api/backups/" + name + "/restore", `{"owner_password":"can-long-password"}`},
		{"PUT", "/api/maint", `{"enabled":true,"freq":"daily","time":"03:30","keep":7}`},
	} {
		if r := sendAs(h, c.method, c.path, c.body, can, nil); r.Code != http.StatusForbidden {
			t.Errorf("sahip olmayan yönetici %s %s: %d, 403 olmalı", c.method, c.path, r.Code)
		}
	}
	up := func(pass string) *httptest.ResponseRecorder {
		return uploadForm(h, owner, fileField(blob), textField("owner_password", pass))
	}
	if r := up(""); r.Code != http.StatusForbidden {
		t.Fatalf("sahip, parolasız geri yükleme: %d %s", r.Code, r.Body)
	}
	if r := up("yanlis-parola-xyz"); r.Code != http.StatusForbidden {
		t.Fatalf("sahip, yanlış parola: %d %s", r.Code, r.Body)
	}
	if r := sendAs(h, "POST", "/api/backups/"+name+"/restore", `{"owner_password":"yanlis-parola-xyz"}`, owner, nil); r.Code != http.StatusForbidden {
		t.Fatalf("sahip, adla geri yükleme yanlış parola: %d %s", r.Code, r.Body)
	}
	if r := uploadForm(h, owner, fileField(blob), textField("inspect", "1")); r.Code != 200 {
		t.Fatalf("önizleme parola istememeli (hiçbir şey yazmaz): %d %s", r.Code, r.Body)
	}
	if r := up("correct-horse-battery"); r.Code != 200 {
		t.Fatalf("sahip, doğru parola: %d %s", r.Code, r.Body)
	}
}

// Yanlış sahip parolası geri yüklemede de giriş sayacına girer.
func TestRestoreOwnerPasswordIsRateLimited(t *testing.T) {
	a, h, owner := maintApp(t)
	a.act = &activity{}
	a.restartF = func() {}
	name, err := a.makeBackup("elle", false)
	if err != nil {
		t.Fatal(err)
	}
	var codes []int
	for range maxFails + 2 {
		codes = append(codes, sendAs(h, "POST", "/api/backups/"+name+"/restore", `{"owner_password":"yanlis-parola-xyz"}`, owner, nil).Code)
	}
	if codes[maxFails-1] != http.StatusForbidden || codes[maxFails] != http.StatusTooManyRequests {
		t.Fatalf("kodlar %v: ilk %d deneme 403, sonrası 429 olmalı", codes, maxFails)
	}
}

// enableOwnerTOTP: sahibe 2FA kurar (TestTwoFactorLoginFlow'daki akış); sırrı ve kurtarma kodlarını döndürür.
// Kurulumda şimdiki adım kullanılır; testler sonraki adımın kodunu ya da kurtarma kodlarını kullanmalı.
func enableOwnerTOTP(t *testing.T, h http.Handler, owner *http.Cookie) (string, []string) {
	t.Helper()
	rec := post(h, "/api/totp/setup", `{}`, owner)
	var setup struct{ Secret string }
	json.Unmarshal(rec.Body.Bytes(), &setup)
	if rec.Code != 200 || setup.Secret == "" {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	code, _ := totpAt(setup.Secret, time.Now().Unix()/30)
	rec = post(h, "/api/totp/enable", `{"code":"`+code+`","password":"correct-horse-battery"}`, owner)
	var en struct{ Recovery []string }
	json.Unmarshal(rec.Body.Bytes(), &en)
	if rec.Code != 200 || len(en.Recovery) != recoveryN {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body)
	}
	return setup.Secret, en.Recovery
}

// Yedek TOTP sırrını, tüm parola özetlerini ve sunucunun özel anahtarını taşır: çalınmış sahip oturumu yedeği
// alıp indiremesin, şifrelemeyi kapatamasın. 2FA kapatma gibi sahip parolası, 2FA açıksa ayrıca kod istenir.
func TestBackupOwnerReauthWithTwoFactor(t *testing.T) {
	a, h, owner := maintApp(t)
	a.act = &activity{}
	a.restartF = func() {}
	sec, rcv := enableOwnerTOTP(t, h, owner)
	name, err := a.makeBackup("elle", false)
	if err != nil {
		t.Fatal(err)
	}
	if r := post(h, "/api/backups", `{}`, owner); r.Code != http.StatusForbidden {
		t.Fatalf("yalnızca oturumla yedek: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/backups", `{"owner_password":"correct-horse-battery"}`, owner); r.Code != http.StatusForbidden {
		t.Fatalf("parola ama kodsuz yedek: %d %s", r.Code, r.Body)
	}
	next, _ := totpAt(sec, time.Now().Unix()/30+1)
	if r := post(h, "/api/backups", `{"owner_password":"correct-horse-battery","owner_code":"`+next+`"}`, owner); r.Code != 200 {
		t.Fatalf("parola + doğru kodla yedek: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/backups", `{"owner_password":"correct-horse-battery","owner_code":"`+next+`"}`, owner); r.Code != http.StatusForbidden {
		t.Fatalf("kullanılmış kod ikinci kez geçti: %d %s", r.Code, r.Body)
	}
	if r := sendAs(h, "GET", "/api/backups/"+name, "", owner, nil); r.Code != http.StatusForbidden {
		t.Fatalf("parolasız indirme: %d", r.Code)
	}
	hdr := map[string]string{"X-Kut-Owner-Pass": url.QueryEscape("correct-horse-battery"), "X-Kut-Owner-Code": url.QueryEscape(rcv[0])}
	if r := sendAs(h, "GET", "/api/backups/"+name, "", owner, hdr); r.Code != 200 {
		t.Fatalf("parola + kurtarma koduyla indirme: %d %s", r.Code, r.Body)
	}
	if r := sendAs(h, "POST", "/api/backups/"+name+"/restore", `{"owner_password":"correct-horse-battery"}`, owner, nil); r.Code != http.StatusForbidden {
		t.Fatalf("geri yükleme parola ama kodsuz: %d %s", r.Code, r.Body)
	}
	base := `{"enabled":true,"freq":"daily","time":"03:30","weekday":1,"keep":7,"log_days":90,"log_archive":true,"archive_months":12`
	if r := sendAs(h, "PUT", "/api/maint", base+`,"clear_pass":true}`, owner, nil); r.Code != http.StatusForbidden {
		t.Fatalf("parolasız clear_pass: %d %s", r.Code, r.Body)
	}
	if r := sendAs(h, "PUT", "/api/maint", base+`,"new_pass":"yeni-yedek-parolasi"}`, owner, nil); r.Code != http.StatusTooManyRequests && r.Code != http.StatusForbidden {
		t.Fatalf("parolasız new_pass: %d %s", r.Code, r.Body)
	}
	// sayaç yukarıdaki bilerek yanlış denemelerle doldu; zamanlama kaydı sahip doğrulamasına hiç girmediği için etkilenmez
	if r := sendAs(h, "PUT", "/api/maint", base+`}`, owner, nil); r.Code != 200 {
		t.Fatalf("zamanlama kaydı parola istememeli: %d %s", r.Code, r.Body)
	}
	if a.maintCfg().get().Backup.Pass != "" {
		t.Fatal("yedek parolası parolasız istekle değişti")
	}
}

// Yazma yetkisi varsayılan ret: yalnızca "admin" rolü yazar; bilinmeyen rol dizesi (elle düzenlenmiş ya da
// ileride eklenecek bir rol) hiçbir şeye erişemez.
func TestUnknownRoleIsDenied(t *testing.T) {
	a, h := v5App(t)
	rec, err := newAdmin("super-long-password")
	if err != nil {
		t.Fatal(err)
	}
	a.users = []User{{Name: "su", Role: "superuser", adminRecord: rec}} // loadUsers bunu reddeder; bellekte savunma katmanı sınanıyor
	c := login(h, "su", "super-long-password")
	if c == nil {
		t.Fatal("giriş")
	}
	if r := patch(h, "/api/peers/x", `{"name":"y"}`, c); r.Code != http.StatusForbidden {
		t.Fatalf("bilinmeyen rolle PATCH: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/peers", `{"name":"y"}`, c); r.Code != http.StatusForbidden {
		t.Fatalf("bilinmeyen rolle POST: %d %s", r.Code, r.Body)
	}
	if code := getCode(h, "/api/status", c); code != http.StatusForbidden {
		t.Fatalf("bilinmeyen rolle GET: %d", code)
	}
}

// 2FA'yı açmak hesabın parolasını ister: çalınmış bir oturum 2FA'yı kendi telefonuna bağlayıp sahibi dışarıda
// bırakamasın.
func TestTOTPEnableRequiresPassword(t *testing.T) {
	_, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	rec := post(h, "/api/totp/setup", `{}`, owner)
	var setup struct{ Secret string }
	json.Unmarshal(rec.Body.Bytes(), &setup)
	if rec.Code != 200 || setup.Secret == "" {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	code, _ := totpAt(setup.Secret, time.Now().Unix()/30)
	if r := post(h, "/api/totp/enable", `{"code":"`+code+`"}`, owner); r.Code != http.StatusForbidden {
		t.Fatalf("parolasız enable: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/totp/enable", `{"code":"`+code+`","password":"yanlis-parola-xyz"}`, owner); r.Code != http.StatusForbidden {
		t.Fatalf("yanlış parolayla enable: %d %s", r.Code, r.Body)
	}
	if r := post(h, "/api/totp/enable", `{"code":"`+code+`","password":"correct-horse-battery"}`, owner); r.Code != 200 {
		t.Fatalf("doğru parolayla enable: %d %s", r.Code, r.Body)
	}
}

// Kullanıcı adı girişten gelir: sunucu günlüğüne satır sonuyla sahte satır ekleyemez, boyu sınırlıdır.
func TestFailedLoginLogIsQuotedAndTruncated(t *testing.T) {
	_, h := v5App(t)
	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	post(h, "/api/login", `{"username":"x\nkut: sahte satir`+strings.Repeat("a", 500)+`","password":"yanlis-parola-xyz"}`, nil)
	out := buf.String()
	if strings.Count(out, "\n") != 1 || strings.Contains(out, "\nkut: sahte") {
		t.Fatalf("günlüğe satır sonu sızdı: %q", out)
	}
	if len(out) > 200 {
		t.Fatalf("kullanıcı adı kırpılmadı (%d bayt): %q", len(out), out)
	}
}

// Canlı akış (SSE): küresel 8 sınırına ek olarak hesap başına 3. Tek bir hesap tüm küresel kotayı tüketip
// diğer hesapların paneli canlı izlemesini engelleyemez.
func TestStreamLimitPerUser(t *testing.T) {
	a, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	for range maxStreamsPerUser {
		if !a.sess.openStream(ownerName) {
			t.Fatal("ilk üç akış açılmalı")
		}
	}
	// akış açılırsa bağlam bitene kadar sürer; gerileme testi askıda bırakmasın
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("GET", "/api/stream", nil).WithContext(ctx)
	req.AddCookie(owner)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("hesap başına 4. akış: %d, 429 olmalı", rec.Code)
	}
	if a.streams.Load() != 0 {
		t.Fatalf("reddedilen akış küresel sayaçta kaldı: %d", a.streams.Load())
	}
	a.sess.closeStream(ownerName)
	if !a.sess.openStream(ownerName) {
		t.Fatal("kapanan akışın yeri açılmalı")
	}
	if !a.sess.openStream("ayse") {
		t.Fatal("başka hesap etkilenmemeli")
	}
}

func TestLimiterSweepsStaleIPs(t *testing.T) {
	l := newLimiter()
	old := time.Now().Add(-2 * failWindow)
	for i := range 1100 {
		l.fails[pairKey(fmt.Sprintf("192.0.2.%d", i), ownerName)] = []time.Time{old}
	}
	l.allow("198.51.100.1", ownerName)
	if len(l.fails) != 3 { // yalnızca yeni denemenin üç kovası (ip|hesap, hesap, ip) kalmalı
		t.Fatalf("süresi geçmiş girdiler süpürülmedi: %d girdi var", len(l.fails))
	}
}

func TestRoleOfEmptyIsNobody(t *testing.T) {
	a, _ := v5App(t)
	if r := a.roleOf(""); r != "" {
		t.Fatalf("roleOf(\"\") = %q, boş olmalı", r)
	}
}

func TestPatchSameRoleKeepsSessions(t *testing.T) {
	_, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	if r := post(h, "/api/users", `{"name":"ayse","password":"ayse-long-password","role":"viewer"}`, owner); r.Code != 200 {
		t.Fatalf("kullanıcı ekle: %d %s", r.Code, r.Body)
	}
	v := login(h, "ayse", "ayse-long-password")
	if r := patch(h, "/api/users/ayse", `{"role":"viewer"}`, owner); r.Code != 200 {
		t.Fatalf("patch: %d %s", r.Code, r.Body)
	}
	if getCode(h, "/api/status", v) != 200 {
		t.Fatal("rol değişmediyse oturum düşmemeli")
	}
}

func TestPasswordLengthCountsRunes(t *testing.T) {
	if _, err := newAdmin("şifre123"); err == nil {
		t.Error("8 karakterlik parola kabul edildi")
	}
	if _, err := newAdmin("şşşşşş"); err == nil {
		t.Error("6 karakterlik (12 bayt) parola kabul edildi")
	}
	if _, err := newAdmin("şşşşşşşşşş"); err != nil {
		t.Errorf("10 karakterlik parola reddedildi: %v", err)
	}
}

// Bir hesabın kurulum sırrı başka bir hesaba verilmemeli.
func TestTOTPPendingBoundToUser(t *testing.T) {
	_, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	if r := post(h, "/api/users", `{"name":"ayse","password":"ayse-long-password","role":"admin"}`, owner); r.Code != 200 {
		t.Fatalf("kullanıcı ekle: %d %s", r.Code, r.Body)
	}
	ayse := login(h, "ayse", "ayse-long-password")
	rec := post(h, "/api/totp/setup", `{}`, owner)
	var setup struct{ Secret, URI string }
	json.Unmarshal(rec.Body.Bytes(), &setup)
	if rec.Code != 200 || setup.Secret == "" {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(setup.URI, "Kut%3Aadmin") && !strings.Contains(setup.URI, "Kut:admin") {
		t.Errorf("otpauth etiketi hesap adını içermeli: %s", setup.URI)
	}
	code, _ := totpAt(setup.Secret, time.Now().Unix()/30)
	rec = post(h, "/api/totp/enable", `{"code":"`+code+`","password":"ayse-long-password"}`, ayse)
	if rec.Code == 200 {
		t.Fatal("başka hesabın kurulum sırrı etkinleştirildi")
	}
	// sahibin kurulumu hâlâ geçerli
	rec = post(h, "/api/totp/enable", `{"code":"`+code+`","password":"correct-horse-battery"}`, owner)
	if rec.Code != 200 {
		t.Fatalf("sahibin kurulumu bozuldu: %d %s", rec.Code, rec.Body)
	}
}

func TestLocalPasswdChangesRunningService(t *testing.T) {
	a, h := v5App(t)
	old := login(h, "", "correct-horse-battery")
	if old == nil {
		t.Fatal("giriş")
	}
	lh := a.handler(true)
	rec := post(lh, "/api/local/passwd", `{"user":"","password":"kisa"}`, nil)
	if rec.Code != 400 {
		t.Fatalf("kısa parola reddedilmeli: %d %s", rec.Code, rec.Body)
	}
	rec = post(lh, "/api/local/passwd", `{"user":"","password":"brand-new-password-1"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("passwd: %d %s", rec.Code, rec.Body)
	}
	if getCode(h, "/api/status", old) != 401 {
		t.Error("eski oturum kapanmalı")
	}
	if r := post(h, "/api/login", `{"password":"correct-horse-battery"}`, nil); r.Code != 401 {
		t.Errorf("eski parola: %d", r.Code)
	}
	if r := post(h, "/api/login", `{"password":"brand-new-password-1"}`, nil); r.Code != 200 {
		t.Errorf("yeni parola: %d %s", r.Code, r.Body)
	}
	var onDisk adminRecord
	if err := loadJSON(adminPath(a.dataDir), &onDisk); err != nil || !onDisk.verify("brand-new-password-1") {
		t.Fatalf("diske yazılmadı: %v", err)
	}
}

// blockFile: yolun yerine boş olmayan bir dizin koyar; o dosyaya atomik yazım başarısız olur.
func blockFile(t *testing.T, path string) {
	t.Helper()
	os.Remove(path)
	if err := os.MkdirAll(filepath.Join(path, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// Uygulanan ama diske yazılamayan değişiklik başarı olarak dönmemeli.
func TestSaveFailureIsReported(t *testing.T) {
	a, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	for _, n := range []string{"a", "b"} {
		if r := post(h, "/api/peers", `{"name":"`+n+`"}`, c); r.Code != 200 {
			t.Fatalf("%s: %d %s", n, r.Code, r.Body)
		}
	}
	id := a.peers[0].ID
	blockFile(t, peersPath(a.dataDir))
	check := func(what string, r *httptest.ResponseRecorder) {
		t.Helper()
		if code, _ := testErrCode(t, r.Body.Bytes()); r.Code != http.StatusInternalServerError || code != "apply.not_saved" {
			t.Errorf("%s: %d %.120s", what, r.Code, r.Body.String())
		}
	}
	check("create", post(h, "/api/peers", `{"name":"c"}`, c))
	check("toggle", post(h, "/api/peers/"+id+"/toggle", `{}`, c))
	check("regenerate", post(h, "/api/peers/"+id+"/regenerate", `{}`, c))
	check("bulk", post(h, "/api/peers/bulk", `{"ids":["`+id+`"],"action":"disable"}`, c))
	req := httptest.NewRequest("DELETE", "/api/peers/"+id, nil)
	req.Header.Set("X-Kut", "1")
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	check("delete", rec)
	blockFile(t, policiesPath(a.dataDir))
	check("policy", post(h, "/api/policies", `{"name":"p","rules":[]}`, c))
}

func TestLocalPasswdKeepsTOTP(t *testing.T) {
	a, _ := v5App(t)
	adm := a.getAdmin()
	adm.TOTPSecret = newSecretForTest(t)
	a.setAdmin(adm)
	if rec := post(a.handler(true), "/api/local/passwd", `{"password":"brand-new-password-1"}`, nil); rec.Code != 200 {
		t.Fatalf("passwd: %d %s", rec.Code, rec.Body)
	}
	if got := a.getAdmin(); got.TOTPSecret != adm.TOTPSecret || !got.verify("brand-new-password-1") {
		t.Fatal("2FA korunmalı ve parola değişmeli")
	}
}

// Parola değiştirme de girişle aynı sınırı korumalı: eşzamanlı yanlış "mevcut parola" denemeleri en çok
// maxFails kez doğrulanır, gerisi 429 alır.
func TestPasswordChangeLimitHoldsUnderConcurrency(t *testing.T) {
	_, h, c := maintApp(t)
	const n = 20
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i] = post(h, "/api/password", `{"current":"yanlis-parola-xyz","new":"yepyeni-parola-123"}`, c).Code
		}()
	}
	wg.Wait()
	var denied, limited int
	for _, code := range codes {
		switch code {
		case http.StatusForbidden:
			denied++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("beklenmeyen kod %d", code)
		}
	}
	if denied > maxFails || limited != n-denied {
		t.Fatalf("403=%d 429=%d; en çok %d deneme doğrulanmalı", denied, limited, maxFails)
	}
}
