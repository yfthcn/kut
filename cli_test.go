package main

import (
	"bytes"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// cliEnv: ortam dilini temizler; testler dili yalnızca kendi verdikleri değerlerden alsın.
func cliEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for _, k := range []string{"KUT_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		t.Setenv(k, kv[k])
	}
}

func initDir(t *testing.T, extra ...string) string {
	t.Helper()
	dir := t.TempDir()
	args := append([]string{"-dry-run", "-data", dir, "-endpoint", "203.0.113.10", "-allow-overlap"}, extra...)
	if err := cmdInit(args); err != nil {
		t.Fatal(err)
	}
	adm, err := newAdmin("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if err := saveJSON(adminPath(dir), adm); err != nil {
		t.Fatal(err)
	}
	return dir
}

func savedLang(t *testing.T, dir string) string {
	t.Helper()
	var s Server
	if err := loadJSON(serverPath(dir), &s); err != nil {
		t.Fatal(err)
	}
	return s.cfg().Lang
}

func TestInitLangFlag(t *testing.T) {
	cliEnv(t, nil)
	if got := savedLang(t, initDir(t, "-lang", "en")); got != "en" {
		t.Errorf("-lang en: Settings.Lang=%q", got)
	}
	if got := savedLang(t, initDir(t, "-lang", "TR")); got != "tr" {
		t.Errorf("-lang TR: Settings.Lang=%q", got)
	}
	// bayrak yoksa kurulumu yapanın çıktı dili başlangıç sunucu dili olur
	cliEnv(t, map[string]string{"LANG": "en_US.UTF-8"})
	if got := savedLang(t, initDir(t)); got != "en" {
		t.Errorf("LANG=en_US: Settings.Lang=%q", got)
	}
	cliEnv(t, nil)
	if got := savedLang(t, initDir(t)); got != "tr" {
		t.Errorf("ortam boş: Settings.Lang=%q, tr beklenir", got)
	}
	err := cmdInit([]string{"-dry-run", "-data", t.TempDir(), "-endpoint", "203.0.113.10", "-lang", "de"})
	if err == nil || !strings.Contains(err.Error(), "-lang") {
		t.Fatalf("desteklenmeyen dil kabul edildi: %v", err)
	}
}

func TestReportInBothLanguages(t *testing.T) {
	cliEnv(t, nil)
	a, err := loadApp(initDir(t), true)
	if err != nil {
		t.Fatal(err)
	}
	titles := map[string]map[string]string{}
	for _, l := range langs {
		rep := a.buildReport(l)
		if len(rep.Checks) == 0 || len(rep.Structure) == 0 || len(rep.System) == 0 {
			t.Fatalf("%s: rapor boş", l)
		}
		titles[l] = map[string]string{}
		for _, c := range rep.Checks {
			titles[l][c.ID] = c.Title
			for _, s := range []string{c.Title, c.Detail, c.Fix} {
				if strings.Contains(s, "report.") || strings.Contains(s, "{") {
					t.Errorf("%s/%s: çevrilmemiş metin: %q", l, c.ID, s)
				}
			}
			if c.Title == "" {
				t.Errorf("%s/%s: başlık boş", l, c.ID)
			}
		}
		for _, p := range append(rep.Structure, rep.System...) {
			if p.K == "" || strings.Contains(p.K, "report.") || strings.Contains(p.V, "report.") || strings.Contains(p.V, "{") {
				t.Errorf("%s: yapı/sistem satırı çevrilmemiş: %+v", l, p)
			}
		}
	}
	// dry-run satırı iki dilde farklı ve katalogdaki metinle aynı
	for _, l := range langs {
		if want := T(l, "report.check.iface.skip.title", nil); titles[l]["iface"] != want {
			t.Errorf("%s: iface başlığı %q, beklenen %q", l, titles[l]["iface"], want)
		}
	}
	if titles["tr"]["update"] == titles["en"]["update"] {
		t.Errorf("update başlığı iki dilde aynı: %q", titles["tr"]["update"])
	}
}

// Yedek satırı gerçek yedek klasörünü gösterir (-data ile değişir), sabit /var/lib/kut/backups değil.
func TestReportBackupShowsDataDir(t *testing.T) {
	cliEnv(t, nil)
	a, err := loadApp(initDir(t), true)
	if err != nil {
		t.Fatal(err)
	}
	find := func(l string) Check {
		for _, c := range a.buildReport(l).Checks {
			if c.ID == "backup" {
				return c
			}
		}
		t.Fatalf("%s: yedek satırı yok", l)
		return Check{}
	}
	if err := a.maintCfg().update(func(c *MaintCfg) {
		c.Backup.Enabled, c.Backup.Freq, c.Backup.LastRun = true, "daily", time.Now().Unix()
	}); err != nil {
		t.Fatal(err)
	}
	for _, l := range langs {
		if c := find(l); c.Level != "ok" || !strings.Contains(c.Detail, a.backupDir()) || strings.Contains(c.Detail, "/var/lib/kut") {
			t.Errorf("%s: başarılı yedek satırı %+v, beklenen yol %s", l, c, a.backupDir())
		}
	}
	if err := a.maintCfg().update(func(c *MaintCfg) { c.Backup.LastErr = "disk dolu" }); err != nil {
		t.Fatal(err)
	}
	for _, l := range langs {
		if c := find(l); c.Level != "warn" || !strings.Contains(c.Fix, a.backupDir()) {
			t.Errorf("%s: başarısız yedek satırı %+v, beklenen yol %s", l, c, a.backupDir())
		}
	}
}

// Erişim matrisinin hücre metinleri de raporun dilinde (sözleşme 2).
func TestReportMatrixFollowsLang(t *testing.T) {
	cliEnv(t, nil)
	a, err := loadApp(initDir(t), true)
	if err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.peers = []Peer{{ID: "p1", Name: "a", IP: "10.77.0.2", Enabled: true}, {ID: "p2", Name: "b", IP: "10.77.0.3", Enabled: true}}
	a.mu.Unlock()
	cells := map[string]string{}
	for _, l := range langs {
		rep := a.buildReport(l)
		if len(rep.Matrix) != 2 || len(rep.Matrix[0]) != 3 {
			t.Fatalf("%s: matris biçimi: %+v", l, rep.Matrix)
		}
		srv := rep.Matrix[0][2]
		if want := T(l, "access.matrix_host", map[string]any{"port": a.panelPort()}); srv.Result != "host" || srv.Text != want {
			t.Errorf("%s: sunucu hücresi %+v, beklenen %q", l, srv, want)
		}
		cells[l] = srv.Text + "|" + rep.Matrix[0][1].Text
	}
	if cells["en"] == cells["tr"] {
		t.Errorf("matris iki dilde aynı: %q", cells["en"])
	}
}

func TestReportPluralAndDuration(t *testing.T) {
	cases := []struct {
		lang, key string
		p         map[string]any
		want      string
	}{
		{"en", "report.check.never.info.title", map[string]any{"n": 1}, "1 device has never connected"},
		{"en", "report.check.never.info.title", map[string]any{"n": 3}, "3 devices have never connected"},
		{"tr", "report.check.never.info.title", map[string]any{"n": 3}, "3 cihaz henüz hiç bağlanmadı"},
		{"en", "cli.doctor.warn", map[string]any{"n": 1}, "1 warning"},
		{"en", "cli.doctor.warn", map[string]any{"n": 0}, "0 warnings"},
		{"tr", "cli.doctor.warn", map[string]any{"n": 2}, "2 uyarı"},
	}
	for _, c := range cases {
		if got := T(c.lang, c.key, c.p); got != c.want {
			t.Errorf("T(%s, %s, %v) = %q, beklenen %q", c.lang, c.key, c.p, got, c.want)
		}
	}
	dur := []struct {
		lang string
		d    time.Duration
		want string
	}{
		{"tr", 49*time.Hour + 5*time.Minute, "2 gün 1 sa"},
		{"en", 49*time.Hour + 5*time.Minute, "2d 1h"},
		{"tr", 3*time.Hour + 7*time.Minute, "3 sa 7 dk"},
		{"en", 3*time.Hour + 7*time.Minute, "3h 7m"},
		{"tr", 90 * time.Second, "1 dk"},
		{"en", -time.Minute, "0m"},
	}
	for _, c := range dur {
		if got := humanDur(c.lang, c.d); got != c.want {
			t.Errorf("humanDur(%s, %v) = %q, beklenen %q", c.lang, c.d, got, c.want)
		}
	}
}

// Güvenlik duvarı durumu anahtar taşıyorsa rapor onu istenen dilde yazar; taşımıyorsa hazır Detail kalır.
func TestFwDetailUsesKey(t *testing.T) {
	st := fwState{State: "out-of-sync", Detail: "hazır metin", Key: "login.submit"}
	if got := fwDetail("en", st); got != "Sign in" {
		t.Errorf("en: %q", got)
	}
	if got := fwDetail("tr", st); got != "Giriş yap" {
		t.Errorf("tr: %q", got)
	}
	if got := fwDetail("en", fwState{Detail: "hazır metin"}); got != "hazır metin" {
		t.Errorf("anahtarsız: %q", got)
	}
}

func TestArgLang(t *testing.T) {
	cliEnv(t, nil)
	if got := argLang([]string{"-lang", "en"}); got != "en" {
		t.Errorf("-lang en: %q", got)
	}
	if got := argLang([]string{"--lang=en-GB", "-name", "x"}); got != "en" {
		t.Errorf("--lang=en-GB: %q", got)
	}
	dir := initDir(t, "-lang", "en")
	if got := argLang([]string{"-data", dir}); got != "en" {
		t.Errorf("sunucu dili: %q", got)
	}
	if got := argLang([]string{"-data=" + dir}); got != "en" {
		t.Errorf("-data=: %q", got)
	}
	t.Setenv("KUT_LANG", "tr")
	if got := argLang([]string{"-data", dir}); got != "tr" {
		t.Errorf("ortam sunucu dilini ezmeli: %q", got)
	}
	if got := argLang([]string{"-lang", "en", "-data", dir}); got != "en" {
		t.Errorf("-lang ortamı ezmeli: %q", got)
	}
	if got := argLang([]string{"-lang"}); got != "tr" {
		t.Errorf("değersiz -lang yok sayılmalı: %q", got)
	}
}

func TestCLIErrText(t *testing.T) {
	_, err := parseSpan("5x")
	var ce *codedErr
	if !errors.As(err, &ce) || ce.Code != "span.invalid" {
		t.Fatalf("parseSpan kodlu hata vermeli: %v", err)
	}
	if got, want := cliErrText("en", err), `could not understand the duration: "5x" (e.g. 8h, 3d, 2w)`; got != want {
		t.Errorf("en: %q", got)
	}
	if got, want := cliErrText("tr", err), `süre anlaşılamadı: "5x" (örn. 8h, 3d, 2w)`; got != want {
		t.Errorf("tr: %q", got)
	}
	if got := cliErrText("en", errors.New("düz")); got != "düz" {
		t.Errorf("kodsuz hata değişmemeli: %q", got)
	}
	// loadApp'in sardığı hata: iç hata da aynı dile çevrilir
	_, err = loadApp(t.TempDir(), true)
	if err == nil {
		t.Fatal("boş dizin açılmamalı")
	}
	if got := cliErrText("en", err); !strings.Contains(got, "`kut init`") || strings.Contains(got, "yapılandırması") {
		t.Errorf("en: %q", got)
	}
	if got := cliErrText("tr", err); !strings.Contains(got, "`kut init`") || strings.Contains(got, "server configuration") {
		t.Errorf("tr: %q", got)
	}
}

func TestFlagUsageLanguage(t *testing.T) {
	for lang, want := range map[string][]string{
		"en": {"Usage of doctor:", "data directory", "(default: /var/lib/kut)", "JSON output"},
		"tr": {"doctor için kullanım:", "veri dizini", "(varsayılan: /var/lib/kut)", "JSON çıktısı"},
	} {
		fs, _ := langFlags("doctor", lang)
		fs.Bool("json", false, T(lang, "cli.flag.doctor_json", nil))
		var buf bytes.Buffer
		fs.SetOutput(&buf)
		fs.Usage()
		for _, w := range want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("%s: yardımda %q yok:\n%s", lang, w, buf.String())
			}
		}
		if strings.Contains(buf.String(), "(default ") {
			t.Errorf("%s: flag paketinin İngilizce varsayılanı sızdı:\n%s", lang, buf.String())
		}
	}
	for _, l := range langs {
		u := T(l, "cli.usage", map[string]any{"app": "Kut", "version": "9.9.9", "tagline": "x"})
		for _, w := range []string{"Kut 9.9.9", "kut init", "-lang tr|en", "kut doctor", "kut restore"} {
			if !strings.Contains(u, w) {
				t.Errorf("%s: kullanım metninde %q yok", l, w)
			}
		}
	}
}

// Sunucudan dönen kodlu hata CLI'ın dilinde yazılır; bilinmeyen kodda sunucunun metnine düşülür.
func TestLocalClientCodedError(t *testing.T) {
	cliEnv(t, nil)
	dir := t.TempDir()
	ln, err := net.Listen("unix", filepath.Join(dir, socketName))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var gotLang atomic.Value
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang.Store(r.Header.Get("X-Kut-Lang"))
		if r.URL.Path == "/api/new" {
			errCode(w, http.StatusBadRequest, "yeni.kod", nil)
			return
		}
		errCode(w, http.StatusUnauthorized, "bad_password", nil)
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	for _, l := range langs {
		t.Setenv("KUT_LANG", l)
		err := newLocalClient(dir, cliLang(dir)).do("GET", "/api/x", nil, nil)
		if want := T(l, "err.bad_password", nil); err == nil || err.Error() != want {
			t.Errorf("%s: %v, beklenen %q", l, err, want)
		}
		if got, _ := gotLang.Load().(string); got != l {
			t.Errorf("%s: sunucuya X-Kut-Lang=%q gitti", l, gotLang.Load())
		}
	}
	t.Setenv("KUT_LANG", "tr")
	err = newLocalClient(dir, cliLang(dir)).do("GET", "/api/new", nil, nil)
	if err == nil || err.Error() != T(refLang, "err.yeni.kod", nil) {
		t.Errorf("bilinmeyen kod sunucunun metnine düşmeli: %v", err)
	}
}

// -lang bayrağı ortamdaki dili ezer: `kut doctor -lang en` sunucuya X-Kut-Lang: en gönderir.
func TestDoctorLangFlagReachesServer(t *testing.T) {
	cliEnv(t, map[string]string{"KUT_LANG": "tr"})
	dir := t.TempDir()
	ln, err := net.Listen("unix", filepath.Join(dir, socketName))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var gotLang atomic.Value
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLang.Store(r.Header.Get("X-Kut-Lang"))
		writeJSON(w, http.StatusOK, Report{})
	})}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	if err := cmdDoctor([]string{"-data", dir, "-lang", "en", "-json"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := gotLang.Load().(string); got != "en" {
		t.Errorf("sunucuya X-Kut-Lang=%q gitti, beklenen en", got)
	}
}

// Gerçek sunucu yolundaki (dry-run'da çalışmayan) rapor satırları da katalogda karşılıksız kalmamalı:
// report.go'daki her add(...) anahtarı ve skip(...) kimliği için başlık iki dilde var olmalı.
func TestReportKeysExistInCatalog(t *testing.T) {
	src, err := os.ReadFile("report.go")
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, m := range regexp.MustCompile(`add\("[a-z]+", "[^"]+", "[a-z]+", "([a-z0-9_.]+)"`).FindAllStringSubmatch(string(src), -1) {
		keys = append(keys, m[1])
	}
	for _, m := range regexp.MustCompile(`skip\("[a-z]+", "([a-z0-9]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		keys = append(keys, m[1]+".skip")
	}
	if len(keys) < 50 {
		t.Fatalf("kaynak taraması %d anahtar buldu; desen bozulmuş olabilir", len(keys))
	}
	for _, l := range langs {
		for _, k := range keys {
			full := "report.check." + k + ".title"
			_, ok := catalogs[l][full]
			if _, plural := catalogs[l][full+".other"]; !ok && !plural {
				t.Errorf("%s: %s yok", l, full)
			}
		}
	}
}

// Bu grubun dosyalarındaki T(...) ve ue(...) çağrılarının anahtarları iki dilde de katalogda olmalı.
func TestCLIAndErrKeysExistInCatalog(t *testing.T) {
	calls := regexp.MustCompile(`T\((?:lang|c\.lang), "([a-z0-9_.]+)",`)
	coded := regexp.MustCompile(`ue\("([a-z0-9_.]+)"`)
	n := 0
	for _, f := range []string{"report.go", "local.go", "main.go", "wg.go", "qr.go", "store.go", "backup.go", "fw.go", "fw6.go"} {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		for _, m := range calls.FindAllStringSubmatch(string(src), -1) {
			keys = append(keys, m[1])
		}
		for _, m := range coded.FindAllStringSubmatch(string(src), -1) {
			keys = append(keys, "err."+m[1])
		}
		for _, l := range langs {
			for _, k := range keys {
				_, ok := catalogs[l][k]
				if _, plural := catalogs[l][k+".other"]; !ok && !plural {
					t.Errorf("%s (%s): %s katalogda yok", f, l, k)
				}
			}
		}
		n += len(keys)
	}
	if n < 100 {
		t.Fatalf("kaynak taraması yalnızca %d anahtar buldu; desen bozulmuş olabilir", n)
	}
}

func TestWholeInts(t *testing.T) {
	got := wholeInts(map[string]any{"n": float64(3), "x": 1.5, "s": "a"})
	if n, ok := got["n"].(int); !ok || n != 3 {
		t.Errorf("n: %#v", got["n"])
	}
	if got["x"] != 1.5 || got["s"] != "a" {
		t.Errorf("tamsayı olmayanlar değişmemeli: %v", got)
	}
}

// captureOut: f çalışırken *std'ye (os.Stdout ya da os.Stderr) yazılanı döndürür.
func captureOut(t *testing.T, std **os.File, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := *std
	*std = w
	done := make(chan string)
	go func() {
		var b bytes.Buffer
		_, _ = b.ReadFrom(r)
		done <- b.String()
	}()
	f()
	*std = old
	w.Close()
	return <-done
}

// kut backup / kut restore: bayrak yardımı, çıktı ve hatalar komut satırının dilinde (ortam dili).
func TestBackupCLILanguage(t *testing.T) {
	for _, l := range langs {
		cliEnv(t, map[string]string{"KUT_LANG": l})
		other := "tr"
		if l == "tr" {
			other = "en"
		}
		dir := t.TempDir() // geri yüklenebilir veri dizini: conf_path /etc/wireguard altında
		spriv, spub, _ := mustKeys(t)
		os.WriteFile(filepath.Join(dir, "server.json"), []byte(`{"private_key":"`+spriv+`","public_key":"`+spub+`","subnet":"10.77.0.0/24","endpoint":"1.2.3.4","port":51820,"iface":"wg0","conf_path":"/etc/wireguard/wg0.conf"}`), 0o600)
		os.WriteFile(filepath.Join(dir, "admin.json"), []byte(`{}`), 0o600)
		for code, err := range map[string]error{
			"clibackup.need_file":    cmdRestore([]string{"-data", t.TempDir()}),
			"clibackup.not_data_dir": cmdBackup([]string{"-data", t.TempDir()}),
			"clibackup.not_empty":    cmdRestore([]string{"-data", dir, "-f", "x"}),
		} {
			var ce *codedErr
			if !errors.As(err, &ce) || ce.Code != code {
				t.Errorf("%s: %s kodlu hata bekleniyordu: %v", l, code, err)
				continue
			}
			if got := cliErrText(l, err); got == "err."+code || got == cliErrText(other, err) {
				t.Errorf("%s: %s hata metni bu dilde değil: %q", l, code, got)
			}
		}

		out := filepath.Join(t.TempDir(), "b.tar.gz")
		var err error
		stdout := captureOut(t, &os.Stdout, func() { err = cmdBackup([]string{"-data", dir, "-o", out}) })
		if err != nil {
			t.Fatal(err)
		}
		want := T(l, "cli.backup.plain_warning", nil)
		if want == "cli.backup.plain_warning" || !strings.Contains(stdout, want) || strings.Contains(stdout, T(other, "cli.backup.plain_warning", nil)) {
			t.Errorf("%s: yedek çıktısı bu dilde değil:\n%s", l, stdout)
		}
		if want := T(l, "cli.backup.written", map[string]any{"name": out, "n": 2}); !strings.Contains(stdout, want) {
			t.Errorf("%s: %q yok:\n%s", l, want, stdout)
		}

		dst := t.TempDir()
		stdout = captureOut(t, &os.Stdout, func() { err = cmdRestore([]string{"-data", dst, "-f", out}) })
		if err != nil {
			t.Fatal(err)
		}
		if want := T(l, "cli.restore.done", map[string]any{"n": 2, "data": dst}); want == "cli.restore.done" || stdout != want {
			t.Errorf("%s: geri yükleme çıktısı %q, beklenen %q", l, stdout, want)
		}

		help := captureOut(t, &os.Stderr, func() { err = cmdRestore([]string{"-h"}) })
		if want := T(l, "cli.flag.restore_file", nil); !errors.Is(err, flag.ErrHelp) || want == "cli.flag.restore_file" || !strings.Contains(help, want) {
			t.Errorf("%s: restore yardımı bu dilde değil (%v):\n%s", l, err, help)
		}
		help = captureOut(t, &os.Stderr, func() { err = cmdBackup([]string{"-h"}) })
		if want := T(l, "cli.flag.backup_encrypt", nil); want == "cli.flag.backup_encrypt" || !strings.Contains(help, want) {
			t.Errorf("%s: backup yardımı bu dilde değil:\n%s", l, help)
		}
	}
}

// CLI iç içe hataları da (ör. geri yüklemede doğrulama hatası) kendi dilinde yazar.
func TestCLIErrTextNested(t *testing.T) {
	err := nest("store.invalid_data", map[string]any{"dir": "/x"}, ue("ip.pool_full", nil))
	if got := cliErrText("tr", err); got == err.Error() || !strings.Contains(got, "/x") {
		t.Fatalf("iç içe hata çevrilmedi: %q", got)
	}
}

func TestUnknownCommandSuggests(t *testing.T) {
	for _, c := range []struct{ in, want string }{{"doctr", "doctor"}, {"bakup", "backup"}, {"lsit", "list"}, {"serv", "serve"}} {
		got := unknownCommand("en", c.in)
		if !strings.Contains(got, "unknown command: "+c.in) || !strings.Contains(got, "did you mean: "+c.want+"?") {
			t.Errorf("%s: %q", c.in, got)
		}
	}
	if got := unknownCommand("tr", "doktorr"); !strings.Contains(got, "bilinmeyen komut: doktorr") || !strings.Contains(got, "doctor") {
		t.Errorf("tr: %q", got)
	}
	if got := unknownCommand("en", "frobnicate"); strings.Contains(got, "did you mean") {
		t.Errorf("no suggestion expected: %q", got)
	}
	if d := editDistance("kut", "küt"); d != 1 {
		t.Errorf("rune distance = %d", d)
	}
}

func TestSocketPermissionAsksSudo(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket permissions")
	}
	dir := t.TempDir()
	ln, err := net.Listen("unix", filepath.Join(dir, socketName))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(filepath.Join(dir, socketName), 0); err != nil {
		t.Fatal(err)
	}
	cliEnv(t, nil)
	c := newLocalClient(dir, cliLang(dir))
	for _, lang := range []string{"en", "tr"} {
		c.lang = lang
		err := c.do("GET", "/api/local/list", nil, nil)
		if err == nil || !strings.Contains(err.Error(), "sudo kut") || strings.Contains(err.Error(), "systemctl status") {
			t.Errorf("%s: %v", lang, err)
		}
	}
	// Soket yoksa eski ileti (servis çalışıyor mu?) kalır.
	if got := dialErrText("en", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENOENT)}); !strings.Contains(got, "systemctl status kut") {
		t.Errorf("enoent: %q", got)
	}
	if got := dialErrText("en", &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}); !strings.Contains(got, "systemctl status kut") {
		t.Errorf("refused: %q", got)
	}
}

// -lang her komutta tanınır (v0.14.1-v0.15.0'da yalnızca init'te tanımlıydı, diğerleri
// "flag provided but not defined" ile düşüyordu). Değeri çıktı dilini seçer; init'te sunucu dilini de belirler.
func TestLangFlagEveryCommand(t *testing.T) {
	cliEnv(t, nil)
	dir := initDir(t, "-lang", "en")
	if got := savedLang(t, dir); got != "en" {
		t.Errorf("init -lang en: sunucu dili %q", got)
	}
	// -h ayrıştırmayı bayraklar tanındıktan sonra ErrHelp ile bitirir: komut çalışmaz (soket beklenmez), tanınmayan
	// bayrak ise ondan önce "not defined" hatası verirdi.
	for name, f := range map[string]func([]string) error{
		"list": cmdList, "doctor": cmdDoctor, "backup": cmdBackup, "restore": cmdRestore, "uninstall": cmdUninstall,
		"passwd": cmdPasswd, "serve": cmdServe, "add": cmdAdd, "2fa-off": cmd2FAOff, "init": cmdInit,
	} {
		for _, form := range [][]string{{"-lang", "tr"}, {"--lang=en"}} {
			var err error
			_ = captureOut(t, &os.Stderr, func() { err = f(append(form, "-h")) })
			if !errors.Is(err, flag.ErrHelp) {
				t.Errorf("%s %v: %v", name, form, err)
			}
		}
	}
	// Yardım metni bayrağı ve çevrilmiş açıklamasını listeler.
	fs, _ := langFlags("list", "tr")
	var b bytes.Buffer
	fs.SetOutput(&b)
	fs.Usage()
	if !strings.Contains(b.String(), "-lang") || !strings.Contains(b.String(), "çıktı dili") {
		t.Errorf("yardım: %q", b.String())
	}
}
