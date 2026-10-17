package main

import (
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kurulum ve kaldırma. install.sh ile kut.service ikiliye gömülüdür: yayında yalnızca ikili ve SHA256SUMS
// yeterlidir (`sudo ./kut-linux-amd64 install`). install.sh tek başına da çalışır; `--uninstall` ile buradaki
// kaldırma mantığını çağırır, böylece iki yol aynı işi yapar.

//go:embed install.sh kut.service
var installFS embed.FS

// exitCode: alt sürecin çıkış kodu; main bunu ileti yazmadan aynen döndürür (betik iletisini kendisi yazdı).
type exitCode int

func (e exitCode) Error() string { return "exit status " + strconv.Itoa(int(e)) }

// geteuid: testlerde root olmadan da plan yolunu sınamak için değiştirilebilir.
var geteuid = os.Geteuid

// ufwMarker: install.sh WireGuard portu için ufw kuralını kendisi eklediyse veri dizinine yazdığı dosya (içerik:
// port). Kaldırma yalnızca bu dosya varsa o kuralı siler; kullanıcının kendi ufw/Docker kurallarına dokunulmaz.
const ufwMarker = "ufw-port"

func cmdInstall(args []string) error {
	lang := argLang(args)
	if geteuid() != 0 {
		return errors.New(T(lang, "cli.install.need_root", nil))
	}
	dir, err := os.MkdirTemp("", "kut-install-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }() // geçici kopya; silinemezse /tmp temizliği alır
	for _, f := range []struct {
		name string
		mode os.FileMode
	}{{"install.sh", 0o700}, {"kut.service", 0o600}} {
		b, err := installFS.ReadFile(f.name)
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, f.name), b, f.mode); err != nil {
			return err
		}
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		return errors.New(T(lang, "cli.install.no_bash", map[string]any{"err": err.Error()}))
	}
	cmd := exec.Command(bash, append([]string{filepath.Join(dir, "install.sh")}, args...)...) //nolint:gosec,noctx // G204: gömülü betik, argümanlar root operatörün kendi bayrakları; etkileşimli kurulumun süresi sınırsız
	// BIN_SRC çalışan görüntünün kendisidir (/proc/<pid>/exe): sudo ile başlatılma ile kopyalama arasında diskteki
	// dosya (ör. kullanıcının yazabildiği ~/Downloads'ta) değiştirilse de kurulan, doğrulanıp çalıştırılan ikilidir.
	cmd.Env = append(os.Environ(), "BIN_SRC=/proc/"+strconv.Itoa(os.Getpid())+"/exe", "KUT_INSTALL_CMD=kut install")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitCode(ee.ExitCode())
		}
		return err
	}
	return nil
}

// ---- Kaldırma ----

type uninstallPlan struct {
	Data    string   // veri dizini
	Backup  string   // şifreli yedeğin yolu ("" = veri yok, yedek alınmaz)
	Iface   string   // WireGuard arayüzü
	Sub     string   // IPv4 VPN ağı ("" = bilinmiyor; iskeletin nat atlaması zincir adından bulunur)
	Sub6    string   // IPv6 VPN ağı ("" = hiç açılmamış)
	Units   []string // durdurulup devre dışı bırakılacak systemd birimleri
	Files   []string // silinecek dosyalar
	UFWPort int      // >0: Kut kurulumunun eklediği ufw kuralı
	Purge   bool     // veri dizini de silinir
}

// planUninstall: kaldırılacakları veri dizinindeki server.json'dan çıkarır. Yalnızca okur. root: dosya yollarının ön
// eki (testlerde geçici dizin; gerçek kullanımda "/").
//
// Sahiplik kanıtı olmadan ortak adlı kaynağa dokunulmaz: server.json okunamazsa (yanlış -data, Kut hiç kurulmamış)
// WireGuard birimi ve yapılandırması plana girmez, çünkü "wg0" başka bir kurulumun tüneli olabilir. Yapılandırma
// dosyası da ancak Kut'un yolunda (ConfPath, /etc/wireguard/<arayüz>.conf ya da dry-run'da veri dizini), düzenli bir
// dosyaysa ve Kut'un yazdığı başlıkla başlıyorsa silinir.
func planUninstall(root, data string, purge bool, now time.Time) uninstallPlan {
	p := uninstallPlan{Data: data, Purge: purge}
	p.Units = []string{"kut"}
	p.Files = []string{
		filepath.Join(root, "etc/systemd/system/kut.service"),
		filepath.Join(root, "usr/local/bin/kut"),
		filepath.Join(root, "etc/sysctl.d/99-kut.conf"),
	}
	var s Server
	if err := loadJSON(serverPath(data), &s); err == nil && ifaceRe.MatchString(s.Iface) {
		p.Backup = filepath.Join(root, "root", "kut-uninstall-"+now.Format("20060102-150405")+".tar.gz")
		p.Iface = s.Iface
		if pf := s.prefix(); pf.IsValid() {
			p.Sub = pf.String()
		}
		if s.cfg().ULA != "" {
			p.Sub6 = s.prefix6().String()
		}
		p.Units = append(p.Units, "wg-quick@"+p.Iface)
		conf := filepath.Clean(s.ConfPath)
		if conf == wgConfPath(p.Iface) || filepath.Dir(conf) == filepath.Clean(data) {
			if f := filepath.Join(root, conf); kutManaged(f) {
				p.Files = append(p.Files, f)
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(data, ufwMarker)); err == nil { //nolint:gosec // G304: veri dizini root operatörün bayrağı
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n > 0 && n < 65536 {
			p.UFWPort = n
		}
	}
	return p
}

// kutManaged: dosya düzenli bir dosya (bağlantı değil) ve renderServerConf'un yazdığı başlıkla başlıyor.
func kutManaged(path string) bool {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	f, err := os.Open(path) //nolint:gosec // G304: yol yukarıda Kut'un yapılandırma yollarıyla sınırlandı
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, len(confHeader))
	n, _ := f.Read(head)
	return string(head[:n]) == confHeader
}

// text: planın okunur hâli (onaydan önce ve -dry-run'da yazılır).
func (p uninstallPlan) text(lang string) string {
	var b strings.Builder
	line := func(key string, params map[string]any) { b.WriteString("  - " + T(lang, key, params) + "\n") }
	b.WriteString(T(lang, "cli.uninstall.plan_head", nil) + "\n")
	if p.Backup != "" {
		line("cli.uninstall.step_backup", map[string]any{"path": p.Backup})
	} else {
		line("cli.uninstall.step_no_backup", map[string]any{"data": p.Data})
	}
	line("cli.uninstall.step_units", map[string]any{"units": strings.Join(p.Units, ", ")})
	line("cli.uninstall.step_firewall", nil)
	if p.UFWPort > 0 {
		line("cli.uninstall.step_ufw", map[string]any{"port": p.UFWPort})
	} else {
		line("cli.uninstall.step_no_ufw", nil)
	}
	line("cli.uninstall.step_files", nil)
	for _, f := range p.Files {
		b.WriteString("      " + f + "\n")
	}
	line("cli.uninstall.step_reload", nil)
	if p.Purge {
		line("cli.uninstall.step_purge", map[string]any{"data": p.Data})
	} else {
		line("cli.uninstall.step_keep", map[string]any{"data": p.Data})
	}
	b.WriteString(T(lang, "cli.uninstall.forward_note", nil) + "\n")
	return b.String()
}

func cmdUninstall(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("uninstall", lang)
	purge := fs.Bool("purge", false, T(lang, "cli.flag.uninstall_purge", nil))
	yes := fs.Bool("yes", false, T(lang, "cli.flag.uninstall_yes", nil))
	dry := fs.Bool("dry-run", false, T(lang, "cli.flag.uninstall_dry_run", nil))
	if err := fs.Parse(args); err != nil {
		return err
	}
	d := filepath.Clean(*data)
	if *purge { // yazım hatası (ör. -data /var) bir sistem dizinini silmesin: yalnızca gerçek bir Kut veri dizini
		if _, err := os.Stat(serverPath(d)); err != nil || !filepath.IsAbs(d) || d == "/" {
			return errors.New(T(lang, "cli.uninstall.bad_data", map[string]any{"data": *data}))
		}
	}
	p := planUninstall("/", d, *purge, time.Now())
	fmt.Print(p.text(lang))
	if *dry {
		fmt.Println(T(lang, "cli.uninstall.dry_run", nil))
		return nil
	}
	if geteuid() != 0 {
		return errors.New(T(lang, "cli.uninstall.need_root", nil))
	}
	if !*yes {
		if !isTerminal(os.Stdin) {
			return errors.New(T(lang, "cli.uninstall.need_yes", nil))
		}
		fmt.Fprint(os.Stderr, T(lang, "cli.uninstall.confirm", nil)+" ")
		ans, _ := stdin.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "e" && a != "yes" && a != "evet" {
			fmt.Println(T(lang, "cli.uninstall.aborted", nil))
			return nil
		}
	}
	return p.run(lang)
}

// run: planı uygular. Yedek alınamazsa hiçbir şey silinmez; sonraki adımlar hataya dayanıklıdır (yarım kalmış bir
// kurulumda da çalışsın), uyarıları yazılır.
func (p uninstallPlan) run(lang string) error {
	if p.Backup != "" {
		pass, err := cliBackupPass(lang, true)
		if err != nil {
			return err
		}
		blob, _, err := buildBackup(p.Data)
		if err != nil {
			return err
		}
		if blob, err = encryptBackup(blob, pass); err != nil {
			return err
		}
		f, err := os.OpenFile(p.Backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(blob); err != nil {
			_ = f.Close()
			_ = os.Remove(p.Backup)
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Println(T(lang, "cli.uninstall.backup_written", map[string]any{"path": p.Backup}))
	}
	warn := func(step string, err error) {
		if err != nil {
			fmt.Fprintln(os.Stderr, T(lang, "cli.uninstall.warn", map[string]any{"step": step, "err": err.Error()}))
		}
	}
	for _, u := range p.Units {
		// wg-quick durunca PostDown iskeleti ve zincirleri zaten kaldırır; aşağıdaki temizlik geride kalanlar için.
		_, err := run(30*time.Second, "systemctl", "disable", "--now", u)
		warn("systemctl disable --now "+u, err)
	}
	// Arayüz hâlâ açıksa (birim dışından `wg-quick up` ile açılmış olabilir) iskeletin DROP kuralları sökülmez:
	// host'un FORWARD politikası ACCEPT ise cihazlar sınırsız yönlendirilirdi. Önce kapatmayı dener.
	ifaceUp := func() bool {
		_, err := run(5*time.Second, "wg", "show", p.Iface, "public-key")
		return p.Iface != "" && err == nil
	}
	if ifaceUp() {
		_, err := run(30*time.Second, "wg-quick", "down", p.Iface)
		warn("wg-quick down "+p.Iface, err)
	}
	if ifaceUp() {
		fmt.Fprintln(os.Stderr, T(lang, "cli.uninstall.iface_up", map[string]any{"iface": p.Iface}))
	} else {
		for _, f := range []struct {
			fn  iptFn
			bin string
			sub string
		}{{ipt, "iptables", p.Sub}, {ipt6, "ip6tables", p.Sub6}} {
			if _, err := exec.LookPath(f.bin); err == nil {
				removeKutFirewall(f.fn, p.Iface, f.sub)
			}
		}
	}
	if p.UFWPort > 0 {
		if _, err := exec.LookPath("ufw"); err == nil {
			_, err := run(15*time.Second, "ufw", "delete", "allow", strconv.Itoa(p.UFWPort)+"/udp")
			warn("ufw delete allow", err)
		}
		_ = os.Remove(filepath.Join(p.Data, ufwMarker))
	}
	for _, f := range p.Files {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			warn("rm "+f, err)
		}
	}
	_, err := run(30*time.Second, "systemctl", "daemon-reload")
	warn("systemctl daemon-reload", err)
	if p.Purge {
		warn("rm -r "+p.Data, os.RemoveAll(p.Data))
	}
	fmt.Println(T(lang, "cli.uninstall.done", nil))
	return nil
}

// removeKutFirewall: Kut'un iskelet kurallarını (etiketli ve v0.14'ün etiketsiz kopyaları) ve KUT-* zincirlerini
// kaldırır. Alt ağ bilinmiyorsa (server.json yok) KUT-* zincirine atlayan kurallar -S çıktısından bulunup silinir.
// Yalnızca Kut'un kendi kurallarına dokunur.
func removeKutFirewall(ipt iptFn, iface, sub string) {
	if sub != "" {
		for _, r := range skeleton(iface, sub) {
			for _, a := range [][]string{r.args, stripTag(r.args)} {
				for range 10 {
					if _, err := ipt(r.table, append([]string{"-D", r.chain}, a...)...); err != nil {
						break
					}
				}
			}
		}
	}
	for _, g := range []struct{ table, chain string }{{"filter", "FORWARD"}, {"filter", "INPUT"}, {"nat", "POSTROUTING"}} {
		out, err := ipt(g.table, "-S", g.chain)
		if err != nil {
			continue
		}
		for _, r := range slices.Backward(ruleLines(out, g.chain)) {
			j := slices.Index(r, "-j")
			if (j >= 0 && j+1 < len(r) && strings.HasPrefix(r[j+1], "KUT-")) || strings.HasPrefix(ruleTag(r), "kut:") {
				_, _ = ipt(g.table, append([]string{"-D", g.chain}, r...)...)
			}
		}
	}
	for _, c := range filterChains {
		_, _ = ipt("filter", "-F", c)
		_, _ = ipt("filter", "-X", c)
	}
	_, _ = ipt("nat", "-F", chainNat)
	_, _ = ipt("nat", "-X", chainNat)
}
