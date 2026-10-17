package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Gömülü kurulum dosyaları depodakilerle aynı (go:embed derleme anındaki kopyayı alır).
func TestInstallFilesEmbedded(t *testing.T) {
	for _, f := range []string{"install.sh", "kut.service"} {
		disk, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		emb, err := installFS.ReadFile(f)
		if err != nil || !bytes.Equal(disk, emb) {
			t.Errorf("%s gömülü kopyası farklı (%v)", f, err)
		}
	}
}

func TestInstallNeedsRoot(t *testing.T) {
	old := geteuid
	geteuid = func() int { return 1000 }
	defer func() { geteuid = old }()
	cliEnv(t, nil)
	if err := cmdInstall([]string{"--lang", "tr"}); err == nil || !strings.Contains(err.Error(), "sudo kut install") {
		t.Errorf("root olmadan: %v", err)
	}
}

func TestUninstallPlanPaths(t *testing.T) {
	cliEnv(t, nil)
	dir := initDir(t)
	root := t.TempDir()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	conf := filepath.Join(root, dir, "wg0.conf")
	if err := os.MkdirAll(filepath.Dir(conf), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(conf, []byte(renderServerConf(Server{Subnet: "10.77.0.0/24", Iface: "wg0"}, nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	p := planUninstall(root, dir, false, now)
	want := []string{
		filepath.Join(root, "etc/systemd/system/kut.service"),
		filepath.Join(root, "usr/local/bin/kut"),
		filepath.Join(root, "etc/sysctl.d/99-kut.conf"),
		filepath.Join(root, dir, "wg0.conf"), // server.json'daki ConfPath (dry-run init: veri dizini)
	}
	if !slices.Equal(p.Files, want) {
		t.Errorf("dosyalar:\n%q\nbeklenen\n%q", p.Files, want)
	}
	if p.Backup != filepath.Join(root, "root/kut-uninstall-20261017-120000.tar.gz") {
		t.Errorf("yedek yolu: %q", p.Backup)
	}
	if !slices.Equal(p.Units, []string{"kut", "wg-quick@wg0"}) || p.Sub != "10.77.0.0/24" || p.Purge || p.UFWPort != 0 {
		t.Errorf("plan: %+v", p)
	}
	txt := p.text("en")
	for _, w := range append(slices.Clone(want), p.Backup, "wg-quick@wg0", "keep the data directory "+dir, "leave ufw and Docker rules alone") {
		if !strings.Contains(txt, w) {
			t.Errorf("plan metninde %q yok:\n%s", w, txt)
		}
	}
	if strings.Contains(txt, "delete the data directory") {
		t.Errorf("-purge yokken veri silinmemeli:\n%s", txt)
	}
	// -purge: veri dizini de silinir.
	pp := planUninstall(root, dir, true, now)
	if txt := pp.text("tr"); !pp.Purge || !strings.Contains(txt, "veri dizini "+dir+" silinir") {
		t.Errorf("-purge planı:\n%s", txt)
	}
	// Kurulum ufw kuralını eklediyse yalnızca o kural silinir.
	if err := os.WriteFile(filepath.Join(dir, ufwMarker), []byte("51820\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pu := planUninstall(root, dir, false, now); pu.UFWPort != 51820 || !strings.Contains(pu.text("en"), "ufw rule 51820/udp") {
		t.Errorf("ufw: %+v", pu)
	}
	// Sahiplik kanıtı yoksa yapılandırma silinmez: Kut başlığı olmayan dosya, bağlantı ya da Kut yolunda olmayan yol.
	if err := os.WriteFile(conf, []byte("[Interface]\nPrivateKey = x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if pf := planUninstall(root, dir, false, now); slices.Contains(pf.Files, conf) {
		t.Error("Kut başlığı olmayan yapılandırma silinmemeli")
	}
	_ = os.Remove(conf)
	target := filepath.Join(root, "elsewhere")
	if err := os.WriteFile(target, []byte(confHeader+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, conf); err != nil {
		t.Fatal(err)
	}
	if pl := planUninstall(root, dir, false, now); slices.Contains(pl.Files, conf) {
		t.Error("bağlantı izlenmemeli")
	}
	var srv Server
	if err := loadJSON(serverPath(dir), &srv); err != nil {
		t.Fatal(err)
	}
	srv.ConfPath = "/etc/shadow"
	if err := saveJSON(serverPath(dir), srv); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/shadow"), []byte(confHeader+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ps := planUninstall(root, dir, false, now); len(ps.Files) != 3 {
		t.Errorf("Kut yolunda olmayan ConfPath silinmemeli: %q", ps.Files)
	}
	// server.json yoksa: yedek yok, başka bir kurulumun olabilecek wg0'ına (birim ve yapılandırma) dokunulmaz.
	empty := planUninstall(root, t.TempDir(), false, now)
	if empty.Backup != "" || len(empty.Files) != 3 || !slices.Equal(empty.Units, []string{"kut"}) || empty.Iface != "" {
		t.Errorf("verisiz plan: %+v", empty)
	}
}

func TestUninstallDryRunPrintsPlan(t *testing.T) {
	cliEnv(t, nil)
	dir := initDir(t)
	var err error
	t.Setenv("KUT_LANG", "en")
	out := captureOut(t, &os.Stdout, func() { err = cmdUninstall([]string{"-data", dir, "-purge", "-dry-run"}) })
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"Kut will be removed", "/usr/local/bin/kut", "/etc/systemd/system/kut.service", "delete the data directory " + dir, "Dry run: nothing was changed."} {
		if !strings.Contains(out, w) {
			t.Errorf("%q yok:\n%s", w, out)
		}
	}
	if _, err := os.Stat(serverPath(dir)); err != nil {
		t.Errorf("deneme hiçbir şey silmemeli: %v", err)
	}
	for _, d := range []string{"/", "/var", t.TempDir(), "relative"} { // Kut veri dizini olmayan hiçbir yer silinmez
		if err := cmdUninstall([]string{"-data", d, "-purge", "-dry-run"}); err == nil {
			t.Errorf("-purge %s reddedilmeli", d)
		}
	}
}

// Kaldırma yalnızca Kut'un kurallarını siler (etiketli ve etiketsiz iskelet, KUT-* atlamaları); yabancı kurallar kalır.
func TestRemoveKutFirewallLeavesForeignRules(t *testing.T) {
	for _, sub := range []string{"10.77.0.0/24", ""} {
		sk := skeleton("wg0", "10.77.0.0/24")
		sim := &simIpt{chains: map[string][]string{}, check: func(string) {}}
		for _, c := range filterChains {
			sim.chains["filter "+c] = []string{"-j ACCEPT"}
		}
		sim.chains["nat "+chainNat] = nil
		foreign := map[string][]string{
			"filter FORWARD":  {"-j DOCKER-USER", "-i docker0 -j ACCEPT"},
			"filter INPUT":    {"-p udp --dport 51820 -j ufw-user-input"},
			"nat POSTROUTING": {"-s 172.17.0.0/16 ! -o docker0 -j MASQUERADE"},
		}
		for k, v := range foreign {
			sim.chains[k] = slices.Clone(v)
		}
		for i, r := range sk { // yarısı etiketli, yarısı v0.14'ten etiketsiz
			a := r.args
			if i%2 == 1 {
				a = stripTag(a)
			}
			k := r.table + " " + r.chain
			sim.chains[k] = append(sim.chains[k], strings.Join(a, " "))
		}
		removeKutFirewall(sim.fn, "wg0", sub)
		for k, v := range foreign {
			for _, r := range sim.chains[k] {
				if !slices.Contains(v, r) && (sub != "" || strings.Contains(r, "KUT-") || strings.Contains(r, "kut:")) {
					t.Errorf("sub=%q %s: Kut kuralı kaldı: %q", sub, k, r)
				}
			}
			for _, r := range v {
				if !slices.Contains(sim.chains[k], r) {
					t.Errorf("sub=%q %s: yabancı kural silindi: %q", sub, k, r)
				}
			}
		}
	}
}
