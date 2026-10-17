package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func v6Server(t *testing.T) Server {
	a := testApp(t)
	s := a.srv
	st := defaultSettings()
	st.IPv6, st.ULA = true, "fdaa:bbbb:cccc::/64"
	s.Settings = &st
	return s
}

func TestIPv6Addressing(t *testing.T) {
	s := v6Server(t)
	cases := map[string]string{"10.77.0.1": "fdaa:bbbb:cccc::1", "10.77.0.2": "fdaa:bbbb:cccc::2", "10.77.0.254": "fdaa:bbbb:cccc::fe"}
	for v4, want := range cases {
		if got := s.ip6Of(v4).String(); got != want {
			t.Errorf("%s → %s, beklenen %s", v4, got, want)
		}
	}
	s2 := s
	s2.Subnet = "10.8.0.0/16"
	if got := s2.ip6Of("10.8.1.5").String(); got != "fdaa:bbbb:cccc::105" {
		t.Errorf("/16 ofseti: %s", got)
	}
	off := s
	off.Settings = &Settings{}
	if off.ip6Of("10.77.0.2").IsValid() || off.v6On() {
		t.Error("IPv6 kapalıyken adres üretilmemeli")
	}
	// VPN ağının dışındaki adresin ofseti anlamsızdır (taşar): IPv6 karşılığı üretilmemeli.
	for _, out := range []string{"10.78.0.5", "10.76.255.255", "192.168.1.2"} {
		if a6 := s.ip6Of(out); a6.IsValid() {
			t.Errorf("alt ağ dışı %s için IPv6 üretilmemeli, üretilen %s", out, a6)
		}
	}
	u, err := newULA()
	if err != nil || !strings.HasPrefix(u, "fd") || !strings.HasSuffix(u, "::/64") {
		t.Errorf("ULA: %q %v", u, err)
	}
}

func TestIPv6ConfigsAndRules(t *testing.T) {
	s := v6Server(t)
	peers, pols := testPolicySet()
	conf := renderServerConf(s, peers)
	for _, w := range []string{"Address = 10.77.0.1/24, fdaa:bbbb:cccc::1/64", "AllowedIPs = 10.77.0.2/32, fdaa:bbbb:cccc::2/128", "ip6tables -w 5 -N KUT-PEERS", "net.ipv6.conf.all.forwarding=1", "accept_ra=2"} {
		if !strings.Contains(conf, w) {
			t.Errorf("sunucu conf'unda %q yok", w)
		}
	}
	// accept_ra, forwarding'den ÖNCE ayarlanmalı (sunucunun kendi IPv6'sı kopmasın)
	if strings.Index(conf, "accept_ra=2") > strings.Index(conf, "forwarding=1") {
		t.Error("accept_ra yönlendirmeden önce gelmeli")
	}
	cc := buildClientConfig(s, "PRIV", peers[0])
	for _, w := range []string{"Address = 10.77.0.2/32, fdaa:bbbb:cccc::2/128", "AllowedIPs = 0.0.0.0/0, ::/0"} {
		if !strings.Contains(cc, w) {
			t.Errorf("internet izinli istemci conf'unda %q yok:\n%s", w, cc)
		}
	}
	cc = buildClientConfig(s, "PRIV", peers[2])
	if !strings.Contains(cc, "AllowedIPs = 10.77.0.0/24, fdaa:bbbb:cccc::/64") {
		t.Errorf("yalnızca-VPN istemci conf'u:\n%s", cc)
	}
	// IPv6 kapalıyken eski çıktı değişmemeli
	s.Settings = nil
	if strings.Contains(renderServerConf(s, peers), "fdaa") || strings.Contains(buildClientConfig(s, "P", peers[0]), "fdaa") {
		t.Error("IPv6 kapalıyken IPv6 çıktısı olmamalı")
	}
	s = v6Server(t)
	f := desiredFirewall6(s, peers, pols, time.Now(), true)
	txt := strings.Join(flat(f), "\n")
	for _, w := range []string{
		"-A KUT-PEERS -s fdaa:bbbb:cccc::3/128 -d fdaa:bbbb:cccc::4/128 -p tcp --dport 443 -j ACCEPT",
		"-A KUT-PEERS -s fdaa:bbbb:cccc::2/128 -d fdaa:bbbb:cccc::/64 -j ACCEPT",
		"-p ipv6-icmp --icmpv6-type 128",
		"-A KUT-INET -s fdaa:bbbb:cccc::2/128 -j ACCEPT",
		"-A KUT-NAT -s fdaa:bbbb:cccc::2/128 ! -o wg0 -j MASQUERADE",
		"-A KUT-PEERS -s fdaa:bbbb:cccc::3/128 -d fdaa:bbbb:cccc::2/128 -p ipv6-icmp -j ACCEPT",
	} {
		if !strings.Contains(txt, w) {
			t.Errorf("IPv6 kural yok: %q\n%s", w, txt)
		}
	}
	// profilsiz cihaz (::4) varsayılanda cihazlar arası kapalı; PeerFree açıkken serbest
	free := "-A KUT-PEERS -s fdaa:bbbb:cccc::4/128 -j ACCEPT"
	if strings.Contains(txt, free) {
		t.Errorf("profilsiz cihaz varsayılanda serbest olmamalı:\n%s", txt)
	}
	fc := s.cfg()
	fc.PeerFree = true
	sf := s
	sf.Settings = &fc
	if ftxt := strings.Join(flat(desiredFirewall6(sf, peers, pols, time.Now(), true)), "\n"); !strings.Contains(ftxt, free) {
		t.Errorf("PeerFree: IPv6 serbest kural yok:\n%s", ftxt)
	}
	// sunucunun IPv6 rotası yoksa internet ACCEPT/NAT66 olmamalı (IPv6 tünelde kesilir)
	f = desiredFirewall6(s, peers, pols, time.Now(), false)
	if len(f.Inet) != 0 || len(f.Nat) != 0 {
		t.Errorf("rota yokken IPv6 çıkışı açılmamalı: %v %v", f.Inet, f.Nat)
	}
	// özel ağ engeli
	f = desiredFirewall6(s, peers, pols, time.Now(), true)
	if !strings.Contains(strings.Join(flat(fwSet{Inet: f.Inet}), "\n"), "-d fc00::/7 -j DROP") {
		t.Error("IPv6 özel ağ engeli yok")
	}
}

func flat(f fwSet) []string {
	var o []string
	for _, g := range [][][]string{f.Peers, f.In, f.Inet, f.Nat} {
		for _, r := range g {
			o = append(o, strings.Join(stripTag(r), " "))
		}
	}
	return o
}

func TestParseInetCounters6(t *testing.T) {
	out := []byte(`Chain KUT-INET (1 references)
    pkts      bytes target     prot in     out     source               destination
       0        0 DROP       all      *      *       fdaa:bbbb:cccc::2/128  fc00::/7
       5      700 ACCEPT     all      *      *       fdaa:bbbb:cccc::2/128  ::/0
`)
	c := parseInetCountersFam(out, true)
	if c["fdaa:bbbb:cccc::2"].Bytes != 700 || len(c) != 1 {
		t.Fatalf("%+v", c)
	}
	// ip6tables v1.8.11 (nf_tables) "opt" sütununu da yazar ve kural yorumunu sona ekler (ölçüldü).
	out = []byte(`Chain KUT-INET (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 DROP       all  --  *      *       fdaa:bbbb:cccc::2    fc00::/7             /* kut:inet-deny:fdaa:bbbb:cccc::2:fc00::/7 */
       9      900 ACCEPT     all  --  *      *       fdaa:bbbb:cccc::2    ::/0                 /* kut:inet:fdaa:bbbb:cccc::2 */
`)
	if c := parseInetCountersFam(out, true); c["fdaa:bbbb:cccc::2"] != (inetCounter{9, 900}) || len(c) != 1 {
		t.Fatalf("opt sütunlu IPv6 çıktısı: %+v", c)
	}
}

func TestNetnsIPv6(t *testing.T) {
	inNetns(t, func() {
		if !haveIP6Tables() {
			t.Skip("ip6tables yok")
		}
		// Bu ortamın çekirdeğinde IPv6 yığını yok (adres/sysctl işlemleri çalışmaz); güvenlik duvarı kısmı gerçek ip6tables'a karşı sınanır.
		old := hostSetup6Fn
		hostSetup6Fn = func(Server) error { return nil }
		defer func() { hostSetup6Fn = old }()
		a := fwApp(t)
		a.srv = v6Server(t)
		peers, pols := testPolicySet()
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Fatalf("syncFirewall: %v\n%s", err, sh(t, "ip6tables -S"))
		}
		if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
			t.Fatalf("fwVerify: %+v\n%s", st, sh(t, "ip6tables -S; ip6tables -t nat -S"))
		}
		fw := sh(t, "ip6tables -S FORWARD")
		for _, j := range []string{"-j KUT-PEERS", "-j KUT-INET"} {
			if strings.Count(fw, j) != 1 {
				t.Errorf("%s tam bir kez olmalı:\n%s", j, fw)
			}
		}
		// IPv6 iskeleti de yalnızca yanıt yönünü kısayoldan geçirir ve wg0'a giden geri kalanını en sonda düşürür.
		if l := strings.Split(strings.TrimSpace(untag(fw)), "\n"); len(l) != 9 || l[1] != "-A FORWARD ! -i wg0 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT" || l[2] != "-A FORWARD -i wg0 -o wg0 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT" || l[3] != "-A FORWARD -i wg0 -o wg0 -p ipv6-icmp -m conntrack --ctstate RELATED -j KUT-ICMP" || l[8] != "-A FORWARD -o wg0 -j DROP" {
			t.Errorf("IPv6 FORWARD iskeleti:\n%s", fw)
		}
		if l := strings.Split(untag(sh(t, "ip6tables -S KUT-IN")), "\n"); len(l) < 2 || l[1] != "-A KUT-IN -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT" {
			t.Errorf("IPv6 KUT-IN'in ilk kuralı:\n%s", strings.Join(l, "\n"))
		}
		pc := untag(sh(t, "ip6tables -S KUT-PEERS"))
		for _, w := range []string{"-s fdaa:bbbb:cccc::3/128 -d fdaa:bbbb:cccc::4/128 -p tcp -m tcp --dport 443 -j ACCEPT", "-s fdaa:bbbb:cccc::4/128 -d fdaa:bbbb:cccc::3/128 -p tcp -m tcp --dport 443 -j ACCEPT"} { // profilsiz ::4: yalnızca geri yön
			if !strings.Contains(pc, w) {
				t.Errorf("KUT-PEERS'te %q yok:\n%s", w, pc)
			}
		}
		// ikinci sync: yinelenme yok, hâlâ ok
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Fatal(err)
		}
		if strings.Count(sh(t, "ip6tables -S FORWARD"), "-j KUT-PEERS") != 1 {
			t.Error("ikinci sync yinelenen kural bıraktı")
		}
		// sapma: IPv6 zinciri boşaltılırsa out-of-sync, sync onarır
		sh(t, "ip6tables -F KUT-PEERS")
		if st := a.fwVerify(a.srv, peers, pols); st.State != "out-of-sync" || st.Key != "fw.chain.count" || st.Params["fam"] != "IPv6" {
			t.Errorf("sapma yakalanmalı: %+v", st)
		}
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Fatal(err)
		}
		if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
			t.Errorf("onarım sonrası: %+v", st)
		}
		// IPv6 kapatılınca kurallar ve adres kalkar; IPv4 sağlam kalır
		off := a.srv
		def := defaultSettings()
		def.ULA = "fdaa:bbbb:cccc::/64"
		off.Settings = &def
		if err := a.syncFirewall(off, peers, pols); err != nil {
			t.Fatal(err)
		}
		if out := sh(t, "ip6tables -S"); strings.Contains(out, "KUT-") {
			t.Errorf("IPv6 kapalıyken KUT zinciri kalmamalı:\n%s", out)
		}
		if st := a.fwVerify(off, peers, pols); st.State != "ok" {
			t.Errorf("IPv4 sağlam kalmalı: %+v", st)
		}
	})
}

// Güvenlik duvarını kuramayan apply hataları kodlu: "Uygulanamadı" yanıtında okuyanın dilinde yazılır.
func TestFirewallApplyErrorsAreCoded(t *testing.T) {
	failOn := func(failTable string) iptFn {
		return func(table string, args ...string) ([]byte, error) {
			if table == failTable && (args[0] == "-I" || args[0] == "-C") {
				return nil, errors.New("iptables: Permission denied")
			}
			return nil, nil
		}
	}
	sk := skeleton("wg0", "10.77.0.0/24")
	if c := errCodeOf(ensureSkeletonF(failOn("filter"), sk)); c != "fw.apply.skeleton" {
		t.Errorf("iskelet: %q", c)
	}
	if c := errCodeOf(ensureSkeletonF(failOn("nat"), sk)); c != "fw.apply.skeleton_nat" {
		t.Errorf("iskelet (nat): %q", c)
	}

	// sahte <bin>-restore: filter tablosunu kabul eder, nat'ı reddeder
	bin := t.TempDir()
	script := "#!/bin/sh\ngrep -q '^[*]nat' && exit 1\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "kutfake-restore"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if c := errCodeOf(applyRestore("kutyok", fwSet{}, "IPv6 ")); c != "fw.apply.restore" {
		t.Errorf("restore: %q", c)
	}
	err := applyRestore("kutfake", fwSet{}, "")
	if c := errCodeOf(err); c != "fw.apply.restore_nat" {
		t.Errorf("restore (nat): %q (%v)", c, err)
	}
	if en, tr := cliErrText("en", err), cliErrText("tr", err); en == tr || strings.Contains(en, "err.") || strings.Contains(tr, "err.") {
		t.Errorf("dile göre yazılmalı: en %q, tr %q", en, tr)
	}

	// IPv6 açık ama ip6tables yok
	t.Setenv("PATH", t.TempDir())
	a := testApp(t)
	if c := errCodeOf(a.syncFirewall6(v6Server(t), nil, nil)); c != "fw6.no_ip6tables" {
		t.Errorf("ip6tables yok: %q", c)
	}
	// IPv6 ön ekiyle sarılan iskelet hatası: iç hata da okuyanın dilinde
	w := ue("fw6.skeleton", map[string]any{"err": ensureSkeletonF(failOn("filter"), sk)})
	if tr := cliErrText("tr", w); tr == cliErrText("en", w) || strings.Contains(tr, "firewall") || strings.Contains(tr, "err.") {
		t.Errorf("sarılmış iskelet hatası tr'ye çevrilmeli: %q", tr)
	}
}
