package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

func peer(id, name, ip string, pol string) Peer {
	return Peer{ID: id, Name: name, IP: ip, PublicKey: "K" + id, PSK: "P", Enabled: true, Policy: pol}
}

func TestParsePorts(t *testing.T) {
	rs, err := parsePorts("80, 443,8000-8100")
	if err != nil || len(rs) != 3 || normPorts(rs) != "80,443,8000-8100" {
		t.Fatalf("beklenmeyen: %v %v", rs, err)
	}
	for _, bad := range []string{"0", "70000", "abc", "90-80", "80,,81", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21"} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("%q reddedilmeli", bad)
		}
	}
	if rs, err := parsePorts(""); err != nil || rs != nil {
		t.Error("boş = tüm portlar")
	}
}

func TestNormalizeRule(t *testing.T) {
	peers := []Peer{peer("a", "Ali", "10.77.0.2", "")}
	ok := []Rule{
		{Target: "server", Proto: "tcp", Ports: "5757"},
		{Target: "server", Proto: "tcp", Ports: " 80 , 443 "},
		{Target: "device", Device: "a", Proto: "any", Both: true},
		{Target: "all", Proto: "icmp"},
	}
	for _, r := range ok {
		if _, err := normalizeRule(r, peers, 1); err != nil {
			t.Errorf("%+v geçerli olmalı: %v", r, err)
		}
	}
	bad := []Rule{
		{Target: "server", Proto: "any", Ports: "80"},
		{Target: "server", Proto: "icmp", Ports: "1"},
		{Target: "device", Device: "yok", Proto: "tcp"},
		{Target: "server", Device: "a", Proto: "tcp"},
		{Target: "server", Proto: "tcp", Both: true},
		{Target: "bilinmeyen", Proto: "tcp"},
		{Target: "server", Proto: "sctp"},
		{Target: "server", Proto: "tcp", Ports: "99999"},
		{Target: "server", Proto: "tcp", Note: strings.Repeat("x", 81)},
	}
	for _, r := range bad {
		if _, err := normalizeRule(r, peers, 1); err == nil {
			t.Errorf("%+v reddedilmeli", r)
		}
	}
	got, _ := normalizeRule(Rule{Target: "server", Proto: "TCP", Ports: " 80 , 443 "}, peers, 1)
	if got.Ports != "80,443" || got.Proto != "tcp" {
		t.Errorf("kanonikleştirme: %+v", got)
	}
}

func TestCheckIP(t *testing.T) {
	a := testApp(t)
	peers := []Peer{peer("a", "Ali", "10.77.0.2", "")}
	cases := []struct {
		ip, self string
		ok       bool
	}{
		{"10.77.0.9", "", true},
		{"10.77.0.2", "", false},   // başka cihazda
		{"10.77.0.2", "a", true},   // kendi IP'si
		{"10.77.0.1", "", false},   // sunucu
		{"10.77.0.0", "", false},   // ağ adresi
		{"10.77.0.255", "", false}, // yayın
		{"10.78.0.5", "", false},   // ağ dışı
		{"abc", "", false},
		{"fe80::1", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		_, err := checkIP(a.srv, peers, c.ip, c.self)
		if (err == nil) != c.ok {
			t.Errorf("checkIP(%q, self=%q) ok=%v, hata=%v", c.ip, c.self, c.ok, err)
		}
	}
}

func TestEvalReach(t *testing.T) {
	now := time.Now()
	peers := []Peer{
		peer("ali", "Ali", "10.77.0.2", "p-admin"),
		peer("veli", "Veli", "10.77.0.3", "p-guest"),
		peer("ayse", "Ayşe", "10.77.0.4", ""),
	}
	pols := []Policy{
		{ID: "p-admin", Name: "Yönetici", Rules: []Rule{
			{Target: "server", Proto: "tcp", Ports: "22,5000"},
			{Target: "all", Proto: "any"},
		}},
		{ID: "p-guest", Name: "Misafir", Rules: []Rule{
			{Target: "server", Proto: "tcp", Ports: "5757,8000-8100", Note: "Jellyfin"},
			{Target: "device", Device: "ayse", Proto: "tcp", Ports: "443", Both: true},
		}},
	}
	ali, veli, ayse := peers[0], peers[1], peers[2]
	free := false
	chk := func(src Peer, dst, proto string, port int, want string) {
		t.Helper()
		v := evalReach("tr", peers, pols, src, dst, proto, port, 5000, free, now)
		if v.Result != want {
			t.Errorf("%s→%s %s/%d: %s (%s), beklenen %s", src.Name, dst, proto, port, v.Result, v.Reason, want)
		}
	}
	chk(veli, "server", "tcp", 5757, "allow")
	chk(veli, "server", "tcp", 8050, "allow")
	chk(veli, "server", "tcp", 22, "deny")
	chk(veli, "server", "tcp", 5000, "deny") // profil var: panel açıkça verilmedikçe kapalı
	chk(veli, "server", "icmp", 0, "allow")  // ping her zaman
	chk(veli, "ayse", "tcp", 443, "allow")
	chk(veli, "ayse", "tcp", 80, "deny")
	chk(veli, "ali", "tcp", 22, "deny")
	chk(ayse, "veli", "tcp", 443, "allow") // profili yok: yalnızca veli kuralındaki Both ters yönü
	chk(ayse, "veli", "tcp", 80, "deny")
	chk(ayse, "ali", "tcp", 80, "deny") // profili yok: cihazlar arası kapalı
	if v := evalReach("tr", peers, pols, ayse, "ali", "tcp", 80, 5000, false, now); v.Reason != T("tr", "access.isolated_between_devices", nil) {
		t.Errorf("profilsiz ret gerekçesi: %+v", v)
	}
	free = true
	chk(ayse, "ali", "tcp", 80, "allow") // PeerFree: v0.13 davranışı, serbest
	chk(ayse, "veli", "udp", 1, "allow")
	free = false
	chk(ayse, "server", "tcp", 5000, "allow")
	chk(ayse, "server", "tcp", 22, "host")
	chk(ali, "server", "tcp", 22, "allow")
	chk(ali, "server", "tcp", 5000, "allow")
	chk(ali, "veli", "udp", 9999, "allow") // tüm cihazlar, any
	chk(ali, "server", "tcp", 5757, "deny")

	// karşılıklı kural: Ayşe'nin profili olsaydı Veli→Ayşe'nin tersi de açılırdı
	peers[2].Policy = "p-none"
	pols = append(pols, Policy{ID: "p-none", Name: "Boş"})
	ayse = peers[2]
	chk(ayse, "veli", "tcp", 443, "allow") // veli kuralındaki Both ters yönü
	chk(ayse, "veli", "tcp", 80, "deny")
	chk(ayse, "ali", "tcp", 80, "deny")

	// kapalı hedef
	peers[0].Enabled = false
	if v := evalReach("tr", peers, pols, veli, "ali", "tcp", 1, 5000, false, now); v.Result != "deny" || v.Reason != T("tr", "access.dst_inactive", nil) {
		t.Errorf("kapalı hedef reddedilmeli: %+v", v)
	}
	// bulunamayan profil = her şey kapalı
	peers[1].Policy = "yok"
	if v := evalReach("tr", peers, pols, veli, "ayse", "tcp", 443, 5000, false, now); v.Result != "deny" {
		t.Errorf("kayıp profil kapalı sayılmalı: %+v", v)
	}
}

func fwText(f fwSet) string { return untag(strings.Join(f.display(), "\n")) }

// untag: kural metnindeki etiketleri (-m comment) siler; kuralın anlamını denetleyen testler etiketten bağımsızdır.
var tagRe = regexp.MustCompile(` -m comment --comment "?[^ "]+"?`)

func untag(s string) string { return tagRe.ReplaceAllString(s, "") }

// sLine: kuralın `iptables -S` çıktısındaki biçimi (yorum çift tırnak içinde).
func sLine(chain string, args []string) string {
	q := slices.Clone(args)
	for i := range q {
		if i > 0 && q[i-1] == "--comment" {
			q[i] = `"` + q[i] + `"`
		}
	}
	return "-A " + chain + " " + strings.Join(q, " ")
}

func TestDesiredFirewall(t *testing.T) {
	a := testApp(t)
	c := Settings{DNS: "1.1.1.1", Keepalive: 25, BlockPrivate: true}
	s := a.srv
	s.Settings = &c
	now := time.Now()
	future := now.Add(time.Hour)
	peers := []Peer{
		{ID: "net", Name: "net", IP: "10.77.0.2", Enabled: true, Internet: true},
		{ID: "yok", Name: "yok", IP: "10.77.0.3", Enabled: true},
		{ID: "dondu", Name: "dondu", IP: "10.77.0.4", Enabled: true, Internet: true, FrozenUntil: &future},
		{ID: "kapali", Name: "kapali", IP: "10.77.0.5", Enabled: false, Internet: true},
		{ID: "misafir", Name: "misafir", IP: "10.77.0.6", Enabled: true, Policy: "g"},
	}
	pols := []Policy{{ID: "g", Name: "Misafir", Rules: []Rule{
		{Target: "server", Proto: "tcp", Ports: "5757,8000-8100"},
		{Target: "device", Device: "yok", Proto: "tcp", Ports: "443"},
		{Target: "device", Device: "yok", Proto: "udp", Ports: "53", Both: true}, // profilsiz cihaza tek izin: ters yön
		{Target: "device", Device: "dondu", Proto: "any"},                        // dondurulmuş hedef: kural üretilmez
	}}}
	f := desiredFirewall(s, peers, pols, 5000, now)
	txt := fwText(f)

	must := []string{
		"-A KUT-INET -s 10.77.0.2/32 -d 10.0.0.0/8 -j DROP",
		"-A KUT-INET -s 10.77.0.2/32 -j ACCEPT",
		"-t nat -A KUT-NAT -s 10.77.0.2/32 ! -o wg0 -j MASQUERADE",
		"-A KUT-PEERS -s 10.77.0.3/32 -d 10.77.0.6/32 -p udp --dport 53 -j ACCEPT", // karşılıklı kuralın ters yönü
		"-A KUT-IN -s 10.77.0.2/32 -p tcp --dport 5000 -j ACCEPT",                  // profili olmayana panel açık
		"-A KUT-IN -s 10.77.0.6/32 -p tcp --dport 5757 -j ACCEPT",
		"-A KUT-IN -s 10.77.0.6/32 -p tcp --dport 8000:8100 -j ACCEPT",
		"-A KUT-IN -s 10.77.0.6/32 -j DROP",
		"-A KUT-PEERS -s 10.77.0.6/32 -d 10.77.0.3/32 -p tcp --dport 443 -j ACCEPT",
		"-A KUT-IN -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT",
		"-A KUT-IN -p icmp -m conntrack --ctstate RELATED -j KUT-ICMP",
		"-A KUT-IN -p icmp --icmp-type 8 -j ACCEPT",
		"-A KUT-ICMP -s 10.77.0.6/32 -m conntrack --ctstate RELATED --ctorigsrc 10.77.0.6 --ctdir ORIGINAL -j ACCEPT",
		"-A KUT-ICMP -s 10.77.0.6/32 -m conntrack --ctstate RELATED --ctreplsrc 10.77.0.6 --ctdir REPLY -j ACCEPT",
		"-A KUT-ICMP -j DROP",
	}
	for _, m := range must {
		if !strings.Contains(txt, m) {
			t.Errorf("eksik kural: %s\n--- tümü ---\n%s", m, txt)
		}
	}
	mustNot := []string{
		"10.77.0.4", // dondurulmuş: hiçbir kuralda yok
		"10.77.0.5", // kapalı
		"-A KUT-INET -s 10.77.0.3/32",
		"-A KUT-INET -s 10.77.0.6/32",
		"-A KUT-IN -s 10.77.0.6/32 -p tcp --dport 5000", // profili olan: panel açıkça verilmedikçe kapalı
		"-A KUT-PEERS -s 10.77.0.6/32 -j ACCEPT",
		"-A KUT-PEERS -s 10.77.0.2/32 -j ACCEPT", // profili yok: varsayılanda cihazlar arası kapalı
		"-A KUT-PEERS -s 10.77.0.3/32 -j ACCEPT",
		"-A KUT-PEERS -s 10.77.0.3/32 -d 10.77.0.6/32 -p tcp", // tek yönlü kural ters yön açmaz
		"-A KUT-IN -s 10.77.0.2/32 -j DROP",                   // profilsiz: sunucu portları ufw'ye kalır
		"-A KUT-IN -s 10.77.0.3/32 -j DROP",
	}
	for _, m := range mustNot {
		if strings.Contains(txt, m) {
			t.Errorf("olmamalı: %s\n--- tümü ---\n%s", m, txt)
		}
	}

	// PeerFree: v0.13 ve öncesinin davranışı, profilsiz cihaz VPN içinde serbest.
	c.PeerFree = true
	ftxt := fwText(desiredFirewall(s, peers, pols, 5000, now))
	for _, m := range []string{"-A KUT-PEERS -s 10.77.0.2/32 -j ACCEPT", "-A KUT-PEERS -s 10.77.0.3/32 -j ACCEPT", "-A KUT-IN -s 10.77.0.3/32 -p tcp --dport 5000 -j ACCEPT"} {
		if !strings.Contains(ftxt, m) {
			t.Errorf("PeerFree: eksik kural: %s\n%s", m, ftxt)
		}
	}
	if strings.Contains(ftxt, "-A KUT-IN -s 10.77.0.3/32 -j DROP") {
		t.Errorf("PeerFree: profilsize KUT-IN DROP yazılmamalı\n%s", ftxt)
	}
	c.PeerFree = false
	// KUT-IN içinde bir cihazın DROP'u o cihazın ACCEPT'lerinden sonra gelmeli
	iDrop, iAcc := -1, -1
	for i, r := range f.In {
		line := strings.Join(stripTag(r), " ")
		if strings.Contains(line, "-s 10.77.0.6/32 -j DROP") {
			iDrop = i
		}
		if strings.Contains(line, "-s 10.77.0.6/32 -p tcp --dport 5757") {
			iAcc = i
		}
	}
	if iDrop < iAcc || iAcc < 0 {
		t.Errorf("DROP, ACCEPT'ten sonra gelmeli (drop=%d accept=%d)", iDrop, iAcc)
	}

	c.BlockPrivate = false
	f = desiredFirewall(s, peers, pols, 5000, now)
	for _, r := range f.Inet {
		if strings.Contains(strings.Join(stripTag(r), " "), "DROP") {
			t.Error("BlockPrivate kapalıyken DROP olmamalı")
		}
	}
}

func TestPolicyReciprocalAndAll(t *testing.T) {
	a := testApp(t)
	now := time.Now()
	peers := []Peer{peer("x", "X", "10.77.0.2", "px"), peer("y", "Y", "10.77.0.3", "py")}
	pols := []Policy{
		{ID: "px", Name: "PX", Rules: []Rule{{Target: "device", Device: "y", Proto: "udp", Ports: "53", Both: true}}},
		{ID: "py", Name: "PY", Rules: []Rule{{Target: "all", Proto: "icmp"}}},
	}
	txt := fwText(desiredFirewall(a.srv, peers, pols, 5000, now))
	for _, m := range []string{
		"-A KUT-PEERS -s 10.77.0.2/32 -d 10.77.0.3/32 -p udp --dport 53 -j ACCEPT",
		"-A KUT-PEERS -s 10.77.0.3/32 -d 10.77.0.2/32 -p udp --dport 53 -j ACCEPT", // karşılıklı
		"-A KUT-PEERS -s 10.77.0.3/32 -d 10.77.0.0/24 -p icmp -j ACCEPT",
	} {
		if !strings.Contains(txt, m) {
			t.Errorf("eksik: %s\n%s", m, txt)
		}
	}
}

func TestClientConfigInternet(t *testing.T) {
	a := testApp(t)
	c := Settings{DNS: "9.9.9.9", MTU: 1380, Keepalive: 25}
	s := a.srv
	s.Settings = &c
	off := buildClientConfig(s, "PRIV", Peer{IP: "10.77.0.2"})
	if !strings.Contains(off, "AllowedIPs = 10.77.0.0/24") || strings.Contains(off, "0.0.0.0/0") || strings.Contains(off, "DNS") {
		t.Errorf("internetsiz config yanlış:\n%s", off)
	}
	on := buildClientConfig(s, "PRIV", Peer{IP: "10.77.0.2", Internet: true})
	for _, w := range []string{"0.0.0.0/0, ::/0", "DNS = 9.9.9.9", "MTU = 1380", "PersistentKeepalive = 25"} {
		if !strings.Contains(on, w) {
			t.Errorf("%q eksik:\n%s", w, on)
		}
	}
}

func TestServerConfFirewallHooks(t *testing.T) {
	a := testApp(t)
	conf := untag(renderServerConf(a.srv, []Peer{{Name: "x", PublicKey: "K", PSK: "P", IP: "10.77.0.2", Enabled: true, Internet: true}}))
	for _, w := range []string{chainInet, chainPeers, chainIn, chainICMP, "PostUp", "PostDown", "iptables -w 5 -C FORWARD"} {
		if !strings.Contains(conf, w) {
			t.Errorf("conf'ta %q yok", w)
		}
	}
	if strings.Contains(conf, "MASQUERADE") {
		t.Error("MASQUERADE conf'ta olmamalı; panel dolduruyor")
	}
	// PostUp'ta jump kuralları ters sırayla eklenmeli: son eklenen en üstte olur
	up := strings.Index(conf, "-I FORWARD 1 -i %i -j DROP")
	top := strings.Index(conf, "-I FORWARD 1 ! -i %i -o %i -m conntrack")
	if up < 0 || top < 0 || up > top {
		t.Error("PostUp sırası: önce alttaki kural (DROP), en son conntrack eklenmeli")
	}
}

func TestMaskSecrets(t *testing.T) {
	out := maskSecrets("PrivateKey = abc\nPresharedKey = def\nPublicKey = ghi\n")
	if strings.Contains(out, "abc") || strings.Contains(out, "def") || !strings.Contains(out, "ghi") {
		t.Errorf("maskeleme hatalı: %q", out)
	}
}

func TestSettingsValidation(t *testing.T) {
	for _, ok := range []string{"203.0.113.10", "vpn.ornek.com", "2001:db8::1"} {
		if _, err := validEndpoint(ok); err != nil {
			t.Errorf("%q geçerli olmalı: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "1.2.3.4:51820", "a b", "-x.com"} {
		if _, err := validEndpoint(bad); err == nil {
			t.Errorf("%q reddedilmeli", bad)
		}
	}
	if _, err := validDNS("1.1.1.1, 8.8.8.8, 9.9.9.9, 4.4.4.4"); err == nil {
		t.Error("4 DNS reddedilmeli")
	}
	if _, err := validDNS("evil.com"); err == nil {
		t.Error("alan adı DNS reddedilmeli")
	}
	if v, err := validDNS(""); err != nil || v != "" {
		t.Error("boş DNS serbest")
	}
}

func TestActivityPersistAndTrim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	a := loadActivity(path)
	for i := 0; i < actCap+50; i++ {
		a.add(Event{T: int64(i), IP: "x", Kind: "k", Text: "e"})
	}
	if got := a.list(actCap + 100); len(got) != actCap || got[0].T != int64(actCap+49) {
		t.Fatalf("beklenen %d en yeni önce, geldi %d", actCap, len(got))
	}
	b := loadActivity(path)
	if got := b.list(5); len(got) != 5 || got[0].T != int64(actCap+49) {
		t.Fatal("yeniden yükleme sonrası kayıp")
	}
}

func TestHistoryRing(t *testing.T) {
	var h *history
	h.add(sample{T: 1}) // nil-safe
	h2 := &history{}
	for i := 0; i < tiers[0].keep+10; i++ {
		h2.add(sample{T: int64(i * 15)})
	}
	if l := h2.list(0); len(l) != tiers[0].keep || l[len(l)-1].T != int64((tiers[0].keep+9)*15) {
		t.Fatal("halka tamponu hatalı")
	}
}

func TestVersionCompare(t *testing.T) {
	for _, c := range []struct {
		l, cur string
		newer  bool
	}{
		{"0.4.1", "0.4.0", true}, {"v0.5.0", "0.4.9", true}, {"1.0.0", "0.9.9", true},
		{"0.4.0", "0.4.0", false}, {"0.3.9", "0.4.0", false}, {"abc", "0.4.0", false}, {"v0.4.0-rc1", "0.4.0", false},
	} {
		if got := newerVersion(c.l, c.cur); got != c.newer {
			t.Errorf("newerVersion(%q,%q)=%v", c.l, c.cur, got)
		}
	}
}

// v0.3 veri dizini sessizce yükseltilmeli: cihazlar, IP'ler ve anahtarlar aynı kalır, yedek alınır.
func TestMigrateFromV03(t *testing.T) {
	dir := t.TempDir()
	spriv, spub, _ := mustKeys(t)
	_, ppub, ppsk := mustKeys(t)
	v03server := `{"private_key":"` + spriv + `","public_key":"` + spub + `","endpoint":"203.0.113.10","port":51820,"subnet":"10.77.0.0/24","iface":"wg0","conf_path":"/etc/wireguard/wg0.conf"}`
	v03peers := `[{"id":"a1","name":"Ali","public_key":"` + ppub + `","psk":"` + ppsk + `","ip":"10.77.0.2","enabled":true,"internet":true,"created":"2026-10-04T10:00:00Z"}]`
	os.WriteFile(filepath.Join(dir, "server.json"), []byte(v03server), 0o600)
	os.WriteFile(filepath.Join(dir, "peers.json"), []byte(v03peers), 0o600)
	rec, _ := newAdmin("uzun-bir-parola-123")
	if err := saveJSON(adminPath(dir), rec); err != nil {
		t.Fatal(err)
	}
	a, err := loadApp(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if a.srv.Schema != currentSchema {
		t.Errorf("şema %d", a.srv.Schema)
	}
	if len(a.peers) != 1 || a.peers[0].IP != "10.77.0.2" || a.peers[0].PublicKey != ppub || !a.peers[0].Internet || a.peers[0].Policy != "" {
		t.Errorf("cihaz değişmemeliydi: %+v", a.peers)
	}
	if a.srv.cfg().DNS == "" {
		t.Error("varsayılan ayarlar eklenmeliydi")
	}
	ents, _ := filepath.Glob(filepath.Join(dir, "backup-schema1-*", "peers.json"))
	if len(ents) != 1 {
		t.Fatalf("yedek yok: %v", ents)
	}
	if b, _ := os.ReadFile(ents[0]); string(b) != v03peers {
		t.Error("yedek orijinalle aynı olmalı")
	}
	if _, err := os.Stat(policiesPath(dir)); err != nil {
		t.Error("policies.json oluşmalıydı")
	}
	// ikinci yükleme yeniden yedek almaz
	if _, err := loadApp(dir, true); err != nil {
		t.Fatal(err)
	}
	ents, _ = filepath.Glob(filepath.Join(dir, "backup-schema1-*"))
	if len(ents) != 1 {
		t.Errorf("ikinci açılışta yedek çoğalmamalı: %v", ents)
	}
}

func TestNewerSchemaRefused(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "server.json"), []byte(`{"private_key":"x","public_key":"y","endpoint":"1.2.3.4","port":1,"subnet":"10.77.0.0/24","iface":"wg0","conf_path":"x","schema":99}`), 0o600)
	rec, _ := newAdmin("uzun-bir-parola-123")
	saveJSON(adminPath(dir), rec)
	if _, err := loadApp(dir, true); err == nil {
		t.Error("daha yeni şema reddedilmeli (veri bozulmasın)")
	}
}

// Bozuk port listesi ya da bilinmeyen protokol "tüm portlar" anlamına gelmemeli (fail-closed, Rule.matches ile tutarlı).
func TestMatchArgsBrokenRuleAllowsNothing(t *testing.T) {
	for _, r := range []Rule{
		{Target: "server", Proto: "tcp", Ports: "80-"},
		{Target: "server", Proto: "udp", Ports: "0"},
		{Target: "server", Proto: "tcp", Ports: "70000"},
		{Target: "server", Proto: "sctp"},
		{Target: "server", Proto: "TCP", Ports: "443"},
	} {
		for _, v6 := range []bool{false, true} {
			if m := matchArgsFam(r, v6); len(m) != 0 {
				t.Errorf("%+v (v6=%v): eşleşme üretmemeli, üretilen %v", r, v6, m)
			}
		}
		if r.matches("tcp", 80) || r.matches("udp", 0) {
			t.Errorf("%+v: matches da izin vermemeli", r)
		}
	}
	// geçerli kurallar etkilenmez
	if m := matchArgsFam(Rule{Proto: "tcp"}, false); len(m) != 1 || strings.Join(m[0], " ") != "-p tcp" {
		t.Errorf("portsuz tcp: %v", m)
	}
	if m := matchArgsFam(Rule{Proto: "udp", Ports: "53,8000-8100"}, false); len(m) != 2 || strings.Join(m[1], " ") != "-p udp --dport 8000:8100" {
		t.Errorf("port listesi: %v", m)
	}
}

// İskelet onarımında eski kopya silinemezse bu sessizce yutulmamalı (yinelenen kural birikir).
func TestEnsureSkeletonLogsDeleteFailure(t *testing.T) {
	sk := skeleton("wg0", "10.77.0.0/24")
	fwd := skelGroup(sk, "filter", "FORWARD")
	chains := map[string][][]string{
		"FORWARD": {fwd[0]}, // yalnızca ilk kural var: iskelet yeniden eklenir, eski kopya altta kalır
		"INPUT":   skelGroup(sk, "filter", "INPUT"),
	}
	fake := func(table string, args ...string) ([]byte, error) {
		switch {
		case args[0] == "-S":
			var b strings.Builder
			for _, r := range chains[args[1]] {
				fmt.Fprintf(&b, "-A %s %s\n", args[1], strings.Join(r, " "))
			}
			return []byte(b.String()), nil
		case args[0] == "-I" && table == "filter":
			chains[args[1]] = append([][]string{args[3:]}, chains[args[1]]...)
			return nil, nil
		case args[0] == "-D":
			return nil, errors.New("iptables: Resource temporarily unavailable.")
		}
		return nil, nil // -N, nat -C
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	if err := ensureSkeletonF(fake, sk); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); !strings.Contains(got, "FORWARD") || !strings.Contains(got, "Resource temporarily unavailable") {
		t.Fatalf("silinemeyen eski kural günlüğe yazılmalı, günlük: %q", got)
	}
}

// İskelet fail-closed olmalı: kurulmuş akışın kısayolu yalnızca yanıt yönüne (REPLY) açık, wg0'a giden
// başka her şey en sonda düşer. Kurulmuş bir akışın ORIGINAL yöndeki paketi her turda profil kurallarından
// geçer; profil daraltılınca ya da zamanlı kural bitince akış da kesilir.
func TestSkeletonReplyOnlyAndForwardDrop(t *testing.T) {
	sk := skeleton("wg0", "10.77.0.0/24")
	want := []string{
		"! -i wg0 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT",
		"-i wg0 -o wg0 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT",
		"-i wg0 -o wg0 -p icmp -m conntrack --ctstate RELATED -j KUT-ICMP",
		"-i wg0 -o wg0 -j KUT-PEERS",
		"-i wg0 -o wg0 -j DROP",
		"-i wg0 -j KUT-INET",
		"-i wg0 -j DROP",
		"-o wg0 -j DROP",
	}
	got := skelGroup(sk, "filter", "FORWARD")
	if len(got) != len(want) {
		t.Fatalf("FORWARD iskeleti %d kural, %d olmalı: %q", len(got), len(want), got)
	}
	for i := range want {
		if g := strings.Join(stripTag(got[i]), " "); g != want[i] {
			t.Errorf("FORWARD %d. kural %q, beklenen %q", i+1, g, want[i])
		}
	}
	// Akışla ilgili ICMP hataları (PMTU): ailenin ICMP protokolüyle, yalnızca RELATED, akış tarafı denetimine (KUT-ICMP).
	if g := strings.Join(stripTag(skelGroup(skeleton("wg0", "fdaa:bbbb:cccc::/64"), "filter", "FORWARD")[2]), " "); g != "-i wg0 -o wg0 -p ipv6-icmp -m conntrack --ctstate RELATED -j KUT-ICMP" {
		t.Errorf("IPv6 FORWARD 3. kural %q", g)
	}
	for proto, f := range map[string]fwSet{
		"icmp":      desiredFirewall(testApp(t).srv, nil, nil, 5000, time.Now()),
		"ipv6-icmp": desiredFirewall6(v6Server(t), nil, nil, time.Now(), true),
	} {
		if g := strings.Join(stripTag(f.In[0]), " "); g != "-A KUT-IN -m conntrack --ctstate ESTABLISHED --ctdir REPLY -j ACCEPT" {
			t.Errorf("KUT-IN'in ilk kuralı yalnızca yanıt yönünü kabul etmeli, olan: %q", g)
		}
		if g := strings.Join(stripTag(f.In[1]), " "); g != "-A KUT-IN -p "+proto+" -m conntrack --ctstate RELATED -j KUT-ICMP" {
			t.Errorf("KUT-IN'in ikinci kuralı akışla ilgili ICMP hatalarını KUT-ICMP'ye göndermeli, olan: %q", g)
		}
		// Cihaz yokken KUT-ICMP yalnızca DROP: hiçbir hata iletisi geçmez.
		if len(f.ICMP) != 1 || strings.Join(stripTag(f.ICMP[0]), " ") != "-A KUT-ICMP -j DROP" {
			t.Errorf("cihazsız KUT-ICMP yalnızca DROP olmalı: %q", f.ICMP)
		}
	}
	// wg-quick kancası: -I FORWARD 1 ile ters sırada eklenir; son kural (-o DROP) ilk eklenen olmalı.
	conf := untag(renderServerConf(testApp(t).srv, nil))
	oDrop := strings.Index(conf, "-I FORWARD 1 -o %i -j DROP")
	iDrop := strings.Index(conf, "-I FORWARD 1 -i %i -j DROP")
	if oDrop < 0 || iDrop < 0 || oDrop > iDrop {
		t.Errorf("PostUp: -o DROP, -i DROP'tan önce eklenmeli (o=%d i=%d)", oDrop, iDrop)
	}
	if !strings.Contains(conf, "-D FORWARD -o %i -j DROP") {
		t.Error("PostDown -o DROP kuralını kaldırmalı")
	}
	// Kancalar da ailenin ICMP kuralını kurar ve kaldırır.
	conf6 := untag(renderServerConf(v6Server(t), nil))
	for _, w := range []string{
		"iptables -w 5 -I FORWARD 1 -i %i -o %i -p icmp -m conntrack --ctstate RELATED -j KUT-ICMP",
		"ip6tables -w 5 -I FORWARD 1 -i %i -o %i -p ipv6-icmp -m conntrack --ctstate RELATED -j KUT-ICMP",
		"ip6tables -w 5 -D FORWARD -i %i -o %i -p ipv6-icmp -m conntrack --ctstate RELATED -j KUT-ICMP",
		"ip6tables -w 5 -N KUT-ICMP 2>/dev/null || ip6tables -w 5 -F KUT-ICMP",
		"ip6tables -w 5 -X KUT-ICMP 2>/dev/null || true",
	} {
		if !strings.Contains(conf6, w) {
			t.Errorf("kancada %q yok", w)
		}
	}
}

// fakeChains: `-S ZİNCİR` isteğine verilen zincir satırlarını döndüren sahte iptables (diğer çağrılar başarılı).
func fakeChains(chains map[string][]string) iptFn {
	return func(_ string, args ...string) ([]byte, error) {
		if args[0] == "-S" {
			return []byte(strings.Join(chains[args[1]], "\n") + "\n"), nil
		}
		return nil, nil
	}
}

// İzleyici yalnızca skeletonOK'un gördüğünü onarır: eski (yönsüz) kısayol ya da eksik son DROP "bozuk" sayılmalı.
func TestSkeletonOKRequiresReplyAndForwardDrop(t *testing.T) {
	sk := skeleton("wg0", "10.77.0.0/24")
	in := []string{"-P INPUT ACCEPT", sLine("INPUT", skelGroup(sk, "filter", "INPUT")[0])}
	cur := []string{"-P FORWARD ACCEPT"}
	for _, r := range skelGroup(sk, "filter", "FORWARD") {
		cur = append(cur, sLine("FORWARD", r))
	}
	if st := skeletonOKF(fakeChains(map[string][]string{"FORWARD": cur, "INPUT": in}), sk, "IPv4"); st.State != "ok" {
		t.Fatalf("güncel iskelet tamam sayılmalı: %s", st.Detail)
	}
	old := append([]string{cur[0], "-A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"}, cur[4:8]...)
	noDrop := cur[:8]
	noICMP := append(append([]string{}, cur[:3]...), cur[4:]...) // ICMP hata kuralından önceki sürüm
	v012 := append([]string{cur[0], "-A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT",
		"-A FORWARD -i wg0 -o wg0 -p icmp -m conntrack --ctstate RELATED -j ACCEPT"}, cur[4:]...) // ICMP akış tarafını denetlemeyen v0.12
	v014 := []string{cur[0]} // etiketsiz iskelet: v0.15 bunu bozuk sayar ve etiketli kopyayla değiştirir
	for _, l := range cur[1:] {
		v014 = append(v014, untag(l))
	}
	for name, fwd := range map[string][]string{"yönsüz kısayol (eski sürüm)": old, "son -o DROP yok": noDrop, "ICMP hata kuralı yok": noICMP, "v0.12 iskeleti": v012, "v0.14 iskeleti (etiketsiz)": v014} {
		if st := skeletonOKF(fakeChains(map[string][]string{"FORWARD": fwd, "INPUT": in}), sk, "IPv4"); st.State == "ok" {
			t.Errorf("%s: iskelet bozuk sayılmalı", name)
		}
	}
}

// FORWARD varsayılan politikası `-S FORWARD`'ın "-P" satırından okunur; okunamazsa boş.
func TestForwardPolicy(t *testing.T) {
	if p := forwardPolicyF(fakeChains(map[string][]string{"FORWARD": {"-P FORWARD DROP", "-A FORWARD -j X"}})); p != "DROP" {
		t.Errorf("politika DROP olmalı, okunan %q", p)
	}
	if p := forwardPolicyF(func(string, ...string) ([]byte, error) { return nil, errors.New("yok") }); p != "" {
		t.Errorf("okunamayınca boş olmalı, okunan %q", p)
	}
}

// Güvenlik duvarı durumu metin değil katalog anahtarı taşır (Key + Params): sunucu sayfası ve rapor onu
// T(lang, Key, Params) ile okuyanın dilinde yazar. Detail aynı anahtarın referans dildeki (en) metnidir.
func TestFwStateKeys(t *testing.T) {
	sk := skeleton("wg0", "10.77.0.0/24")
	in := []string{"-P INPUT ACCEPT", sLine("INPUT", skelGroup(sk, "filter", "INPUT")[0])}
	var fwd []string
	for _, r := range skelGroup(sk, "filter", "FORWARD") {
		fwd = append(fwd, "-A FORWARD "+strings.Join(r, " "))
	}
	// failOn: verilen işlem/zincir için hata döndüren, gerisinde iskeleti tam gösteren sahte iptables.
	failOn := func(op, chain string) iptFn {
		ok := fakeChains(map[string][]string{"FORWARD": fwd, "INPUT": in})
		return func(table string, args ...string) ([]byte, error) {
			if args[0] == op && args[1] == chain {
				return nil, errors.New("boom")
			}
			return ok(table, args...)
		}
	}
	want := fwSet{Peers: [][]string{{"-A", chainPeers, "-s", "10.77.0.2/32", "-j", "ACCEPT"}, {"-A", chainPeers, "-s", "10.77.0.3/32", "-j", "ACCEPT"}}}
	type fsCase struct {
		name, state, key string
		st               fwState
		params           map[string]any
	}
	a := testApp(t)
	cases := []fsCase{
		{"iskelet üstü", "no-jump", "fw.skeleton.top",
			skeletonOKF(fakeChains(map[string][]string{"FORWARD": fwd[:1], "INPUT": in}), sk, "IPv4"),
			map[string]any{"fam": "IPv4", "chain": "FORWARD"}},
		{"iskelet okunamadı", "no-jump", "fw.skeleton.read_failed",
			skeletonOKF(failOn("-S", "FORWARD"), sk, "IPv6"),
			map[string]any{"fam": "IPv6", "chain": "FORWARD", "err": "boom"}},
		{"nat atlaması", "no-jump", "fw.skeleton.nat_jump",
			skeletonOKF(failOn("-C", "POSTROUTING"), sk, "IPv4"),
			map[string]any{"fam": "IPv4"}},
		{"zincir yok", "no-jump", "fw.skeleton.chain_missing",
			skeletonOKF(failOn("-S", chainInet), sk, "IPv4"),
			map[string]any{"fam": "IPv4", "chain": chainInet}},
		{"zincir okunamadı", "no-jump", "fw.chain.read_failed",
			verifyChainsF(failOn("-S", chainPeers), want, "IPv6"),
			map[string]any{"fam": "IPv6", "chain": chainPeers}},
		{"kural sayısı", "out-of-sync", "fw.chain.count",
			verifyChainsF(fakeChains(map[string][]string{chainPeers: {"-A KUT-PEERS -s 10.77.0.2/32 -j ACCEPT"}}), want, "IPv4"),
			map[string]any{"fam": "IPv4", "chain": chainPeers, "n": 1, "want": 2}},
		{"kural farkı", "out-of-sync", "fw.chain.rule_differs",
			verifyChainsF(fakeChains(map[string][]string{chainPeers: {"-A KUT-PEERS -s 10.77.0.2/32 -j ACCEPT", "-A KUT-PEERS -s 10.77.0.9/32 -j ACCEPT"}}), want, "IPv4"),
			map[string]any{"fam": "IPv4", "chain": chainPeers, "pos": 2}},
		{"dry-run", "dry", "fw.dry", a.fwCheck(a.srv, nil, nil), nil},
	}
	// wg ve ip6tables PATH'te yokken: arayüz kapalı görünür, IPv6 doğrulaması ip6tables yokluğunu bildirir.
	t.Setenv("PATH", t.TempDir())
	live := fwApp(t)
	cases = append(cases,
		fsCase{"arayüz kapalı", "down", "fw.down", live.fwCheck(live.srv, nil, nil), nil},
		fsCase{"ip6tables yok", "no-jump", "fw.no_ip6tables", live.fwVerify6(v6Server(t), nil, nil), nil},
	)
	for _, c := range cases {
		st := c.st
		if st.State != c.state || st.Key != c.key || fmt.Sprint(st.Params) != fmt.Sprint(c.params) {
			t.Errorf("%s: {%s %s %v}, beklenen {%s %s %v}", c.name, st.State, st.Key, st.Params, c.state, c.key, c.params)
			continue
		}
		if st.Detail != T(refLang, st.Key, st.Params) {
			t.Errorf("%s: Detail referans dildeki metin olmalı: %q", c.name, st.Detail)
		}
		for _, l := range langs {
			if got := T(l, st.Key, st.Params); got == st.Key || strings.Contains(got, "{") {
				t.Errorf("%s: %s kataloğunda anahtar ya da yer tutucu eksik: %q", c.name, l, got)
			}
		}
	}
	// İzleyici kararı metne değil anahtara bağlı (fwNeedsRepair): sabit bir katalog anahtarıdır.
	if errNoIP6Tables != "fw.no_ip6tables" {
		t.Errorf("errNoIP6Tables bir katalog anahtarı olmalı: %q", errNoIP6Tables)
	}
	// Çoğul: tek kuralda "rule", birden çokta "rules" (sözleşme 6).
	one := T("en", "fw.chain.count", map[string]any{"fam": "IPv4", "chain": chainPeers, "n": 1, "want": 2})
	many := T("en", "fw.chain.count", map[string]any{"fam": "IPv4", "chain": chainPeers, "n": 3, "want": 2})
	if one == many || !strings.Contains(one, "1 rule,") || !strings.Contains(many, "3 rules") {
		t.Errorf("çoğul biçimi seçilmeli: %q / %q", one, many)
	}
}
