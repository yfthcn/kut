package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type tarEntry struct {
	name string
	data []byte
}

// tarGz: verilen sırayla (yinelenen ad dahil) düz bir yedek arşivi üretir.
func tarGz(t *testing.T, ents []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// validBackupEntries: parseBackup'tan geçen bir yedeğin kayıtları.
func validBackupEntries(t *testing.T) []tarEntry {
	t.Helper()
	s, ps, pols := validStateFixture(t)
	adm, err := newAdmin("uzun-bir-parola-123")
	if err != nil {
		t.Fatal(err)
	}
	return []tarEntry{
		{"server.json", mustJSON(t, s)},
		{"peers.json", mustJSON(t, ps)},
		{"policies.json", mustJSON(t, pols)},
		{"admin.json", mustJSON(t, adm)},
		{"users.json", []byte(`[]`)},
		{"notify.json", []byte(`{}`)},
	}
}

func TestParseBackupRejectsBadContent(t *testing.T) {
	if _, err := parseBackup(tarGz(t, validBackupEntries(t))); err != nil {
		t.Fatalf("geçerli yedek reddedildi: %v", err)
	}
	replace := func(name string, data []byte) []tarEntry {
		ents := validBackupEntries(t)
		for i := range ents {
			if ents[i].name == name {
				ents[i].data = data
			}
		}
		return ents
	}
	_, ps, _ := validStateFixture(t)
	ps[0].Name = "x\nPostUp = touch /tmp/pwned"
	for _, c := range []struct {
		name string
		ents []tarEntry
		want string
	}{
		{"satır sonlu cihaz adı", replace("peers.json", mustJSON(t, ps)), "name of device #1"},
		{"yinelenen kayıt", append(validBackupEntries(t), tarEntry{"peers.json", []byte(`[]`)}), "peers.json"},
		{"bozuk users.json", replace("users.json", []byte(`{"x":`)), "users.json"},
		{"yanlış tipli users.json", replace("users.json", []byte(`{"name":"a"}`)), "users.json"},
		{"bozuk notify.json", replace("notify.json", []byte(`[1,2]`)), "notify.json"},
		{"bilinmeyen rol", replace("users.json", []byte(`[{"name":"ayse","role":"superuser"}]`)), "users.json"},
		{"sahip adında hesap", replace("users.json", []byte(`[{"name":"admin","role":"admin"}]`)), "users.json"},
		{"yerel adında hesap", replace("users.json", []byte(`[{"name":"yerel","role":"admin"}]`)), "users.json"},
		{"yinelenen hesap", replace("users.json", []byte(`[{"name":"ayse","role":"viewer"},{"name":"ayse","role":"admin"}]`)), "users.json"},
		{"geçersiz hesap adı", replace("users.json", []byte(`[{"name":"Ayse\nx","role":"viewer"}]`)), "users.json"},
		{"dosya şemalı webhook", replace("notify.json", []byte(`{"webhook":{"enabled":true,"url":"file:///etc/shadow"}}`)), "notify.json"},
		{"hostsuz webhook", replace("notify.json", []byte(`{"webhook":{"url":"https://"}}`)), "notify.json"},
		{"bozuk bot jetonu", replace("notify.json", []byte(`{"telegram":{"token":"x\ny"}}`)), "notify.json"},
		{"bozuk sohbet kimliği", replace("notify.json", []byte(`{"telegram":{"chat_id":"abc"}}`)), "notify.json"},
		{"bozuk sessiz saat", replace("notify.json", []byte(`{"quiet_from":"25:00"}`)), "notify.json"},
		{"çok büyük kayıt", append(validBackupEntries(t), tarEntry{"activity.jsonl", make([]byte, 64<<20+1)}), "activity.jsonl"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseBackup(tarGz(t, c.ents))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("reddedilmeli ve hata %q içermeli: %v", c.want, err)
			}
		})
	}
}

// Diskteki veri de aynı denetimden geçer: bozuk durumla panel açılmaz (wg0.conf'a hiçbir şey yazılmadan).
func TestLoadAppRejectsInvalidState(t *testing.T) {
	write := func(t *testing.T, mutate func(*Server, []Peer)) string {
		dir := t.TempDir()
		s, ps, pols := validStateFixture(t)
		mutate(&s, ps)
		adm, _ := newAdmin("uzun-bir-parola-123")
		for name, v := range map[string]any{"server.json": s, "peers.json": ps, "policies.json": pols, "admin.json": adm} {
			if err := os.WriteFile(dir+"/"+name, mustJSON(t, v), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
	if _, err := loadApp(write(t, func(*Server, []Peer) {}), true); err != nil {
		t.Fatalf("geçerli veri dizini reddedildi: %v", err)
	}
	if _, err := loadApp(write(t, func(_ *Server, ps []Peer) { ps[0].Name = "x\nPostUp = id" }), true); err == nil || !strings.Contains(err.Error(), "ad") {
		t.Fatalf("satır sonlu cihaz adıyla açılmamalı: %v", err)
	}
	if _, err := loadApp(write(t, func(s *Server, _ []Peer) { s.ConfPath = "/etc/cron.d/x" }), true); err == nil || !strings.Contains(err.Error(), "conf_path") {
		t.Fatalf("başka bir dosyaya yazan conf_path ile açılmamalı: %v", err)
	}
	dir := write(t, func(*Server, []Peer) {})
	if err := os.WriteFile(dir+"/users.json", []byte(`[{"name":"ayse","role":"superuser"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadApp(dir, true); err == nil || !strings.Contains(err.Error(), "users.json") {
		t.Fatalf("bilinmeyen rollü hesapla açılmamalı: %v", err)
	}
}

// Özel alt ağ şartı bir politika kuralı: yalnızca kut init'te ölümcül. Şarttan önce genel bir alt ağla kurulmuş
// sunucunun paneli açılmaya devam eder; rapor (kut doctor) uyarır.
func TestLoadAppAcceptsPublicSubnetWithWarning(t *testing.T) {
	dir := t.TempDir()
	s, ps, pols := validStateFixture(t)
	s.Subnet, ps[0].IP, ps[1].IP = "198.51.100.0/24", "198.51.100.2", "198.51.100.3"
	adm, _ := newAdmin("uzun-bir-parola-123")
	for name, v := range map[string]any{"server.json": s, "peers.json": ps, "policies.json": pols, "admin.json": adm} {
		if err := os.WriteFile(dir+"/"+name, mustJSON(t, v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, err := loadApp(dir, true)
	if err != nil {
		t.Fatalf("genel alt ağlı eski kurulum açılmalı: %v", err)
	}
	var got *Check
	for _, c := range a.buildReport(refLang).Checks {
		if c.ID == "subnet" {
			got = &c
		}
	}
	if got == nil || got.Level != "warn" || got.Group != "network" || !strings.Contains(got.Detail, "198.51.100.0/24") {
		t.Fatalf("raporda alt ağ uyarısı olmalı: %+v", got)
	}
	// özel alt ağda uyarı yok
	b, _ := loadApp(func() string {
		d := t.TempDir()
		s, ps, pols := validStateFixture(t)
		for name, v := range map[string]any{"server.json": s, "peers.json": ps, "policies.json": pols, "admin.json": adm} {
			if err := os.WriteFile(d+"/"+name, mustJSON(t, v), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}(), true)
	for _, c := range b.buildReport(refLang).Checks {
		if c.ID == "subnet" && c.Level != "ok" {
			t.Fatalf("özel alt ağda uyarı olmamalı: %+v", c)
		}
	}
}

func TestValidateAccountsAndNotify(t *testing.T) {
	if err := validateAccounts([]User{{Name: "ayse", Role: roleViewer}, {Name: "can.b", Role: roleAdmin}}); err != nil {
		t.Fatalf("geçerli hesaplar reddedildi: %v", err)
	}
	if err := validateAccounts(nil); err != nil {
		t.Fatalf("boş liste reddedildi: %v", err)
	}
	var c NotifyCfg
	c.Telegram.Token, c.Telegram.ChatID = "123456789:AAH"+strings.Repeat("x", 32), "-100123"
	c.Webhook.URL, c.QuietFrom, c.QuietTo = "https://ntfy.example.com/kut", "23:00", "07:00"
	if err := validateNotify(c); err != nil {
		t.Fatalf("geçerli bildirim ayarı reddedildi: %v", err)
	}
	if err := validateNotify(defaultNotify()); err != nil {
		t.Fatalf("varsayılan bildirim ayarı reddedildi: %v", err)
	}
}

// mustKeys: geçerli bir WireGuard anahtar üçlüsü (wg.go'daki üreticiyle).
func mustKeys(t *testing.T) (priv, pub, psk string) {
	t.Helper()
	priv, pub, psk, err := newKeys()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub, psk
}

// validStateFixture: validateState'ten geçen eksiksiz bir durum; tablo testindeki her satır bir alanı bozar.
func validStateFixture(t *testing.T) (Server, []Peer, []Policy) {
	t.Helper()
	spriv, spub, _ := mustKeys(t)
	_, p1, k1 := mustKeys(t)
	_, p2, k2 := mustKeys(t)
	srv := Server{PrivateKey: spriv, PublicKey: spub, Endpoint: "203.0.113.10", Port: 51820,
		Subnet: "10.77.0.0/24", Iface: "wg0", ConfPath: "/etc/wireguard/wg0.conf", Schema: currentSchema}
	peers := []Peer{
		{ID: "a", Name: "Ali telefonu", PublicKey: p1, PSK: k1, IP: "10.77.0.2", Enabled: true, Policy: "p"},
		{ID: "b", Name: "laptop", PublicKey: p2, PSK: k2, IP: "10.77.0.3", Enabled: true},
	}
	pols := []Policy{{ID: "p", Name: "Ev", Rules: []Rule{
		{Target: "server", Proto: "tcp", Ports: "22,8000-8100"},
		{Target: "device", Device: "b", Proto: "icmp"},
		{Target: "all", Proto: "any", Schedule: &Schedule{Days: []int{1, 2}, From: "08:00", To: "17:00", Scope: "tunnel"}},
	}}}
	return srv, peers, pols
}

// withCfg: sunucu ayarlarının (varsayılandan başlayarak) bir alanını değiştiren tablo satırı.
func withCfg(f func(*Settings)) func(*Server, []Peer, []Policy) {
	return func(s *Server, _ []Peer, _ []Policy) {
		c := s.cfg()
		f(&c)
		s.Settings = &c
	}
}

func TestValidateState(t *testing.T) {
	for _, c := range []struct {
		name   string
		mutate func(s *Server, ps []Peer, pols []Policy)
		want   string // boşsa hata beklenmez; doluysa hatanın kodu (codedErr.Code) bu olmalı
	}{
		{"geçerli durum", func(*Server, []Peer, []Policy) {}, ""},
		{"dry-run yolu", func(s *Server, _ []Peer, _ []Policy) { s.ConfPath = "veri/wg0.conf" }, ""},
		{"satır sonlu cihaz adı", func(_ *Server, ps []Peer, _ []Policy) {
			ps[0].Name = "x\nPostUp = touch /tmp/pwned"
		}, "validate.peer_name"},
		{"alt ağ dışı IP", func(_ *Server, ps []Peer, _ []Policy) { ps[1].IP = "10.78.0.3" }, "validate.peer_ip_range"},
		{"kısa anahtar", func(_ *Server, ps []Peer, _ []Policy) { ps[0].PublicKey = "A" }, "validate.peer_key"},
		{"başka arayüzün yolu", func(s *Server, _ []Peer, _ []Policy) { s.ConfPath = "/etc/wireguard/wg1.conf" }, "validate.conf_path_iface"},
		{"satır sonlu arayüz", func(s *Server, _ []Peer, _ []Policy) { s.Iface = "wg0\n"; s.ConfPath = "/etc/wireguard/wg0\n.conf" }, "validate.iface"},
		{"satır sonlu yol", func(s *Server, _ []Peer, _ []Policy) { s.ConfPath = "/tmp\n/wg0.conf" }, "validate.conf_path_iface"},
		{"bozuk alt ağ", func(s *Server, _ []Peer, _ []Policy) { s.Subnet = "10.77.0.0/24\n" }, "validate.subnet_ipv4"},
		{"IPv6 alt ağ", func(s *Server, _ []Peer, _ []Policy) { s.Subnet = "fd00::/64" }, "validate.subnet_ipv4"},
		{"sunucu özel anahtarı", func(s *Server, _ []Peer, _ []Policy) { s.PrivateKey = "PRIV" }, "validate.server_key"},
		{"sunucu açık anahtarı", func(s *Server, _ []Peer, _ []Policy) { s.PublicKey = s.PublicKey + "\n" }, "validate.server_key"},
		{"PSK yok", func(_ *Server, ps []Peer, _ []Policy) { ps[1].PSK = "" }, "validate.peer_key"},
		{"bozuk port kuralı", func(_ *Server, _ []Peer, pols []Policy) { pols[0].Rules[0].Ports = "22\n-A KUT-IN -j ACCEPT" }, "validate.policy_rule"},
		{"bozuk protokol", func(_ *Server, _ []Peer, pols []Policy) { pols[0].Rules[0].Proto = "tcp -j ACCEPT" }, "validate.policy_rule"},
		{"olmayan cihaza kural", func(_ *Server, _ []Peer, pols []Policy) { pols[0].Rules[1].Device = "zzz" }, "validate.policy_rule"},
		// Alt ağ: /16-/29, ağ adresiyle başlar. Özel adres alanı şartı yalnızca kut init'te (eski kurulumlar açılsın).
		{"tüm adres alanı", func(s *Server, _ []Peer, _ []Policy) { s.Subnet = "0.0.0.0/0" }, "validate.subnet_range"},
		{"maskelenmemiş alt ağ", func(s *Server, _ []Peer, _ []Policy) { s.Subnet = "10.77.0.5/24" }, "validate.subnet_range"},
		{"çok geniş alt ağ", func(s *Server, _ []Peer, _ []Policy) { s.Subnet = "10.0.0.0/8" }, "validate.subnet_range"},
		{"çok dar alt ağ", func(s *Server, _ []Peer, _ []Policy) { s.Subnet = "10.77.0.0/30" }, "validate.subnet_range"},
		{"genel alt ağ", func(s *Server, ps []Peer, _ []Policy) {
			s.Subnet, ps[0].IP, ps[1].IP = "198.51.100.0/24", "198.51.100.2", "198.51.100.3"
		}, ""},
		{"CGNAT alt ağı", func(s *Server, ps []Peer, _ []Policy) {
			s.Subnet, ps[0].IP, ps[1].IP = "100.64.0.0/24", "100.64.0.2", "100.64.0.3"
		}, ""},
		{"172.16/12 alt ağı", func(s *Server, ps []Peer, _ []Policy) {
			s.Subnet, ps[0].IP, ps[1].IP = "172.20.0.0/16", "172.20.0.2", "172.20.1.3"
		}, ""},
		// Cihaz IP'leri ve kimlikleri benzersiz; ağ/yayın/sunucu adresi cihaza verilmez.
		{"tekrarlanan IP", func(_ *Server, ps []Peer, _ []Policy) { ps[1].IP = ps[0].IP }, "validate.peer_ip_dup"},
		{"sunucu IP'si", func(_ *Server, ps []Peer, _ []Policy) { ps[0].IP = "10.77.0.1" }, "validate.peer_ip_reserved"},
		{"ağ adresi", func(_ *Server, ps []Peer, _ []Policy) { ps[0].IP = "10.77.0.0" }, "validate.peer_ip_reserved"},
		{"yayın adresi", func(_ *Server, ps []Peer, _ []Policy) { ps[0].IP = "10.77.0.255" }, "validate.peer_ip_reserved"},
		{"tekrarlanan kimlik", func(_ *Server, ps []Peer, _ []Policy) { ps[1].ID = ps[0].ID }, "validate.peer_id_dup"},
		{"tekrarlanan açık anahtar", func(_ *Server, ps []Peer, _ []Policy) { ps[1].PublicKey = ps[0].PublicKey }, "validate.peer_pubkey_dup"},
		// Ayarlar: panelin handlePutSettings'te uyguladığı kuralların aynısı.
		{"boş uç nokta", func(s *Server, _ []Peer, _ []Policy) { s.Endpoint = "" }, "validate.endpoint"},
		{"satır sonlu uç nokta", func(s *Server, _ []Peer, _ []Policy) { s.Endpoint = "vpn.example.com\nPostUp = id" }, "validate.endpoint"},
		{"sonda satır sonlu uç nokta", func(s *Server, _ []Peer, _ []Policy) { s.Endpoint = "vpn.example.com\n" }, "validate.endpoint"},
		{"bölgeli uç nokta", func(s *Server, _ []Peer, _ []Policy) { s.Endpoint = "fe80::1%a\nPostUp = id" }, "validate.endpoint"},
		{"IPv6 uç nokta", func(s *Server, _ []Peer, _ []Policy) { s.Endpoint = "2001:db8::1" }, ""},
		{"satır sonlu DNS", withCfg(func(c *Settings) { c.DNS = "1.1.1.1\nPostUp = id" }), "validate.dns"},
		{"sonda satır sonlu DNS", withCfg(func(c *Settings) { c.DNS = "1.1.1.1\n" }), "validate.dns"},
		{"bölgeli DNS", withCfg(func(c *Settings) { c.DNS = "1.1.1.1, fe80::1%x" }), "validate.dns"},
		{"boş DNS", withCfg(func(c *Settings) { c.DNS = "" }), ""},
		{"büyük MTU", withCfg(func(c *Settings) { c.MTU = 9000 }), "validate.mtu"},
		{"küçük MTU", withCfg(func(c *Settings) { c.MTU = 576 }), "validate.mtu"},
		{"geçerli MTU", withCfg(func(c *Settings) { c.MTU = 1420 }), ""},
		{"büyük keepalive", withCfg(func(c *Settings) { c.Keepalive = 500 }), "validate.keepalive"},
		{"negatif keepalive", withCfg(func(c *Settings) { c.Keepalive = -1 }), "validate.keepalive"},
		{"port 0", func(s *Server, _ []Peer, _ []Policy) { s.Port = 0 }, "validate.port"},
		{"büyük port", func(s *Server, _ []Peer, _ []Policy) { s.Port = 70000 }, "validate.port"},
		{"ULA dışı IPv6 önek", withCfg(func(c *Settings) { c.IPv6, c.ULA = true, "2001:db8::/64" }), "validate.ula"},
		{"/48 ULA", withCfg(func(c *Settings) { c.IPv6, c.ULA = true, "fd12:3456:789a::/48" }), "validate.ula"},
		{"bozuk ULA", withCfg(func(c *Settings) { c.ULA = "fd12::/64\nPostUp = id" }), "validate.ula"},
		{"geçerli ULA", withCfg(func(c *Settings) { c.IPv6, c.ULA = true, "fd12:3456:789a::/64" }), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, ps, pols := validStateFixture(t)
			c.mutate(&s, ps, pols)
			err := validateState(s, ps, pols)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("geçerli durum reddedildi: %v", err)
			case c.want != "" && err == nil:
				t.Fatal("bozuk durum kabul edildi")
			case c.want != "" && errCodeOf(err) != c.want:
				t.Fatalf("hata kodu %q, beklenen %q (%v)", errCodeOf(err), c.want, err)
			}
		})
	}
}

// Doğrulama yalnızca okur: kural zamanlaması gibi işaretçili alanlar yerinde değiştirilmemeli.
func TestValidateStateDoesNotMutate(t *testing.T) {
	s, ps, pols := validStateFixture(t)
	pols[0].Rules[2].Schedule.Scope = "internet" // normalizeRule bunu "tunnel" yapar; kopya üzerinde yapmalı
	pols[0].Rules[2].Schedule.Days = []int{2, 1, 2}
	_ = validateState(s, ps, pols)
	if sc := pols[0].Rules[2].Schedule; sc.Scope != "internet" || len(sc.Days) != 3 {
		t.Fatalf("doğrulama girdiyi değiştirdi: %+v", sc)
	}
}

// Gerçek kipte conf_path yalnızca /etc/wireguard/<arayüz>.conf olabilir. Taban adı doğru ama dizini başka olan
// bir yol (ör. /etc/sysctl.d/wg0.conf) validateState'ten geçer; sunucu anahtarlı yapılandırmayı oraya root
// olarak yazdırmasın diye yükleme ve geri yükleme ayrıca bunu ister.
func TestRealModeConfPath(t *testing.T) {
	s, ps, pols := validStateFixture(t)
	if err := checkRealConfPath(s); err != nil {
		t.Fatalf("geçerli yol reddedildi: %v", err)
	}
	s.ConfPath = "/etc/sysctl.d/wg0.conf"
	if err := validateState(s, ps, pols); err != nil {
		t.Fatalf("ön koşul: taban adı doğru yol validateState'ten geçmeli: %v", err)
	}
	if err := checkRealConfPath(s); err == nil || !strings.Contains(err.Error(), "conf_path") {
		t.Fatalf("başka dizindeki conf_path kabul edildi: %v", err)
	}
	if err := checkBackupConfPath(map[string][]byte{"server.json": mustJSON(t, s)}); err == nil {
		t.Fatal("yedekteki başka dizine yazan conf_path kabul edildi")
	}

	dir := t.TempDir()
	adm, _ := newAdmin("uzun-bir-parola-123")
	for name, v := range map[string]any{"server.json": s, "peers.json": ps, "policies.json": pols, "admin.json": adm} {
		if err := os.WriteFile(dir+"/"+name, mustJSON(t, v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadApp(dir, false); err == nil || !strings.Contains(err.Error(), "conf_path") {
		t.Fatalf("gerçek kipte başka dizindeki conf_path ile açılmamalı: %v", err)
	}
	if _, err := loadApp(dir, true); err != nil {
		t.Fatalf("dry-run yolu veri dizinine çevirdiği için açılmalı: %v", err)
	}
}

// IPv6 bölge kısmı (%...) satır sonu dahil her şeyi taşıyabilir; değer istemci yapılandırmasına
// "Endpoint = …" / "DNS = …" satırı olarak yazıldığı için bölgeli adres hiç kabul edilmez.
func TestValidEndpointDNSRejectsZone(t *testing.T) {
	for _, s := range []string{"fe80::1%a\nPostUp = id", "::%=", "fe80::1%eth0", "[fe80::1%a]"} {
		if ep, err := validEndpoint(s); err == nil {
			t.Errorf("validEndpoint(%q) kabul etti: %q", s, ep)
		}
	}
	for _, s := range []string{"fe80::1%a\nPostUp = id", "::%=", "1.1.1.1, fe80::1%x"} {
		if d, err := validDNS(s); err == nil {
			t.Errorf("validDNS(%q) kabul etti: %q", s, d)
		}
	}
	for in, want := range map[string]string{"2001:db8::1": "2001:db8::1", "[2001:db8::1]": "2001:db8::1", "2001:DB8::1": "2001:db8::1", "vpn.example.com": "vpn.example.com", " 203.0.113.10 ": "203.0.113.10"} {
		if ep, err := validEndpoint(in); err != nil || ep != want {
			t.Errorf("validEndpoint(%q) = %q, %v; beklenen %q", in, ep, err, want)
		}
	}
	if d, err := validDNS("1.1.1.1, 2606:4700:4700::1111"); err != nil || d != "1.1.1.1, 2606:4700:4700::1111" {
		t.Errorf("validDNS geçerli adresleri reddetti: %q %v", d, err)
	}
}

// kut init, panelin açılışta isteyeceği alt ağ kurallarını uygular ve yeni kurulumda ayrıca özel adres alanı
// ister (panel açılışta bunu yalnızca uyarı olarak raporlar, bkz. TestLoadAppAcceptsPublicSubnetWithWarning).
func TestInitRejectsPublicSubnet(t *testing.T) {
	err := cmdInit([]string{"-dry-run", "-data", t.TempDir(), "-endpoint", "203.0.113.10", "-subnet", "8.8.0.0/16", "-allow-overlap"})
	if err == nil || !strings.Contains(err.Error(), "-subnet") {
		t.Fatalf("genel IPv4 alt ağı kabul edildi: %v", err)
	}
	if err := cmdInit([]string{"-dry-run", "-data", t.TempDir(), "-endpoint", "203.0.113.10", "-subnet", "10.88.0.0/24", "-allow-overlap"}); err != nil {
		t.Fatalf("özel alt ağ reddedildi: %v", err)
	}
}
