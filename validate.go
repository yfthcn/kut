package main

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

// validateState: diskten ya da yedekten gelen durumu, panel API'sinin uyguladığı kurallarla yeniden denetler.
// Bu alanlar wg0.conf'a ve iptables-restore betiğine ham yazıldığı için satır sonu/garip değer root komutuna dönüşebilir.
func validateState(s Server, peers []Peer, pols []Policy) error {
	if !ifaceRe.MatchString(s.Iface) {
		return ue("validate.iface", map[string]any{"iface": strconv.Quote(s.Iface)})
	}
	// Gerçek kurulumda /etc/wireguard/<arayüz>.conf, dry-run'da <veri dizini>/<arayüz>.conf.
	if strings.ContainsAny(s.ConfPath, "\r\n") || filepath.Base(s.ConfPath) != s.Iface+".conf" {
		return ue("validate.conf_path_iface", map[string]any{"path": strconv.Quote(s.ConfPath), "iface": s.Iface})
	}
	pfx, err := netip.ParsePrefix(s.Subnet)
	if err != nil || !pfx.Addr().Is4() {
		return ue("validate.subnet_ipv4", map[string]any{"subnet": strconv.Quote(s.Subnet)})
	}
	// Ağ adresiyle başlar, /16-/29. Özel adres alanı şartı yalnızca kut init'te: politika kuralıdır, güvenlik
	// kuralı değil; şarttan önce kurulmuş sunucuların paneli açılmaya devam etsin (rapor uyarır).
	if pfx != pfx.Masked() || pfx.Bits() < minSubnetBits || pfx.Bits() > maxSubnetBits {
		return ue("validate.subnet_range", map[string]any{"subnet": strconv.Quote(s.Subnet), "min": minSubnetBits, "max": maxSubnetBits})
	}
	if !validKey(s.PrivateKey) || !validKey(s.PublicKey) {
		return ue("validate.server_key", nil)
	}
	if err := validateSettings(s); err != nil {
		return err
	}
	ids, keys, ips := map[string]bool{}, map[string]bool{}, map[netip.Addr]bool{}
	for i, p := range peers {
		if !nameRe.MatchString(p.Name) {
			return ue("validate.peer_name", map[string]any{"n": i + 1, "name": strconv.Quote(p.Name)})
		}
		if ids[p.ID] {
			return ue("validate.peer_id_dup", map[string]any{"name": strconv.Quote(p.Name), "id": strconv.Quote(p.ID)})
		}
		ids[p.ID] = true
		if !validKey(p.PublicKey) || !validKey(p.PSK) {
			return ue("validate.peer_key", map[string]any{"name": strconv.Quote(p.Name)})
		}
		if keys[p.PublicKey] {
			return ue("validate.peer_pubkey_dup", map[string]any{"name": strconv.Quote(p.Name)})
		}
		keys[p.PublicKey] = true
		ip, err := netip.ParseAddr(p.IP)
		if err != nil || !s.prefix().Contains(ip) {
			return ue("validate.peer_ip_range", map[string]any{"name": strconv.Quote(p.Name), "ip": strconv.Quote(p.IP), "subnet": s.prefix().String()})
		}
		if ip == pfx.Addr() || ip == lastAddr(pfx) || ip == s.serverIP() {
			return ue("validate.peer_ip_reserved", map[string]any{"name": strconv.Quote(p.Name), "ip": strconv.Quote(p.IP)})
		}
		if ips[ip] {
			return ue("validate.peer_ip_dup", map[string]any{"name": strconv.Quote(p.Name), "ip": strconv.Quote(p.IP)})
		}
		ips[ip] = true
	}
	for _, pol := range pols {
		for i, r := range pol.Rules {
			if r.Schedule != nil {
				// normalizeRule zamanlamayı işaretçi üzerinden değiştirir; doğrulama girdiye dokunmamalı.
				sc := *r.Schedule
				r.Schedule = &sc
			}
			if _, err := normalizeRule(r, peers, i+1); err != nil {
				return ue("validate.policy_rule", map[string]any{"policy": strconv.Quote(pol.Name), "msg": err.Error()})
			}
		}
	}
	return nil
}

// VPN alt ağının izin verilen uzunluk aralığı (cmdInit'teki -subnet denetimiyle aynı).
const (
	minSubnetBits = 16
	maxSubnetBits = 29
)

var privateNets4 = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// privateSubnet: RFC 1918 ya da paylaşımlı adres alanı (100.64/10).
func privateSubnet(a netip.Addr) bool {
	for _, p := range privateNets4 {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// validateSettings: server.json'daki uç nokta, port ve ayarlar; handlePutSettings'in uyguladığı kuralların aynısı.
// Ham değer de denetlenir: doğrulayıcılar baştaki/sondaki boşluğu (satır sonu dahil) kırpar, oysa diskteki değer
// istemci yapılandırmasına olduğu gibi yazılır.
func validateSettings(s Server) error {
	if _, err := validEndpoint(s.Endpoint); err != nil || strings.TrimSpace(s.Endpoint) != s.Endpoint {
		return ue("validate.endpoint", map[string]any{"endpoint": strconv.Quote(s.Endpoint)})
	}
	if s.Port < 1 || s.Port > 65535 {
		return ue("validate.port", map[string]any{"port": s.Port})
	}
	c := s.cfg()
	if _, err := validDNS(c.DNS); err != nil || strings.ContainsAny(c.DNS, "\r\n") {
		return ue("validate.dns", map[string]any{"dns": strconv.Quote(c.DNS)})
	}
	if c.MTU != 0 && (c.MTU < 1280 || c.MTU > 1500) {
		return ue("validate.mtu", map[string]any{"mtu": c.MTU})
	}
	if c.Keepalive < 0 || c.Keepalive > 120 {
		return ue("validate.keepalive", map[string]any{"keepalive": c.Keepalive})
	}
	if c.ULA != "" {
		p, err := netip.ParsePrefix(c.ULA)
		if err != nil || p.Bits() != 64 || p != p.Masked() || !netip.MustParsePrefix("fd00::/8").Contains(p.Addr()) {
			return ue("validate.ula", map[string]any{"ula": strconv.Quote(c.ULA)})
		}
	}
	return nil
}

// validateAccounts: users.json — handleCreateUser'ın kabul ettiği adlar ve roller; sahip ("admin") ve yerel
// kanal ("yerel") adları ek hesapta olamaz, aynı ad iki kez geçemez.
func validateAccounts(users []User) error {
	seen := map[string]bool{}
	for i, u := range users {
		if !userRe.MatchString(u.Name) || u.Name == ownerName || u.Name == localUser {
			return ue("validate.user_name", map[string]any{"n": i + 1, "name": strconv.Quote(u.Name)})
		}
		if seen[u.Name] {
			return ue("validate.user_dup", map[string]any{"name": strconv.Quote(u.Name)})
		}
		seen[u.Name] = true
		if !validRole(u.Role) {
			return ue("validate.user_role", map[string]any{"name": strconv.Quote(u.Name), "role": strconv.Quote(u.Role)})
		}
	}
	return nil
}

// validateNotify: notify.json — handlePutNotify'daki biçim kontrollerinin aynısı.
func validateNotify(c NotifyCfg) error {
	if c.Telegram.Token != "" && !tokenRe.MatchString(c.Telegram.Token) {
		return ue("validate.notify_token", nil)
	}
	if c.Telegram.ChatID != "" && !chatIDRe.MatchString(c.Telegram.ChatID) {
		return ue("validate.notify_chat", nil)
	}
	if u := c.Webhook.URL; u != "" {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || len(u) > 512 {
			return ue("validate.notify_webhook", nil)
		}
	}
	for _, q := range []string{c.QuietFrom, c.QuietTo} {
		if q != "" && !clockRe.MatchString(q) {
			return ue("validate.notify_quiet", map[string]any{"value": strconv.Quote(q)})
		}
	}
	return nil
}

// validKey: WireGuard anahtarı — 32 baytın standart base64 kodlaması. Kod çözücü satır sonlarını yok saydığı için
// geri kodlanmış hâliyle birebir aynı olması da istenir (araya satır sonu ya da başka karakter giremez).
func validKey(k string) bool {
	b, err := base64.StdEncoding.DecodeString(k)
	return err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == k
}

// wgConfPath: gerçek kurulumda arayüz yapılandırmasının tek geçerli yeri (kut init de bunu yazar).
func wgConfPath(iface string) string { return "/etc/wireguard/" + iface + ".conf" }

// checkRealConfPath: dry-run olmayan kurulumda conf_path yalnızca /etc/wireguard/<arayüz>.conf olabilir. validateState
// yalnızca taban adına bakar (dry-run'da yol veri dizinindedir); gerçek kipte başka bir dizin, sunucu anahtarlı
// yapılandırmanın root olarak oraya yazılması demektir.
func checkRealConfPath(s Server) error {
	if want := wgConfPath(s.Iface); s.ConfPath != want {
		return ue("validate.conf_path_want", map[string]any{"path": strconv.Quote(s.ConfPath), "want": want})
	}
	return nil
}

// checkBackupConfPath: yedekteki server.json için checkRealConfPath (parseBackup'tan geçmiş yedek varsayılır).
func checkBackupConfPath(got map[string][]byte) error {
	var s Server
	if err := json.Unmarshal(got["server.json"], &s); err != nil {
		return ue("validate.server_unreadable", map[string]any{"msg": err.Error()})
	}
	return checkRealConfPath(s)
}
