package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ---- Anahtar üretimi (yalnızca standart kütüphane: crypto/ecdh X25519) ----

func genPrivateKey() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	// `wg genkey` ile aynı clamp işlemi
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

func publicKey(priv string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(priv)
	if err != nil || len(raw) != 32 {
		return "", ue("wg.bad_private_key", nil)
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k.PublicKey().Bytes()), nil
}

func genPSK() (string, error) {
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(k[:]), nil
}

// newKeys: bir profil için özel anahtar, açık anahtar ve preshared key üretir.
func newKeys() (priv, pub, psk string, err error) {
	if priv, err = genPrivateKey(); err != nil {
		return
	}
	if pub, err = publicKey(priv); err != nil {
		return
	}
	psk, err = genPSK()
	return
}

// ---- Dosya yazımı ----

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path) //nolint:gosec // G703: name kendi oluşturduğumuz geçici dosya, path yapılandırma yolu (validateState/checkRealConfPath)
}

// ---- Yapılandırma üretimi ----

// confHeader: Kut'un yazdığı yapılandırmanın ilk satırı; kut uninstall dosyayı yalnızca bu başlıkla silerse.
const confHeader = "# Managed by Kut — manual changes are overwritten."

// renderServerConf, wg0.conf içeriğini üretir. NAT/FORWARD kuralları PostUp ile zincirlere bağlanır;
// zincirlerin içeriğini (hangi profil internete çıkabilir) panel çalışırken yönetir (fw.go).
func renderServerConf(s Server, peers []Peer) string {
	c := s.cfg()
	var b strings.Builder
	b.WriteString(confHeader + "\n")
	b.WriteString("[Interface]\n")
	if s.v6On() {
		fmt.Fprintf(&b, "Address = %s/%d, %s/%d\n", s.serverIP(), s.prefix().Bits(), s.serverIP6(), s.prefix6().Bits())
	} else {
		fmt.Fprintf(&b, "Address = %s/%d\n", s.serverIP(), s.prefix().Bits())
	}
	fmt.Fprintf(&b, "ListenPort = %d\n", s.Port)
	fmt.Fprintf(&b, "PrivateKey = %s\n", s.PrivateKey)
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	for _, l := range postUp(s) {
		fmt.Fprintf(&b, "PostUp = %s\n", l)
	}
	if s.v6On() {
		for _, l := range postUp6(s) {
			fmt.Fprintf(&b, "PostUp = %s\n", l)
		}
	}
	for _, l := range postDown(s) {
		fmt.Fprintf(&b, "PostDown = %s\n", l)
	}
	if s.v6On() {
		for _, l := range postDown6(s) {
			fmt.Fprintf(&b, "PostDown = %s\n", l)
		}
	}
	now := time.Now()
	for _, p := range peers {
		if !p.active(now) {
			continue // kapalı ya da dondurulmuş peer sunucudan çıkarılır, bağlıysa anında düşer
		}
		allowed := p.IP + "/32"
		if a6 := s.ip6Of(p.IP); a6.IsValid() {
			allowed += ", " + a6.String() + "/128"
		}
		fmt.Fprintf(&b, "\n# %s\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s\n", p.Name, p.PublicKey, p.PSK, allowed)
	}
	return b.String()
}

var secretLine = regexp.MustCompile(`(?m)^(PrivateKey|PresharedKey) = .*$`)

// maskSecrets: arayüzde gösterilen conf önizlemesinde gizli anahtarları maskeler.
func maskSecrets(conf string) string {
	return secretLine.ReplaceAllString(conf, "$1 = ********")
}

// buildClientConfig: AllowedIPs profilin internet ayarına göre belirlenir.
//   - internet kapalı: yalnızca VPN alt ağı; internet kişinin kendi bağlantısından çıkar, DNS'e dokunulmaz
//   - internet açık  : 0.0.0.0/0, ::/0 (IPv6 sızmasın); DNS ayarlardan gelir
func buildClientConfig(s Server, priv string, p Peer) string {
	c := s.cfg()
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if a6 := s.ip6Of(p.IP); a6.IsValid() {
		fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s/32, %s/128\n", priv, p.IP, a6)
	} else {
		fmt.Fprintf(&b, "PrivateKey = %s\nAddress = %s/32\n", priv, p.IP)
	}
	if p.Internet && c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	if c.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\nPresharedKey = %s\nEndpoint = %s\n", s.PublicKey, p.PSK, s.endpoint())
	allowed := s.prefix().String()
	if s.v6On() {
		allowed += ", " + s.prefix6().String()
	}
	if p.Internet {
		allowed = "0.0.0.0/0, ::/0"
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", allowed)
	if c.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.Keepalive)
	}
	return b.String()
}

func (a *App) clientConfig(priv string, p Peer) string { return buildClientConfig(a.getSrv(), priv, p) }

// ---- Uygulama (çağıran a.mu'yu tutmalı) ----

func run(timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: run() yalnızca koddaki sabit komutlarla çağrılır; kabuk yok
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// apply, wg0.conf'u yeniden yazar; arayüz açıksa `wg syncconf` ile canlı uygular ve güvenlik
// duvarı zincirlerini eşitler. Bağlı peer'ların bağlantısı kopmaz.
func (a *App) apply(peers []Peer) error { return a.applyWith(peers, a.pol) }

func (a *App) applyWith(peers []Peer, pols []Policy) error {
	s := a.getSrv()
	if err := writeFileAtomic(s.ConfPath, []byte(renderServerConf(s, peers))); err != nil {
		return ue("wg.conf_write_failed", map[string]any{"err": err.Error()})
	}
	if a.dry || !a.ifaceUp(s) {
		return nil // arayüz kapalıysa wg-quick başlayınca dosyayı okuyacak
	}
	// a.mu altında çalışır: takılan bir araç paneli kilitlemesin diye zaman aşımı zorunlu.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	strip := exec.CommandContext(ctx, "wg-quick", "strip", s.ConfPath) //nolint:gosec // G204: ConfPath validateState/checkRealConfPath'ten geçer; kabuk yok
	var stderr bytes.Buffer
	strip.Stderr = &stderr
	stripped, err := strip.Output()
	if err != nil {
		return fmt.Errorf("wg-quick strip: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	// Ayıklanmış yapılandırma özel anahtarı içerir: geçici dosyaya değil, stdin'den verilir (wg-quick(8)'deki
	// `wg syncconf wg0 <(wg-quick strip wg0)` kalıbının eşi).
	if err := runStdin(string(stripped), "wg", "syncconf", s.Iface, "/dev/stdin"); err != nil {
		return err
	}
	return a.syncFirewall(s, peers, pols)
}

type peerStat struct {
	Endpoint  string
	Handshake int64
	Rx, Tx    uint64
}

// wgDump, `wg show <iface> dump` çıktısını ayrıştırır. İkinci değer: arayüz açık mı.
func (a *App) wgDump(peers []Peer) (map[string]peerStat, bool) {
	stats := map[string]peerStat{}
	if a.dry {
		// Arayüzü görebilmen için ilk iki etkin peer'a zamanla artan sahte sayaçlar veriyoruz.
		now := time.Now()
		start := a.started
		if start.IsZero() {
			start = now
		}
		el := now.Sub(start).Seconds()
		n := 0
		for _, p := range peers {
			if !p.active(now) {
				continue
			}
			if n >= 2 {
				break
			}
			// oran(t) = r0*(1+0.6*sin(t/20)) B/s; sayaç = integrali (her zaman artar)
			integ := func(r0 float64) uint64 { return uint64(r0 * (el + 0.6*20*(1-math.Cos(el/20)))) }
			stats[p.PublicKey] = peerStat{
				Endpoint:  fmt.Sprintf("198.51.100.%d:41820", 7+n),
				Handshake: now.Unix() - int64(23+n*9),
				Rx:        1_200_000 + integ(float64(14_000+n*6_000)),
				Tx:        9_800_000 + integ(float64(52_000+n*30_000)),
			}
			n++
		}
		return stats, false
	}
	out, err := run(5*time.Second, "wg", "show", a.getSrv().Iface, "dump")
	if err != nil {
		return stats, false
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, ln := range lines[1:] {
		f := strings.Split(ln, "\t")
		if len(f) < 8 {
			continue
		}
		hs, _ := strconv.ParseInt(f[4], 10, 64)
		rx, _ := strconv.ParseUint(f[5], 10, 64)
		tx, _ := strconv.ParseUint(f[6], 10, 64)
		ep := f[2]
		if ep == "(none)" {
			ep = ""
		}
		stats[f[0]] = peerStat{ep, hs, rx, tx}
	}
	return stats, true
}
