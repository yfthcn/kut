package main

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// IPv6 (isteğe bağlı, varsayılan kapalı)
//
// Açıkken tünel çift yığın olur: VPN ağı için rastgele bir ULA /64 (fdXX:XXXX:XXXX::/64) üretilir ve
// her cihazın IPv6 adresi IPv4 adresinden türetilir (aynı sunucu-ağı ofseti; 10.77.0.5 → fd..::5).
// Güvenlik duvarı IPv4'tekinin aynasıdır: aynı KUT-* zincirleri ip6tables'ta da bulunur, aynı profil
// kuralları IPv6 adreslerine uygulanır ve ayrıca fail-closed çalışır.
// İnternete IPv6 çıkışı (NAT66) yalnızca sunucunun küresel IPv6 varsayılan rotası varsa kurulur;
// yoksa IPv6 trafik tünelde kesilir (IPv4 çıkışı etkilenmez, IPv6 sızıntısı olmaz).

var privateNets6 = []string{"fc00::/7", "fe80::/10"}

// errNoIP6Tables: fwVerify6'nın ip6tables yokken verdiği durumun katalog anahtarı; izleyici bu durumda onarmayı
// denemez (onarım da başarısız olur).
const errNoIP6Tables = "fw.no_ip6tables"

// ulaPrefix: rastgele fdXX:XXXX:XXXX::/64.
func newULA() (string, error) {
	var b [5]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	var a [16]byte
	a[0] = 0xfd
	copy(a[1:6], b[:])
	return netip.PrefixFrom(netip.AddrFrom16(a), 64).String(), nil
}

func (s Server) v6On() bool {
	c := s.cfg()
	if !c.IPv6 || c.ULA == "" {
		return false
	}
	_, err := netip.ParsePrefix(c.ULA)
	return err == nil
}

func (s Server) prefix6() netip.Prefix {
	p, _ := netip.ParsePrefix(s.cfg().ULA)
	return p.Masked()
}

// ip6Of: IPv4 adresine karşılık gelen IPv6 adresi (VPN ağındaki ofset aynen taşınır).
func (s Server) ip6Of(v4 string) netip.Addr {
	a, err := netip.ParseAddr(v4)
	if err != nil || !a.Is4() || !s.v6On() {
		return netip.Addr{}
	}
	if !s.prefix().Contains(a) {
		return netip.Addr{}
	}
	base := s.prefix().Addr().As4()
	cur := a.As4()
	off := uint32(cur[0])<<24 | uint32(cur[1])<<16 | uint32(cur[2])<<8 | uint32(cur[3])
	off -= uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	b := s.prefix6().Addr().As16()
	b[12], b[13], b[14], b[15] = byte(off>>24), byte(off>>16), byte(off>>8), byte(off) //nolint:gosec // G115: bilerek bayt bayt kesme (alt 8 bit)
	return netip.AddrFrom16(b)
}

func (s Server) serverIP6() netip.Addr { return s.ip6Of(s.serverIP().String()) }

func ipt6(table string, args ...string) ([]byte, error) { return iptFam("ip6tables", table, args...) }

// hostV6Route: sunucunun IPv6 varsayılan rotası var mı (NAT66 ancak o zaman anlamlı) ve rota arayüzleri.
func hostV6Route() (bool, []string) {
	out, err := run(3*time.Second, "ip", "-6", "route", "show", "default")
	if err != nil {
		return false, nil
	}
	var devs []string
	seen := map[string]bool{}
	for ln := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(ln)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "dev" && !seen[f[i+1]] {
				seen[f[i+1]] = true
				devs = append(devs, f[i+1])
			}
		}
	}
	return len(devs) > 0, devs
}

// postUp6/postDown6: wg-quick kancaları (IPv6 açıkken). Arayüz açılırken IPv6 zincirleri hemen kurulur.
func postUp6(s Server) []string {
	l := hookUp("ip6tables", s.prefix6().String())
	// Yönlendirmeyi açmak, çekirdeğin Router Advertisement'ı yok saymasına yol açar; önce sunucunun kendi
	// IPv6 bağlantısını koruyan accept_ra=2 ayarlanır.
	l = append(l,
		`for d in $(ip -6 route show default 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | sort -u); do sysctl -q -w net.ipv6.conf.$d.accept_ra=2; done`,
		"sysctl -q -w net.ipv6.conf.all.forwarding=1",
	)
	return l
}

func postDown6(s Server) []string { return hookDown("ip6tables", s.prefix6().String()) }

// desiredFirewall6: IPv6 KUT-* zincirlerinin olması gereken içeriği. natOK: sunucunun küresel IPv6 rotası var.
func desiredFirewall6(s Server, peers []Peer, pols []Policy, now time.Time, natOK bool) fwSet {
	return desiredFam(s, peers, pols, now, fwFamily{
		addr: func(p Peer) (string, bool) {
			a6 := s.ip6Of(p.IP)
			return a6.String() + "/128", a6.IsValid()
		},
		subnet:  s.prefix6().String(),
		icmp:    []string{"-p", "ipv6-icmp", "--icmpv6-type", "128", "-j", "ACCEPT"},
		private: privateNets6, v6: true, nat: natOK,
	})
}

func haveIP6Tables() bool {
	for _, b := range []string{"ip6tables", "ip6tables-restore"} {
		if _, err := exec.LookPath(b); err != nil {
			return false
		}
	}
	return true
}

// hostSetup6: IPv6 adresi, accept_ra ve yönlendirme. Çağıran önce IPv6 iskeletini kurmuş olmalı (fail-closed).
// hostSetup6Fn: testlerde (IPv6 yığını olmayan çekirdeklerde) değiştirilebilir.
var hostSetup6Fn = hostSetup6

func hostSetup6(s Server) error {
	if _, err := run(5*time.Second, "ip", "-6", "addr", "replace", fmt.Sprintf("%s/%d", s.serverIP6(), s.prefix6().Bits()), "dev", s.Iface); err != nil {
		return ue("fw6.addr", map[string]any{"err": err.Error()})
	}
	_, devs := hostV6Route()
	for _, d := range devs {
		// accept_ra=2 olmadan yönlendirme açılırsa çekirdek RA'yı yok sayar ve sunucunun kendi IPv6 bağlantısı kopar.
		if _, err := run(3*time.Second, "sysctl", "-q", "-w", "net.ipv6.conf."+d+".accept_ra=2"); err != nil {
			return ue("fw6.accept_ra", map[string]any{"dev": d, "err": err.Error()})
		}
	}
	if _, err := run(3*time.Second, "sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"); err != nil {
		return ue("fw6.forwarding", map[string]any{"err": err.Error()})
	}
	return nil
}

// syncFirewall6: IPv6 açıksa zincirleri kurar/eşitler; kapalıysa (ve daha önce açılmışsa) temizler.
func (a *App) syncFirewall6(s Server, peers []Peer, pols []Policy) error {
	if !s.v6On() {
		if a.v6Live.Load() {
			a.teardown6(s)
			a.v6Live.Store(false)
		}
		return nil
	}
	if !haveIP6Tables() {
		return ue("fw6.no_ip6tables", nil)
	}
	sk := skeleton(s.Iface, s.prefix6().String())
	a.v6Live.Store(true) // kurallar kurulmaya başladı: geri alma/kapatma bunları temizlemeli
	if err := ensureSkeletonF(ipt6, sk); err != nil {
		return ue("fw6.skeleton", map[string]any{"err": err}) // iç hata kodluysa okuyanın dilinde yazılır (cliErrText)
	}
	cleanupStaleSkelF(ipt6, sk, s.Iface, true)
	natOK, _ := hostV6Route()
	if err := applyRestore("ip6tables", desiredFirewall6(s, peers, pols, time.Now(), natOK), "IPv6 "); err != nil {
		return err
	}
	// Güvenlik duvarı hazır: şimdi adres ve yönlendirme (sırası önemli).
	return hostSetup6Fn(s)
}

// teardown6: IPv6 kapatılınca Kut'un IPv6 kurallarını ve adresini kaldırır.
func (a *App) teardown6(s Server) {
	if haveIP6Tables() {
		for _, r := range skeleton(s.Iface, s.prefix6().String()) {
			for _, args := range [][]string{r.args, stripTag(r.args)} { // etiketsiz: v0.14'ten kalmış olabilir
				for range 5 {
					if _, err := ipt6(r.table, append([]string{"-D", r.chain}, args...)...); err != nil {
						break
					}
				}
			}
		}
		for _, c := range filterChains {
			_, _ = ipt6("filter", "-F", c)
			_, _ = ipt6("filter", "-X", c)
		}
		_, _ = ipt6("nat", "-F", chainNat)
		_, _ = ipt6("nat", "-X", chainNat)
	}
	if p := s.cfg().ULA; p != "" {
		if pf, err := netip.ParsePrefix(p); err == nil {
			_, _ = run(5*time.Second, "ip", "-6", "addr", "del", fmt.Sprintf("%s/%d", s.ip6OfBase(pf), pf.Bits()), "dev", s.Iface)
		}
	}
}

// ip6OfBase: ULA önekinden sunucu adresi (::1) — IPv6 kapatılırken ayarlar artık v6On saymaz, o yüzden önekten türetilir.
func (s Server) ip6OfBase(pf netip.Prefix) netip.Addr {
	b := pf.Masked().Addr().As16()
	b[15] = 1
	return netip.AddrFrom16(b)
}

// fwVerify6: IPv6 iskeleti ve zincir içerikleri olması gerekenle aynı mı.
func (a *App) fwVerify6(s Server, peers []Peer, pols []Policy) fwState {
	if !haveIP6Tables() {
		return fwMsg("no-jump", errNoIP6Tables, nil)
	}
	if st := skeletonOKF(ipt6, skeleton(s.Iface, s.prefix6().String()), "IPv6"); st.State != "ok" {
		return st
	}
	natOK, _ := hostV6Route()
	return verifyChainsF(ipt6, desiredFirewall6(s, peers, pols, time.Now(), natOK), "IPv6")
}
