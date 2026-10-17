package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Güvenlik duvarı modeli
//
// Kut yalnızca kendi zincirlerini yönetir; host'un ufw/docker kurallarına dokunmaz.
//
//	FORWARD (en üstte, bu sırayla):
//	  1) ! -i wg0 -o wg0 ESTABLISHED,RELATED, yön REPLY -> ACCEPT  internetten dönüş trafiği (ve yoldaki ICMP hataları)
//	  2) -i wg0 -o wg0 ESTABLISHED, yön REPLY -> ACCEPT  cihazlar arası akışın yanıt yönü
//	  3) -i wg0 -o wg0 ICMP RELATED -> KUT-ICMP    var olan akışla ilgili ICMP hataları (PMTU); yalnızca akışın tarafı gönderebilir
//	  4) -i wg0 -o wg0              -> KUT-PEERS   cihazdan cihaza trafik; yalnızca içindeki ACCEPT kuralları geçer
//	  5) -i wg0 -o wg0              -> DROP        KUT-PEERS'te eşleşmeyen cihazlar arası trafik düşer
//	  6) -i wg0                     -> KUT-INET    internete çıkış; yalnızca "internet çıkışı" açık cihazlar
//	  7) -i wg0                     -> DROP        geri kalan her şey düşer
//	  8) -o wg0                     -> DROP        başka arayüzden cihazlara yeni trafik (host politikası ACCEPT olsa da)
//	INPUT (en üstte):
//	  1) -i wg0                     -> KUT-IN      cihazdan sunucunun kendisine gelen trafik
//	KUT-ICMP (FORWARD 3 ve KUT-IN'den): her etkin cihaz P için "kaynak P ve P bu akışın tarafı" -> ACCEPT, sonda DROP.
//	  Böylece akışı bilen üçüncü bir cihaz başkasının akışına sahte ICMP hata iletisi (PMTU düşürme, port unreachable)
//	  gönderemez. Zincir boş ya da bozuksa ICMP KUT-PEERS'e düşer: en kötü PMTU kaybolur, erişim açılmaz.
//	nat/POSTROUTING:
//	  -s <VPN ağı>                  -> KUT-NAT     yalnızca internet çıkışlı cihazlara MASQUERADE
//
// KUT-* zincirlerinin içeriğini panel üretir ve iptables-restore ile tek işlemde (atomik) değiştirir.
// Zincirler boşken hiçbir cihaz hiçbir yere gidemez (fail-closed). WireGuard her peer'i kendi /32
// adresine kilitlediği için kaynak IP taklit edilemez; kurallar bu yüzden kaynak IP'ye dayanır.
//
// Kurulmuş akış kısayolu (FORWARD 1-2 ve KUT-IN'in ilk kuralı) yalnızca REPLY yönündeki paketleri kabul eder:
// akışı başlatan tarafın (ORIGINAL) her paketi profil kurallarından yeniden geçer. Böylece profil daraltılınca,
// kural silinince ya da zamanlı kural bitince açık bağlantılar (SSH, ters kabuk) da kesilir.
const (
	chainPeers = "KUT-PEERS"
	chainIn    = "KUT-IN"
	chainInet  = "KUT-INET"
	chainICMP  = "KUT-ICMP"
	chainNat   = "KUT-NAT"

	// v0.3'ten kalan adlar (yükseltmede temizlenir)
	legacyInet = "WGUI-INET"
	legacyNat  = "WGUI-NAT"
)

// filterChains: KUT-ICMP sonda, çünkü KUT-IN ona atlar; kancalar ve teardown6 zincirleri bu sırayla boşaltıp
// sildiğinden ona atlayan zincir önce boşalmış olur (yoksa -X "zincir kullanımda" diye başarısız olur).
var filterChains = []string{chainPeers, chainIn, chainInet, chainICMP}

// internet çıkışlı cihazlar bu ağlara (sunucunun yerel ağı, sağlayıcı iç ağı, CGNAT) gidemesin (isteğe bağlı).
var privateNets = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"}

type skelRule struct {
	table, chain string
	args         []string // etiketli (-m comment) biçim
}

// ---- Kural etiketleri ----
//
// Kut'un yazdığı her kural "-m comment --comment kut:<tür>:<ayrıntı>" taşır. Etiket zincir içinde tektir; Sunucu
// sayfası canlı sayaçları kurala sırasından değil etiketinden bağlar. Etikette yalnızca IP, cihaz/profil kimliği ve
// kural sırası bulunur, ad asla: ad kullanıcı girdisidir (boşluk, Türkçe harf) ve `iptables -S` çıktısını herkese açık
// günlüklere taşır. Etiket "-j"den hemen önce durur: iptables eşleşmeleri verildiği sırada yazar, böylece -S çıktısı
// (tırnaklar soyulunca, normTokens) üretilen jetonlarla birebir aynı kalır.

const maxTagLen = 200

// tagSafe: etikete girecek parçayı ASCII'ye ve kabuk/iptables-restore için zararsız karakterlere indirger.
func tagSafe(v string) string {
	b := []byte(v)
	for i, c := range b {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(":._/=>+-", c) >= 0
		if !ok {
			b[i] = '_'
		}
	}
	return string(b)
}

// withTag: kurala etiketi ekler (son "-j"den önce; -j yoksa sona).
func withTag(args []string, tag string) []string {
	j := len(args)
	for i := len(args) - 2; i >= 0; i-- {
		if args[i] == "-j" {
			j = i
			break
		}
	}
	out := make([]string, 0, len(args)+4)
	out = append(out, args[:j]...)
	out = append(out, "-m", "comment", "--comment", tag)
	return append(out, args[j:]...)
}

// stripTag: kuralın etiketsiz biçimi (v0.14 ve öncesinin yazdığı kural; yükseltmede bulunup silinir).
func stripTag(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		if args[i] == "-m" && i+3 < len(args) && args[i+1] == "comment" && args[i+2] == "--comment" {
			i += 3
			continue
		}
		out = append(out, args[i])
	}
	return out
}

// ruleTag: kuralın etiketi (yoksa "").
func ruleTag(args []string) string {
	for i := 0; i+3 < len(args); i++ {
		if args[i] == "-m" && args[i+1] == "comment" && args[i+2] == "--comment" {
			return strings.Trim(args[i+3], `"`)
		}
	}
	return ""
}

// uniqueTag: etiketi zincir içinde tekleştirir ve uzunluğu sınırlar. Uzun etiket, özetiyle (sha256'nın ilk 12 hanesi)
// kısaltılır; aynı etiket ikinci kez gelirse ":2", ":3"… eklenir.
func uniqueTag(seen map[string]bool, chain, tag string) string {
	tag = tagSafe(tag)
	if len(tag) > maxTagLen {
		h := sha256.Sum256([]byte(tag))
		tag = tag[:maxTagLen-16] + ":h=" + hex.EncodeToString(h[:6])
	}
	t := tag
	for n := 2; seen[chain+" "+t]; n++ {
		suf, base := ":"+strconv.Itoa(n), tag
		if len(base)+len(suf) > maxTagLen {
			base = base[:maxTagLen-len(suf)]
		}
		t = base + suf
	}
	seen[chain+" "+t] = true
	return t
}

func skel(table, chain, tag string, args ...string) skelRule {
	return skelRule{table, chain, withTag(args, "kut:skel:"+tag)}
}

// replyOnly: kurulmuş akışların yalnızca yanıt yönü. Jeton sırası `iptables -S`'in yazdığıyla aynı olmalı
// (topMatchesF/verifyChainsF metin karşılaştırır): libxt_conntrack kaydederken --ctstate'i her zaman
// --ctdir'den önce yazar, girişteki sıradan bağımsız (iptables v1.8.11 nf_tables'ta ölçüldü).
var replyOnly = []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "--ctdir", "REPLY", "-j", "ACCEPT"}

// establishedReply: wg0'dan gelen kurulmuş akışların yanıt yönü. RELATED burada yoktur: wg0'dan gelen RELATED
// paketler (ICMP hataları) relatedICMP ile KUT-ICMP'den geçer, çünkü kaynağı akışın tarafı olmayan bir cihaz da
// olabilir (sahte hata iletisi).
var establishedReply = []string{"-m", "conntrack", "--ctstate", "ESTABLISHED", "--ctdir", "REPLY", "-j", "ACCEPT"}

// relatedICMP: var olan bir akışla ilgili ICMP hata iletileri (yol MTU'su keşfi: "fragmentation needed" /
// "packet too big"; port/host unreachable) KUT-ICMP'ye gider; orada yalnızca akışın iki tarafından biri
// gönderdiyse geçer. Profil kuralları port/protokol eşler ve ICMP hatalarını tutmaz; bu kapı olmadan PMTU
// bozulur. Yalnızca RELATED: echo gibi yeni bir ICMP akışı (NEW) ya da hiçbir akışla eşleşmeyen hata (INVALID)
// bu kurala uymaz. Jeton sırası `iptables -S` çıktısıyla aynı (v1.8.11'de ölçüldü).
func relatedICMP(v6 bool) []string {
	p := "icmp"
	if v6 {
		p = "ipv6-icmp"
	}
	return []string{"-p", p, "-m", "conntrack", "--ctstate", "RELATED", "-j", chainICMP}
}

// icmpOwner: KUT-ICMP'de cihaz P'nin kuralları. P akışı başlattıysa (ORIGINAL yönde hata gönderir) akışın özgün
// kaynağı P, P yanıtlayan tarafsa (REPLY yönünde gönderir) yanıt kaynağı P olmalı. -s P'ye güvenilir, çünkü
// WireGuard her cihazı kendi adresine (AllowedIPs = P/32, /128) kilitler. src: "adres/önek"; conntrack adresi
// önekiz yazar. Jeton sırası `iptables -S` ile aynı: --ctorigsrc/--ctreplsrc, --ctdir'den önce (v1.8.11'de ölçüldü).
func icmpOwner(src string) [][]string {
	ip, _, _ := strings.Cut(src, "/")
	return [][]string{
		rule(chainICMP, []string{"-s", src, "-m", "conntrack", "--ctstate", "RELATED", "--ctorigsrc", ip, "--ctdir", "ORIGINAL", "-j", "ACCEPT"}),
		rule(chainICMP, []string{"-s", src, "-m", "conntrack", "--ctstate", "RELATED", "--ctreplsrc", ip, "--ctdir", "REPLY", "-j", "ACCEPT"}),
	}
}

// skeleton: zincirlere bağlanan sabit kurallar; her zincir için üstten alta sıralı. Aile VPN ağından anlaşılır
// (IPv6 öneki ':' içerir); ICMP kuralının protokolü yalnızca buna bağlıdır.
// Etiketler kabukta da güvenlidir (wg-quick kancaları bash ile çalışır): yalnızca harf, rakam, ':' ve '-'.
func skeleton(iface, sub string) []skelRule {
	return []skelRule{
		skel("filter", "FORWARD", "fwd-reply", append([]string{"!", "-i", iface, "-o", iface}, replyOnly...)...),
		skel("filter", "FORWARD", "fwd-peer-reply", append([]string{"-i", iface, "-o", iface}, establishedReply...)...),
		skel("filter", "FORWARD", "fwd-icmp", append([]string{"-i", iface, "-o", iface}, relatedICMP(strings.Contains(sub, ":"))...)...),
		skel("filter", "FORWARD", "fwd-peers", "-i", iface, "-o", iface, "-j", chainPeers),
		skel("filter", "FORWARD", "fwd-peers-drop", "-i", iface, "-o", iface, "-j", "DROP"),
		skel("filter", "FORWARD", "fwd-inet", "-i", iface, "-j", chainInet),
		skel("filter", "FORWARD", "fwd-in-drop", "-i", iface, "-j", "DROP"),
		skel("filter", "FORWARD", "fwd-out-drop", "-o", iface, "-j", "DROP"),
		skel("filter", "INPUT", "in", "-i", iface, "-j", chainIn),
		skel("nat", "POSTROUTING", "nat", "-s", sub, "-j", chainNat),
	}
}

func tableArgs(table string) string {
	if table == "nat" {
		return "-t nat "
	}
	return ""
}

// postUp/postDown: wg-quick kancaları. Arayüz açılırken zincirler ve sabit kurallar hemen kurulur
// (panel henüz başlamadan da fail-closed). Panel çalışırken aynı kuralları kendisi doğrular.
func postUp(s Server) []string { return hookUp("iptables", s.prefix().String()) }

func postDown(s Server) []string { return hookDown("iptables", s.prefix().String()) }

// hookUp/hookDown: postUp/postDown kancalarının iptables (bin) ve ip6tables için ortak gövdesi.
func hookUp(bin, sub string) []string {
	var l []string
	for _, c := range filterChains {
		l = append(l, fmt.Sprintf("%s -w 5 -N %s 2>/dev/null || %s -w 5 -F %s", bin, c, bin, c))
	}
	l = append(l, fmt.Sprintf("%s -w 5 -t nat -N %s 2>/dev/null || %s -w 5 -t nat -F %s", bin, chainNat, bin, chainNat))
	sk := skeleton("%i", sub)
	for _, r := range slices.Backward(sk) {
		a := strings.Join(r.args, " ")
		t := tableArgs(r.table)
		l = append(l, fmt.Sprintf("%s -w 5 %s-C %s %s 2>/dev/null || %s -w 5 %s-I %s 1 %s", bin, t, r.chain, a, bin, t, r.chain, a))
	}
	return l
}

// hookDown: iskeletin etiketli kurallarını, ayrıca v0.14 ve öncesinin etiketsiz kopyalarını (panel geçişi
// yapmadan arayüz kapanırsa) siler; sonra KUT-* zincirlerini boşaltıp kaldırır. Her komut "yok" hatasına dayanıklı.
func hookDown(bin, sub string) []string {
	var l []string
	for _, r := range skeleton("%i", sub) {
		for _, a := range [][]string{r.args, stripTag(r.args)} {
			l = append(l, fmt.Sprintf("%s -w 5 %s-D %s %s 2>/dev/null || true", bin, tableArgs(r.table), r.chain, strings.Join(a, " ")))
		}
	}
	for _, c := range filterChains {
		l = append(l, fmt.Sprintf("%s -w 5 -F %s 2>/dev/null || true", bin, c), fmt.Sprintf("%s -w 5 -X %s 2>/dev/null || true", bin, c))
	}
	l = append(l, fmt.Sprintf("%s -w 5 -t nat -F %s 2>/dev/null || true", bin, chainNat), fmt.Sprintf("%s -w 5 -t nat -X %s 2>/dev/null || true", bin, chainNat))
	return l
}

// ---- Olması gereken içerik ----

type fwSet struct {
	Peers, In, Inet, ICMP, Nat [][]string
	Info                       []fwRule // her kuralın anlamı (zincirlerdeki sırayla); Sunucu sayfası için
}

// fwRule: bir kuralın yapılandırılmış hâli. Kaynağı kuralı üreten desiredFam'dır; etiket kuralın yorumuyla aynıdır.
// Family, DeviceName ve Raw gösterilirken doldurulur.
type fwRule struct {
	Chain      string `json:"chain"`
	Family     string `json:"family"` // ipv4 | ipv6
	Tag        string `json:"tag"`
	DeviceID   string `json:"device_id,omitempty"`
	DeviceName string `json:"device_name,omitempty"`
	Kind       string `json:"kind"`             // est | icmp-related | ping | panel | peer | peer-free | server | in-drop | icmp-orig | icmp-repl | icmp-drop | inet-deny | inet | nat
	Target     string `json:"target,omitempty"` // hedef: cihaz kimliği, "server", "all", ağ (CIDR)
	TargetName string `json:"target_name,omitempty"`
	Proto      string `json:"proto,omitempty"`
	Port       string `json:"port,omitempty"`
	Action     string `json:"action"`
	Raw        string `json:"raw"`
	Reverse    bool   `json:"reverse,omitempty"` // karşılıklı kuralın ters yönü
	Key        string `json:"key"`               // aile|zincir|etiket: sayaçların anahtarı
	args       []string
}

func (f fwSet) filter() [][]string {
	var all [][]string
	all = append(all, f.Peers...)
	all = append(all, f.In...)
	all = append(all, f.Inet...)
	all = append(all, f.ICMP...)
	return all
}

// matchArgsFam: bir kuralın iptables eşleşme bölümleri (port listesi için eleman başına bir kural).
func matchArgsFam(r Rule, v6 bool) [][]string {
	switch r.Proto {
	case "any":
		return [][]string{{}}
	case "icmp":
		if v6 {
			return [][]string{{"-p", "ipv6-icmp"}}
		}
		return [][]string{{"-p", "icmp"}}
	}
	rs, err := parsePorts(r.Ports)
	if err != nil || (r.Proto != "tcp" && r.Proto != "udp") {
		return nil // bozuk kural hiçbir şeye izin vermez (Rule.matches ile tutarlı)
	}
	if len(rs) == 0 {
		return [][]string{{"-p", r.Proto}}
	}
	var out [][]string
	for _, x := range rs {
		spec := strconv.Itoa(x.lo)
		if x.hi != x.lo {
			spec = fmt.Sprintf("%d:%d", x.lo, x.hi)
		}
		out = append(out, []string{"-p", r.Proto, "--dport", spec})
	}
	return out
}

func rule(chain string, parts ...[]string) []string {
	r := []string{"-A", chain}
	for _, p := range parts {
		r = append(r, p...)
	}
	return r
}

// fwFamily: v4/v6 arasında değişen her şey; kural üretimi tek yerde (desiredFam) durur.
type fwFamily struct {
	addr      func(p Peer) (string, bool) // cihazın bu ailedeki adresi (/32 ya da /128); yoksa false
	subnet    string
	icmp      []string // sunucuya ping izni
	private   []string // "özel ağları engelle" listesi
	v6        bool
	panelPort int  // >0 ise profili olmayan cihaza panel portu açılır (yalnızca v4)
	nat       bool // internet çıkışı kuralları üretilsin mi (v6'da küresel rota yoksa hayır)
}

// desiredFirewall: KUT-* zincirlerinin olması gereken IPv4 içeriği ("-A ZİNCİR ..." biçiminde).
func desiredFirewall(s Server, peers []Peer, pols []Policy, panelPort int, now time.Time) fwSet {
	return desiredFam(s, peers, pols, now, fwFamily{
		addr:    func(p Peer) (string, bool) { return p.IP + "/32", true },
		subnet:  s.prefix().String(),
		icmp:    []string{"-p", "icmp", "--icmp-type", "8", "-j", "ACCEPT"},
		private: privateNets, panelPort: panelPort, nat: true,
	})
}

func desiredFam(s Server, peers []Peer, pols []Policy, now time.Time, fam fwFamily) fwSet {
	var f fwSet
	c := s.cfg()
	idx := polIndex(pols)
	byID := map[string]Peer{}
	for _, p := range peers {
		byID[p.ID] = p
	}
	gs := grants(peers, pols, now)
	seen := map[string]bool{}
	// add: kuralı etiketiyle zincire ve Info'ya ekler. dst kuralın yazılacağı zincir dilimidir.
	add := func(dst *[][]string, m fwRule, parts ...[]string) {
		r := rule(m.Chain, parts...)
		m.Tag = uniqueTag(seen, m.Chain, m.Tag)
		r = withTag(r, m.Tag)
		m.Action = r[len(r)-1]
		m.args = r
		*dst = append(*dst, r)
		f.Info = append(f.Info, m)
	}

	add(&f.In, fwRule{Chain: chainIn, Kind: "est", Tag: "kut:in:est-reply"}, establishedReply)
	add(&f.In, fwRule{Chain: chainIn, Kind: "icmp-related", Tag: "kut:in:icmp-related"}, relatedICMP(fam.v6))
	add(&f.In, fwRule{Chain: chainIn, Kind: "ping", Tag: "kut:in:ping", Target: "server", Proto: "icmp"}, fam.icmp)

	for _, p := range peers {
		if !p.active(now) {
			continue
		}
		src, ok := fam.addr(p)
		if !ok {
			continue
		}
		ip, _, _ := strings.Cut(src, "/")
		for i, r := range icmpOwner(src) {
			kind := [...]string{"icmp-orig", "icmp-repl"}[i]
			add(&f.ICMP, fwRule{Chain: chainICMP, Kind: kind, DeviceID: p.ID, Tag: "kut:" + kind + ":" + ip}, r[2:])
		}
		_, has := effectivePolicy(p, idx)
		if !has && fam.panelPort > 0 {
			port := strconv.Itoa(fam.panelPort)
			add(&f.In, fwRule{Chain: chainIn, Kind: "panel", DeviceID: p.ID, Target: "server", Proto: "tcp", Port: port, Tag: "kut:panel:" + ip},
				[]string{"-s", src, "-p", "tcp", "--dport", port, "-j", "ACCEPT"})
		}
		if !has && c.PeerFree {
			add(&f.Peers, fwRule{Chain: chainPeers, Kind: "peer-free", DeviceID: p.ID, Target: "all", Proto: "any", Tag: "kut:peer-free:" + ip},
				[]string{"-s", src, "-j", "ACCEPT"})
		} else {
			// Profilsiz cihazın burada tek izni, başka bir profilin karşılıklı (Both) kuralından gelen geri yöndür;
			// sunucu portları ufw'ye kalır, bu yüzden KUT-IN DROP yalnızca profilli cihaza yazılır.
			for _, g := range gs {
				if g.Src != p.ID {
					continue
				}
				var dst []string
				dstTag := g.Dst
				switch g.Dst {
				case "server":
				case "all":
					dst = []string{"-d", fam.subnet}
				default:
					d, ok := byID[g.Dst]
					if !ok || !d.active(now) {
						continue
					}
					da, ok := fam.addr(d)
					if !ok {
						continue
					}
					dst = []string{"-d", da}
					dstTag, _, _ = strings.Cut(da, "/")
				}
				suffix := ":prof=" + g.PolID + ":r" + strconv.Itoa(g.Idx)
				if g.Reverse {
					suffix += ":rev"
				}
				for _, m := range matchArgsFam(g.Rule, fam.v6) {
					proto, port := g.Rule.Proto, ""
					if i := slices.Index(m, "--dport"); i >= 0 {
						port = m[i+1]
					}
					spec := proto
					if port != "" {
						spec += "/" + port
					}
					info := fwRule{DeviceID: p.ID, Target: g.Dst, Proto: proto, Port: port, Reverse: g.Reverse}
					if g.Dst == "server" {
						info.Chain, info.Kind, info.Tag = chainIn, "server", "kut:srv:"+ip+":"+spec+suffix
						add(&f.In, info, []string{"-s", src}, m, []string{"-j", "ACCEPT"})
					} else {
						info.Chain, info.Kind, info.Tag = chainPeers, "peer", "kut:peer:"+ip+">"+dstTag+":"+spec+suffix
						add(&f.Peers, info, []string{"-s", src}, dst, m, []string{"-j", "ACCEPT"})
					}
				}
			}
			if has {
				add(&f.In, fwRule{Chain: chainIn, Kind: "in-drop", DeviceID: p.ID, Target: "server", Tag: "kut:in-drop:" + ip},
					[]string{"-s", src, "-j", "DROP"})
			}
		}

		if fam.nat && p.inetOn(now) {
			if c.BlockPrivate {
				for _, n := range fam.private {
					add(&f.Inet, fwRule{Chain: chainInet, Kind: "inet-deny", DeviceID: p.ID, Target: n, Tag: "kut:inet-deny:" + ip + ":" + n},
						[]string{"-s", src, "-d", n, "-j", "DROP"})
				}
			}
			add(&f.Inet, fwRule{Chain: chainInet, Kind: "inet", DeviceID: p.ID, Target: "internet", Tag: "kut:inet:" + ip},
				[]string{"-s", src, "-j", "ACCEPT"})
			add(&f.Nat, fwRule{Chain: chainNat, Kind: "nat", DeviceID: p.ID, Target: "internet", Tag: "kut:nat:" + ip},
				[]string{"-s", src, "!", "-o", s.Iface, "-j", "MASQUERADE"})
		}
	}
	add(&f.ICMP, fwRule{Chain: chainICMP, Kind: "icmp-drop", Tag: "kut:icmp:drop"}, []string{"-j", "DROP"})
	return f
}

func ruleText(table string, r []string) string {
	t := "iptables "
	if table != "" {
		t += "-t " + table + " "
	}
	return t + strings.Join(r, " ")
}

// display: Sunucu sayfasında gösterilen kurallar.
func (f fwSet) display() []string {
	out := []string{}
	for _, r := range f.filter() {
		out = append(out, ruleText("", r))
	}
	for _, r := range f.Nat {
		out = append(out, ruleText("nat", r))
	}
	return out
}

// ---- iptables çağrıları ----

// iptFam: iptables ya da ip6tables çağrısı (bin); nat tablosu için -t nat eklenir.
func iptFam(bin, table string, args ...string) ([]byte, error) {
	a := []string{"-w", "5"}
	if table == "nat" {
		a = append(a, "-t", "nat")
	}
	return run(8*time.Second, bin, append(a, args...)...)
}

func ipt(table string, args ...string) ([]byte, error) { return iptFam("iptables", table, args...) }

func runStdin(stdin string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...) //nolint:gosec // G204: komut adı ve argümanlar koddaki sabitlerden ya da validateState'ten geçmiş yapılandırmadan gelir; kabuk yok
	cmd.Stdin = strings.NewReader(stdin)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(out.String()))
	}
	return nil
}

// ruleLines: `iptables -S ZİNCİR` çıktısındaki "-A ZİNCİR ..." satırlarının kurallar bölümü (jetonlar), normalleştirilmiş.
func ruleLines(out []byte, chain string) [][]string {
	var res [][]string
	prefix := "-A " + chain + " "
	for ln := range strings.SplitSeq(string(out), "\n") {
		if after, ok := strings.CutPrefix(ln, prefix); ok {
			res = append(res, normTokens(strings.Fields(after)))
		}
	}
	return res
}

// normTokens: iptables'ın ima ettiği "-m tcp/udp/icmp" eşleşmelerini yok sayar ve `iptables -S`'in yorumu sardığı
// çift tırnakları soyar; böylece -S çıktısı üretilen jetonlarla birebir karşılaştırılır. Etiket boşluk içermediği
// için strings.Fields yorumu bölmez.
func normTokens(t []string) []string {
	var o []string
	for i := 0; i < len(t); i++ {
		if t[i] == "-m" && i+1 < len(t) && (t[i+1] == "tcp" || t[i+1] == "udp" || t[i+1] == "icmp" || t[i+1] == "icmp6") {
			i++
			continue
		}
		v := t[i]
		if i > 0 && t[i-1] == "--comment" && len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		o = append(o, v)
	}
	return o
}

func tokEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (a *App) ifaceUp(s Server) bool {
	_, err := run(5*time.Second, "wg", "show", s.Iface, "public-key")
	return err == nil
}

// iptFn: iptables ya da ip6tables çağırıcısı (aile bağımsız yardımcılar için).
type iptFn func(table string, args ...string) ([]byte, error)

// topMatchesF: zincirin ilk len(want) kuralı beklenenle birebir aynı mı?
func topMatchesF(ipt iptFn, table, chain string, want [][]string) (bool, error) {
	out, err := ipt(table, "-S", chain)
	if err != nil {
		return false, err
	}
	got := ruleLines(out, chain)
	if len(got) < len(want) {
		return false, nil
	}
	for i := range want {
		if !tokEq(got[i], normTokens(want[i])) {
			return false, nil
		}
	}
	return true, nil
}

// forwardPolicyF: FORWARD zincirinin varsayılan politikası (`-S FORWARD`'ın "-P FORWARD X" satırı); okunamazsa "".
func forwardPolicyF(ipt iptFn) string {
	out, err := ipt("filter", "-S", "FORWARD")
	if err != nil {
		return ""
	}
	for ln := range strings.SplitSeq(string(out), "\n") {
		if p, ok := strings.CutPrefix(ln, "-P FORWARD "); ok {
			return strings.TrimSpace(p)
		}
	}
	return ""
}

func skelGroup(sk []skelRule, table, chain string) [][]string {
	var g [][]string
	for _, r := range sk {
		if r.table == table && r.chain == chain {
			g = append(g, r.args)
		}
	}
	return g
}

// skeletonOK: sabit kurallar yerinde ve doğru sırada mı? Tamamsa State "ok", değilse nedeniyle "no-jump".
func skeletonOK(s Server) fwState {
	return skeletonOKF(ipt, skeleton(s.Iface, s.prefix().String()), "IPv4")
}

// skeletonOKF: fam ("IPv4"/"IPv6") yalnızca gösterilen nedende kullanılır.
func skeletonOKF(ipt iptFn, sk []skelRule, fam string) fwState {
	broken := func(key string, p map[string]any) fwState {
		p["fam"] = fam
		return fwMsg("no-jump", "fw.skeleton."+key, p)
	}
	for _, ch := range []string{"FORWARD", "INPUT"} {
		ok, err := topMatchesF(ipt, "filter", ch, skelGroup(sk, "filter", ch))
		if err != nil {
			return broken("read_failed", map[string]any{"chain": ch, "err": err.Error()})
		}
		if !ok {
			return broken("top", map[string]any{"chain": ch})
		}
	}
	for _, r := range sk {
		if r.table == "nat" {
			if _, err := ipt("nat", append([]string{"-C", r.chain}, r.args...)...); err != nil {
				return broken("nat_jump", map[string]any{})
			}
		}
	}
	for _, c := range filterChains {
		if _, err := ipt("filter", "-S", c); err != nil {
			return broken("chain_missing", map[string]any{"chain": c})
		}
	}
	if _, err := ipt("nat", "-S", chainNat); err != nil {
		return broken("chain_missing", map[string]any{"chain": chainNat})
	}
	return fwState{State: "ok"}
}

// ensureSkeleton: zincirleri ve sabit kuralları kurar/onarır. Önce yenisi eklenir, sonra eskisi silinir;
// böylece araya hiçbir zaman "kuralsız" bir an girmez.
func (a *App) ensureSkeleton(s Server) error {
	if err := ensureSkeletonF(ipt, skeleton(s.Iface, s.prefix().String())); err != nil {
		return err
	}
	a.cleanupLegacy(s)
	return nil
}

func ensureSkeletonF(ipt iptFn, sk []skelRule) error {
	for _, c := range filterChains {
		_, _ = ipt("filter", "-N", c) // varsa hata verir, yoksay
	}
	_, _ = ipt("nat", "-N", chainNat)

	for _, g := range []struct{ table, chain string }{{"filter", "FORWARD"}, {"filter", "INPUT"}} {
		want := skelGroup(sk, g.table, g.chain)
		if ok, err := topMatchesF(ipt, g.table, g.chain, want); err == nil && ok {
			continue
		}
		for _, w := range slices.Backward(want) {
			if _, err := ipt(g.table, append([]string{"-I", g.chain, "1"}, w...)...); err != nil {
				return ue("fw.apply.skeleton", map[string]any{"err": err.Error()})
			}
		}
		// Aşağıda kalan eski kopyaları (ve yinelenenleri) numarayla sil.
		out, err := ipt(g.table, "-S", g.chain)
		if err != nil {
			return err
		}
		lines := ruleLines(out, g.chain)
		for i := len(lines) - 1; i >= len(want); i-- {
			for _, w := range want {
				if tokEq(lines[i], normTokens(w)) {
					if _, err := ipt(g.table, "-D", g.chain, strconv.Itoa(i+1)); err != nil {
						log.Printf("güvenlik duvarı iskeleti: %s zincirindeki eski kopya (%d. kural) silinemedi: %v", g.chain, i+1, err)
					}
					break
				}
			}
		}
	}
	for _, r := range sk {
		if r.table == "nat" {
			if _, err := ipt("nat", append([]string{"-C", r.chain}, r.args...)...); err != nil {
				if _, err := ipt("nat", append([]string{"-I", r.chain, "1"}, r.args...)...); err != nil {
					return ue("fw.apply.skeleton_nat", map[string]any{"err": err.Error()})
				}
			}
		}
	}
	return nil
}

// cleanupLegacy: v0.3'ün bıraktığı kuralları ve WGUI-* zincirlerini, ayrıca eski yönsüz kısayolu kaldırır (yoksa sessizce geçer).
func (a *App) cleanupLegacy(s Server) {
	sub := s.prefix().String()
	for range 10 {
		if _, err := ipt("filter", "-D", "FORWARD", "-i", s.Iface, "-o", s.Iface, "-j", "ACCEPT"); err != nil {
			break
		}
	}
	for range 10 {
		if _, err := ipt("filter", "-D", "FORWARD", "-i", s.Iface, "-j", legacyInet); err != nil {
			break
		}
	}
	for range 10 {
		if _, err := ipt("nat", "-D", "POSTROUTING", "-s", sub, "-j", legacyNat); err != nil {
			break
		}
	}
	_, _ = ipt("filter", "-F", legacyInet)
	_, _ = ipt("filter", "-X", legacyInet)
	_, _ = ipt("nat", "-F", legacyNat)
	_, _ = ipt("nat", "-X", legacyNat)
	cleanupStaleSkelF(ipt, skeleton(s.Iface, sub), s.Iface, false)
}

// cleanupStaleSkelF: önceki sürümlerin FORWARD'a koyduğu, artık iskelette olmayan kuralları (bütün kopyalarıyla)
// siler: --ctdir REPLY'den önceki yönsüz kurulmuş-akış kısayolu, v0.12'nin her arayüzden gelen yanıt kuralı ve
// akış tarafını denetlemeyen ICMP RELATED kabulü. Yeni iskelet kurulduktan sonra çağrılır; o noktada bu kurallar
// son DROP'ların altında kaldığı için hiçbir wg0 paketine ulaşmıyordur, silmek trafiği değiştirmez. KUT-IN'deki
// eşleri ayrıca silinmez: zincir her eşitlemede iptables-restore ile baştan yazılır.
//
// v0.14 ve öncesinin etiketsiz iskelet kuralları da (FORWARD, INPUT, nat POSTROUTING) burada silinir. iptables -D
// yorumu da karşılaştırır (v1.8.11 nf_tables'ta ölçüldü): etiketsiz biçim etiketli yeni kurala dokunmaz. Yeni kural
// ensureSkeletonF'te önce eklendiği için silme anında araya boşluk girmez.
func cleanupStaleSkelF(ipt iptFn, sk []skelRule, iface string, v6 bool) {
	for _, r := range sk {
		old := stripTag(r.args)
		for range 10 {
			if _, err := ipt(r.table, append([]string{"-D", r.chain}, old...)...); err != nil {
				break
			}
		}
	}
	icmp := relatedICMP(v6)
	icmp[len(icmp)-1] = "ACCEPT"
	for _, r := range [][]string{
		{"-o", iface, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
		append([]string{"-o", iface}, replyOnly...),
		append([]string{"-i", iface, "-o", iface}, icmp...),
	} {
		for range 10 {
			if _, err := ipt("filter", append([]string{"-D", "FORWARD"}, r...)...); err != nil {
				break
			}
		}
	}
}

type fwState struct {
	State  string `json:"state"` // dry | down | ok | no-jump | out-of-sync
	Detail string `json:"detail,omitempty"`
	// Key + Params: Detail'in katalog anahtarı (fw.*); gösteren taraf T(lang, Key, Params) ile kendi dilinde yazar.
	Key    string         `json:"key,omitempty"`
	Params map[string]any `json:"params,omitempty"`
	// ForwardPolicy: host'un IPv4 FORWARD varsayılan politikası (bilgi; Kut'un iskeleti wg0 trafiğini ondan bağımsız kapatır).
	ForwardPolicy string `json:"forward_policy,omitempty"`
}

// fwMsg: durumun Key/Params/Detail üçlüsünü tek yerde doldurur; Detail referans dildedir (günlük ve test için).
func fwMsg(state, key string, params map[string]any) fwState {
	return fwState{State: state, Key: key, Params: params, Detail: T(refLang, key, params)}
}

// fwCheck: çalışan güvenlik duvarının olması gerekenle birebir uyumunu kontrol eder.
func (a *App) fwCheck(s Server, peers []Peer, pols []Policy) fwState {
	if a.dry {
		return fwMsg("dry", "fw.dry", nil)
	}
	if !a.ifaceUp(s) {
		return fwMsg("down", "fw.down", nil)
	}
	st := a.fwVerify(s, peers, pols)
	if p := forwardPolicyF(ipt); p != "" {
		// Yalnızca "ok"ta mesaja yazılır: diğer durumlarda Key arıza nedenidir ve izleyici onu karşılaştırır (fwNeedsRepair).
		if st.State == "ok" {
			st = fwMsg("ok", "fw.forward_policy", map[string]any{"policy": p})
		}
		st.ForwardPolicy = p
	}
	return st
}

// fwVerify: iskelet ve zincir içerikleri olması gerekenle birebir aynı mı? (arayüzün açık olduğu varsayılır)
func (a *App) fwVerify(s Server, peers []Peer, pols []Policy) fwState {
	if st := skeletonOK(s); st.State != "ok" {
		return st
	}
	f := desiredFirewall(s, peers, pols, a.panelPort(), time.Now())
	if st := verifyChainsF(ipt, f, "IPv4"); st.State != "ok" {
		return st
	}
	if s.v6On() {
		return a.fwVerify6(s, peers, pols)
	}
	return fwState{State: "ok"}
}

// verifyChainsF: KUT-* zincirlerinin içeriği olması gerekenle aynı mı. fam: gösterilen nedendeki aile ("IPv4"/"IPv6").
func verifyChainsF(ipt iptFn, f fwSet, fam string) fwState {
	for _, c := range []struct {
		table, chain string
		want         [][]string
	}{
		{"filter", chainPeers, f.Peers}, {"filter", chainIn, f.In}, {"filter", chainInet, f.Inet}, {"filter", chainICMP, f.ICMP}, {"nat", chainNat, f.Nat},
	} {
		out, err := ipt(c.table, "-S", c.chain)
		if err != nil {
			return fwMsg("no-jump", "fw.chain.read_failed", map[string]any{"fam": fam, "chain": c.chain})
		}
		got := ruleLines(out, c.chain)
		if len(got) != len(c.want) {
			return fwMsg("out-of-sync", "fw.chain.count", map[string]any{"fam": fam, "chain": c.chain, "n": len(got), "want": len(c.want)})
		}
		for i := range got {
			if !tokEq(got[i], normTokens(c.want[i][2:])) {
				return fwMsg("out-of-sync", "fw.chain.rule_differs", map[string]any{"fam": fam, "chain": c.chain, "pos": i + 1})
			}
		}
	}
	return fwState{State: "ok"}
}

func restoreScript(f fwSet) (filter, nat string) {
	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range filterChains {
		b.WriteString("-F " + c + "\n")
	}
	for _, r := range f.filter() {
		b.WriteString(strings.Join(r, " ") + "\n")
	}
	b.WriteString("COMMIT\n")
	var n strings.Builder
	n.WriteString("*nat\n-F " + chainNat + "\n")
	for _, r := range f.Nat {
		n.WriteString(strings.Join(r, " ") + "\n")
	}
	n.WriteString("COMMIT\n")
	return b.String(), n.String()
}

// syncFirewall: önce iskeleti onarır, sonra KUT-* zincirlerini iptables-restore ile tek işlemde değiştirir.
func (a *App) syncFirewall(s Server, peers []Peer, pols []Policy) error {
	if a.dry {
		return nil
	}
	if err := a.ensureSkeleton(s); err != nil {
		return err
	}
	f := desiredFirewall(s, peers, pols, a.panelPort(), time.Now())
	if err := applyRestore("iptables", f, ""); err != nil {
		return err
	}
	return a.syncFirewall6(s, peers, pols)
}

// applyRestore: KUT-* zincirlerini bin-restore ile değiştirir (önce filter, sonra nat). label: IPv6 için "IPv6 " ön eki.
func applyRestore(bin string, f fwSet, label string) error {
	filter, nat := restoreScript(f)
	if err := runStdin(filter, bin+"-restore", "-w", "5", "--noflush"); err != nil {
		return ue("fw.apply.restore", map[string]any{"label": label, "err": err.Error()})
	}
	if err := runStdin(nat, bin+"-restore", "-w", "5", "--noflush"); err != nil {
		return ue("fw.apply.restore_nat", map[string]any{"label": label, "err": err.Error()})
	}
	return nil
}
