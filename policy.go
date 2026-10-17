package main

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Erişim profilleri
//
// Bir erişim profili, ona atanan cihazların VPN içinde kime ve sunucuda hangi portlara erişebileceğini söyler.
// Profil atanmamış cihaz yalnızca sunucuya ulaşır (ping, panel portu; diğer sunucu portlarına host güvenlik duvarı karar verir);
// cihazlar arası tek izni başka bir profilin karşılıklı kuralının geri yönüdür. Settings.PeerFree v0.13 davranışını
// (VPN içinde serbest) geri açar.
// Profil atanmış cihaz ise yalnızca listede yazanı yapabilir; gerisi düşer. Kurallar yönlüdür.

const (
	maxRules     = 40
	maxPortToks  = 20
	maxDescRunes = 200
	maxRuleNote  = 80
)

type Rule struct {
	Target string `json:"target"`           // server | device | all
	Device string `json:"device,omitempty"` // target=device ise cihaz kimliği
	Proto  string `json:"proto"`            // tcp | udp | icmp | any
	Ports  string `json:"ports,omitempty"`  // "" = tüm portlar; "443", "8000-8100", "80,443"
	Note   string `json:"note,omitempty"`
	Both   bool   `json:"both,omitempty"` // yalnızca target=device: hedef cihaz da aynı portlarla bize erişebilir
	// Schedule doluysa kural yalnızca bu gün/saat aralığında geçerlidir (Scope alanı kurallarda kullanılmaz).
	Schedule *Schedule `json:"schedule,omitempty"`
}

type Policy struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Desc    string    `json:"desc,omitempty"`
	Rules   []Rule    `json:"rules"`
	Groups  []string  `json:"groups,omitempty"` // bu profil, profili olmayan şu gruplardaki cihazların varsayılanıdır
	Created time.Time `json:"created"`
}

type portRange struct{ lo, hi int }

func (r portRange) String() string {
	if r.lo == r.hi {
		return strconv.Itoa(r.lo)
	}
	return fmt.Sprintf("%d-%d", r.lo, r.hi)
}

// parsePorts: "80, 443,8000-8100" -> aralıklar. Boş dize = tüm portlar (nil).
func parsePorts(s string) ([]portRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	toks := strings.Split(s, ",")
	if len(toks) > maxPortToks {
		return nil, ue("rule.port_too_many", map[string]any{"max": maxPortToks})
	}
	var out []portRange
	for _, t := range toks {
		t = strings.TrimSpace(t)
		if t == "" {
			return nil, ue("rule.port_empty_item", nil)
		}
		lo, hi := t, t
		if i := strings.IndexByte(t, '-'); i >= 0 {
			lo, hi = strings.TrimSpace(t[:i]), strings.TrimSpace(t[i+1:])
		}
		a, err1 := strconv.Atoi(lo)
		b, err2 := strconv.Atoi(hi)
		if err1 != nil || err2 != nil || a < 1 || b > 65535 || a > b {
			return nil, ue("rule.port_bad", map[string]any{"port": strconv.Quote(t)})
		}
		out = append(out, portRange{a, b})
	}
	return out, nil
}

func normPorts(rs []portRange) string {
	p := make([]string, len(rs))
	for i, r := range rs {
		p[i] = r.String()
	}
	return strings.Join(p, ",")
}

func validPolicyName(s string) bool { return nameRe.MatchString(s) }

// cleanText: kırpılmış metin; uzunluk sınırını aşıyor ya da satır sonu/denetim karakteri içeriyorsa ok=false.
func cleanText(s string, limit int) (string, bool) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > limit || strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return "", false
	}
	return s, true
}

// withParam: kodlu hatanın bir kopyasına parametre ekler (kodsuz hata olduğu gibi döner).
func withParam(err error, key string, val any) error {
	var ce *codedErr
	if !errors.As(err, &ce) {
		return err
	}
	p := make(map[string]any, len(ce.Params)+1)
	maps.Copy(p, ce.Params)
	p[key] = val
	return ue(ce.Code, p)
}

// ruleScheduleErr: kural içindeki zamanlama hatasını ("schedule.bad_time") kural sırasını anan koda ("rule.schedule_bad_time") çevirir.
func ruleScheduleErr(err error, n int) error {
	var ce *codedErr
	if errors.As(err, &ce) && strings.HasPrefix(ce.Code, "schedule.") {
		return ue("rule.schedule_"+strings.TrimPrefix(ce.Code, "schedule."), map[string]any{"n": n})
	}
	return err
}

// normalizeRule: kuralı doğrular ve kanonik hâle getirir. n: kuralın profildeki sırası (1'den); hata iletisi ona atıf yapar.
func normalizeRule(r Rule, peers []Peer, n int) (Rule, error) {
	r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
	r.Target = strings.ToLower(strings.TrimSpace(r.Target))
	switch r.Target {
	case "server", "all":
		if r.Device != "" {
			return r, ue("rule.device_only", map[string]any{"n": n})
		}
	case "device":
		if !slices.ContainsFunc(peers, func(p Peer) bool { return p.ID == r.Device }) {
			return r, ue("rule.device_missing", map[string]any{"n": n})
		}
	default:
		return r, ue("rule.bad_target", map[string]any{"n": n})
	}
	if r.Both && r.Target != "device" {
		return r, ue("rule.both_single", map[string]any{"n": n})
	}
	switch r.Proto {
	case "tcp", "udp":
		rs, err := parsePorts(r.Ports)
		if err != nil {
			return r, withParam(err, "n", n)
		}
		r.Ports = normPorts(rs)
	case "icmp", "any":
		if strings.TrimSpace(r.Ports) != "" {
			return r, ue("rule.ports_tcp_udp_only", map[string]any{"n": n})
		}
		r.Ports = ""
	default:
		return r, ue("rule.bad_proto", map[string]any{"n": n})
	}
	note, ok := cleanText(r.Note, maxRuleNote)
	if !ok {
		return r, ue("rule.note_invalid", map[string]any{"n": n, "limit": maxRuleNote})
	}
	r.Note = note
	if r.Schedule != nil {
		r.Schedule.Scope = "tunnel"
		ns, err := normalizeSchedule(r.Schedule)
		if err != nil {
			return r, ruleScheduleErr(err, n)
		}
		r.Schedule = ns
	}
	return r, nil
}

func normalizePolicy(p Policy, peers []Peer) (Policy, error) {
	p.Name = strings.TrimSpace(p.Name)
	if !validPolicyName(p.Name) {
		return p, ue("policy.bad_name", nil)
	}
	d, ok := cleanText(p.Desc, maxDescRunes)
	if !ok {
		return p, ue("policy.desc_invalid", map[string]any{"limit": maxDescRunes})
	}
	p.Desc = d
	if len(p.Rules) > maxRules {
		return p, ue("policy.too_many_rules", map[string]any{"max": maxRules})
	}
	rules := make([]Rule, 0, len(p.Rules))
	for i, r := range p.Rules {
		nr, err := normalizeRule(r, peers, i+1)
		if err != nil {
			return p, err
		}
		rules = append(rules, nr)
	}
	p.Rules = rules
	seen := map[string]bool{}
	var gl []string
	for _, g := range p.Groups {
		g = strings.TrimSpace(g)
		if g == "" || seen[strings.ToLower(g)] {
			continue
		}
		if !groupRe.MatchString(g) {
			return p, ue("policy.bad_group", map[string]any{"group": strconv.Quote(g)})
		}
		seen[strings.ToLower(g)] = true
		gl = append(gl, g)
	}
	if len(gl) > 20 {
		return p, ue("policy.too_many_groups", map[string]any{"max": 20})
	}
	p.Groups = gl
	return p, nil
}

// groupKey: grup varsayılan profilinin polIndex anahtarı (küçük harf).
func groupKey(g string) string { return "group:" + strings.ToLower(g) }

// checkGroupClaims: bir grup birden fazla profilin varsayılanı olamaz.
func checkGroupClaims(pols []Policy, self Policy) error {
	for _, o := range pols {
		if o.ID == self.ID {
			continue
		}
		for _, g := range o.Groups {
			for _, h := range self.Groups {
				if strings.EqualFold(g, h) {
					return ue("policy.group_claimed", map[string]any{"group": h, "policy": o.Name})
				}
			}
		}
	}
	return nil
}

// ---- Değerlendirme ----

func polIndex(pols []Policy) map[string]Policy {
	m := make(map[string]Policy, len(pols))
	for _, p := range pols {
		m[p.ID] = p
		for _, g := range p.Groups {
			m[groupKey(g)] = p
		}
	}
	return m
}

// effectivePolicy: cihazın profili. Atanmışsa ama bulunamıyorsa adsız, kuralsız (her şeyi kapatan) profil döner;
// gerçek profillerin adı asla boş olmaz, gösteren taraf boş adı access.policy_missing ile yazar.
func effectivePolicy(p Peer, idx map[string]Policy) (Policy, bool) {
	if p.Policy == "" {
		if p.Group != "" {
			if gp, ok := idx[groupKey(p.Group)]; ok {
				return gp, true
			}
		}
		return Policy{}, false
	}
	pol, ok := idx[p.Policy]
	if !ok {
		return Policy{}, true
	}
	return pol, true
}

type grant struct {
	Src, Dst string // Src: cihaz kimliği; Dst: "server" | "all" | cihaz kimliği
	Rule     Rule
	Policy   string // kuralın geldiği profilin adı
	PolID    string // profilin kimliği (kural etiketinde ad yerine kullanılır)
	Idx      int    // kuralın profildeki sırası (1'den başlar)
	Reverse  bool   // "karşılıklı" kuralın ters yönü
	Off      bool   // kuralın zaman aralığı şu an dışında (yalnızca all=true ile döner)
}

// grants: profili olan her cihaz için kuralları (ve karşılıklı olanların ters yönünü) üretir.
func grants(peers []Peer, pols []Policy, now time.Time) []grant {
	return grantsAt(peers, pols, now, false)
}

// grantsAt: all=true ise zaman aralığı dışındaki kurallar da Off işaretiyle döner.
func grantsAt(peers []Peer, pols []Policy, now time.Time, all bool) []grant {
	idx := polIndex(pols)
	var out []grant
	for _, s := range peers {
		pol, has := effectivePolicy(s, idx)
		if !has {
			continue
		}
		for i, r := range pol.Rules {
			off := r.Schedule != nil && !r.Schedule.allows(now)
			if off && !all {
				continue
			}
			switch r.Target {
			case "server":
				out = append(out, grant{Src: s.ID, Dst: "server", Rule: r, Policy: pol.Name, PolID: pol.ID, Idx: i + 1, Off: off})
			case "all":
				out = append(out, grant{Src: s.ID, Dst: "all", Rule: r, Policy: pol.Name, PolID: pol.ID, Idx: i + 1, Off: off})
			case "device":
				out = append(out, grant{Src: s.ID, Dst: r.Device, Rule: r, Policy: pol.Name, PolID: pol.ID, Idx: i + 1, Off: off})
				if r.Both {
					out = append(out, grant{Src: r.Device, Dst: s.ID, Rule: r, Policy: pol.Name, PolID: pol.ID, Idx: i + 1, Reverse: true, Off: off})
				}
			}
		}
	}
	return out
}

// hits: bu izin dst hedefini kapsıyor mu ("all" yalnızca cihazları kapsar, sunucuyu değil).
func (g grant) hits(dst string) bool { return g.Dst == dst || (g.Dst == "all" && dst != "server") }

func (r Rule) matches(proto string, port int) bool {
	switch r.Proto {
	case "any":
		return true
	case "icmp":
		return proto == "icmp"
	}
	if r.Proto != proto {
		return false
	}
	if r.Ports == "" {
		return true
	}
	rs, _ := parsePorts(r.Ports)
	for _, x := range rs {
		if port >= x.lo && port <= x.hi {
			return true
		}
	}
	return false
}

// Rule.textIn: kuralın okunur özeti ("TCP 443 (Web)"), lang dilinde.
func (r Rule) textIn(lang string) string {
	var s string
	switch r.Proto {
	case "any":
		s = T(lang, "access.all_traffic", nil)
	case "icmp":
		s = T(lang, "access.ping", nil)
	default:
		s = strings.ToUpper(r.Proto)
		if r.Ports == "" {
			s += " " + T(lang, "access.all_ports", nil)
		} else {
			s += " " + strings.ReplaceAll(r.Ports, ",", ", ")
		}
	}
	if r.Note != "" {
		s += " (" + r.Note + ")"
	}
	if r.Schedule != nil {
		s += " · " + r.Schedule.textIn(lang)
	}
	return s
}

type Verdict struct {
	Result string `json:"result"` // allow | deny | host
	Reason string `json:"reason"`
}

// evalReach: src cihazının dst hedefine (sunucu ya da başka bir cihaz) proto/port ile erişip erişemeyeceği.
// dst: "server" ya da cihaz kimliği. panelPort, profili olmayan cihazlara açık olan panel portudur.
// free: profili olmayan cihazlar VPN içinde serbest mi (Settings.PeerFree). Reason, lang dilinde yazılır.
func evalReach(lang string, peers []Peer, pols []Policy, src Peer, dst string, proto string, port int, panelPort int, free bool, now time.Time) Verdict {
	idx := polIndex(pols)
	var dstPeer Peer
	if dst != "server" {
		i := slices.IndexFunc(peers, func(p Peer) bool { return p.ID == dst })
		if i < 0 {
			return Verdict{"deny", T(lang, "access.dst_not_found", nil)}
		}
		dstPeer = peers[i]
		if dstPeer.ID == src.ID {
			return Verdict{"deny", T(lang, "access.same_device", nil)}
		}
		if !dstPeer.active(now) {
			return Verdict{"deny", T(lang, "access.dst_inactive", nil)}
		}
	}
	if !src.active(now) {
		return Verdict{"deny", T(lang, "access.src_inactive", nil)}
	}
	pol, has := effectivePolicy(src, idx)
	if pol.Name == "" {
		pol.Name = T(lang, "access.policy_missing", nil)
	}
	if !has {
		if dst != "server" && free {
			return Verdict{"allow", T(lang, "access.free_between_devices", nil)}
		}
		if dst != "server" {
			// Tek olası izin, karşı cihazın profilindeki karşılıklı kuraldır.
			for _, g := range grantsAt(peers, pols, now, false) {
				if g.Src == src.ID && g.hits(dst) && g.Rule.matches(proto, port) {
					return Verdict{"allow", T(lang, "access.policy_allows_reverse", map[string]any{"policy": g.Policy, "rule": g.Rule.textIn(lang)})}
				}
			}
			return Verdict{"deny", T(lang, "access.isolated_between_devices", nil)}
		}
		if proto == "icmp" {
			return Verdict{"allow", T(lang, "access.ping_open", nil)}
		}
		if proto == "tcp" && port == panelPort {
			return Verdict{"allow", T(lang, "access.panel_open", nil)}
		}
		return Verdict{"host", T(lang, "access.host_decides", nil)}
	}
	if dst == "server" && proto == "icmp" {
		return Verdict{"allow", T(lang, "access.ping_open", nil)}
	}
	var offRule *grant
	for _, g := range grantsAt(peers, pols, now, true) {
		if g.Src != src.ID {
			continue
		}
		if !g.hits(dst) {
			continue
		}
		if g.Rule.matches(proto, port) {
			if g.Off {
				gg := g
				offRule = &gg
				continue
			}
			key := "access.policy_allows"
			if g.Reverse {
				key = "access.policy_allows_reverse"
			}
			return Verdict{"allow", T(lang, key, map[string]any{"policy": g.Policy, "rule": g.Rule.textIn(lang)})}
		}
	}
	if offRule != nil {
		return Verdict{"deny", T(lang, "access.policy_off_window", map[string]any{"policy": offRule.Policy, "rule": offRule.Rule.textIn(lang)})}
	}
	return Verdict{"deny", T(lang, "access.policy_no_rule", map[string]any{"policy": pol.Name})}
}

// reachSummaryIn: src -> dst için izin verilen trafiğin özeti (matris hücresi), lang dilinde.
func reachSummaryIn(lang string, peers []Peer, pols []Policy, src Peer, dst string, panelPort int, free bool, now time.Time) (result, text string) {
	idx := polIndex(pols)
	if _, has := effectivePolicy(src, idx); !has {
		if dst == "server" {
			return "host", T(lang, "access.matrix_host", map[string]any{"port": panelPort})
		}
		if free {
			return "allow", T(lang, "access.matrix_free", nil)
		}
		// Kapalıyken yalnızca karşılıklı kuralların geri yönü kalır; aşağıdaki özet onu toplar.
	}
	var parts []string
	seen := map[string]bool{}
	for _, g := range grants(peers, pols, now) {
		if g.Src != src.ID || !g.hits(dst) {
			continue
		}
		t := g.Rule.textIn(lang)
		if !seen[t] {
			seen[t] = true
			parts = append(parts, t)
		}
	}
	if len(parts) == 0 {
		return "deny", ""
	}
	return "allow", strings.Join(parts, "; ")
}

// ---- IP doğrulama ----

// checkIP: bir cihaza verilecek VPN IP'sinin geçerli ve boş olduğunu doğrular. selfID: düzenlenen cihaz (kendi IP'si çakışma sayılmaz).
func checkIP(s Server, peers []Peer, ip string, selfID string) (netip.Addr, error) {
	ip = strings.TrimSpace(ip)
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is4() {
		return addr, ue("ip.not_ipv4", map[string]any{"example": s.serverIP().Next().String()})
	}
	pfx := s.prefix()
	if !pfx.Contains(addr) {
		return addr, ue("ip.outside", map[string]any{"subnet": pfx.String()})
	}
	if addr == pfx.Addr() {
		return addr, ue("ip.is_network", nil)
	}
	last := lastAddr(pfx)
	if addr == last {
		return addr, ue("ip.is_broadcast", nil)
	}
	if addr == s.serverIP() {
		return addr, ue("ip.is_server", nil)
	}
	for _, p := range peers {
		if p.ID != selfID && p.IP == addr.String() {
			return addr, ue("ip.in_use", map[string]any{"ip": addr.String(), "name": p.Name})
		}
	}
	return addr, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	hostBits := 32 - p.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= (uint32(1) << hostBits) - 1
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}) //nolint:gosec // G115: bilerek bayt bayt kesme (alt 8 bit)
}
