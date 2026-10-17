package main

import (
	"bufio"
	"bytes"
	"hash/fnv"
	"maps"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sunucu sayfasının güvenlik duvarı görünümü: iskelet ve KUT-* zincirlerindeki her kural yapılandırılmış olarak
// (fwRule) ve canlı sayaçlarıyla. Kurallar desiredFirewall'dan gelir (yorum etiketleriyle aynı kaynak); sayaçlar
// `iptables -L ZİNCİR -v -x -n` çıktısından kuralın sırasına değil etiketine göre bağlanır.

// counterChains: sayaç okunan zincirler (tablo, zincir).
var counterChains = []struct{ table, chain string }{
	{"filter", "FORWARD"}, {"filter", "INPUT"},
	{"filter", chainPeers}, {"filter", chainIn}, {"filter", chainInet}, {"filter", chainICMP},
	{"nat", "POSTROUTING"}, {"nat", chainNat},
}

// ruleKey: kuralın sayfa genelinde tek anahtarı. Etiket zincirinde tektir; aynı etiket IPv4 ve IPv6'da bulunabilir.
func ruleKey(family, chain, tag string) string { return family + "|" + chain + "|" + tag }

// rawRule: kuralın kopyalanabilir iptables satırı. Yorum tırnaklıdır: etikette '>' bulunabilir ve tırnaksız
// yapıştırılınca kabuk onu yönlendirme sayardı.
func rawRule(bin, table string, args []string) string {
	q := make([]string, len(args))
	copy(q, args)
	for i := range q {
		if i > 0 && q[i-1] == "--comment" {
			q[i] = `"` + q[i] + `"`
		}
	}
	t := bin + " "
	if table == "nat" {
		t += "-t nat "
	}
	return t + strings.Join(q, " ")
}

// fwRules: sayfada gösterilen bütün kurallar (iskelet önce), IPv6 açıksa onunkiler de.
func (a *App) fwRules(s Server, peers []Peer, pols []Policy, now time.Time) []fwRule {
	names := map[string]string{}
	for _, p := range peers {
		names[p.ID] = p.Name
	}
	var out []fwRule
	fam := func(family, bin, sub string, f fwSet) {
		for _, r := range skeleton(s.Iface, sub) {
			tag := ruleTag(r.args)
			out = append(out, fwRule{Chain: r.chain, Family: family, Tag: tag, Kind: "skel", Action: r.args[len(r.args)-1],
				Raw: rawRule(bin, r.table, append([]string{"-A", r.chain}, r.args...))})
		}
		for _, in := range f.Info {
			in.Family = family
			in.DeviceName = names[in.DeviceID]
			in.TargetName = names[in.Target]
			table := ""
			if in.Chain == chainNat {
				table = "nat"
			}
			in.Raw = rawRule(bin, table, in.args)
			out = append(out, in)
		}
	}
	fam("ipv4", "iptables", s.prefix().String(), desiredFirewall(s, peers, pols, a.panelPort(), now))
	if s.v6On() {
		natOK, _ := hostV6Route()
		fam("ipv6", "ip6tables", s.prefix6().String(), desiredFirewall6(s, peers, pols, now, natOK || a.dry))
	}
	for i := range out {
		out[i].Key = ruleKey(out[i].Family, out[i].Chain, out[i].Tag)
	}
	return out
}

// parseRuleCounters: `iptables -L ZİNCİR -v -x -n` çıktısındaki Kut kurallarının sayaçları, etikete göre.
// Yorum satır sonunda "/* etiket */" olarak yazılır (v1.8.11'de ölçüldü); boşluk içeren bir yorum ya da tırnaklı
// yazım da doğru okunur. Etiketsiz ya da Kut'a ait olmayan kurallar atlanır.
func parseRuleCounters(out []byte) map[string][2]uint64 {
	res := map[string][2]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		ln := sc.Text()
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		pk, err1 := strconv.ParseUint(f[0], 10, 64)
		by, err2 := strconv.ParseUint(f[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		i := strings.Index(ln, "/* ")
		j := strings.LastIndex(ln, " */")
		if i < 0 || j <= i+2 {
			continue
		}
		tag := strings.Trim(strings.TrimSpace(ln[i+3:j]), `"`)
		if !strings.HasPrefix(tag, "kut:") {
			continue
		}
		res[tag] = [2]uint64{pk, by}
	}
	return res
}

// readRuleCounters: bir ailenin sayaçları (anahtar: ruleKey). Okunamayan zincir (yok, ip6tables yok) atlanır.
// deadline geçince kalan zincirler okunmaz: xtables kilidi takılırsa çağrı başına 8 sn'lik zaman aşımı 16 zincirde
// dakikaları bulurdu. Okunmayan kuralın sayacı yoktur (sayfa "—" yazar), bir sonraki yoklamada yeniden denenir.
func readRuleCounters(ipt iptFn, family string, deadline time.Time) map[string][2]uint64 {
	res := map[string][2]uint64{}
	for _, c := range counterChains {
		if time.Now().After(deadline) {
			break
		}
		out, err := ipt(c.table, "-L", c.chain, "-v", "-x", "-n")
		if err != nil {
			continue
		}
		for tag, v := range parseRuleCounters(out) {
			res[ruleKey(family, c.chain, tag)] = v
		}
	}
	return res
}

// counterCache: aynı anda açık birden çok sekme her 5 sn'de 8-16 iptables çağrısını katlamasın. Kilit yalnızca
// önbelleğe bakarken tutulur, iptables çağrılarında değil: yenilemeyi tek istek yapar (busy), bu sırada gelenler
// varsa eski veriyi bekletmeden alır; veri hiç yoksa (ilk istek) yenilemenin bitmesini bekler.
type counterCache struct {
	mu   sync.Mutex
	at   time.Time
	data map[string][2]uint64
	busy chan struct{}               // yenileme sürerken açık, bitince kapanır
	load func() map[string][2]uint64 // testlerde okuyucu; nil ise gerçek okuma
}

const (
	counterTTL    = 2 * time.Second
	counterBudget = 5 * time.Second // bir yenilemenin bütün zincirler için toplam süresi
)

func (a *App) ruleCounters(s Server, peers []Peer, pols []Policy) map[string][2]uint64 {
	c := &a.ctrs
	for {
		c.mu.Lock()
		if c.data != nil && time.Since(c.at) < counterTTL {
			d := c.data
			c.mu.Unlock()
			return d
		}
		if c.busy != nil {
			if c.data != nil { // yenileme sürüyor: eski veri beklemekten iyidir
				d := c.data
				c.mu.Unlock()
				return d
			}
			ch := c.busy
			c.mu.Unlock()
			<-ch
			continue
		}
		ch := make(chan struct{})
		c.busy = ch
		load := c.load
		c.mu.Unlock()

		var res map[string][2]uint64
		func() {
			defer func() { // okuma panik etse de bekleyenler serbest kalsın
				c.mu.Lock()
				if res != nil {
					c.at, c.data = time.Now(), res
				}
				c.busy = nil
				c.mu.Unlock()
				close(ch)
			}()
			switch {
			case load != nil:
				res = load()
			case a.dry:
				now := time.Now()
				res = simulatedCounters(a.fwRules(s, peers, pols, now), now)
			default:
				deadline := time.Now().Add(counterBudget)
				res = readRuleCounters(ipt, "ipv4", deadline)
				if s.v6On() && haveIP6Tables() {
					maps.Copy(res, readRuleCounters(ipt6, "ipv6", deadline))
				}
			}
		}()
		if res == nil {
			res = map[string][2]uint64{}
		}
		return res
	}
}

// simEpoch: benzetilmiş sayaçların başlangıcı (süreç başı); sayılar gerçekçi küçüklükte başlar.
var simEpoch = time.Now()

// simulatedCounters: yalnızca -dry-run'da (iptables'a dokunulmaz): arayüzün sayaç ve vurgu davranışı yerelde
// denenebilsin diye zamanla artan, kurala göre sabit sayılar. Sayfa bunların gerçek olmadığını yazar.
func simulatedCounters(rules []fwRule, now time.Time) map[string][2]uint64 {
	res := map[string][2]uint64{}
	tick := uint64(max(now.Sub(simEpoch), 0) / (5 * time.Second)) //nolint:gosec // G115: negatif değil
	for _, r := range rules {
		h := fnv.New32a()
		_, _ = h.Write([]byte(r.Key))
		v := uint64(h.Sum32())
		if v%3 != 0 { // kuralların üçte biri trafik alıyor görünür
			res[r.Key] = [2]uint64{v % 50, (v % 50) * 120}
			continue
		}
		pk := v%50 + tick*(1+v%4)
		res[r.Key] = [2]uint64{pk, pk * (64 + v%1400)}
	}
	return res
}

func (a *App) handleServerCounters(w http.ResponseWriter, _ *http.Request) {
	s := a.getSrv()
	peers, pols := a.snapshot()
	writeJSON(w, http.StatusOK, a.ruleCounters(s, peers, pols))
}
