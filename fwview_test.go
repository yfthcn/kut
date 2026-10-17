package main

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Gerçek çıktı biçimleri iptables v1.8.11 (nf_tables) ile ölçüldü: yorum satır sonunda "/* etiket */".
const sampleCounters4 = `Chain KUT-PEERS (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      12     1440 ACCEPT     6    --  *      *       10.77.0.2            10.77.0.4            tcp dpt:443 /* kut:peer:10.77.0.2>10.77.0.4:tcp/443:prof=p1:r3 */
       0        0 ACCEPT     0    --  *      *       10.77.0.3            0.0.0.0/0            /* "kut:peer-free:10.77.0.3" */
       7      700 ACCEPT     0    --  *      *       10.77.0.9            0.0.0.0/0            /* someone else's rule */
       5      500 ACCEPT     0    --  *      *       10.77.0.8            0.0.0.0/0
`

const sampleCounters6 = `Chain KUT-INET (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       3      312 DROP       all  --  *      *       fdaa:bbbb:cccc::2    fc00::/7             /* kut:inet-deny:fdaa:bbbb:cccc::2:fc00::/7 */
 1234567 98765432 ACCEPT     all  --  *      *       fdaa:bbbb:cccc::2    ::/0                 /* kut:inet:fdaa:bbbb:cccc::2 */
`

func TestParseRuleCounters(t *testing.T) {
	c := parseRuleCounters([]byte(sampleCounters4))
	if len(c) != 2 || c["kut:peer:10.77.0.2>10.77.0.4:tcp/443:prof=p1:r3"] != [2]uint64{12, 1440} || c["kut:peer-free:10.77.0.3"] != [2]uint64{0, 0} {
		t.Errorf("IPv4 (tırnaklı yorum dahil): %v", c)
	}
	c6 := parseRuleCounters([]byte(sampleCounters6))
	if len(c6) != 2 || c6["kut:inet:fdaa:bbbb:cccc::2"] != [2]uint64{1234567, 98765432} || c6["kut:inet-deny:fdaa:bbbb:cccc::2:fc00::/7"] != [2]uint64{3, 312} {
		t.Errorf("IPv6: %v", c6)
	}
	// Zincir yok: iptables hata döner; o zincir atlanır, diğerleri okunur.
	fake := func(table string, args ...string) ([]byte, error) {
		if args[1] == chainPeers {
			return []byte(sampleCounters4), nil
		}
		return nil, errors.New("iptables: No chain/target/match by that name.")
	}
	got := readRuleCounters(fake, "ipv4", time.Now().Add(time.Minute))
	if len(got) != 2 || got[ruleKey("ipv4", chainPeers, "kut:peer-free:10.77.0.3")] != [2]uint64{0, 0} {
		t.Errorf("eksik zincir: %v", got)
	}
	if len(parseRuleCounters(nil)) != 0 || len(parseRuleCounters([]byte("garbage /* kut:x"))) != 0 {
		t.Error("boş/bozuk çıktı sayaç üretmemeli")
	}
}

// Sunucu sayfasının kuralları: yapılandırılmış, adlar yalnızca device_name/target_name alanında, sayaç anahtarıyla.
func TestServerRulesStructured(t *testing.T) {
	a, h := v5App(t)
	_, peers, pols := tagFixture(t)
	a.srv = v6Server(t)
	a.peers, a.pol = peers, pols
	c := login(h, "", "correct-horse-battery")
	rec := rqH(h, "GET", "/api/server", nil, c, nil)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var d struct {
		Firewall struct {
			Rules     []fwRule             `json:"rules"`
			Counters  map[string][2]uint64 `json:"counters"`
			Simulated bool                 `json:"simulated"`
		} `json:"firewall"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	rules := d.Firewall.Rules
	keys := map[string]bool{}
	var sawPeer, sawSkel6, sawName bool
	for _, r := range rules {
		if r.Key != ruleKey(r.Family, r.Chain, r.Tag) || keys[r.Key] {
			t.Errorf("anahtar tek ve tutarlı olmalı: %+v", r)
		}
		keys[r.Key] = true
		if !strings.Contains(r.Raw, `--comment "`+r.Tag+`"`) {
			t.Errorf("ham satırda tırnaklı etiket yok: %q", r.Raw)
		}
		if r.Kind == "peer" && r.DeviceID == "a1" && r.Target == "c3" {
			sawPeer = r.DeviceName == "Ayşe'nin Telefonu" && r.TargetName == "ğüşıöç ÖÇŞİĞÜ" && r.Proto == "tcp" && r.Port == "443" && r.Action == "ACCEPT"
		}
		if r.Kind == "skel" && r.Family == "ipv6" && r.Chain == "INPUT" && strings.HasPrefix(r.Raw, "ip6tables -A INPUT") {
			sawSkel6 = true
		}
		if strings.Contains(r.Raw, "Ayşe") {
			sawName = true
		}
	}
	if !sawPeer || !sawSkel6 || sawName {
		t.Errorf("peer=%v skel6=%v adHam=%v", sawPeer, sawSkel6, sawName)
	}
	if !d.Firewall.Simulated || len(d.Firewall.Counters) == 0 {
		t.Errorf("dry-run'da benzetilmiş sayaçlar: %v", d.Firewall.Counters)
	}
	for k := range d.Firewall.Counters {
		if !keys[k] {
			t.Errorf("sayaç anahtarı bir kurala ait değil: %q", k)
		}
	}
	// Sayaç ucu: aynı anahtarlar, zamanla artmayan değer yok.
	rec = rqH(h, "GET", "/api/server/counters", nil, c, nil)
	var ctr map[string][2]uint64
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &ctr) != nil || len(ctr) != len(d.Firewall.Counters) {
		t.Fatalf("counters: %d %s", rec.Code, rec.Body)
	}
	if rec := rqH(h, "GET", "/api/server/counters", nil, nil, nil); rec.Code != 401 {
		t.Errorf("oturumsuz sayaç: %d", rec.Code)
	}
	later := simulatedCounters(rules, time.Now().Add(time.Hour))
	for k, v := range ctr {
		if later[k][0] < v[0] {
			t.Errorf("benzetilmiş sayaç geri gitti: %s", k)
		}
	}
}

// Sayaç önbelleği iptables okunurken kilidi tutmaz: yenileme sürerken gelen istek eski veriyi hemen alır,
// aynı anda gelen ilk istekler tek okuma yapar, takılan okuma süre bütçesinde kesilir.
func TestCounterCacheDoesNotBlock(t *testing.T) {
	a := testApp(t)
	release := make(chan struct{})
	var calls atomic.Int32
	a.ctrs.load = func() map[string][2]uint64 {
		calls.Add(1)
		<-release // takılmış iptables
		return map[string][2]uint64{"k": {2, 20}}
	}
	// İlk istekler: veri yok, tek okuma yapılır, hepsi onu bekler.
	var wg sync.WaitGroup
	got := make([]map[string][2]uint64, 5)
	for i := range got {
		wg.Add(1)
		go func() { defer wg.Done(); got[i] = a.ruleCounters(a.srv, nil, nil) }()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("eşzamanlı ilk istekler tek okuma yapmalı, %d okuma", n)
	}
	for i, g := range got {
		if g["k"] != [2]uint64{2, 20} {
			t.Errorf("istek %d: %v", i, g)
		}
	}
	// Önbellek eskiyince yenileme takılsa da başka istek eski veriyi bekletmeden alır.
	a.ctrs.mu.Lock()
	a.ctrs.at = time.Now().Add(-time.Minute)
	a.ctrs.mu.Unlock()
	stuck := make(chan struct{})
	a.ctrs.load = func() map[string][2]uint64 { <-stuck; return map[string][2]uint64{"k": {3, 30}} }
	go a.ruleCounters(a.srv, nil, nil)
	time.Sleep(50 * time.Millisecond)
	done := make(chan map[string][2]uint64)
	go func() { done <- a.ruleCounters(a.srv, nil, nil) }()
	select {
	case d := <-done:
		if d["k"] != [2]uint64{2, 20} {
			t.Errorf("eski veri beklenirdi: %v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("yenileme sürerken istek bekledi (kilit tutuluyor)")
	}
	close(stuck)
	time.Sleep(50 * time.Millisecond)
	if d := a.ruleCounters(a.srv, nil, nil); d["k"] != [2]uint64{3, 30} {
		t.Errorf("yenileme bitince yeni veri: %v", d)
	}
	// Okuma paniklese de bekleyen kalmaz, bir sonraki istek yeniden dener.
	a.ctrs.mu.Lock()
	a.ctrs.at, a.ctrs.data = time.Time{}, nil
	a.ctrs.mu.Unlock()
	a.ctrs.load = func() map[string][2]uint64 { panic("iptables") }
	func() {
		defer func() { _ = recover() }()
		a.ruleCounters(a.srv, nil, nil)
	}()
	a.ctrs.load = func() map[string][2]uint64 { return map[string][2]uint64{"k": {4, 40}} }
	if d := a.ruleCounters(a.srv, nil, nil); d["k"] != [2]uint64{4, 40} {
		t.Errorf("panik sonrası: %v", d)
	}
}

// Süre bütçesi geçince kalan zincirler okunmaz.
func TestReadRuleCountersDeadline(t *testing.T) {
	n := 0
	slow := func(string, ...string) ([]byte, error) {
		n++
		time.Sleep(30 * time.Millisecond)
		return []byte(sampleCounters4), nil
	}
	readRuleCounters(slow, "ipv4", time.Now().Add(70*time.Millisecond))
	if n >= len(counterChains) || n < 1 {
		t.Errorf("bütçe aşılınca okuma durmalı: %d/%d zincir okundu", n, len(counterChains))
	}
}
