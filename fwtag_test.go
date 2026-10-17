package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// tagFixture: adında boşluk ve Türkçe harf olan cihazlar ve profiller; her kural türü en az bir kez üretilir.
func tagFixture(t *testing.T) (Server, []Peer, []Policy) {
	t.Helper()
	s := v6Server(t)
	c := s.cfg()
	c.BlockPrivate = true
	s.Settings = &c
	peers := []Peer{
		{ID: "a1", Name: "Ayşe'nin Telefonu", IP: "10.77.0.2", Enabled: true, Internet: true, Policy: "p1"},
		{ID: "b2", Name: "Çağrı İş Bilgisayarı", IP: "10.77.0.3", Enabled: true, Policy: "p2"},
		{ID: "c3", Name: "ğüşıöç ÖÇŞİĞÜ", IP: "10.77.0.4", Enabled: true},
	}
	pols := []Policy{
		{ID: "p1", Name: "Yönetici Profili", Rules: []Rule{
			{Target: "server", Proto: "tcp", Ports: "22,8000-8100"},
			{Target: "all", Proto: "any"},
			{Target: "device", Device: "c3", Proto: "tcp", Ports: "443", Both: true},
		}},
		{ID: "p2", Name: "Misafir Ağı", Rules: []Rule{
			{Target: "device", Device: "a1", Proto: "icmp"},
			{Target: "server", Proto: "udp", Ports: "53"},
		}},
	}
	return s, peers, pols
}

func allSets(t *testing.T) map[string]fwSet {
	s, peers, pols := tagFixture(t)
	return map[string]fwSet{
		"v4": desiredFirewall(s, peers, pols, 5000, time.Now()),
		"v6": desiredFirewall6(s, peers, pols, time.Now(), true),
	}
}

func chainsOf(f fwSet) map[string][][]string {
	return map[string][][]string{chainPeers: f.Peers, chainIn: f.In, chainInet: f.Inet, chainICMP: f.ICMP, chainNat: f.Nat}
}

// Her kural etiketlidir; etiket ASCII, boşluksuz, en çok 200 karakter, zincirinde tek ve ad içermez.
func TestRuleTagsSafeAndUnique(t *testing.T) {
	_, peers, pols := tagFixture(t)
	var names []string
	for _, p := range peers {
		names = append(names, p.Name, strings.Fields(p.Name)[0])
	}
	for _, p := range pols {
		names = append(names, p.Name, strings.Fields(p.Name)[0])
	}
	check := func(where, tag string) {
		if !strings.HasPrefix(tag, "kut:") || len(tag) > maxTagLen {
			t.Errorf("%s: etiket biçimi: %q", where, tag)
		}
		for _, r := range tag {
			if r > 0x7e || r <= ' ' || r == '"' || r == '\'' {
				t.Errorf("%s: etikette ASCII dışı ya da boşluk/tırnak: %q", where, tag)
			}
		}
		for _, n := range names {
			if strings.Contains(tag, n) {
				t.Errorf("%s: etikette ad var (%q): %q", where, n, tag)
			}
		}
	}
	for fam, f := range allSets(t) {
		total := 0
		for chain, rules := range chainsOf(f) {
			seen := map[string]bool{}
			for _, r := range rules {
				tag := ruleTag(r)
				if tag == "" {
					t.Errorf("%s %s: etiketsiz kural: %q", fam, chain, r)
					continue
				}
				check(fam+" "+chain, tag)
				if seen[tag] {
					t.Errorf("%s %s: etiket tekrarı: %q", fam, chain, tag)
				}
				seen[tag] = true
			}
			total += len(rules)
		}
		if len(f.Info) != total {
			t.Errorf("%s: Info %d kural, zincirlerde %d", fam, len(f.Info), total)
		}
		for _, in := range f.Info {
			if in.Tag != ruleTag(in.args) || in.Action != in.args[len(in.args)-1] || in.Chain != in.args[1] {
				t.Errorf("%s: Info kuralla uyuşmuyor: %+v", fam, in)
			}
		}
	}
	s, _, _ := tagFixture(t)
	for _, sub := range []string{s.prefix().String(), s.prefix6().String()} {
		seen := map[string]bool{}
		for _, r := range skeleton("wg0", sub) {
			tag := ruleTag(r.args)
			check("iskelet", tag)
			if seen[r.chain+tag] {
				t.Errorf("iskelet etiketi tekrarı: %s %s", r.chain, tag)
			}
			seen[r.chain+tag] = true
			for _, c := range tag { // wg-quick kancaları bash ile çalışır: kabuk özel karakteri olmamalı
				if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != ':' && c != '-' {
					t.Errorf("iskelet etiketinde kabuk açısından güvensiz karakter: %q", tag)
				}
			}
		}
	}
}

// Etiket biçimi: tür ve ayrıntı IP, profil kimliği ve kural sırasıyla.
func TestRuleTagFormat(t *testing.T) {
	f := allSets(t)["v4"]
	var tags []string
	for _, rules := range chainsOf(f) {
		for _, r := range rules {
			tags = append(tags, ruleTag(r))
		}
	}
	all := strings.Join(tags, "\n")
	for _, w := range []string{
		"kut:in:est-reply", "kut:in:icmp-related", "kut:in:ping",
		"kut:panel:10.77.0.4",
		"kut:srv:10.77.0.2:tcp/22:prof=p1:r1", "kut:srv:10.77.0.2:tcp/8000:8100:prof=p1:r1", "kut:srv:10.77.0.3:udp/53:prof=p2:r2",
		"kut:in-drop:10.77.0.2", "kut:in-drop:10.77.0.3",
		"kut:peer:10.77.0.2>all:any:prof=p1:r2",
		"kut:peer:10.77.0.2>10.77.0.4:tcp/443:prof=p1:r3", "kut:peer:10.77.0.4>10.77.0.2:tcp/443:prof=p1:r3:rev",
		"kut:peer:10.77.0.3>10.77.0.2:icmp:prof=p2:r1",
		"kut:icmp-orig:10.77.0.2", "kut:icmp-repl:10.77.0.2", "kut:icmp:drop",
		"kut:inet-deny:10.77.0.2:10.0.0.0/8", "kut:inet:10.77.0.2", "kut:nat:10.77.0.2",
	} {
		if !strings.Contains("\n"+all+"\n", "\n"+w+"\n") {
			t.Errorf("etiket yok: %s\n%s", w, all)
		}
	}
}

// `iptables -S` yorumu çift tırnakla yazar; ruleLines/normTokens tırnağı soyar, kural üretilenle birebir eşleşir.
// Aksi hâlde verifyChainsF her 15 sn'de "uyumsuz" der ve kuralları yeniden yazardı.
func TestTaggedRulesRoundTrip(t *testing.T) {
	for fam, f := range allSets(t) {
		for chain, rules := range chainsOf(f) {
			var out strings.Builder
			out.WriteString("-N " + chain + "\n")
			for _, r := range rules {
				out.WriteString(sLine(chain, r[2:]) + "\n")
			}
			if !strings.Contains(out.String(), `--comment "kut:`) {
				t.Fatalf("%s %s: sınama çıktısı tırnaklı olmalı", fam, chain)
			}
			got := ruleLines([]byte(out.String()), chain)
			if len(got) != len(rules) {
				t.Fatalf("%s %s: %d satır, beklenen %d", fam, chain, len(got), len(rules))
			}
			for i := range rules {
				if !tokEq(got[i], normTokens(rules[i][2:])) {
					t.Errorf("%s %s %d: %q != %q", fam, chain, i, got[i], rules[i][2:])
				}
			}
			fake := fakeChains(map[string][]string{chain: strings.Split(strings.TrimSpace(out.String()), "\n")})
			if st := verifyChainsF(func(table string, args ...string) ([]byte, error) {
				if args[1] != chain {
					return chainOut(chainsOf(f)[args[1]], args[1]), nil
				}
				return fake(table, args...)
			}, f, fam); st.State != "ok" {
				t.Errorf("%s %s: doğrulama: %+v", fam, chain, st)
			}
		}
	}
	// Tırnaksız -S çıktısı (eski iptables) da aynı kurala eşlenir.
	if !tokEq(normTokens(strings.Fields(`-s 10.77.0.2/32 -m comment --comment kut:inet:10.77.0.2 -j ACCEPT`)), normTokens(strings.Fields(`-s 10.77.0.2/32 -m comment --comment "kut:inet:10.77.0.2" -j ACCEPT`))) {
		t.Error("tırnaklı ve tırnaksız yorum aynı sayılmalı")
	}
}

func chainOut(rules [][]string, chain string) []byte {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(sLine(chain, r[2:]) + "\n")
	}
	return []byte(b.String())
}

func TestUniqueTag(t *testing.T) {
	seen := map[string]bool{}
	if a, b := uniqueTag(seen, "C", "kut:x"), uniqueTag(seen, "C", "kut:x"); a != "kut:x" || b != "kut:x:2" {
		t.Errorf("tekrar: %q %q", a, b)
	}
	if a := uniqueTag(seen, "D", "kut:x"); a != "kut:x" {
		t.Errorf("başka zincirde aynı etiket serbest: %q", a)
	}
	long := "kut:" + strings.Repeat("a", 300)
	l1, l2 := uniqueTag(seen, "C", long), uniqueTag(seen, "C", long)
	if len(l1) > maxTagLen || len(l2) > maxTagLen || l1 == l2 {
		t.Errorf("uzun etiket: %d %d eşit=%v", len(l1), len(l2), l1 == l2)
	}
	if g := uniqueTag(seen, "C", "kut:ş ğ\"x"); g != "kut:___x" && !strings.HasPrefix(g, "kut:") {
		t.Errorf("güvensiz karakter: %q", g)
	}
	if g := tagSafe("kut:ş ğ\"x"); strings.ContainsAny(g, " \"şğ") {
		t.Errorf("tagSafe: %q", g)
	}
	if r := withTag([]string{"-s", "1.2.3.4/32", "-j", "ACCEPT"}, "kut:t"); strings.Join(r, " ") != "-s 1.2.3.4/32 -m comment --comment kut:t -j ACCEPT" {
		t.Errorf("withTag: %q", r)
	}
	if r := stripTag(withTag([]string{"-o", "wg0", "-j", "DROP"}, "kut:t")); strings.Join(r, " ") != "-o wg0 -j DROP" {
		t.Errorf("stripTag: %q", r)
	}
}

// simIpt: -S/-C/-I/-D/-N işlemlerini bellekte uygulayan sahte iptables; her değişiklikten sonra check çağrılır.
type simIpt struct {
	chains map[string][]string // "tablo zincir" -> kurallar (jetonlar boşlukla)
	check  func(op string)
}

func (s *simIpt) fn(table string, args ...string) ([]byte, error) {
	key := table + " " + args[0+1]
	spec := strings.Join(args[2:], " ")
	switch args[0] {
	case "-N":
		if _, ok := s.chains[key]; ok {
			return nil, errors.New("exists")
		}
		s.chains[key] = nil
	case "-S":
		var b strings.Builder
		for _, r := range s.chains[key] {
			fmt.Fprintf(&b, "-A %s %s\n", args[1], r)
		}
		return []byte(b.String()), nil
	case "-C":
		if !slices.Contains(s.chains[key], spec) {
			return nil, errors.New("Bad rule")
		}
	case "-I":
		s.chains[key] = slices.Insert(s.chains[key], 0, strings.Join(args[3:], " "))
		s.check("-I " + key)
	case "-D":
		l := s.chains[key]
		if n, err := strconv.Atoi(spec); err == nil && len(args) == 3 {
			s.chains[key] = slices.Delete(l, n-1, n)
		} else if i := slices.Index(l, spec); i >= 0 {
			s.chains[key] = slices.Delete(l, i, i+1)
		} else {
			return nil, errors.New("Bad rule")
		}
		s.check("-D " + key)
	}
	return nil, nil
}

// v0.14 → v0.15 iskelet geçişi hiçbir adımda bir atlamayı (ya da DROP'u) eksiltmez: her an her iskelet kuralının
// etiketli ya da etiketsiz bir kopyası zincirde durur. Sonunda yalnızca etiketli kopyalar, tam birer tane kalır.
func TestSkeletonMigrationNeverLeavesGap(t *testing.T) {
	for _, fam := range []struct {
		sub string
		v6  bool
	}{{"10.77.0.0/24", false}, {"fdaa:bbbb:cccc::/64", true}} {
		sk := skeleton("wg0", fam.sub)
		sim := &simIpt{chains: map[string][]string{}}
		for _, c := range append(slices.Clone(filterChains), "FORWARD", "INPUT") {
			sim.chains["filter "+c] = nil
		}
		sim.chains["nat "+chainNat] = nil
		sim.chains["nat POSTROUTING"] = []string{"-s 172.17.0.0/16 ! -o docker0 -j MASQUERADE"} // yabancı kural
		for _, r := range sk {
			k := r.table + " " + r.chain
			sim.chains[k] = append(sim.chains[k], strings.Join(stripTag(r.args), " "))
		}
		sim.chains["filter FORWARD"] = append(sim.chains["filter FORWARD"], "-j DOCKER-USER")
		ops := 0
		sim.check = func(op string) {
			ops++
			for _, r := range sk {
				l := sim.chains[r.table+" "+r.chain]
				if !slices.Contains(l, strings.Join(r.args, " ")) && !slices.Contains(l, strings.Join(stripTag(r.args), " ")) {
					t.Errorf("v6=%v: %s sonrası boşluk: %q yok\n%q", fam.v6, op, ruleTag(r.args), l)
				}
			}
		}
		if err := ensureSkeletonF(sim.fn, sk); err != nil {
			t.Fatal(err)
		}
		cleanupStaleSkelF(sim.fn, sk, "wg0", fam.v6)
		if ops == 0 {
			t.Fatal("geçiş hiçbir şey değiştirmedi")
		}
		for _, g := range []struct{ table, chain string }{{"filter", "FORWARD"}, {"filter", "INPUT"}, {"nat", "POSTROUTING"}} {
			var want []string
			for _, r := range skelGroup(sk, g.table, g.chain) {
				want = append(want, strings.Join(r, " "))
			}
			got := sim.chains[g.table+" "+g.chain]
			if !slices.Equal(got[:len(want)], want) {
				t.Errorf("v6=%v %s: üstte etiketli iskelet olmalı:\n%q", fam.v6, g.chain, got)
			}
			for _, r := range got[len(want):] {
				if strings.Contains(r, "wg0") || strings.Contains(r, "KUT-") {
					t.Errorf("v6=%v %s: eski iskelet kopyası kaldı: %q", fam.v6, g.chain, r)
				}
			}
		}
		if !slices.Contains(sim.chains["filter FORWARD"], "-j DOCKER-USER") || !slices.Contains(sim.chains["nat POSTROUTING"], "-s 172.17.0.0/16 ! -o docker0 -j MASQUERADE") {
			t.Errorf("v6=%v: yabancı kurallar silinmemeli", fam.v6)
		}
	}
}

// PostDown, PostUp'ın kurduğu her nesneyi (iskelet kuralı, zincir; IPv4 ve açıksa IPv6) kaldırır ve her komut
// "yok" hatasına dayanıklıdır (|| true): arayüz kapanırken bir eksik kural kalan temizliği durdurmaz.
func TestPostDownCoversPostUp(t *testing.T) {
	for name, s := range map[string]Server{"v4": testApp(t).srv, "v6": v6Server(t)} {
		conf := renderServerConf(s, nil)
		var up, down []string
		for ln := range strings.SplitSeq(conf, "\n") {
			if v, ok := strings.CutPrefix(ln, "PostUp = "); ok {
				up = append(up, v)
			} else if v, ok := strings.CutPrefix(ln, "PostDown = "); ok {
				down = append(down, v)
			}
		}
		for _, d := range down {
			if !strings.HasSuffix(d, "|| true") {
				t.Errorf("%s: PostDown hataya dayanıksız: %q", name, d)
			}
		}
		has := func(w string) bool {
			return slices.ContainsFunc(down, func(d string) bool { return strings.HasPrefix(d, w+" ") || d == w })
		}
		objects := 0
		for _, u := range up {
			f := strings.Fields(u)
			if len(f) < 4 || (f[0] != "iptables" && f[0] != "ip6tables") {
				continue // sysctl satırları nesne kurmaz
			}
			bin, rest := f[0], strings.Join(f[3:], " ")
			tbl := ""
			if strings.HasPrefix(rest, "-t nat ") {
				tbl, rest = "-t nat ", strings.TrimPrefix(rest, "-t nat ")
			}
			switch {
			case strings.HasPrefix(rest, "-N "):
				c := strings.Fields(rest)[1]
				for _, op := range []string{"-F", "-X"} {
					if !has(bin + " -w 5 " + tbl + op + " " + c + " 2>/dev/null") {
						t.Errorf("%s: %s %s%s %s için PostDown yok", name, bin, tbl, op, c)
					}
				}
				objects++
			case strings.HasPrefix(rest, "-C "):
				// "-C ZİNCİR kural 2>/dev/null || ... -I ZİNCİR 1 kural": kural -D ile kaldırılmalı.
				spec := strings.TrimPrefix(strings.SplitN(rest, " 2>/dev/null", 2)[0], "-C ")
				if !has(bin + " -w 5 " + tbl + "-D " + spec + " 2>/dev/null") {
					t.Errorf("%s: %q için PostDown -D yok", name, spec)
				}
				// v0.14'ün etiketsiz kopyası da kaldırılır (panel geçişi yapmadan arayüz kapanırsa).
				if old := untag(spec); !has(bin + " -w 5 " + tbl + "-D " + old + " 2>/dev/null") {
					t.Errorf("%s: %q (etiketsiz) için PostDown -D yok", name, old)
				}
				objects++
			default:
				t.Errorf("%s: tanınmayan PostUp: %q", name, u)
			}
		}
		want := len(filterChains) + 1 + len(skeleton("wg0", "x"))
		if name == "v6" {
			want *= 2
		}
		if objects != want {
			t.Errorf("%s: PostUp %d nesne kurdu, beklenen %d", name, objects, want)
		}
	}
}
