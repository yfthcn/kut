package main

import (
	"bufio"
	"bytes"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Internet çıkışı kullanım ölçümü: KUT-INET'te her cihaz için "-s <ip> -j ACCEPT" kuralı vardır ve yalnızca
// internete giden paketleri sayar (özel ağlara giden paketler önceki DROP kurallarında kalır).
// Sayaç artıyorsa cihaz sunucu üzerinden internete trafik gönderiyor demektir.

type inetCounter struct {
	Packets uint64
	Bytes   uint64
}

type inetUsage struct {
	Bytes uint64 // panel açıldığından beri tünelden internete giden bayt
	Last  int64  // son trafik görülen an (unix); 0 = hiç
}

type inetTracker struct {
	mu   sync.Mutex
	prev map[string]inetCounter
	use  map[string]inetUsage
}

// parseInetCounters: `iptables -nvxL KUT-INET` çıktısından ACCEPT kurallarının sayaçlarını okur.
func parseInetCounters(out []byte) map[string]inetCounter { return parseInetCountersFam(out, false) }

// parseInetCountersFam: kaynak sütunu başlık satırından ("pkts bytes target prot opt in out source ...") bulunur.
// ip6tables'ın "opt" sütunu sürüme göre vardır ya da yoktur (v1.8.11 nf_tables yazar, eskiler yazmaz); başlık
// yoksa eski varsayım kullanılır: IPv4'te kaynak 7., IPv6'da 6. alan.
func parseInetCountersFam(out []byte, v6 bool) map[string]inetCounter {
	res := map[string]inetCounter{}
	si := 7
	if v6 {
		si = 6
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) > 0 && f[0] == "pkts" {
			if i := slices.Index(f, "source"); i > 0 {
				si = i
			}
			continue
		}
		if len(f) < si+2 || f[2] != "ACCEPT" {
			continue
		}
		pk, err1 := strconv.ParseUint(f[0], 10, 64)
		by, err2 := strconv.ParseUint(f[1], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		src := strings.TrimSuffix(strings.TrimSuffix(f[si], "/32"), "/128")
		if src == "0.0.0.0/0" || src == "::/0" || src == "anywhere" {
			continue
		}
		res[src] = inetCounter{pk, by}
	}
	return res
}

func readInetCounters(v6 bool) map[string]inetCounter {
	out, err := ipt("filter", "-n", "-v", "-x", "-L", chainInet)
	if err != nil {
		return nil
	}
	res := parseInetCounters(out)
	// IPv6 sayaçları (zincir yoksa/IPv6 kapalıysa sessizce geçilir); anahtar IPv6 adresidir.
	if v6 {
		if out6, err := ipt6("filter", "-n", "-v", "-x", "-L", chainInet); err == nil {
			maps.Copy(res, parseInetCountersFam(out6, true))
		}
	}
	return res
}

// observe: yeni sayaç okumasını işler. Zincir yeniden yazılınca sayaçlar sıfırlanır; düşüş "sıfırlandı" demektir.
func (t *inetTracker) observe(cur map[string]inetCounter, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.prev == nil {
		t.prev = map[string]inetCounter{}
		t.use = map[string]inetUsage{}
	}
	for ip, c := range cur {
		p, seen := t.prev[ip]
		var dPk, dBy uint64
		switch {
		case !seen:
			// ilk okuma: sayaç zaten bir şey gösteriyorsa trafik var demek, ama ne zaman olduğunu bilmiyoruz
			dPk, dBy = c.Packets, c.Bytes
		case c.Packets >= p.Packets:
			dPk, dBy = c.Packets-p.Packets, c.Bytes-p.Bytes
		default: // sıfırlandı
			dPk, dBy = c.Packets, c.Bytes
		}
		u := t.use[ip]
		if dPk > 0 {
			u.Bytes += dBy
			u.Last = now.Unix()
		}
		t.use[ip] = u
		t.prev[ip] = c
	}
	for ip := range t.prev {
		if _, ok := cur[ip]; !ok {
			delete(t.prev, ip) // kural kalktı (izin kapatıldı ya da cihaz silindi)
		}
	}
}

func (t *inetTracker) get(ip string) inetUsage {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.use[ip]
}
