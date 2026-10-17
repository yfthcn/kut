package main

import (
	"context"
	"fmt"
	"log"
	"maps"
	"slices"
	"time"
)

const monitorEvery = 15 * time.Second

// monitor: dondurma süresi dolan peer'ları geri açar, son görülme bilgisini saklar,
// trafik geçmişini kaydeder ve güvenlik duvarını eşitler.
func (a *App) monitor(ctx context.Context) {
	t := time.NewTicker(monitorEvery)
	defer t.Stop()
	safely("monitor", a.tick) // ilk örnek hemen
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			safely("monitor", a.tick)
		}
	}
}

// fwNeedsRepair: izleyicinin güvenlik duvarını yeniden yazması gereken durumlar. İskelet ya da zincir kaybı
// (no-jump) da onarılır; yalnızca ip6tables yokken denenmez, çünkü onarım da aynı nedenle başarısız olur.
func fwNeedsRepair(st fwState) bool {
	return st.State == "out-of-sync" || (st.State == "no-jump" && st.Key != errNoIP6Tables)
}

func (a *App) tick() {
	a.mu.Lock()
	snapshot := slices.Clone(a.peers)
	a.mu.Unlock()
	stats, _ := a.wgDump(snapshot) // kilit dışında: wg komutu çalıştırır
	if !a.dry {
		a.watchOffline(snapshot, time.Now())
	}
	a.maintTick(time.Now())

	var rx, tx uint64
	for _, st := range stats {
		rx += st.Rx
		tx += st.Tx
	}
	nowU := time.Now().Unix()
	a.hist.add(sample{T: nowU, Rx: rx, Tx: tx})
	keep := make(map[string]bool, len(snapshot))
	for _, p := range snapshot {
		keep[p.PublicKey] = true
		if st, ok := stats[p.PublicKey]; ok {
			a.phist.add(p.PublicKey, sample{T: nowU, Rx: st.Rx, Tx: st.Tx})
		}
	}
	a.phist.prune(keep)
	a.maybeAutoCheck()
	if !a.dry {
		if c := readInetCounters(a.v6Live.Load()); c != nil {
			a.inet.observe(c, time.Now())
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.getSrv()
	now := time.Now()
	next := slices.Clone(a.peers)
	changed, needApply := false, false
	var unfrozen, expiredNow []string
	type flip struct {
		name string
		on   bool
	}
	type ruleFlip struct {
		policy, rule string
		on           bool
	}
	var flips []flip
	prevWas := make(map[string]bool, len(a.schedWas))
	maps.Copy(prevWas, a.schedWas)
	for i := range next {
		p := &next[i]
		if p.FrozenUntil != nil && !now.Before(*p.FrozenUntil) {
			p.FrozenUntil = nil // süre doldu: peer sunucuya geri eklenecek
			changed, needApply = true, true
			unfrozen = append(unfrozen, p.Name)
		}
		if p.Schedule != nil {
			cur := p.inWindow(now)
			if was, ok := a.schedWas[p.ID]; ok && was != cur {
				changed, needApply = true, true
				flips = append(flips, flip{p.Name, cur})
			}
			if a.schedWas == nil {
				a.schedWas = map[string]bool{}
			}
			a.schedWas[p.ID] = cur
		} else {
			delete(a.schedWas, p.ID)
		}
		if p.Enabled && p.expired(now) {
			p.Enabled = false // misafir süresi doldu: peer sunucudan kalkar
			p.FrozenUntil = nil
			changed, needApply = true, true
			expiredNow = append(expiredNow, p.Name)
		}
		if a.dry {
			continue // sahte dry-run verisini saklama
		}
		if st, ok := stats[p.PublicKey]; ok && st.Handshake > 0 {
			// Her el sıkışmada yazmamak için: en az 5 dk ilerleme ya da uç nokta değişimi
			if p.LastSeen == 0 {
				a.logEventT("sistem", "peer_first", "log.peer_first", map[string]any{"name": p.Name})
			}
			if st.Handshake-p.LastSeen >= 300 || (st.Endpoint != "" && st.Endpoint != p.LastEndpoint) {
				p.LastSeen = st.Handshake
				if st.Endpoint != "" {
					p.LastEndpoint = st.Endpoint
				}
				changed = true
			}
		}
	}
	// Silinen cihazların zamanlama durumu birikmesin: yalnızca listede kalan kimlikler tutulur.
	alive := make(map[string]bool, len(next))
	for _, p := range next {
		alive[p.ID] = true
	}
	for id := range a.schedWas {
		if !alive[id] {
			delete(a.schedWas, id)
		}
	}
	// Kural bazlı zaman aralıkları: bir kuralın penceresi açıldı/kapandıysa güvenlik duvarı yeniden yazılır.
	ruleNow := map[string]bool{}
	var ruleFlips []ruleFlip
	for _, pol := range a.pol {
		for i, r := range pol.Rules {
			if r.Schedule == nil {
				continue
			}
			k := fmt.Sprintf("%s#%d", pol.ID, i)
			cur := r.Schedule.allows(now)
			ruleNow[k] = cur
			if was, ok := a.ruleWas[k]; ok && was != cur {
				ruleFlips = append(ruleFlips, ruleFlip{pol.Name, r.textIn(a.srvLang()), cur})
			}
		}
	}
	prevRule := a.ruleWas
	a.ruleWas = ruleNow
	if len(ruleFlips) > 0 {
		changed, needApply = true, true
	}
	if changed {
		if needApply {
			if err := a.apply(next); err != nil {
				log.Printf("zamanlı değişiklik uygulanamadı: %v", err)
				a.schedWas = prevWas // sonraki turda yeniden denensin
				a.ruleWas = prevRule
				return // eski durum korunur, sonraki turda yeniden denenir
			}
			schedKey := map[bool]string{true: "log.schedule.start", false: "log.schedule.end"}
			ruleKey := map[bool]string{true: "log.rule_schedule.start", false: "log.rule_schedule.end"}
			for _, n := range unfrozen {
				a.logEventT("sistem", "unfreeze_auto", "log.unfreeze_auto", map[string]any{"name": n})
			}
			for _, f := range flips {
				a.logEventT("sistem", "schedule", schedKey[f.on], map[string]any{"name": f.name})
			}
			for _, f := range ruleFlips {
				a.logEventT("sistem", "rule_schedule", ruleKey[f.on], map[string]any{"policy": f.policy, "rule": f.rule})
			}
			for _, n := range expiredNow {
				a.logEventT("sistem", "peer_expired", "log.peer_expired", map[string]any{"name": n})
			}
		}
		a.peers = next
		if err := a.savePeers(next); err != nil {
			log.Printf("peers.json yazılamadı: %v", err)
		}
		return
	}
	// Değişiklik yoksa güvenlik duvarının yerinde olduğunu doğrula; kayıpsa (ör. kurallar silindiyse) geri yaz.
	if !a.dry && fwNeedsRepair(a.fwCheck(s, a.peers, a.pol)) {
		if err := a.syncFirewall(s, a.peers, a.pol); err != nil {
			log.Printf("güvenlik duvarı eşitlenemedi: %v", err)
		} else {
			a.logEventT("sistem", "firewall", "log.firewall.repaired", nil)
		}
	}
}
