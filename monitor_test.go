package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// İzleyici yalnızca içerik farkını değil, iskelet/zincir kaybını da onarmalı; ip6tables yoksa onarım
// zaten başarısız olacağı için denenmez.
func TestFwNeedsRepair(t *testing.T) {
	for _, c := range []struct {
		st   fwState
		want bool
	}{
		{fwState{State: "ok"}, false},
		{fwState{State: "dry"}, false},
		{fwState{State: "down", Key: "fw.down", Detail: "The WireGuard interface is down"}, false},
		{fwState{State: "out-of-sync", Key: "fw.chain.count", Detail: "IPv4 KUT-PEERS chain has 1 rule, expected 2"}, true},
		{fwState{State: "no-jump", Key: "fw.skeleton.top", Detail: "IPv4 firewall skeleton is missing or out of order (the FORWARD chain does not start with Kut's rules). The panel repairs it within a few seconds."}, true},
		{fwState{State: "no-jump", Key: "fw.chain.read_failed", Detail: "IPv4 KUT-PEERS could not be read"}, true},
		{fwState{State: "no-jump", Key: "fw.chain.read_failed", Detail: "IPv6 KUT-IN could not be read"}, true},
		// Karar metne değil anahtara bağlı: Detail hangi dilde olursa olsun ip6tables yokken onarım denenmez.
		{fwState{State: "no-jump", Key: errNoIP6Tables, Detail: "ip6tables not found"}, false},
	} {
		if got := fwNeedsRepair(c.st); got != c.want {
			t.Errorf("fwNeedsRepair(%+v) = %v, beklenen %v", c.st, got, c.want)
		}
	}
}

// fakeWG: PATH'in başına yalnızca `wg show <iface> dump` yanıtlayan bir wg koyar; diğer her çağrı
// (ör. `wg show wg0 public-key`) başarısız olur, yani arayüz kapalı görünür ve hiçbir şey uygulanmaz.
func fakeWG(t *testing.T, dumpPeers string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nif [ \"$1\" = show ] && [ \"$3\" = dump ]; then\nprintf 'priv\\tpub\\t51820\\toff\\n'\nprintf '%s'\nexit 0\nfi\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "wg"), fmt.Appendf(nil, script, dumpPeers), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Kural penceresi, yalnızca "son görülme" güncellenen bir turda değişirse de aynı turda uygulanmalı
// (eskiden peer değişikliği varsa kural geçişi atlanıyor, olay da yazılmıyordu).
func TestTickAppliesRuleFlipWithLastSeenUpdate(t *testing.T) {
	now := time.Now()
	fakeWG(t, fmt.Sprintf("KEY\\t(none)\\t198.51.100.7:4000\\t10.77.0.2/32\\t%d\\t10\\t20\\t0\\n", now.Unix()))
	a := testApp(t)
	a.dry = false
	a.act = &activity{}
	a.peers = []Peer{{ID: "1", Name: "ali", PublicKey: "KEY", PSK: "P", IP: "10.77.0.2", Enabled: true, Policy: "p"}}
	sch := &Schedule{Days: []int{0, 1, 2, 3, 4, 5, 6}, From: now.Add(-2 * time.Hour).Format("15:04"), To: now.Add(2 * time.Hour).Format("15:04"), Scope: "tunnel"}
	a.pol = []Policy{{ID: "p", Name: "Ev", Rules: []Rule{{Target: "server", Proto: "tcp", Ports: "22", Schedule: sch}}}}
	if !sch.allows(now) {
		t.Fatal("test kurgusu: pencere şu anı içermeli")
	}
	a.ruleWas = map[string]bool{"p#0": false} // önceki turda kapalıydı → bu tur açılıyor
	a.tick()
	if a.peers[0].LastSeen == 0 {
		t.Fatal("test kurgusu: sahte wg dökümü son görülmeyi güncellemeliydi")
	}
	var kinds []string
	for _, e := range a.act.list(100) {
		kinds = append(kinds, e.Kind)
	}
	if !strings.Contains(strings.Join(kinds, ","), "rule_schedule") {
		t.Fatalf("kural zamanı aynı turda uygulanmalıydı; olaylar: %v", kinds)
	}
	// olaylar katalog anahtarıyla (sözleşme 4)
	codes := map[string]Event{}
	for _, e := range a.act.list(100) {
		codes[e.Code] = e
	}
	if e, ok := codes["log.rule_schedule.start"]; !ok || e.Params["policy"] != "Ev" || e.Text == e.Code {
		t.Errorf("kural olayı kodu: %+v", codes)
	}
	if e, ok := codes["log.peer_first"]; !ok || e.Params["name"] != "ali" {
		t.Errorf("ilk bağlantı olayı kodu: %+v", codes)
	}
	if _, err := os.Stat(a.srv.ConfPath); err != nil {
		t.Errorf("uygulama yapılandırmayı yazmalıydı: %v", err)
	}
}

// Süreç içi sızıntı: 5000 cihazlık ekle/değiştir/sil turları + izleyici turu + bildirim olayları. Isınma
// sonrası ilk ölçüme göre HeapInuse iki katını geçmemeli; silinen cihazlara bağlı haritalar boşalmalı.
func TestNoLeakUnderDeviceChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("uzun test: -short'ta atlanır")
	}
	const N, perRound = 5000, 300
	a := testApp(t)
	a.act = &activity{}
	a.hist, a.phist, a.lim = &history{}, &peerHistory{}, newLimiter()
	a.mt = newMaint("")
	a.mt.update(func(c *MaintCfg) { c.Backup.Enabled = false })
	// günlük tavanına kadar doldur: sınırlı günlüğün dolması büyüme sayılmasın
	for range actCap {
		a.act.add(Event{T: 1, Kind: "x", Text: "dolgu"})
	}
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body) }))
	defer sink.Close()
	retryDelays = []time.Duration{0}
	a.nf = newNotifier("")
	nc := defaultNotify()
	nc.Webhook.Enabled, nc.Webhook.URL = true, sink.URL
	a.nf.set(nc)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go a.nf.run(ctx)
	a.act.onAdd = a.nf.onEvent

	now := time.Now()
	today := int(now.Weekday())
	away := &Schedule{Days: []int{(today + 3) % 7}, From: "00:00", To: "23:59", Scope: "tunnel"}
	here := &Schedule{Days: []int{0, 1, 2, 3, 4, 5, 6}, From: "00:00", To: "23:59", Scope: "tunnel"}
	setPeers := func(ps []Peer) {
		a.mu.Lock()
		a.peers = ps
		a.mu.Unlock()
	}
	round := func(r int) {
		stale := now.Add(-30 * time.Hour).Unix()
		ps := make([]Peer, N)
		for i := range ps {
			ps[i] = Peer{ID: fmt.Sprintf("r%d-%d", r, i), Name: fmt.Sprintf("cihaz-%d-%d", r, i), PublicKey: fmt.Sprintf("PUB-%d-%d", r, i), PSK: "P",
				IP: fmt.Sprintf("10.77.%d.%d", i/250, i%250+1), Enabled: true, LastSeen: stale, Policy: "p"}
			if i%2 == 0 {
				ps[i].Schedule = away
			}
		}
		rs := here
		if r%2 == 0 {
			rs = away
		}
		a.mu.Lock()
		a.pol = []Policy{{ID: "p", Name: "Ev", Rules: []Rule{{Target: "server", Proto: "tcp", Ports: "22", Schedule: rs}}}}
		a.mu.Unlock()
		setPeers(ps) // ekle
		a.tick()
		a.watchOffline(ps, now)
		ed := slices.Clone(ps) // değiştir: pencereler açılır, adlar değişir
		for i := range ed {
			ed[i].Name += "-x"
			if ed[i].Schedule != nil {
				ed[i].Schedule = here
			}
		}
		setPeers(ed)
		a.tick()
		a.watchOffline(ed, now)
		setPeers(nil) // sil
		a.tick()
		a.watchOffline(nil, now)
		for i := range perRound { // bildirim olayları: farklı IP'lerden başarısız ve yeni IP'den girişler
			ip := fmt.Sprintf("198.%d.%d.%d", 18+r, i/256, i%256)
			for range 3 {
				a.act.add(Event{T: now.Unix(), IP: ip, Kind: "login_fail"})
			}
			a.act.add(Event{T: now.Unix(), IP: ip, User: "admin", Kind: "login"})
			a.lim.allow(ip, "admin")
		}
		// limiter penceresi doldu (zaman geçti): eski kayıtlar bir sonraki denemede toplu silinir
		a.lim.mu.Lock()
		for _, ts := range a.lim.fails {
			for j := range ts {
				ts[j] = ts[j].Add(-failWindow - time.Second)
			}
		}
		a.lim.mu.Unlock()
	}
	heap := func() uint64 {
		runtime.GC()
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapInuse
	}
	round(0) // ısınma
	round(1)
	first := heap()
	for r := 2; r < 8; r++ {
		round(r)
	}
	a.lim.allow("203.0.113.1", "admin") // budamayı tetikle
	last := heap()
	t.Logf("HeapInuse: ilk %d KB, son %d KB (oran %.2f)", first>>10, last>>10, float64(last)/float64(first))
	if last > 2*first {
		t.Errorf("bellek büyüyor: ilk %d, son %d bayt", first, last)
	}
	a.mu.Lock()
	sw, rw := len(a.schedWas), len(a.ruleWas)
	a.mu.Unlock()
	a.phist.mu.Lock()
	ph := len(a.phist.m)
	a.phist.mu.Unlock()
	a.nf.mu.Lock()
	off, rec := len(a.nf.offline), len(a.nf.recent)
	a.nf.mu.Unlock()
	a.lim.mu.Lock()
	lf := len(a.lim.fails)
	a.lim.mu.Unlock()
	t.Logf("boyutlar: phist=%d schedWas=%d ruleWas=%d offline=%d recent=%d limiter=%d", ph, sw, rw, off, rec, lf)
	if ph != 0 || sw != 0 || off != 0 {
		t.Errorf("silinen cihazlar haritada kaldı: phist=%d schedWas=%d offline=%d", ph, sw, off)
	}
	if rw > 1 {
		t.Errorf("ruleWas kural sayısını aşıyor: %d", rw)
	}
	if rec > notifyPerHr {
		t.Errorf("notifier.recent gönderilebilecek bildirim sayısını (%d) aşıyor: %d", notifyPerHr, rec)
	}
	if lf > 1024+3*perRound {
		t.Errorf("limiter.fails budanmıyor: %d", lf)
	}
}
