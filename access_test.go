package main

import (
	"strings"
	"testing"
	"time"
)

func TestRuleScheduleGrants(t *testing.T) {
	peers := []Peer{{ID: "a", Name: "a", IP: "10.10.0.2", Enabled: true, Policy: "p1"}}
	pol := Policy{ID: "p1", Name: "Oyun", Rules: []Rule{
		{Target: "server", Proto: "tcp", Ports: "25565", Schedule: &Schedule{Days: []int{1, 2, 3, 4, 5}, From: "16:00", To: "21:00", Scope: "tunnel"}},
		{Target: "server", Proto: "tcp", Ports: "80"},
	}}
	in := time.Date(2026, 10, 14, 17, 0, 0, 0, time.Local)  // Çarşamba
	out := time.Date(2026, 10, 14, 22, 0, 0, 0, time.Local) // saat dışı
	if n := len(grants(peers, []Policy{pol}, in)); n != 2 {
		t.Fatalf("pencere içinde 2 izin beklenir, %d", n)
	}
	if n := len(grants(peers, []Policy{pol}, out)); n != 1 {
		t.Fatalf("pencere dışında 1 izin beklenir, %d", n)
	}
	v := evalReach("tr", peers, []Policy{pol}, peers[0], "server", "tcp", 25565, 5000, false, out)
	want := T("tr", "access.policy_off_window", map[string]any{"policy": "Oyun", "rule": pol.Rules[0].textIn("tr")})
	if v.Result != "deny" || v.Reason != want {
		t.Fatalf("verdict: %+v, beklenen gerekçe %q", v, want)
	}
	// gerekçe isteğin dilinde üretilir
	if en := evalReach("en", peers, []Policy{pol}, peers[0], "server", "tcp", 25565, 5000, false, out); en.Reason == v.Reason || !strings.Contains(en.Reason, "outside the time window") {
		t.Fatalf("en gerekçe: %q", en.Reason)
	}
	if v := evalReach("tr", peers, []Policy{pol}, peers[0], "server", "tcp", 25565, 5000, false, in); v.Result != "allow" {
		t.Fatalf("verdict: %+v", v)
	}
}

func TestNormalizeRuleScheduleAndGroups(t *testing.T) {
	_, err := normalizePolicy(Policy{Name: "x", Rules: []Rule{{Target: "server", Proto: "tcp", Ports: "80", Schedule: &Schedule{Days: nil, From: "08:00", To: "09:00"}}}}, nil)
	if err == nil {
		t.Fatal("günsüz zaman kuralı reddedilmeli")
	}
	p, err := normalizePolicy(Policy{Name: "x", Groups: []string{" Çocuklar ", "çocuklar", ""}}, nil)
	if err != nil || len(p.Groups) != 1 {
		t.Fatalf("%v %v", p.Groups, err)
	}
	if _, err := normalizePolicy(Policy{Name: "x", Groups: []string{"a\nb"}}, nil); err == nil {
		t.Fatal("geçersiz grup reddedilmeli")
	}
	other := Policy{ID: "o", Name: "o", Groups: []string{"çocuklar"}}
	if checkGroupClaims([]Policy{other}, Policy{ID: "n", Groups: []string{"Çocuklar"}}) == nil {
		t.Fatal("aynı grup iki profile verilemez")
	}
}

func TestGroupDefaultPolicy(t *testing.T) {
	pols := []Policy{{ID: "g", Name: "Kısıtlı", Groups: []string{"Çocuklar"}, Rules: []Rule{{Target: "server", Proto: "tcp", Ports: "80"}}},
		{ID: "own", Name: "Özel"}}
	idx := polIndex(pols)
	if p, ok := effectivePolicy(Peer{Group: "çocuklar"}, idx); !ok || p.ID != "g" {
		t.Fatalf("grup profili gelmeli: %+v %v", p, ok)
	}
	if p, ok := effectivePolicy(Peer{Group: "Çocuklar", Policy: "own"}, idx); !ok || p.ID != "own" {
		t.Fatalf("elle atanan öncelikli: %+v", p)
	}
	if _, ok := effectivePolicy(Peer{Group: "Başka"}, idx); ok {
		t.Fatal("başka grup profil almamalı")
	}
	peers := []Peer{{ID: "a", IP: "10.10.0.2", Group: "Çocuklar", Enabled: true}}
	if len(grants(peers, pols, time.Now())) != 1 {
		t.Fatal("grup üyesi için izin üretilmeli")
	}
}

func TestRestartEndpoint(t *testing.T) {
	a, h, c := maintApp(t)
	a.act = &activity{}
	called := make(chan struct{}, 1)
	a.restartF = func() { called <- struct{}{} }
	restartDelay = 10 * time.Millisecond
	if rec := post(h, "/api/server/restart", `{}`, nil); rec.Code == 200 {
		t.Fatal("oturumsuz yeniden başlatma kabul edildi")
	}
	rec := post(h, "/api/server/restart", `{}`, c)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	select {
	case <-called:
	case <-time.After(3 * time.Second):
		t.Fatal("yeniden başlatma çağrılmadı")
	}
}

func TestFirewallRuleScheduleAndGroup(t *testing.T) {
	s := testApp(t).srv
	s.Settings = &Settings{DNS: "1.1.1.1", Keepalive: 25, BlockPrivate: true}
	in := time.Date(2026, 10, 14, 17, 0, 0, 0, time.Local)
	out := time.Date(2026, 10, 14, 23, 0, 0, 0, time.Local)
	peers := []Peer{{ID: "k", Name: "k", IP: "10.77.0.2", Enabled: true, Group: "Çocuklar"}}
	pols := []Policy{{ID: "g", Name: "Çocuk", Groups: []string{"çocuklar"}, Rules: []Rule{
		{Target: "server", Proto: "tcp", Ports: "25565", Schedule: &Schedule{Days: []int{0, 1, 2, 3, 4, 5, 6}, From: "16:00", To: "21:00", Scope: "tunnel"}},
	}}}
	if !strings.Contains(fwText(desiredFirewall(s, peers, pols, 5000, in)), "--dport 25565") {
		t.Fatal("pencere içinde grup üyesine port açık olmalı")
	}
	if strings.Contains(fwText(desiredFirewall(s, peers, pols, 5000, out)), "--dport 25565") {
		t.Fatal("pencere dışında port kapalı olmalı")
	}
	// profil sahibi (grup üyesi) pencere dışında bile serbest kalmamalı
	if strings.Contains(fwText(desiredFirewall(s, peers, pols, 5000, out)), "-A KUT-PEERS -s 10.77.0.2/32 -j ACCEPT") {
		t.Fatal("grup profili olan cihaz serbest bırakılmamalı")
	}
}
