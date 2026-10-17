package main

import (
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	srv := Server{PrivateKey: "x", PublicKey: "y", Endpoint: "203.0.113.10", Port: 51820,
		Subnet: "10.77.0.0/24", Iface: "wg0", ConfPath: filepath.Join(dir, "wg0.conf")}
	return &App{dataDir: dir, dry: true, srv: srv}
}

func TestFrozenAndDisabledNotInConf(t *testing.T) {
	a := testApp(t)
	future := time.Now().Add(time.Hour)
	peers := []Peer{
		{Name: "dondurulmus", PublicKey: "A", PSK: "P", IP: "10.77.0.2", Enabled: true, FrozenUntil: &future},
		{Name: "acik", PublicKey: "B", PSK: "P", IP: "10.77.0.3", Enabled: true},
		{Name: "kapali", PublicKey: "C", PSK: "P", IP: "10.77.0.4", Enabled: false},
	}
	conf := renderServerConf(a.srv, peers)
	if !strings.Contains(conf, "# acik") {
		t.Error("açık peer conf'ta yok")
	}
	for _, n := range []string{"# dondurulmus", "# kapali"} {
		if strings.Contains(conf, n) {
			t.Errorf("%q conf'ta olmamalı", n)
		}
	}
	if strings.Contains(conf, "MASQUERADE") {
		t.Error("NAT kuralı olmamalı")
	}
}

// Dondurma süresi dolunca izleyici peer'ı geri açmalı, conf'a yazmalı ve kaydetmeli.
func TestFreezeExpiryRestoresPeer(t *testing.T) {
	a := testApp(t)
	past := time.Now().Add(-time.Minute)
	a.peers = []Peer{{ID: "1", Name: "ali", PublicKey: "A", PSK: "P", IP: "10.77.0.2", Enabled: true, FrozenUntil: &past}}
	a.tick()
	if a.peers[0].FrozenUntil != nil {
		t.Fatal("süre doldu ama dondurma kalkmadı")
	}
	conf, err := os.ReadFile(a.srv.ConfPath)
	if err != nil || !strings.Contains(string(conf), "# ali") {
		t.Fatalf("peer conf'a geri yazılmadı: %v", err)
	}
	var saved []Peer
	if err := loadJSON(peersPath(a.dataDir), &saved); err != nil || saved[0].FrozenUntil != nil {
		t.Fatalf("peers.json güncellenmedi: %v", err)
	}
}

func TestStillFrozenStaysFrozen(t *testing.T) {
	a := testApp(t)
	future := time.Now().Add(time.Hour)
	a.peers = []Peer{{ID: "1", Name: "ali", PublicKey: "A", PSK: "P", IP: "10.77.0.2", Enabled: true, FrozenUntil: &future}}
	a.tick()
	if a.peers[0].FrozenUntil == nil {
		t.Fatal("süresi dolmamış dondurma kalktı")
	}
}

func TestNextIPFillsGapAndSkipsServer(t *testing.T) {
	a := testApp(t)
	peers := []Peer{{IP: "10.77.0.2"}, {IP: "10.77.0.4"}}
	ip, err := a.nextIP(peers)
	if err != nil || ip != "10.77.0.3" {
		t.Fatalf("beklenen 10.77.0.3, gelen %q (%v)", ip, err)
	}
}

// Havuz dolunca kodlu hata: arayüz err.ip.pool_full'u kendi dilinde yazar.
func TestNextIPPoolFullIsCoded(t *testing.T) {
	a := testApp(t)
	var peers []Peer
	for ip := a.srv.serverIP().Next(); a.srv.prefix().Contains(ip); ip = ip.Next() {
		peers = append(peers, Peer{IP: ip.String()})
	}
	if _, err := a.nextIP(peers); errCodeOf(err) != "ip.pool_full" {
		t.Fatalf("dolu havuz: %v (%q)", err, errCodeOf(err))
	}
}

func TestOverlapLocal(t *testing.T) {
	// Yerel arayüz adreslerinden birini içeren ağ kesişmeli (loopback hariç tutulmaz: 127/8).
	if _, bad := overlapLocalExcept(netip.MustParsePrefix("127.0.0.0/24"), ""); !bad {
		t.Error("127.0.0.0/24 loopback ile kesişmeli")
	}
	// TEST-NET-2 hiçbir makinede arayüz ağı olmaz.
	if lp, bad := overlapLocalExcept(netip.MustParsePrefix("198.51.100.0/24"), ""); bad {
		t.Errorf("beklenmeyen çakışma: %s", lp)
	}
}

// Yerel soketten gelen isteğin IP alanı dilden bağımsız sabit "local" (günlüğe yazılır; arayüz kendi dilinde gösterir).
func TestClientIPLocalSocketIsLanguageNeutral(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	for _, ra := range []string{"", "@", "bozuk-adres"} {
		r.RemoteAddr = ra
		if got := clientIP(r); got != "local" {
			t.Errorf("RemoteAddr %q: %q, beklenen \"local\"", ra, got)
		}
	}
	r.RemoteAddr = "198.51.100.7:4000"
	if got := clientIP(r); got != "198.51.100.7" {
		t.Errorf("TCP istemcisi: %q", got)
	}
}
