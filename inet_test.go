package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleInet = `Chain KUT-INET (1 references)
    pkts      bytes target     prot opt in     out     source               destination
       0        0 DROP       0    --  *      *       10.77.0.3            10.0.0.0/8
       5      400 DROP       0    --  *      *       10.77.0.3            192.168.0.0/16
     120    90000 ACCEPT     0    --  *      *       10.77.0.3            0.0.0.0/0
       0        0 ACCEPT     0    --  *      *       10.77.0.4            0.0.0.0/0
`

func TestParseInetCounters(t *testing.T) {
	c := parseInetCounters([]byte(sampleInet))
	if len(c) != 2 || c["10.77.0.3"] != (inetCounter{120, 90000}) || c["10.77.0.4"].Packets != 0 {
		t.Fatalf("beklenmeyen: %+v", c)
	}
}

func TestInetTracker(t *testing.T) {
	var tr inetTracker
	t0 := time.Unix(1000, 0)
	tr.observe(map[string]inetCounter{"10.77.0.4": {0, 0}}, t0)
	if u := tr.get("10.77.0.4"); u.Last != 0 || u.Bytes != 0 {
		t.Fatalf("trafik yokken kullanım görünmemeli: %+v", u)
	}
	tr.observe(map[string]inetCounter{"10.77.0.4": {3, 300}}, t0.Add(15*time.Second))
	if u := tr.get("10.77.0.4"); u.Last != 1015 || u.Bytes != 300 {
		t.Fatalf("artış işlenmedi: %+v", u)
	}
	tr.observe(map[string]inetCounter{"10.77.0.4": {3, 300}}, t0.Add(30*time.Second))
	if u := tr.get("10.77.0.4"); u.Last != 1015 {
		t.Fatalf("artış yokken Last değişmemeli: %+v", u)
	}
	// zincir yeniden yazıldı: sayaç sıfırlandı, sonra 2 paket geldi
	tr.observe(map[string]inetCounter{"10.77.0.4": {2, 100}}, t0.Add(45*time.Second))
	if u := tr.get("10.77.0.4"); u.Last != 1045 || u.Bytes != 400 {
		t.Fatalf("sıfırlanma işlenmedi: %+v", u)
	}
}

func TestPatchInternetPermission(t *testing.T) {
	a := testApp(t)
	a.sess, a.lim, a.hist, a.act = newSessions(), newLimiter(), &history{}, &activity{}
	a.peers = []Peer{{ID: "p1", Name: "pc", PublicKey: "A", PSK: "P", IP: "10.77.0.2", Enabled: true, Internet: true}}
	h := a.handler(true)
	req := httptest.NewRequest("PATCH", "/api/peers/p1", strings.NewReader(`{"name":"pc","note":"","internet":false}`))
	req.Header.Set("X-Kut", "1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("kod %d: %s", rec.Code, rec.Body)
	}
	if a.peers[0].Internet {
		t.Fatal("internet izni kapanmalıydı")
	}
	// internet alanı yoksa değişmemeli
	a.peers[0].Internet = true
	req = httptest.NewRequest("PATCH", "/api/peers/p1", strings.NewReader(`{"name":"pc","note":"x"}`))
	req.Header.Set("X-Kut", "1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if !a.peers[0].Internet {
		t.Fatal("alan gönderilmediyse izin değişmemeli")
	}
}
