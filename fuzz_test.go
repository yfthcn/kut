package main

// Dışarıdan gelen veriyi ayrıştıran fonksiyonlar için fuzz testleri. `go test` bunları yalnızca tohum
// girdileriyle (birim test gibi) çalıştırır; uzun koşu için: go test -run '^$' -fuzz '^FuzzParsePorts$' -fuzztime 60s

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Port listesi panelden ve yedekten gelir; geçerli sayılan her aralık 1-65535 içinde ve sıralı olmalı.
func FuzzParsePorts(f *testing.F) {
	for _, s := range []string{"", "80", "80,443", "8000-8100", "80-", "0", "70000", "1-65535", " 22 , 80 ", "5-3", "1,1,1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		rs, err := parsePorts(s)
		if err != nil {
			return
		}
		for _, r := range rs {
			if r.lo < 1 || r.hi > 65535 || r.lo > r.hi {
				t.Fatalf("parsePorts(%q) geçersiz aralık kabul etti: %+v", s, r)
			}
		}
	})
}

// Normalleştirilen her kural güvenlik duvarına çevrilebilmeli; reddedilen kural hiçbir şeye izin vermemeli.
func FuzzNormalizeRule(f *testing.F) {
	for _, s := range []string{
		`{"target":"server","proto":"tcp","ports":"22"}`,
		`{"target":"device","device":"b","proto":"udp","ports":"53","both":true}`,
		`{"target":"all","proto":"any"}`,
		`{"target":"server","proto":"tcp","ports":"80-"}`,
		`{"target":"server","proto":"sctp"}`,
		`{"target":"all","proto":"icmp","schedule":{"days":[1,2],"from":"22:00","to":"06:00"}}`,
	} {
		f.Add([]byte(s))
	}
	peers := []Peer{{ID: "a", Name: "a", IP: "10.77.0.2"}, {ID: "b", Name: "b", IP: "10.77.0.3"}}
	f.Fuzz(func(t *testing.T, b []byte) {
		var r Rule
		if json.Unmarshal(b, &r) != nil {
			return
		}
		raw := r
		for _, v6 := range []bool{false, true} {
			_ = matchArgsFam(raw, v6) // ham (doğrulanmamış) kural da panic üretmemeli
		}
		n, err := normalizeRule(r, peers, 1)
		if err != nil {
			return
		}
		for _, v6 := range []bool{false, true} {
			for _, args := range matchArgsFam(n, v6) {
				for _, a := range args {
					if strings.ContainsAny(a, " \t\r\n") {
						t.Fatalf("iptables argümanında boşluk/satır sonu: %q (kural %+v)", a, n)
					}
				}
			}
		}
	})
}

// Yüklenen yedek dosyası tamamen saldırgan denetiminde olabilir: panic yok, yalnızca bilinen dosyalar döner.
func FuzzParseBackup(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("KUTENC1\n"))
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range []struct{ name, body string }{{"server.json", "{}"}, {"../evil", "x"}, {"peers.json", "[]"}} {
		_ = tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o600, Size: int64(len(e.body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte(e.body))
	}
	_ = tw.Close()
	_ = gz.Close()
	f.Add(buf.Bytes())
	allowed := map[string]bool{}
	for _, n := range backupFiles {
		allowed[n] = true
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := parseBackup(b)
		if err != nil {
			return
		}
		for name := range got {
			if !allowed[name] {
				t.Fatalf("bilinmeyen dosya kabul edildi: %q", name)
			}
		}
	})
}

// Şifreli yedek başlığı ve gövdesi saldırgan denetiminde: panic yok, yanlış veri asla "çözüldü" sayılmaz.
func FuzzDecryptBackup(f *testing.F) {
	enc, err := encryptBackup([]byte("gizli yedek"), "dogru-parola-123")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(enc, "dogru-parola-123")
	f.Add(enc, "yanlis")
	f.Add([]byte("KUTENC1\n\x00\x00\x00\x01"), "x")
	f.Fuzz(func(t *testing.T, b []byte, pass string) {
		out, err := decryptBackup(b, pass)
		if err == nil && !bytes.Equal(b, enc) && string(out) == "gizli yedek" && pass != "dogru-parola-123" {
			t.Fatal("yanlış parola ya da değiştirilmiş veri çözüldü")
		}
	})
}

// Uç nokta ve DNS doğrulayıcıları: kabul edilen değer istemci yapılandırmasına satır olarak yazılır.
func FuzzValidEndpointDNS(f *testing.F) {
	for _, s := range []string{"203.0.113.10", "vpn.example.com", "[2001:db8::1]", "a\nPostUp = id", "1.1.1.1, 1.0.0.1", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if ep, err := validEndpoint(s); err == nil && strings.ContainsAny(ep, "\r\n=") {
			t.Fatalf("validEndpoint(%q) yapılandırmayı bozan değer kabul etti: %q", s, ep)
		}
		if d, err := validDNS(s); err == nil && strings.ContainsAny(d, "\r\n=") {
			t.Fatalf("validDNS(%q) yapılandırmayı bozan değer kabul etti: %q", s, d)
		}
	})
}

// TOTP kodu girişten gelir: panic yok, tekrar kullanılan adım kabul edilmez.
func FuzzTOTPVerify(f *testing.F) {
	f.Add("123456", int64(0))
	f.Add("", int64(0))
	f.Add("abcdefgh", int64(1<<62))
	const secret = "JBSWY3DPEHPK3PXP"
	now := time.Unix(1_700_000_000, 0)
	f.Fuzz(func(t *testing.T, code string, last int64) {
		step, ok := totpVerify(secret, code, now, last)
		if ok && step <= last {
			t.Fatalf("kullanılmış adım kabul edildi: step=%d last=%d", step, last)
		}
	})
}

// CSV hücresi formül olarak yorumlanmamalı.
func FuzzCSVSafe(f *testing.F) {
	for _, s := range []string{"=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "normal", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := csvSafe(s)
		if out != "" && strings.ContainsRune("=+-@\t\r", rune(out[0])) {
			t.Fatalf("csvSafe(%q) = %q formülle başlıyor", s, out)
		}
	})
}

// QR kodlayıcı istemci yapılandırmasını alır; uzun ya da garip metinde panic yerine hata dönmeli.
func FuzzQREncode(f *testing.F) {
	f.Add("[Interface]\nPrivateKey = x\n")
	f.Add(strings.Repeat("A", 2000))
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = qrEncode(s)
	})
}

// Sürüm karşılaştırması GitHub yanıtından gelen etiketle yapılır.
func FuzzNewerVersion(f *testing.F) {
	for _, s := range []string{"v0.12.0", "0.11.2", "v1", "", "v999999999999999999999.0.0", "v0.x.1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_ = newerVersion(s, version)
		if newerVersion(version, version) {
			t.Fatal("aynı sürüm daha yeni sayıldı")
		}
	})
}

// iptables sayaç çıktısı ayrıştırıcısı: panic yok.
func FuzzParseInetCounters(f *testing.F) {
	f.Add([]byte("Chain KUT-INET (1 references)\n pkts bytes target prot opt in out source destination\n 10 1000 RETURN all -- wg0 eth0 10.77.0.2 0.0.0.0/0\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = parseInetCounters(b)
		_ = parseInetCountersFam(b, true)
	})
}
