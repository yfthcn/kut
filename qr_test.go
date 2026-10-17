package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"strings"
	"testing"
)

// Kod sözcüğü tablosu, spesifikasyondaki toplam kod sözcüğü sayısıyla tutarlı olmalı.
func TestECCTable(t *testing.T) {
	for v := 1; v <= 15; v++ {
		e := eccL[v]
		total := e.ecc*(e.g1n+e.g2n) + e.g1n*e.g1d + e.g2n*e.g2d
		if total != rawModules(v)/8 {
			t.Errorf("sürüm %d: tablo %d kod sözcüğü diyor, olması gereken %d", v, total, rawModules(v)/8)
		}
	}
}

func TestKeyRoundTrip(t *testing.T) {
	priv, err := genPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicKey(priv)
	if err != nil || len(pub) != 44 {
		t.Fatalf("açık anahtar hatalı: %q %v", pub, err)
	}
}

func TestAdminHash(t *testing.T) {
	r, err := newAdmin("dogru-parola-123")
	if err != nil {
		t.Fatal(err)
	}
	if !r.verify("dogru-parola-123") || r.verify("yanlis-parola-123") {
		t.Fatal("parola doğrulaması hatalı")
	}
	if _, err := newAdmin("kisa"); err == nil {
		t.Fatal("kısa parola kabul edildi")
	}
}

// QR_PNG_OUT=/yol/dizin go test -run TestQRPNG  → farklı uzunluklarda PNG üretir (harici çözücüyle doğrulamak için).
func TestQRPNG(t *testing.T) {
	dir := os.Getenv("QR_PNG_OUT")
	if dir == "" {
		t.Skip("QR_PNG_OUT tanımlı değil")
	}
	for _, n := range []int{10, 60, 150, 298, 330, 480} {
		text := strings.Repeat("WireGuard-", n/10+1)[:n]
		q, err := qrEncode(text)
		if err != nil {
			t.Fatal(err)
		}
		const scale, quiet = 8, 4
		px := (q.size + 2*quiet) * scale
		img := image.NewGray(image.Rect(0, 0, px, px))
		for i := range img.Pix {
			img.Pix[i] = 255
		}
		for y := 0; y < q.size; y++ {
			for x := 0; x < q.size; x++ {
				if !q.mod[y][x] {
					continue
				}
				for dy := 0; dy < scale; dy++ {
					for dx := 0; dx < scale; dx++ {
						img.SetGray((x+quiet)*scale+dx, (y+quiet)*scale+dy, color.Gray{0})
					}
				}
			}
		}
		f, _ := os.Create(dir + "/qr_" + itoa(n) + ".png")
		png.Encode(f, img)
		f.Close()
		os.WriteFile(dir+"/qr_"+itoa(n)+".txt", []byte(text), 0o600)
	}
}

func itoa(n int) string {
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

// rawModules: sürümün toplam veri modülü sayısı (tablo sağlaması için; üretim kodunda kullanılmaz).
func rawModules(ver int) int {
	r := (16*ver+128)*ver + 64
	if ver >= 2 {
		n := ver/7 + 2
		r -= (25*n-10)*n - 55
		if ver >= 7 {
			r -= 36
		}
	}
	return r
}
