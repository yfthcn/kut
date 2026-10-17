package main

import (
	"image"
	"image/color"
	"image/png"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestQRMasks(t *testing.T) {
	dir := os.Getenv("QR_MASK_OUT")
	if dir == "" {
		t.Skip()
	}
	defer func() { forceMask = -1 }()
	for _, n := range []int{20, 100, 150, 300} {
		for m := 0; m < 8; m++ {
			forceMask = m
			text := strings.Repeat("WireGuard-test_", 40)[:n]
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
					if q.mod[y][x] {
						for dy := 0; dy < scale; dy++ {
							for dx := 0; dx < scale; dx++ {
								img.SetGray((x+quiet)*scale+dx, (y+quiet)*scale+dy, color.Gray{0})
							}
						}
					}
				}
			}
			name := dir + "/m" + strconv.Itoa(m) + "_n" + strconv.Itoa(n)
			f, _ := os.Create(name + ".png")
			png.Encode(f, img)
			f.Close()
			os.WriteFile(name+".txt", []byte(text), 0o600)
		}
	}
}
