package main

import (
	"fmt"
	"strings"
)

// Sıfır bağımlılıklı QR üreteci: bayt modu, hata düzeltme seviyesi L, sürüm 1-15,
// maske otomatik seçilir. WireGuard istemci yapılandırması (~300 bayt) için yeterli.

type eccParams struct{ ecc, g1n, g1d, g2n, g2d int } // blok başına ECC, grup1 blok/veri, grup2 blok/veri

var eccL = [16]eccParams{
	{}, {7, 1, 19, 0, 0}, {10, 1, 34, 0, 0}, {15, 1, 55, 0, 0}, {20, 1, 80, 0, 0},
	{26, 1, 108, 0, 0}, {18, 2, 68, 0, 0}, {20, 2, 78, 0, 0}, {24, 2, 97, 0, 0},
	{30, 2, 116, 0, 0}, {18, 2, 68, 2, 69}, {20, 4, 81, 0, 0}, {24, 2, 92, 2, 93},
	{26, 4, 107, 0, 0}, {30, 3, 115, 1, 116}, {22, 5, 87, 1, 88},
}

var alignPos = [16][]int{
	nil, nil, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}, {6, 22, 38}, {6, 24, 42},
	{6, 26, 46}, {6, 28, 50}, {6, 30, 54}, {6, 32, 58}, {6, 34, 62}, {6, 26, 46, 66}, {6, 26, 48, 70},
}

// ---- Reed-Solomon (GF(256), polinom 0x11D) ----

func gfMul(x, y byte) byte {
	z := 0
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ ((z >> 7) * 0x11D)
		z ^= int((y>>uint(i))&1) * int(x)
	}
	return byte(z)
}

func rsGenerator(deg int) []byte {
	res := make([]byte, deg)
	res[deg-1] = 1
	root := byte(1)
	for range deg {
		for j := range deg {
			res[j] = gfMul(res[j], root)
			if j+1 < deg {
				res[j] ^= res[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return res
}

func rsRemainder(data, gen []byte) []byte {
	res := make([]byte, len(gen))
	for _, b := range data {
		f := b ^ res[0]
		copy(res, res[1:])
		res[len(res)-1] = 0
		for i := range res {
			res[i] ^= gfMul(gen[i], f)
		}
	}
	return res
}

// ---- Bit tamponu ----

type bitBuf struct {
	b []byte
	n int
}

func (b *bitBuf) add(val uint, n int) {
	for i := n - 1; i >= 0; i-- {
		if b.n%8 == 0 {
			b.b = append(b.b, 0)
		}
		if (val>>uint(i))&1 == 1 {
			b.b[b.n/8] |= 0x80 >> uint(b.n%8)
		}
		b.n++
	}
}

// ---- QR matrisi ----

type qrCode struct {
	size int
	mod  [][]bool
	fn   [][]bool // fonksiyon modülleri (maskelenmez)
}

// forceMask >= 0 ise maske seçimi atlanır (testlerde her maskeyi ayrı doğrulamak için).
var forceMask = -1

func qrEncode(text string) (*qrCode, error) {
	data := []byte(text)
	ver := 0
	for v := 1; v <= 15; v++ {
		e := eccL[v]
		cc := 8
		if v >= 10 {
			cc = 16
		}
		if 4+cc+8*len(data) <= (e.g1n*e.g1d+e.g2n*e.g2d)*8 {
			ver = v
			break
		}
	}
	if ver == 0 {
		return nil, ue("qr.too_long", nil)
	}
	e := eccL[ver]
	capBits := (e.g1n*e.g1d + e.g2n*e.g2d) * 8
	cc := 8
	if ver >= 10 {
		cc = 16
	}

	var bb bitBuf
	bb.add(0b0100, 4)
	bb.add(uint(len(data)), cc)
	for _, c := range data {
		bb.add(uint(c), 8)
	}
	bb.add(0, min(4, capBits-bb.n))
	bb.add(0, (8-bb.n%8)%8)
	for pad := byte(0xEC); bb.n < capBits; pad ^= 0xEC ^ 0x11 {
		bb.add(uint(pad), 8)
	}

	nb := e.g1n + e.g2n
	gen := rsGenerator(e.ecc)
	blocks := make([][]byte, 0, nb)
	eccs := make([][]byte, 0, nb)
	pos := 0
	for i := range nb {
		l := e.g1d
		if i >= e.g1n {
			l = e.g2d
		}
		d := bb.b[pos : pos+l]
		pos += l
		blocks = append(blocks, d)
		eccs = append(eccs, rsRemainder(d, gen))
	}
	var final []byte
	for i := range max(e.g1d, e.g2d) {
		for _, d := range blocks {
			if i < len(d) {
				final = append(final, d[i])
			}
		}
	}
	for i := range e.ecc {
		for _, ec := range eccs {
			final = append(final, ec[i])
		}
	}

	size := ver*4 + 17
	q := &qrCode{size: size, mod: make([][]bool, size), fn: make([][]bool, size)}
	for i := range q.mod {
		q.mod[i] = make([]bool, size)
		q.fn[i] = make([]bool, size)
	}
	q.drawFunctionPatterns(ver)
	q.placeData(final)

	best, bestPen := 0, 1<<30
	for m := range 8 {
		q.applyMask(m)
		q.drawFormat(m)
		if p := q.penalty(); p < bestPen {
			best, bestPen = m, p
		}
		q.applyMask(m) // geri al
	}
	if forceMask >= 0 {
		best = forceMask // yalnızca testler için
	}
	q.applyMask(best)
	q.drawFormat(best)
	return q, nil
}

func bit(x, i int) bool { return (x>>uint(i))&1 != 0 }

func (q *qrCode) setFn(x, y int, dark bool) {
	if x >= 0 && x < q.size && y >= 0 && y < q.size {
		q.mod[y][x] = dark
		q.fn[y][x] = true
	}
}

func (q *qrCode) drawFunctionPatterns(ver int) {
	for i := range q.size {
		q.setFn(6, i, i%2 == 0)
		q.setFn(i, 6, i%2 == 0)
	}
	for _, c := range [][2]int{{3, 3}, {q.size - 4, 3}, {3, q.size - 4}} {
		for dy := -4; dy <= 4; dy++ {
			for dx := -4; dx <= 4; dx++ {
				d := max(abs(dx), abs(dy))
				q.setFn(c[0]+dx, c[1]+dy, d != 2 && d != 4)
			}
		}
	}
	pos := alignPos[ver]
	n := len(pos)
	for i := range n {
		for j := range n {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue
			}
			for dy := -2; dy <= 2; dy++ {
				for dx := -2; dx <= 2; dx++ {
					q.setFn(pos[i]+dx, pos[j]+dy, max(abs(dx), abs(dy)) != 1)
				}
			}
		}
	}
	q.drawFormat(0)
	q.drawVersion(ver)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// drawFormat: hata düzeltme seviyesi L (bitler 01) + maske numarası, BCH(15,5).
func (q *qrCode) drawFormat(mask int) {
	data := 1<<3 | mask
	rem := data
	for range 10 {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	bits := (data<<10 | rem) ^ 0x5412
	for i := range 6 {
		q.setFn(8, i, bit(bits, i))
	}
	q.setFn(8, 7, bit(bits, 6))
	q.setFn(8, 8, bit(bits, 7))
	q.setFn(7, 8, bit(bits, 8))
	for i := 9; i < 15; i++ {
		q.setFn(14-i, 8, bit(bits, i))
	}
	for i := range 8 {
		q.setFn(q.size-1-i, 8, bit(bits, i))
	}
	for i := 8; i < 15; i++ {
		q.setFn(8, q.size-15+i, bit(bits, i))
	}
	q.setFn(8, q.size-8, true) // sabit koyu modül
}

func (q *qrCode) drawVersion(ver int) {
	if ver < 7 {
		return
	}
	rem := ver
	for range 12 {
		rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
	}
	bits := ver<<12 | rem
	for i := range 18 {
		b := bit(bits, i)
		a := q.size - 11 + i%3
		c := i / 3
		q.setFn(a, c, b)
		q.setFn(c, a, b)
	}
}

func (q *qrCode) placeData(data []byte) {
	i := 0
	for right := q.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5
		}
		for vert := range q.size {
			for j := range 2 {
				x := right - j
				y := vert
				if ((right + 1) & 2) == 0 {
					y = q.size - 1 - vert
				}
				if !q.fn[y][x] && i < len(data)*8 {
					q.mod[y][x] = bit(int(data[i>>3]), 7-(i&7))
					i++
				}
			}
		}
	}
}

func (q *qrCode) applyMask(m int) {
	for y := range q.size {
		for x := range q.size {
			var inv bool
			switch m {
			case 0:
				inv = (x+y)%2 == 0
			case 1:
				inv = y%2 == 0
			case 2:
				inv = x%3 == 0
			case 3:
				inv = (x+y)%3 == 0
			case 4:
				inv = (x/3+y/2)%2 == 0
			case 5:
				inv = x*y%2+x*y%3 == 0
			case 6:
				inv = (x*y%2+x*y%3)%2 == 0
			case 7:
				inv = ((x+y)%2+x*y%3)%2 == 0
			}
			if inv && !q.fn[y][x] {
				q.mod[y][x] = !q.mod[y][x]
			}
		}
	}
}

// penalty: spesifikasyondaki dört ceza kuralı.
func (q *qrCode) penalty() int {
	n := q.size
	at := func(i, j int, col bool) bool {
		if col {
			return q.mod[j][i]
		}
		return q.mod[i][j]
	}
	res := 0
	for i := range n {
		for _, col := range []bool{false, true} {
			run := 1
			for j := 1; j < n; j++ {
				if at(i, j, col) == at(i, j-1, col) {
					run++
				} else {
					if run >= 5 {
						res += 3 + run - 5
					}
					run = 1
				}
			}
			if run >= 5 {
				res += 3 + run - 5
			}
			for s := 0; s+11 <= n; s++ {
				v := 0
				for k := range 11 {
					v <<= 1
					if at(i, s+k, col) {
						v |= 1
					}
				}
				if v == 0b10111010000 || v == 0b00001011101 {
					res += 40
				}
			}
		}
	}
	dark := 0
	for y := range n {
		for x := range n {
			if q.mod[y][x] {
				dark++
				if x+1 < n && y+1 < n && q.mod[y][x+1] && q.mod[y+1][x] && q.mod[y+1][x+1] {
					res += 3
				}
			} else if x+1 < n && y+1 < n && !q.mod[y][x+1] && !q.mod[y+1][x] && !q.mod[y+1][x+1] {
				res += 3
			}
		}
	}
	total := n * n
	k := (abs(dark*20-total*10)+total-1)/total - 1
	return res + k*10
}

// svg: beyaz zeminli, 4 modül sessiz bölgeli tek <path> SVG.
func (q *qrCode) svg() string {
	const quiet = 4
	n := q.size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR code"><rect width="%d" height="%d" fill="#fff"/><path fill="#000" d="`, n, n, n, n)
	for y := range q.size {
		for x := range q.size {
			if q.mod[y][x] {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}
