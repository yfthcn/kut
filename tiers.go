package main

// Trafik geçmişi: çok katmanlı halkalar (azalan çözünürlük). Bellekte tutulur, 10 dakikada bir ve kapanırken
// history.json.gz dosyasına yazılır; servis yeniden başlasa da grafikler silinmez.

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"slices"
	"sync"
	"time"
)

type sample struct {
	T  int64  `json:"t"`
	Rx uint64 `json:"rx"` // sunucunun aldığı (profillerin yüklemesi)
	Tx uint64 `json:"tx"` // sunucunun gönderdiği (profillerin indirmesi)
}

type tier struct {
	name string
	step int64 // örnekler arası en az sn
	keep int   // en çok örnek
}

// 1 saat @15 sn · 24 saat @5 dk · 7 gün @30 dk · 30 gün @2 sa
var tiers = [4]tier{{"hour", 15, 240}, {"day", 300, 288}, {"week", 1800, 336}, {"month", 7200, 360}}

func rangeLevel(r string) int {
	for i, t := range tiers {
		if t.name == r {
			return i
		}
	}
	return 0
}

type series [4][]sample

func (s *series) add(x sample) {
	for i, t := range tiers {
		n := len(s[i])
		tol := int64(0)
		if t.step <= 15 {
			tol = 1 // izleyici turu birkaç ms oynayabilir
		}
		if n == 0 || x.T-s[i][n-1].T >= t.step-tol {
			s[i] = append(s[i], x)
			if len(s[i]) > t.keep {
				s[i] = s[i][len(s[i])-t.keep:]
			}
		}
	}
}

// trim: kapsama süresinden eski örnekleri atar (diskten yüklerken).
func (s *series) trim(now int64) {
	for i, t := range tiers {
		lim := now - t.step*int64(t.keep) - t.step
		k := 0
		for k < len(s[i]) && s[i][k].T < lim {
			k++
		}
		s[i] = s[i][k:]
	}
}

type history struct {
	mu sync.Mutex
	s  series
}

func (h *history) add(x sample) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.s.add(x)
	h.mu.Unlock()
}

func (h *history) list(level int) []sample {
	if h == nil || level < 0 || level >= len(tiers) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.s[level])
}

type peerHistory struct {
	mu sync.Mutex
	m  map[string]*series // genel anahtar → katmanlar
}

func (h *peerHistory) add(pub string, x sample) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.m == nil {
		h.m = map[string]*series{}
	}
	r := h.m[pub]
	if r == nil {
		r = &series{}
		h.m[pub] = r
	}
	r.add(x)
}

// prune: silinen cihazların geçmişini bırak.
func (h *peerHistory) prune(keep map[string]bool) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for k := range h.m {
		if !keep[k] {
			delete(h.m, k)
		}
	}
}

func (h *peerHistory) list(pub string, level int) []sample {
	if h == nil || level < 0 || level >= len(tiers) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	r := h.m[pub]
	if r == nil {
		return nil
	}
	return slices.Clone(r[level])
}

// ---- Diske yazma (sıkıştırılmış, [t,rx,tx] dizileri) ----

type histFile struct {
	V      int                       `json:"v"`
	Saved  int64                     `json:"saved"`
	Global [4][][3]uint64            `json:"global"`
	Peers  map[string][4][][3]uint64 `json:"peers"`
}

func pack(s *series) (o [4][][3]uint64) {
	for i := range s {
		o[i] = make([][3]uint64, len(s[i]))
		for j, x := range s[i] {
			o[i][j] = [3]uint64{uint64(x.T), x.Rx, x.Tx} //nolint:gosec // G115: x.T unix saniyesi, hep pozitif
		}
	}
	return
}

func unpack(o [4][][3]uint64) (s series) {
	for i := range o {
		for _, x := range o[i] {
			s[i] = append(s[i], sample{T: int64(x[0]), Rx: x[1], Tx: x[2]}) //nolint:gosec // G115: 2^63 üstü değer negatife döner ve trim onu atar
		}
	}
	return
}

func saveHistory(path string, h *history, ph *peerHistory) error {
	if h == nil || ph == nil || path == "" {
		return nil
	}
	f := histFile{V: 1, Saved: time.Now().Unix(), Peers: map[string][4][][3]uint64{}}
	h.mu.Lock()
	f.Global = pack(&h.s)
	h.mu.Unlock()
	ph.mu.Lock()
	for k, s := range ph.m {
		f.Peers[k] = pack(s)
	}
	ph.mu.Unlock()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if err := json.NewEncoder(gz).Encode(f); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return writeFileAtomic(path, buf.Bytes())
}

func loadHistory(path string, h *history, ph *peerHistory, now int64) {
	fh, err := os.Open(path) //nolint:gosec // G304: path veri dizinindeki sabit history yolu; HTTP girdisi yok
	if err != nil {
		return
	}
	defer fh.Close()
	gz, err := gzip.NewReader(fh)
	if err != nil {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(gz, 64<<20))
	if err != nil {
		return
	}
	var f histFile
	if json.Unmarshal(raw, &f) != nil || f.V != 1 {
		return
	}
	g := unpack(f.Global)
	g.trim(now)
	h.mu.Lock()
	h.s = g
	h.mu.Unlock()
	ph.mu.Lock()
	ph.m = map[string]*series{}
	for k, o := range f.Peers {
		s := unpack(o)
		s.trim(now)
		ph.m[k] = &s
	}
	ph.mu.Unlock()
}
