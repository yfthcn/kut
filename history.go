package main

import (
	"compress/gzip"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---- Etkinlik günlüğü: kim, ne zaman, ne yaptı (activity.jsonl, 0600) ----

const (
	actCap       = 20000 // bellekte tutulan en çok olay (üstü eskiden başlayarak atılır)
	actDefault   = 300   // arayüzde ilk gösterilen olay sayısı
	actCompactAt = 1500  // dosyada fazladan bu kadar satır birikince yeniden yaz
)

type Event struct {
	T    int64  `json:"t"`
	IP   string `json:"ip"`
	User string `json:"u,omitempty"` // işlemi yapan hesap
	Kind string `json:"kind"`
	Text string `json:"text"` // yazıldığı anda sunucu dilinde metin (bildirim, dışa aktarma, arama); eski kayıtlarda tek bilgi
	// Code + Params: arayüz olayı izleyenin dilinde yeniden yazar (katalog anahtarı, ör. "log.peer_create"). Eski kayıtlarda boş.
	Code   string         `json:"code,omitempty"`
	Params map[string]any `json:"params,omitempty"`
}

type activity struct {
	mu    sync.Mutex
	path  string
	evs   []Event
	lines int         // dosyadaki yaklaşık satır sayısı
	onAdd func(Event) // olay eklenince (kilit dışında) çağrılır; bildirimler için
}

func loadActivity(path string) *activity {
	l := &activity{path: path}
	b, err := os.ReadFile(path) //nolint:gosec // G304: path veri dizinindeki sabit activity.jsonl yolu; HTTP girdisi yok
	if err != nil {
		return l
	}
	for ln := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		var e Event
		if json.Unmarshal([]byte(ln), &e) == nil && e.T != 0 {
			l.evs = append(l.evs, e)
		}
	}
	l.lines = len(l.evs)
	if len(l.evs) > actCap {
		l.evs = l.evs[len(l.evs)-actCap:]
	}
	if l.lines > len(l.evs)+actCompactAt {
		l.rewrite()
	}
	return l
}

func (l *activity) rewrite() {
	var b strings.Builder
	for _, e := range l.evs {
		j, _ := json.Marshal(e)
		b.Write(j)
		b.WriteByte('\n')
	}
	if writeFileAtomic(l.path, []byte(b.String())) == nil {
		l.lines = len(l.evs)
	}
}

func (l *activity) add(e Event) {
	if l == nil {
		return
	}
	if cb := l.onAdd; cb != nil {
		defer cb(e) // kilit bırakıldıktan sonra çalışır
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, e)
	if len(l.evs) > actCap {
		l.evs = l.evs[len(l.evs)-actCap:]
	}
	if l.path == "" {
		return
	}
	if f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil { //nolint:gosec // G703: veri dizini + sabit dosya adı
		j, _ := json.Marshal(e)
		_, werr := f.Write(append(j, '\n'))
		_ = f.Close()
		if werr != nil {
			log.Printf("etkinlik günlüğü yazılamadı: %v", werr)
		} else {
			l.lines++
		}
	}
	if l.lines > len(l.evs)+actCompactAt {
		l.rewrite()
	}
}

// list: en yeni olaylar başta.
func (l *activity) list(n int) []Event {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, 0, min(n, len(l.evs)))
	for i := len(l.evs) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, l.evs[i])
	}
	return out
}

// compact: cutoff'tan eski olayları günlükten çıkarır. archive açıksa önce aylık dosyalara (activity-YYYY-MM.jsonl.gz)
// eklenir; arşiv yazılamazsa hiçbir şey silinmez. gzip parçaları art arda eklenebilir, dosya tek akış gibi okunur.
func (l *activity) compact(cutoff int64, archDir string, archive bool) (int, error) {
	if l == nil {
		return 0, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	var keep, old []Event
	for _, e := range l.evs {
		if e.T < cutoff {
			old = append(old, e)
		} else {
			keep = append(keep, e)
		}
	}
	if len(old) == 0 {
		return 0, nil
	}
	if archive && archDir != "" {
		if err := os.MkdirAll(archDir, 0o700); err != nil {
			return 0, err
		}
		byMonth := map[string][]Event{}
		for _, e := range old {
			m := time.Unix(e.T, 0).Format("2006-01")
			byMonth[m] = append(byMonth[m], e)
		}
		for m, evs := range byMonth {
			f, err := os.OpenFile(filepath.Join(archDir, "activity-"+m+".jsonl.gz"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: yol veri dizini + sabit arşiv dizini + ay damgası (zaman kaynaklı); HTTP girdisi yok
			if err != nil {
				return 0, err
			}
			gz := gzip.NewWriter(f)
			for _, e := range evs {
				j, _ := json.Marshal(e)
				_, _ = gz.Write(append(j, '\n')) // hata yapışkandır, aşağıdaki gz.Close() döndürür
			}
			if err := gz.Close(); err != nil {
				_ = f.Close()
				return 0, err
			}
			if err := f.Close(); err != nil {
				return 0, err
			}
		}
	}
	l.evs = keep
	if l.path != "" {
		l.rewrite()
	}
	return len(old), nil
}

// pruneArchives: months aydan eski aylık arşivleri siler (0 = hiç silme).
func pruneArchives(dir string, months int, now time.Time) int {
	if months <= 0 {
		return 0
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	limit := now.AddDate(0, -months, 0).Format("2006-01")
	n := 0
	for _, e := range ents {
		nm := e.Name()
		if !strings.HasPrefix(nm, "activity-") || !strings.HasSuffix(nm, ".jsonl.gz") {
			continue
		}
		m := strings.TrimSuffix(strings.TrimPrefix(nm, "activity-"), ".jsonl.gz")
		if _, err := time.Parse("2006-01", m); err == nil && m < limit {
			if os.Remove(filepath.Join(dir, nm)) == nil {
				n++
			}
		}
	}
	return n
}

// oldest: en eski olayın zamanı (0 = günlük boş).
func (l *activity) stats() (total int, oldest int64) {
	if l == nil {
		return 0, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.evs) > 0 {
		oldest = l.evs[0].T
	}
	return len(l.evs), oldest
}
