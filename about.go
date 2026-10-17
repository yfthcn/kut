package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Hakkında bilgileri. Hepsi isteğe bağlıdır: güncelleme denetimi varsayılan olarak kapalıdır,
// kapalıyken Kut hiçbir dış adrese bağlanmaz. Hiçbir zaman otomatik güncelleme yapmaz, veri göndermez.
const (
	appName    = "Kut"
	repoSlug   = "yfthcn/kut"
	githubUser = "yfthcn"
	siteURL    = "https://kaktusdev.net"
	siteName   = "kaktusdev.net"
)

type updateResult struct {
	CheckedAt int64  `json:"checked_at"` // 0 = hiç denetlenmedi
	Latest    string `json:"latest,omitempty"`
	URL       string `json:"url,omitempty"`
	Newer     bool   `json:"newer"`
	// Code + Params: hata katalog anahtarı (err.<Code>); Error yanıt yazılırken isteği yapanın dilinde doldurulur.
	Code   string         `json:"code,omitempty"`
	Params map[string]any `json:"params,omitempty"`
	Error  string         `json:"error,omitempty"`
}

// in: sonucun lang dilindeki görünümü (önbellekteki sonuç dilden bağımsız saklanır).
func (u updateResult) in(lang string) updateResult {
	if u.Code != "" {
		u.Error = T(lang, "err."+u.Code, u.Params)
	}
	return u
}

type updateState struct {
	mu   sync.Mutex
	res  updateResult
	last time.Time // elle denetimin son başlama zamanı
}

// manualCheckGap: elle "Şimdi denetle" çağrıları arasındaki en kısa süre.
const manualCheckGap = 30 * time.Second

// throttle: son elle denetimden manualCheckGap dolmadıysa önbellekteki sonucu ve true döner;
// dolduysa zamanı now yapar ve false döner (çağıran gerçek denetimi yapar).
func (u *updateState) throttle(now time.Time) (updateResult, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.last.IsZero() && now.Sub(u.last) < manualCheckGap {
		return u.res, true
	}
	u.last = now
	return updateResult{}, false
}

func (u *updateState) get() updateResult {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.res
}

func (u *updateState) set(r updateResult) {
	u.mu.Lock()
	u.res = r
	u.mu.Unlock()
}

// parseVer: "v0.4.1" -> [0 4 1]
func parseVer(s string) ([3]int, bool) {
	var v [3]int
	s = strings.TrimPrefix(strings.TrimSpace(s), "v")
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return v, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return v, false
		}
		v[i] = n
	}
	return v, true
}

func newerVersion(latest, current string) bool {
	l, ok1 := parseVer(latest)
	c, ok2 := parseVer(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// checkUpdate: GitHub'dan son sürüm bilgisini sorar (yalnızca kullanıcı isteğiyle ya da ayar açıksa günde bir).
func (a *App) checkUpdate() updateResult {
	res := updateResult{CheckedAt: time.Now().Unix()}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://api.github.com/repos/"+repoSlug+"/releases/latest", nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "kut/"+version)
	cl := &http.Client{Timeout: 8 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		res.Code = "update.unreachable"
		a.upd.set(res)
		return res
	}
	defer resp.Body.Close() //nolint:errcheck // yanıt gövdesi okunduktan sonra kapanış hatası işlenemez
	switch {
	case resp.StatusCode == http.StatusNotFound:
		res.Code = "update.no_release"
	case resp.StatusCode != http.StatusOK:
		res.Code, res.Params = "update.http", map[string]any{"status": resp.StatusCode}
	default:
		var rel struct {
			Tag string `json:"tag_name"`
			URL string `json:"html_url"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil || rel.Tag == "" {
			res.Code = "update.bad_response"
		} else {
			res.Latest = strings.TrimPrefix(rel.Tag, "v")
			if strings.HasPrefix(rel.URL, "https://github.com/") {
				res.URL = rel.URL
			}
			res.Newer = newerVersion(rel.Tag, version)
		}
	}
	a.upd.set(res)
	return res
}

// maybeAutoCheck: ayar açıksa ve son denetimden 24 saat geçtiyse arka planda denetler.
func (a *App) maybeAutoCheck() {
	if !a.getSrv().cfg().UpdateCheck {
		return
	}
	if time.Since(time.Unix(a.upd.get().CheckedAt, 0)) < 24*time.Hour {
		return
	}
	go a.checkUpdate()
}

func (a *App) handleAbout(w http.ResponseWriter, r *http.Request) {
	rev, revTime := "", ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
				if len(rev) > 8 {
					rev = rev[:8]
				}
			case "vcs.time":
				revTime = s.Value
			}
		}
	}
	srv := a.getSrv()
	writeJSON(w, http.StatusOK, map[string]any{
		"name": appName, "tagline": T(a.reqLang(r), "login.subtitle", nil), "version": version, "schema": currentSchema,
		"go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
		"commit": rev, "commit_time": revTime,
		"repo": "https://github.com/" + repoSlug, "github_user": githubUser,
		"github": "https://github.com/" + githubUser, "site": siteURL, "site_name": siteName,
		"started": a.started.Unix(), "data_dir": a.dataDir,
		"update_check": srv.cfg().UpdateCheck, "update": a.upd.get().in(a.reqLang(r)),
	})
}

// handleUpdateCheck: kullanıcı "Şimdi denetle" dediğinde çalışır.
func (a *App) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if res, limited := a.upd.throttle(time.Now()); limited {
		writeJSON(w, http.StatusOK, res.in(a.reqLang(r)))
		return
	}
	writeJSON(w, http.StatusOK, a.checkUpdate().in(a.reqLang(r)))
}
