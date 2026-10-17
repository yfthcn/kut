package main

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// eventGroup: olay türünün süzgeç grubu.
func eventGroup(kind string) string {
	switch kind {
	case "login", "logout":
		return "giris"
	case "login_fail", "password_fail", "totp_fail":
		return "guvenlik"
	case "peer_create", "peer_delete", "peer_edit", "peer_toggle", "peer_freeze", "peer_unfreeze", "peer_regenerate", "peer_bulk":
		return "cihaz"
	case "policy_create", "policy_edit", "policy_delete":
		return "profil"
	case "user_create", "user_edit", "user_delete", "password", "totp_on", "totp_off":
		return "hesap"
	case "settings", "apply":
		return "ayar"
	}
	return "sistem" // unfreeze_auto, peer_expired, schedule, güncelleme denetimi…
}

// filterEvents: ?q= (metin/IP/hesap), ?u= (hesap), ?since= (son N saniye), ?g= (virgüllü gruplar).
// Dönüş: süzülmüş olaylar ve grup sayıları (grup süzgeci hariç diğerleri uygulanmış hâlde).
func filterEvents(evs []Event, q url.Values, now time.Time) ([]Event, map[string]int) {
	text := strings.ToLower(strings.TrimSpace(q.Get("q")))
	user := strings.ToLower(strings.TrimSpace(q.Get("u")))
	var since int64
	if n, err := strconv.ParseInt(q.Get("since"), 10, 64); err == nil && n > 0 {
		since = now.Unix() - n
	}
	groups := map[string]bool{}
	for g := range strings.SplitSeq(q.Get("g"), ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups[g] = true
		}
	}
	counts := map[string]int{}
	out := []Event{}
	for _, e := range evs {
		if since > 0 && e.T < since {
			continue
		}
		if user != "" && strings.ToLower(e.User) != user {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(e.Text+" "+e.IP+" "+e.User+" "+e.Kind), text) {
			continue
		}
		g := eventGroup(e.Kind)
		counts[g]++
		if len(groups) > 0 && !groups[g] {
			continue
		}
		out = append(out, e)
	}
	return out, counts
}

// csvSafe: Excel/Sheets'in hücreyi formül sanmasını engeller (CSV enjeksiyonu).
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// handleLogExport: etkinlik günlüğünü CSV ya da JSON olarak indirir (saklanan son olaylar, eskiden yeniye).
func (a *App) handleLogExport(w http.ResponseWriter, r *http.Request) {
	evs, _ := filterEvents(a.act.list(actCap), r.URL.Query(), time.Now())
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	stamp := time.Now().Format("20060102-150405")
	if r.URL.Query().Get("format") == "json" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="kut-log-`+stamp+`.json"`)
		_ = json.NewEncoder(w).Encode(evs)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kut-log-`+stamp+`.csv"`)
	cw := csv.NewWriter(w)
	// başlık sunucu dilinde: olay metinleri (Text) de yazıldıkları anda sunucu dilinde üretilir
	l := a.srvLang()
	_ = cw.Write([]string{T(l, "logexport.col.time", nil), T(l, "logexport.col.source", nil), T(l, "logexport.col.user", nil), T(l, "logexport.col.event", nil), T(l, "logexport.col.text", nil)})
	for _, e := range evs {
		_ = cw.Write([]string{time.Unix(e.T, 0).Format(time.RFC3339), csvSafe(e.IP), csvSafe(e.User), csvSafe(e.Kind), csvSafe(e.Text)})
	}
	cw.Flush()
}
