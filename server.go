package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"
)

//go:embed web
var webFS embed.FS

const (
	cookieName    = "kut_session"
	csrfHeader    = "X-Kut"
	maxFreezeMins = 90 * 24 * 60
	maxExpireMins = 365 * 24 * 60
	maxNoteRunes  = 120
	socketName    = "kut.sock"
)

var nameRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,31}$`)

// handler: local=true yerel yönetim soketi içindir (dosya izinleriyle korunur, oturum istemez).
func (a *App) handler(local bool) http.Handler {
	authf := a.auth
	if local {
		authf = func(next http.HandlerFunc) http.HandlerFunc {
			return func(w http.ResponseWriter, r *http.Request) { next(w, withUser(r, localUser)) }
		}
	}
	mux := http.NewServeMux()
	sub, _ := fs.Sub(webFS, "web")
	mux.HandleFunc("GET /locales/{file}", handleLocale) // parçalı kataloğun birleşik hâli
	mux.Handle("GET /", http.FileServerFS(sub))
	mux.HandleFunc("POST /api/login", a.handleLogin)
	mux.HandleFunc("GET /api/login-info", a.handleLoginInfo)
	mux.HandleFunc("GET /api/me", authf(a.handleMe))
	mux.HandleFunc("PUT /api/me/lang", authf(a.handlePutMyLang))
	mux.HandleFunc("PUT /api/settings/lang", authf(a.adminOnly(a.handlePutServerLang)))
	mux.HandleFunc("GET /api/users", authf(a.adminOnly(a.handleListUsers)))
	mux.HandleFunc("POST /api/users", authf(a.adminOnly(a.handleCreateUser)))
	mux.HandleFunc("PATCH /api/users/{name}", authf(a.adminOnly(a.handleUpdateUser)))
	mux.HandleFunc("DELETE /api/users/{name}", authf(a.adminOnly(a.handleDeleteUser)))
	mux.HandleFunc("POST /api/logout", authf(a.handleLogout))
	mux.HandleFunc("GET /api/totp", authf(a.handleTOTPStatus))
	mux.HandleFunc("POST /api/totp/setup", authf(a.handleTOTPSetup))
	mux.HandleFunc("POST /api/totp/enable", authf(a.handleTOTPEnable))
	mux.HandleFunc("POST /api/totp/disable", authf(a.handleTOTPDisable))
	if local {
		mux.HandleFunc("POST /api/local/2fa-off", a.handleLocal2FAOff)
		mux.HandleFunc("POST /api/local/passwd", a.handleLocalPasswd)
	}
	mux.HandleFunc("GET /api/status", authf(a.handleStatus))
	if !local {
		mux.HandleFunc("GET /api/stream", a.auth(a.handleStream))
	}
	mux.HandleFunc("GET /api/history", authf(a.handleHistory))
	mux.HandleFunc("GET /api/activity", authf(a.handleActivity))
	mux.HandleFunc("GET /api/peers/{id}/history", authf(a.handlePeerHistory))
	mux.HandleFunc("GET /api/activity/export", authf(a.handleLogExport))
	mux.HandleFunc("GET /api/server", authf(a.handleServer))
	mux.HandleFunc("GET /api/server/counters", authf(a.handleServerCounters))
	mux.HandleFunc("GET /api/report", authf(a.handleReport))
	mux.HandleFunc("GET /api/about", authf(a.handleAbout))
	mux.HandleFunc("POST /api/update/check", authf(a.adminOnly(a.handleUpdateCheck)))
	mux.HandleFunc("POST /api/server/apply", authf(a.handleApply))
	mux.HandleFunc("GET /api/settings", authf(a.handleGetSettings))
	mux.HandleFunc("PUT /api/settings", authf(a.handlePutSettings))
	mux.HandleFunc("GET /api/notify", authf(a.adminOnly(a.handleGetNotify)))
	mux.HandleFunc("PUT /api/notify", authf(a.adminOnly(a.handlePutNotify)))
	mux.HandleFunc("POST /api/notify/test", authf(a.adminOnly(a.handleNotifyTest)))
	mux.HandleFunc("POST /api/notify/telegram-find", authf(a.adminOnly(a.handleTelegramFind)))
	mux.HandleFunc("GET /api/maint", authf(a.adminOnly(a.handleGetMaint)))
	mux.HandleFunc("PUT /api/maint", authf(a.ownerOnly(a.handlePutMaint)))
	mux.HandleFunc("POST /api/server/restart", authf(a.adminOnly(a.handleRestart)))
	mux.HandleFunc("POST /api/backups", authf(a.ownerOnly(a.handleBackupNow)))
	mux.HandleFunc("POST /api/backups/upload", authf(a.ownerOnly(a.handleBackupUpload)))
	mux.HandleFunc("GET /api/backups/{name}", authf(a.ownerOnly(a.handleBackupGet)))
	mux.HandleFunc("DELETE /api/backups/{name}", authf(a.ownerOnly(a.handleBackupDelete)))
	mux.HandleFunc("POST /api/backups/{name}/restore", authf(a.ownerOnly(a.handleBackupRestore)))
	mux.HandleFunc("POST /api/password", authf(a.handlePassword))
	mux.HandleFunc("GET /api/ipcheck", authf(a.handleIPCheck))
	mux.HandleFunc("GET /api/reach", authf(a.handleReach))
	mux.HandleFunc("GET /api/policies", authf(a.handleListPolicies))
	mux.HandleFunc("POST /api/policies", authf(a.handleCreatePolicy))
	mux.HandleFunc("PUT /api/policies/{id}", authf(a.handleUpdatePolicy))
	mux.HandleFunc("DELETE /api/policies/{id}", authf(a.handleDeletePolicy))
	mux.HandleFunc("POST /api/peers", authf(a.handleCreatePeer))
	mux.HandleFunc("POST /api/peers/bulk", authf(a.handleBulk))
	mux.HandleFunc("PATCH /api/peers/{id}", authf(a.handleEdit))
	mux.HandleFunc("POST /api/peers/{id}/toggle", authf(a.handleToggle))
	mux.HandleFunc("POST /api/peers/{id}/freeze", authf(a.handleFreeze))
	mux.HandleFunc("POST /api/peers/{id}/unfreeze", authf(a.handleUnfreeze))
	mux.HandleFunc("POST /api/peers/{id}/regenerate", authf(a.handleRegenerate))
	mux.HandleFunc("DELETE /api/peers/{id}", authf(a.handleDelete))
	return recoverer(secure(mux))
}

// secure: güvenlik başlıkları + CSRF (durum değiştiren isteklerde özel başlık şart).
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != "1" {
			errCode(w, http.StatusForbidden, "forbidden", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			errCode(w, http.StatusUnauthorized, "no_session", nil)
			return
		}
		u, ok := a.sess.user(c.Value)
		role := a.roleOf(u)
		if !ok || role == "" { // oturum yok ya da hesap silinmiş
			errCode(w, http.StatusUnauthorized, "no_session", nil)
			return
		}
		// Varsayılan ret: bilinmeyen rol hiçbir şeye erişemez; yazma yalnızca admin'e (izleyicinin izin listesi hariç).
		if !validRole(role) {
			errCode(w, http.StatusForbidden, "forbidden", nil)
			return
		}
		if role != roleAdmin && r.Method != http.MethodGet && r.Method != http.MethodHead && !viewerMayWrite(r.URL.Path) {
			errCode(w, http.StatusForbidden, "viewer_readonly", nil)
			return
		}
		next(w, withUser(r, u))
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errJSON(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeN(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		errCode(w, http.StatusBadRequest, "bad_request", nil)
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool { return decodeN(w, r, v, 8192) }

func clientIP(r *http.Request) string {
	if r.RemoteAddr == "" || r.RemoteAddr == "@" {
		return "local"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "local"
	}
	return host
}

// apiErr: mutate içindeki doğrulama hataları için (HTTP durumu + kodlu hata).
type apiErr struct {
	status int
	err    error
}

func (e apiErr) Error() string { return e.err.Error() }
func (e apiErr) Unwrap() error { return e.err }

// logEv: tek bir olay satırı (katalog anahtarı + parametreler). Birden çok parçası olan işlemler (cihaz düzenleme,
// ayarlar) her parçayı ayrı satır olarak yazar: birleşik tek cümle kataloğa sığmaz, her parça izleyenin dilinde yazılır.
type logEv struct {
	key    string
	params map[string]any
}

func (a *App) logReqEvs(r *http.Request, kind string, evs []logEv) {
	for _, e := range evs {
		a.logReqT(r, kind, e.key, e.params)
	}
}

// logUserT: oturumu olmayan istekte (giriş) hesabı açıkça verilen olay.
func (a *App) logUserT(ip, user, kind, key string, params map[string]any) {
	a.act.add(Event{T: time.Now().Unix(), IP: ip, User: user, Kind: kind, Text: T(a.srvLang(), key, params), Code: key, Params: params})
}

// ---- Giriş / çıkış ----

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	name := normUser(in.Username)
	if name == "" {
		name = ownerName
	}
	// Her deneme doğrulamadan önce ip|hesap anahtarıyla sayılır; başarılı giriş yalnızca kendi anahtarını sıfırlar
	// (başka bir hesabın başarılı girişi sahibe yönelik denemelerin sayacını silemez).
	if !a.lim.allow(ip, name) {
		errCode(w, http.StatusTooManyRequests, "too_many_attempts", nil)
		return
	}
	rec, _, found := a.lookupUser(name)
	if !found {
		a.getAdmin().verify(in.Password) // hesap var/yok farkı süreden anlaşılmasın
	}
	if !found || !rec.verify(in.Password) {
		log.Printf("başarısız giriş: %s (%q)", ip, truncate(name, 64)) //nolint:gosec // G706: ad %q ile tırnaklı ve 64 karaktere kısaltılmış; ip RemoteAddr; ad girişten gelir: tırnaklı (satır sonu kaçışlı) ve kısaltılmış
		a.logUserT(ip, truncate(name, 64), "login_fail", "log.login_fail", nil)
		code := "bad_password"
		if strings.TrimSpace(in.Username) != "" {
			code = "bad_credentials"
		}
		errCode(w, http.StatusUnauthorized, code, nil)
		return
	}
	// Parola doğru. İki adımlı doğrulama açıksa ikinci adım gerekir.
	a.adminMu.Lock()
	rec, _, found = a.lookupUser(name) // kilit altında en güncel kayıt
	if !found {
		a.adminMu.Unlock()
		errCode(w, http.StatusUnauthorized, "no_session", nil)
		return
	}
	if rec.TOTPSecret != "" {
		if strings.TrimSpace(in.Code) == "" {
			a.adminMu.Unlock()
			writeJSON(w, http.StatusOK, map[string]bool{"totp_required": true}) // oturum yok, hata sayılmaz
			return
		}
		if !a.checkSecondFactor(&rec, in.Code) {
			a.adminMu.Unlock()
			a.logUserT(ip, truncate(name, 64), "login_fail", "log.login_fail.code", nil)
			errCode(w, http.StatusUnauthorized, "bad_code", nil)
			return
		}
		if err := a.saveUserRec(name, rec); err != nil { // kullanılan adım/kurtarma kodu kalıcı olsun
			a.adminMu.Unlock()
			errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
			return
		}
	}
	a.adminMu.Unlock()
	a.lim.succeed(ip, name)
	a.logUserT(ip, name, "login", "log.login", nil)
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: panel VPN içinde düz HTTP sunulur; Secure çerez tarayıcıda hiç gönderilmez. HttpOnly + SameSite=Strict var
		Name: cookieName, Value: a.sess.create(name), Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// truncate: en fazla n karakter (rune), kesildiyse sonuna "…".
func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.sess.revoke(c.Value)
	}
	a.logReqT(r, "logout", "log.logout", nil)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode}) //nolint:gosec // G124: bkz. yukarıdaki çerez
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Durum / geçmiş / günlük ----

type peerView struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Note        string    `json:"note"`
	IP          string    `json:"ip"`
	PublicKey   string    `json:"public_key"`
	State       string    `json:"state"` // active | disabled | frozen | expired | outside (saat penceresi dışı)
	Enabled     bool      `json:"enabled"`
	Internet    bool      `json:"internet"`
	Policy      string    `json:"policy"`               // erişim profili kimliği ("" = yok)
	PolicyName  string    `json:"policy_name"`          // adı ("" = yok)
	PolicySrc   string    `json:"policy_src,omitempty"` // "group" = grup varsayılanından geliyor
	Online      bool      `json:"online"`
	FrozenUntil int64     `json:"frozen_until"` // unix; 0 = dondurulmamış
	ExpiresAt   int64     `json:"expires_at"`   // unix; 0 = süresiz
	Group       string    `json:"group"`
	Kind        string    `json:"kind"`
	IP6         string    `json:"ip6"`
	Schedule    *Schedule `json:"schedule"`
	InWindow    bool      `json:"in_window"`   // zamanlaması yoksa true
	Handshake   int64     `json:"handshake"`   // canlı son el sıkışma
	LastSeen    int64     `json:"last_seen"`   // canlı ya da saklanmış en yeni
	InetBytes   uint64    `json:"inet_bytes"`  // panel açıldığından beri tünelden internete giden bayt
	InetLast    int64     `json:"inet_last"`   // tünelden internete son trafik (unix); 0 = görülmedi
	Rx          uint64    `json:"rx"`          // sunucunun aldığı = cihazın yüklemesi
	Tx          uint64    `json:"tx"`          // sunucunun gönderdiği = cihazın indirmesi
	Endpoint    string    `json:"endpoint"`    // canlı, yoksa son bilinen
	AllowedIPs  string    `json:"allowed_ips"` // istemcinin tünele yönlendirdiği ağlar
	Created     time.Time `json:"created"`
}

func (a *App) snapshot() ([]Peer, []Policy) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.peers), slices.Clone(a.pol)
}

func (a *App) buildStatus() map[string]any {
	peers, pols := a.snapshot()
	s := a.getSrv()
	idx := polIndex(pols)
	stats, up := a.wgDump(peers)
	nowT := time.Now()
	now := nowT.Unix()
	views := make([]peerView, 0, len(peers))
	for _, p := range peers {
		st := stats[p.PublicKey]
		state := "active"
		var until, expires int64
		if p.ExpiresAt != nil {
			expires = p.ExpiresAt.Unix()
		}
		switch {
		case p.expired(nowT):
			state = "expired"
		case !p.Enabled:
			state = "disabled"
		case p.scheduleOff(nowT):
			state = "outside"
		case p.frozen(nowT):
			state = "frozen"
			until = p.FrozenUntil.Unix()
		}
		ep := st.Endpoint
		if ep == "" {
			ep = p.LastEndpoint
		}
		allowed := s.prefix().String()
		if p.Internet {
			allowed = "0.0.0.0/0, ::/0"
		}
		pname := ""
		psrc := ""
		if pol, has := effectivePolicy(p, idx); has {
			pname = pol.Name
			if pname == "" { // atanmış ama bulunamayan profil; durum tüm izleyicilere ortak akar: sunucu dili
				pname = T(a.srvLang(), "access.policy_missing", nil)
			}
			if p.Policy == "" {
				psrc = "group"
			}
		}
		iu := a.inet.get(p.IP)
		a6 := ip6s(s, p.IP)
		if a6 != "" {
			u6 := a.inet.get(a6)
			iu.Bytes += u6.Bytes
			iu.Last = max(iu.Last, u6.Last)
		}
		views = append(views, peerView{
			ID: p.ID, Name: p.Name, Note: p.Note, IP: p.IP, PublicKey: p.PublicKey,
			State: state, Enabled: p.Enabled, Internet: p.Internet, Policy: p.Policy, PolicyName: pname, PolicySrc: psrc, FrozenUntil: until, ExpiresAt: expires, Group: p.Group, Kind: p.Kind, IP6: a6, Schedule: p.Schedule, InWindow: p.inWindow(nowT),
			Online:    state == "active" && st.Handshake > 0 && now-st.Handshake < 180,
			Handshake: st.Handshake, LastSeen: max(st.Handshake, p.LastSeen),
			InetBytes: iu.Bytes, InetLast: iu.Last, Rx: st.Rx, Tx: st.Tx, Endpoint: ep, AllowedIPs: allowed, Created: p.Created,
		})
	}
	next, _ := a.nextIP(peers)
	return map[string]any{
		"server": map[string]any{
			"endpoint": s.endpoint(), "subnet": s.prefix().String(), "iface": s.Iface, "port": s.Port,
			"public_key": s.PublicKey, "up": up, "dry_run": a.dry, "server_ip": s.serverIP().String(),
			"next_ip": next, "panel_port": a.panelPort(), "unprofiled_free": s.cfg().PeerFree, "version": version, "time": now, "tz": nowT.Format("MST -07:00"),
		},
		"peers": views,
	}
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.buildStatus())
}

// handleStream: canlı durum akışı (Server-Sent Events). Tarayıcı bağlantı koparsa kendiliğinden yeniden bağlanır.
func (a *App) handleStream(w http.ResponseWriter, r *http.Request) {
	if a.streams.Add(1) > 8 {
		a.streams.Add(-1)
		errCode(w, http.StatusTooManyRequests, "stream.too_many", nil)
		return
	}
	defer a.streams.Add(-1)
	me := userOf(r)
	if !a.sess.openStream(me) { // tek hesap küresel kotanın tamamını tüketemesin
		errCode(w, http.StatusTooManyRequests, "stream.too_many", nil)
		return
	}
	defer a.sess.closeStream(me)
	fl, ok := w.(http.Flusher)
	if !ok {
		errCode(w, http.StatusInternalServerError, "stream.unsupported", nil)
		return
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{}) // sunucunun 30 sn yazma sınırını bu bağlantı için kaldır
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	send := func(event string, v any) bool {
		b, _ := json.Marshal(v)
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	if !send("status", a.buildStatus()) {
		return
	}
	tk := time.NewTicker(4 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tk.C:
			if c, err := r.Cookie(cookieName); err != nil || !a.sess.valid(c.Value) {
				send("logout", map[string]bool{"logout": true})
				return
			}
			if !send("status", a.buildStatus()) {
				return
			}
		}
	}
}

func (a *App) handleHistory(w http.ResponseWriter, r *http.Request) {
	lv := rangeLevel(r.URL.Query().Get("range"))
	smp := a.hist.list(lv)
	if smp == nil {
		smp = []sample{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"samples": smp, "interval": int(tiers[lv].step)})
}

// handlePeerHistory: tek cihazın trafik örnekleri (?range=hour|day|week|month).
func (a *App) handlePeerHistory(w http.ResponseWriter, r *http.Request) {
	peers, _ := a.snapshot()
	for _, p := range peers {
		if p.ID == r.PathValue("id") {
			lv := rangeLevel(r.URL.Query().Get("range"))
			smp := a.phist.list(p.PublicKey, lv)
			if smp == nil {
				smp = []sample{}
			}
			iv := int(tiers[lv].step)
			writeJSON(w, http.StatusOK, map[string]any{"samples": smp, "interval": iv})
			return
		}
	}
	errCode(w, http.StatusNotFound, "peer.not_found", nil)
}

func (a *App) handleActivity(w http.ResponseWriter, r *http.Request) {
	all := a.act.list(actCap)
	evs, counts := filterEvents(all, r.URL.Query(), time.Now())
	n := 300
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 && v <= actCap {
		n = v
	}
	if len(evs) > n {
		evs = evs[:n]
	}
	users := map[string]bool{}
	for _, e := range all {
		if e.User != "" {
			users[e.User] = true
		}
	}
	ul := []string{}
	for u := range users {
		ul = append(ul, u)
	}
	slices.Sort(ul)
	total, oldest := a.act.stats()
	writeJSON(w, http.StatusOK, map[string]any{"events": evs, "counts": counts, "users": ul, "total": total, "oldest": oldest, "log_days": a.maintCfg().get().LogDays})
}

// ---- Sunucu sayfası ----

func (a *App) handleServer(w http.ResponseWriter, r *http.Request) {
	s := a.getSrv()
	peers, pols := a.snapshot()
	stats, up := a.wgDump(peers)
	fw := a.fwCheck(s, peers, pols)
	fwDetail := fw.Detail
	if fw.Key != "" { // durum metni isteği yapanın dilinde; anahtar henüz doldurulmamışsa referans dildeki Detail
		fwDetail = T(a.reqLang(r), fw.Key, fw.Params)
	}
	rules := a.fwRules(s, peers, pols, time.Now())
	active := 0
	now := time.Now()
	for _, p := range peers {
		if p.active(now) {
			active++
		}
	}
	addr := fmt.Sprintf("%s/%d", s.serverIP(), s.prefix().Bits())
	if s.v6On() {
		addr += ", " + fmt.Sprintf("%s/%d", s.serverIP6(), s.prefix6().Bits())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"iface": s.Iface, "up": up, "dry_run": a.dry,
		"address": addr, "subnet": s.prefix().String(),
		"port": s.Port, "endpoint": s.endpoint(), "public_key": s.PublicKey, "conf_path": s.ConfPath,
		"mtu": s.cfg().MTU, "listen": a.listen,
		"peers_total": len(peers), "peers_active": active, "peers_in_kernel": len(stats),
		"conf":     maskSecrets(renderServerConf(s, peers)),
		"firewall": map[string]any{"state": fw.State, "detail": fwDetail, "rules": rules, "counters": a.ruleCounters(s, peers, pols), "simulated": a.dry},
	})
}

// rollback: a.mu tutulurken, başarısız bir apply sonrası diskteki/bellekteki son iyi hâli yeniden uygular.
func (a *App) rollback() {
	if err := a.apply(a.peers); err != nil {
		log.Printf("geri alma başarısız (güvenlik duvarı/wg bellekle ayrışmış olabilir): %v", err)
	}
}

// handleApply: yapılandırmayı ve güvenlik duvarını elle yeniden uygular.
func (a *App) handleApply(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	err := a.apply(a.peers)
	a.mu.Unlock()
	if err != nil {
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return
	}
	a.logReqT(r, "apply", "log.apply", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- IP denetimi / erişim testi ----

func (a *App) handleIPCheck(w http.ResponseWriter, r *http.Request) {
	peers, _ := a.snapshot()
	lang := a.reqLang(r)
	_, err := checkIP(a.getSrv(), peers, r.URL.Query().Get("ip"), r.URL.Query().Get("id"))
	if err != nil {
		resp := map[string]any{"ok": false, "message": err.Error()}
		var ce *codedErr
		if errors.As(err, &ce) {
			resp["code"], resp["params"], resp["message"] = ce.Code, ce.Params, T(lang, "err."+ce.Code, ce.Params)
		}
		writeJSON(w, http.StatusOK, resp)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": T(lang, "access.ip_available", nil)})
}

func (a *App) handleReach(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	proto := strings.ToLower(q.Get("proto"))
	port, _ := strconv.Atoi(q.Get("port"))
	switch proto {
	case "tcp", "udp":
		if port < 1 || port > 65535 {
			errCode(w, http.StatusBadRequest, "reach.bad_port", nil)
			return
		}
	case "icmp":
	default:
		errCode(w, http.StatusBadRequest, "reach.bad_proto", nil)
		return
	}
	peers, pols := a.snapshot()
	si := slices.IndexFunc(peers, func(p Peer) bool { return p.ID == q.Get("src") })
	if si < 0 {
		errCode(w, http.StatusNotFound, "reach.src_not_found", nil)
		return
	}
	src := peers[si]
	writeJSON(w, http.StatusOK, evalReach(a.reqLang(r), peers, pols, src, q.Get("dst"), proto, port, a.panelPort(), a.getSrv().cfg().PeerFree, time.Now()))
}

// ---- Peer işlemleri ----

func newID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func validName(w http.ResponseWriter, name string) bool {
	if !nameRe.MatchString(name) {
		errCode(w, http.StatusBadRequest, "peer.bad_name", nil)
		return false
	}
	return true
}

func validNote(w http.ResponseWriter, note string) bool {
	if utf8.RuneCountInString(note) > maxNoteRunes || strings.IndexFunc(note, unicode.IsControl) >= 0 {
		errCode(w, http.StatusBadRequest, "peer.bad_note", map[string]any{"limit": maxNoteRunes})
		return false
	}
	return true
}

func policyExists(pols []Policy, id string) bool {
	for _, p := range pols {
		if p.ID == id {
			return true
		}
	}
	return false
}

// configResponse: özel anahtar içeren yapılandırmayı yalnızca bu yanıtta döndürür; diske yazılmaz.
func (a *App) configResponse(w http.ResponseWriter, priv string, p Peer) {
	cfg := a.clientConfig(priv, p)
	svg := ""
	if qr, err := qrEncode(cfg); err == nil {
		svg = qr.svg()
	}
	writeJSON(w, http.StatusOK, map[string]any{"peer": p.ID, "name": p.Name, "ip": p.IP, "ip6": ip6s(a.getSrv(), p.IP), "internet": p.Internet, "config": cfg, "qr": svg})
}

func (a *App) handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name     string    `json:"name"`
		Note     string    `json:"note"`
		Internet bool      `json:"internet"`
		IP       string    `json:"ip"`
		Policy   string    `json:"policy"`
		Expires  int       `json:"expires_minutes"` // 0 = süresiz
		Group    string    `json:"group"`
		Kind     string    `json:"kind"`
		Schedule *Schedule `json:"schedule"`
	}
	if !decode(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	note := strings.TrimSpace(in.Note)
	if !validName(w, name) || !validNote(w, note) {
		return
	}
	if in.Expires < 0 || in.Expires > maxExpireMins {
		errCode(w, http.StatusBadRequest, "peer.expiry_too_long", nil)
		return
	}
	in.Group = strings.TrimSpace(in.Group)
	if !validGroup(w, in.Group) || !validKind(w, in.Kind) {
		return
	}
	sched, serr := normalizeSchedule(in.Schedule)
	if serr != nil {
		errOf(w, http.StatusBadRequest, serr)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	for _, p := range a.peers {
		if strings.EqualFold(p.Name, name) {
			errCode(w, http.StatusConflict, "peer.name_taken", nil)
			return
		}
	}
	if in.Policy != "" && !policyExists(a.pol, in.Policy) {
		errCode(w, http.StatusBadRequest, "policy.not_found", nil)
		return
	}
	var ip string
	if strings.TrimSpace(in.IP) != "" {
		addr, err := checkIP(a.getSrv(), a.peers, in.IP, "")
		if err != nil {
			errOf(w, http.StatusConflict, err)
			return
		}
		ip = addr.String()
	} else {
		var err error
		if ip, err = a.nextIP(a.peers); err != nil {
			errOf(w, http.StatusConflict, err)
			return
		}
	}
	priv, pub, psk, err := newKeys()
	if err != nil {
		errCode(w, http.StatusInternalServerError, "peer.key_failed", map[string]any{"msg": err.Error()})
		return
	}
	peer := Peer{ID: newID(), Name: name, Note: note, PublicKey: pub, PSK: psk, IP: ip, Enabled: true, Internet: in.Internet, Policy: in.Policy, Group: in.Group, Kind: in.Kind, Schedule: sched, Created: time.Now().UTC()}
	if in.Expires > 0 {
		t := time.Now().Add(time.Duration(in.Expires) * time.Minute).UTC()
		peer.ExpiresAt = &t
	}

	next := append(slices.Clone(a.peers), peer)
	if err := a.apply(next); err != nil {
		log.Printf("apply: %v", err)
		a.rollback()
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return
	}
	a.peers = next
	if err := a.savePeers(next); err != nil {
		log.Printf("peers.json yazılamadı: %v", err)
		errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
		return
	}
	createKey := "log.peer_create.vpn"
	if peer.Internet {
		createKey = "log.peer_create.internet"
	}
	a.logReqT(r, "peer_create", createKey, map[string]any{"name": peer.Name, "ip": peer.IP})
	a.configResponse(w, priv, peer)
}

// handleRegenerate: yeni anahtar üretir; isteğe bağlı olarak IP'yi ve internet çıkışını günceller.
// İstemci config'indeki Address/AllowedIPs/DNS değiştiği için kişinin yeni config'i kurması gerekir; eski config çalışmaz.
func (a *App) handleRegenerate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Internet bool   `json:"internet"`
		IP       string `json:"ip"`
	}
	if !decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")

	a.mu.Lock()
	defer a.mu.Unlock()
	idx := slices.IndexFunc(a.peers, func(p Peer) bool { return p.ID == id })
	if idx < 0 {
		errCode(w, http.StatusNotFound, "peer.not_found", nil)
		return
	}
	newIP := a.peers[idx].IP
	if strings.TrimSpace(in.IP) != "" && strings.TrimSpace(in.IP) != newIP {
		addr, err := checkIP(a.getSrv(), a.peers, in.IP, id)
		if err != nil {
			errOf(w, http.StatusConflict, err)
			return
		}
		newIP = addr.String()
	}
	priv, pub, psk, err := newKeys()
	if err != nil {
		errCode(w, http.StatusInternalServerError, "peer.key_failed", map[string]any{"msg": err.Error()})
		return
	}
	next := slices.Clone(a.peers)
	p := next[idx]
	was, wasIP := p.Internet, p.IP
	p.PublicKey, p.PSK, p.Internet, p.IP = pub, psk, in.Internet, newIP
	p.LastSeen, p.LastEndpoint = 0, ""
	next[idx] = p
	if err := a.apply(next); err != nil {
		log.Printf("apply: %v", err)
		a.rollback()
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return
	}
	a.peers = next
	if err := a.savePeers(next); err != nil {
		log.Printf("peers.json yazılamadı: %v", err)
		errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
		return
	}
	short := func(internet bool) string { return map[bool]string{true: "inet", false: "vpn"}[internet] }
	regenKey := "log.peer_regenerate." + short(was) + "_" + short(p.Internet)
	regenParams := map[string]any{"name": p.Name}
	if wasIP != p.IP {
		regenKey += "_ip"
		regenParams["old"], regenParams["new"] = wasIP, p.IP
	}
	a.logReqT(r, "peer_regenerate", regenKey, regenParams)
	a.configResponse(w, priv, p)
}

// mutate: peer'ı bulur, f ile değiştirir, uygular, kaydeder. Uygulama başarısızsa eski hâl geri yazılır.
// Başarılıysa true döner (çağıran günlüğe yazabilir).
func (a *App) mutate(w http.ResponseWriter, r *http.Request, id string, f func(peers []Peer, i int) ([]Peer, error)) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := slices.IndexFunc(a.peers, func(p Peer) bool { return p.ID == id })
	if idx < 0 {
		errCode(w, http.StatusNotFound, "peer.not_found", nil)
		return false
	}
	next, err := f(slices.Clone(a.peers), idx)
	if err != nil {
		var ae apiErr
		if errors.As(err, &ae) {
			errOf(w, ae.status, ae.err)
		} else {
			errOf(w, http.StatusInternalServerError, err)
		}
		return false
	}
	if err := a.apply(next); err != nil {
		log.Printf("apply: %v", err)
		a.rollback()
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return false
	}
	a.peers = next
	if err := a.savePeers(next); err != nil {
		log.Printf("peers.json yazılamadı: %v", err)
		errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
		return false
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	return true
}

// handleToggle: kalıcı aç/kapa. Açıp kapamak dondurmayı da sıfırlar.
func (a *App) handleToggle(w http.ResponseWriter, r *http.Request) {
	var ev logEv
	if a.mutate(w, r, r.PathValue("id"), func(peers []Peer, i int) ([]Peer, error) {
		if peers[i].expired(time.Now()) {
			// Süresi dolmuş cihaz (monitor henüz kapatmamış olsa bile) kapalı sayılır; elle açmak onu süresiz yapar.
			peers[i].Enabled, peers[i].ExpiresAt = true, nil
		} else {
			peers[i].Enabled = !peers[i].Enabled
		}
		peers[i].FrozenUntil = nil
		ev = logEv{"log.peer_toggle.off", map[string]any{"name": peers[i].Name}}
		if peers[i].Enabled {
			ev.key = "log.peer_toggle.on"
		}
		return peers, nil
	}) {
		a.logReqT(r, "peer_toggle", ev.key, ev.params)
	}
}

// handleFreeze: süreli askıya alma. Süre dolunca monitor cihazı geri açar.
func (a *App) handleFreeze(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Minutes int `json:"minutes"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Minutes < 1 || in.Minutes > maxFreezeMins {
		errCode(w, http.StatusBadRequest, "peer.bad_freeze_time", nil)
		return
	}
	var name string
	if a.mutate(w, r, r.PathValue("id"), func(peers []Peer, i int) ([]Peer, error) {
		if !peers[i].Enabled {
			return nil, apiErr{http.StatusConflict, ue("peer.freeze_disabled", nil)}
		}
		t := time.Now().Add(time.Duration(in.Minutes) * time.Minute).UTC()
		peers[i].FrozenUntil = &t
		name = peers[i].Name
		return peers, nil
	}) {
		a.logReqT(r, "peer_freeze", "log.peer_freeze", map[string]any{"name": name, "n": in.Minutes})
	}
}

func (a *App) handleUnfreeze(w http.ResponseWriter, r *http.Request) {
	var name string
	if a.mutate(w, r, r.PathValue("id"), func(peers []Peer, i int) ([]Peer, error) {
		peers[i].FrozenUntil = nil
		name = peers[i].Name
		return peers, nil
	}) {
		a.logReqT(r, "peer_unfreeze", "log.peer_unfreeze", map[string]any{"name": name})
	}
}

func (a *App) handleEdit(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name          string    `json:"name"`
		Note          string    `json:"note"`
		Policy        *string   `json:"policy"`
		Internet      *bool     `json:"internet"`
		Expires       *int      `json:"expires_minutes"` // nil = dokunma; 0 = süresiz yap; >0 = şimdiden itibaren
		Group         *string   `json:"group"`
		Kind          *string   `json:"kind"`
		Schedule      *Schedule `json:"schedule"`
		ClearSchedule bool      `json:"clear_schedule"`
	}
	if !decode(w, r, &in) {
		return
	}
	sched, serr := normalizeSchedule(in.Schedule)
	if serr != nil {
		errOf(w, http.StatusBadRequest, serr)
		return
	}
	if in.Group != nil {
		g := strings.TrimSpace(*in.Group)
		in.Group = &g
		if !validGroup(w, g) {
			return
		}
	}
	if in.Kind != nil && !validKind(w, *in.Kind) {
		return
	}
	if in.Expires != nil && (*in.Expires < 0 || *in.Expires > maxExpireMins) {
		errCode(w, http.StatusBadRequest, "peer.expiry_too_long", nil)
		return
	}
	name := strings.TrimSpace(in.Name)
	note := strings.TrimSpace(in.Note)
	if !validName(w, name) || !validNote(w, note) {
		return
	}
	var evs []logEv
	if a.mutate(w, r, r.PathValue("id"), func(peers []Peer, i int) ([]Peer, error) {
		for j, q := range peers {
			if j != i && strings.EqualFold(q.Name, name) {
				return nil, apiErr{http.StatusConflict, ue("peer.name_taken", nil)}
			}
		}
		if peers[i].Name != name {
			evs = append(evs, logEv{"log.peer_edit.rename", map[string]any{"old": peers[i].Name, "name": name}})
		} else {
			evs = append(evs, logEv{"log.peer_edit", map[string]any{"name": name}})
		}
		peers[i].Name = name
		peers[i].Note = note
		if in.Policy != nil && *in.Policy != peers[i].Policy {
			if *in.Policy != "" && !policyExists(a.pol, *in.Policy) {
				return nil, apiErr{http.StatusBadRequest, ue("policy.not_found", nil)}
			}
			peers[i].Policy = *in.Policy
			if *in.Policy == "" {
				evs = append(evs, logEv{"log.peer_edit.policy_removed", map[string]any{"name": name}})
			} else if j := slices.IndexFunc(a.pol, func(p Policy) bool { return p.ID == *in.Policy }); j >= 0 {
				evs = append(evs, logEv{"log.peer_edit.policy_set", map[string]any{"name": name, "policy": a.pol[j].Name}})
			}
		}
		if sched != nil {
			peers[i].Schedule = sched
			// Gün listesi dile bağlı bir metindir ama olayın parametreleri tek dil için saklanır (her dilin şablonu aynı
			// yer tutucuları kullanır): sunucu dilinde yazılır, başka dilde izleyen gün kısaltmalarını o dilde görür.
			sp := map[string]any{"name": name, "days": daysText(a.srvLang(), sched.Days), "from": sched.From, "to": sched.To}
			evs = append(evs, logEv{"log.peer_edit.schedule_" + sched.Scope, sp})
		} else if in.ClearSchedule && peers[i].Schedule != nil {
			peers[i].Schedule = nil
			evs = append(evs, logEv{"log.peer_edit.schedule_removed", map[string]any{"name": name}})
		}
		if in.Group != nil && *in.Group != peers[i].Group {
			peers[i].Group = *in.Group
			if *in.Group == "" {
				evs = append(evs, logEv{"log.peer_edit.group_none", map[string]any{"name": name}})
			} else {
				evs = append(evs, logEv{"log.peer_edit.group_set", map[string]any{"name": name, "group": *in.Group}})
			}
		}
		if in.Kind != nil && *in.Kind != peers[i].Kind {
			peers[i].Kind = *in.Kind
			if *in.Kind == "" {
				evs = append(evs, logEv{"log.peer_edit.kind_other", map[string]any{"name": name}})
			} else {
				evs = append(evs, logEv{"log.peer_edit.kind_set", map[string]any{"name": name, "kind": *in.Kind}})
			}
		}
		if in.Expires != nil {
			if *in.Expires == 0 {
				if peers[i].ExpiresAt != nil {
					evs = append(evs, logEv{"log.peer_edit.expiry_removed", map[string]any{"name": name}})
				}
				peers[i].ExpiresAt = nil
			} else {
				if peers[i].expired(time.Now()) {
					peers[i].Enabled = true // süresi dolmuş cihaza yeni süre verilirse yeniden açılır
				}
				t := time.Now().Add(time.Duration(*in.Expires) * time.Minute).UTC()
				peers[i].ExpiresAt = &t
				evs = append(evs, logEv{"log.peer_edit.expiry_set", map[string]any{"name": name, "n": *in.Expires}})
			}
		}
		if in.Internet != nil && *in.Internet != peers[i].Internet {
			peers[i].Internet = *in.Internet
			if *in.Internet {
				evs = append(evs, logEv{"log.peer_edit.internet_on", map[string]any{"name": name}})
			} else {
				evs = append(evs, logEv{"log.peer_edit.internet_off", map[string]any{"name": name}})
			}
		}
		return peers, nil
	}) {
		a.logReqEvs(r, "peer_edit", evs)
	}
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := slices.IndexFunc(a.peers, func(p Peer) bool { return p.ID == id })
	if idx < 0 {
		errCode(w, http.StatusNotFound, "peer.not_found", nil)
		return
	}
	gone := a.peers[idx]
	nextPeers := slices.Concat(a.peers[:idx], a.peers[idx+1:])
	// Silinen cihazı hedef alan kuralları da kaldır (yetim kural kalmasın).
	removed := 0
	nextPols := make([]Policy, len(a.pol))
	for i, p := range a.pol {
		np := p
		np.Rules = nil
		for _, r := range p.Rules {
			if r.Target == "device" && r.Device == id {
				removed++
				continue
			}
			np.Rules = append(np.Rules, r)
		}
		if np.Rules == nil {
			np.Rules = []Rule{}
		}
		nextPols[i] = np
	}
	if err := a.applyWith(nextPeers, nextPols); err != nil {
		log.Printf("apply: %v", err)
		a.rollback()
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return
	}
	a.peers, a.pol = nextPeers, nextPols
	if err := a.savePeers(nextPeers); err != nil {
		log.Printf("peers.json yazılamadı: %v", err)
		errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
		return
	}
	if removed > 0 {
		if err := a.savePolicies(nextPols); err != nil {
			log.Printf("policies.json yazılamadı: %v", err)
			errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
			return
		}
	}
	delParams := map[string]any{"name": gone.Name, "ip": gone.IP}
	if removed > 0 {
		delParams["n"] = removed
		a.logReqT(r, "peer_delete", "log.peer_delete.rules", delParams)
	} else {
		a.logReqT(r, "peer_delete", "log.peer_delete", delParams)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Erişim profilleri ----

type policyView struct {
	Policy
	Devices []map[string]string `json:"devices"`
	// GroupDevices: profili grup varsayılanı olarak kullanan (kendi profili olmayan) cihazlar.
	GroupDevices []map[string]string `json:"group_devices"`
}

func (a *App) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	peers, pols := a.snapshot()
	out := make([]policyView, 0, len(pols))
	for _, p := range pols {
		v := policyView{Policy: p, Devices: []map[string]string{}, GroupDevices: []map[string]string{}}
		if v.Rules == nil {
			v.Rules = []Rule{}
		}
		for _, d := range peers {
			if d.Policy == p.ID {
				v.Devices = append(v.Devices, map[string]string{"id": d.ID, "name": d.Name})
			} else if d.Policy == "" && d.Group != "" {
				for _, g := range p.Groups {
					if strings.EqualFold(g, d.Group) {
						v.GroupDevices = append(v.GroupDevices, map[string]string{"id": d.ID, "name": d.Name})
					}
				}
			}
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"policies": out, "panel_port": a.panelPort()})
}

type policyIn struct {
	Name   string   `json:"name"`
	Desc   string   `json:"desc"`
	Rules  []Rule   `json:"rules"`
	Groups []string `json:"groups"`
}

func (a *App) savePolicyChange(w http.ResponseWriter, r *http.Request, next []Policy) bool {
	if err := a.applyWith(a.peers, next); err != nil {
		log.Printf("apply: %v", err)
		a.rollback()
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return false
	}
	a.pol = next
	if err := a.savePolicies(next); err != nil {
		log.Printf("policies.json yazılamadı: %v", err)
		errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
		return false
	}
	return true
}

func (a *App) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var in policyIn
	if !decodeN(w, r, &in, 64<<10) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	np, err := normalizePolicy(Policy{Name: in.Name, Desc: in.Desc, Rules: in.Rules, Groups: in.Groups}, a.peers)
	if err != nil {
		errOf(w, http.StatusBadRequest, err)
		return
	}
	for _, p := range a.pol {
		if strings.EqualFold(p.Name, np.Name) {
			errCode(w, http.StatusConflict, "policy.name_taken", nil)
			return
		}
	}
	np.ID, np.Created = newID(), time.Now().UTC()
	if err := checkGroupClaims(a.pol, np); err != nil {
		errOf(w, http.StatusConflict, err)
		return
	}
	if !a.savePolicyChange(w, r, append(slices.Clone(a.pol), np)) {
		return
	}
	a.logReqT(r, "policy_create", "log.policy_create", map[string]any{"name": np.Name, "n": len(np.Rules)})
	writeJSON(w, http.StatusOK, map[string]string{"id": np.ID})
}

func (a *App) handleUpdatePolicy(w http.ResponseWriter, r *http.Request) {
	var in policyIn
	if !decodeN(w, r, &in, 64<<10) {
		return
	}
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := slices.IndexFunc(a.pol, func(p Policy) bool { return p.ID == id })
	if idx < 0 {
		errCode(w, http.StatusNotFound, "policy.not_found", nil)
		return
	}
	np, err := normalizePolicy(Policy{Name: in.Name, Desc: in.Desc, Rules: in.Rules, Groups: in.Groups}, a.peers)
	if err != nil {
		errOf(w, http.StatusBadRequest, err)
		return
	}
	for j, p := range a.pol {
		if j != idx && strings.EqualFold(p.Name, np.Name) {
			errCode(w, http.StatusConflict, "policy.name_taken", nil)
			return
		}
	}
	np.ID, np.Created = id, a.pol[idx].Created
	if err := checkGroupClaims(a.pol, np); err != nil {
		errOf(w, http.StatusConflict, err)
		return
	}
	next := slices.Clone(a.pol)
	next[idx] = np
	if !a.savePolicyChange(w, r, next) {
		return
	}
	a.logReqT(r, "policy_edit", "log.policy_edit", map[string]any{"name": np.Name, "n": len(np.Rules)})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleDeletePolicy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	a.mu.Lock()
	defer a.mu.Unlock()
	idx := slices.IndexFunc(a.pol, func(p Policy) bool { return p.ID == id })
	if idx < 0 {
		errCode(w, http.StatusNotFound, "policy.not_found", nil)
		return
	}
	var users []string
	for _, p := range a.peers {
		if p.Policy == id {
			users = append(users, p.Name)
		}
	}
	if len(users) > 0 {
		errCode(w, http.StatusConflict, "policy.in_use", map[string]any{"n": len(users), "devices": strings.Join(users, ", ")})
		return
	}
	name := a.pol[idx].Name
	next := slices.Concat(a.pol[:idx], a.pol[idx+1:])
	if !a.savePolicyChange(w, r, next) {
		return
	}
	a.logReqT(r, "policy_delete", "log.policy_delete", map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- Çalıştırma ----

// chmodSocket: yerel soketin izin ayarı; testte başarısızlığı sınamak için değiştirilebilir.
var chmodSocket = os.Chmod

// listenLocalSocket: yerel yönetim soketini açar ve yalnızca sahibine (0600) erişilebilir yapar. İzin ayarlanamazsa
// soket kapatılır (geniş izinli bir soket root yönetimini açardı) ve nil döner; soket açılamazsa da nil döner.
func listenLocalSocket(sockPath string) net.Listener {
	sl, err := net.Listen("unix", sockPath) //nolint:noctx // başlangıçta bir kez dinlenir; iptal edilecek bağlam yok
	if err != nil {
		log.Printf("yerel soket açılamadı (kut add/list/doctor çalışmaz): %v", err)
		return nil
	}
	if err := chmodSocket(sockPath, 0o600); err != nil {
		log.Printf("yerel soketin izni ayarlanamadı, soket kapatıldı (kut add/list/doctor çalışmaz): %v", err)
		_ = sl.Close()
		return nil
	}
	return sl
}

func (a *App) serve(addr string) error {
	a.listen = addr
	a.mu.Lock()
	if err := a.apply(a.peers); err != nil {
		log.Printf("başlangıç uygulaması başarısız (devam ediliyor): %v", err)
	}
	a.mu.Unlock()

	ln, err := net.Listen("tcp", addr) //nolint:noctx // başlangıçta bir kez dinlenir; iptal edilecek bağlam yok
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	timeouts := func(h http.Handler) *http.Server {
		return &http.Server{
			Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
			BaseContext: func(net.Listener) context.Context { return ctx }, // SIGTERM'de SSE akışları hemen biter
		}
	}
	srv := timeouts(a.handler(false))

	// Yerel yönetim soketi: `kut add/list/doctor` buradan konuşur. Yalnızca sahibi (root) erişir.
	sockPath := filepath.Join(a.dataDir, socketName)
	_ = os.Remove(sockPath)
	var lsrv *http.Server
	if sl := listenLocalSocket(sockPath); sl != nil {
		lsrv = timeouts(a.handler(true))
		go func() {
			if err := lsrv.Serve(sl); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("yerel soket sunucusu durdu: %v", err)
			}
		}()
	}

	go a.monitor(ctx)
	go a.notif().run(ctx)
	a.logEventT("sistem", "start", "log.start", map[string]any{"version": version})
	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(sh); err != nil {
			log.Printf("panel kapatılamadı: %v", err)
		}
		if err := saveHistory(filepath.Join(a.dataDir, "history.json.gz"), a.hist, a.phist); err != nil {
			log.Printf("trafik geçmişi yazılamadı: %v", err)
		}
		if lsrv != nil {
			lsh, lcancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer lcancel()
			_ = lsrv.Shutdown(lsh)
			_ = os.Remove(sockPath)
		}
	}()
	mode := ""
	if a.dry {
		mode = " [dry-run]"
	}
	log.Printf("Kut %s http://%s dinliyor%s", version, ln.Addr(), mode)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("sunucu: %w", err)
	}
	<-done // geçmiş diske yazılmadan süreç çıkmasın
	return nil
}

func ip6s(s Server, v4 string) string {
	if a := s.ip6Of(v4); a.IsValid() {
		return a.String()
	}
	return ""
}
