package main

import (
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

// validEndpoint: sunucunun genel IP'si ya da alan adı (port olmadan).
func validEndpoint(ep string) (string, error) {
	ep = strings.TrimSpace(ep)
	ep = strings.TrimSuffix(strings.TrimPrefix(ep, "["), "]")
	if ep == "" {
		return "", ue("settings.endpoint_empty", nil)
	}
	if strings.ContainsAny(ep, "\r\n") {
		return "", ue("settings.endpoint_invalid", nil)
	}
	if a, err := netip.ParseAddr(ep); err == nil {
		// Bölge kısmı (%...) satır sonu dahil her şeyi taşır ve istemci yapılandırmasına satır olarak yazılır.
		if a.Zone() != "" {
			return "", ue("settings.endpoint_zone", nil)
		}
		return a.String(), nil
	}
	if strings.Contains(ep, ":") {
		return "", ue("settings.endpoint_port", nil)
	}
	if !hostRe.MatchString(ep) {
		return "", ue("settings.endpoint_invalid", nil)
	}
	return ep, nil
}

// validDNS: virgülle ayrılmış en fazla 3 IP; boş olabilir.
func validDNS(s string) (string, error) {
	var out []string
	for f := range strings.SplitSeq(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil || a.Zone() != "" {
			return "", ue("settings.dns_invalid", map[string]any{"dns": strconv.Quote(f)})
		}
		out = append(out, a.String())
	}
	if len(out) > 3 {
		return "", ue("settings.dns_too_many", map[string]any{"max": 3})
	}
	return strings.Join(out, ", "), nil
}

type settingsIn struct {
	Endpoint     string `json:"endpoint"`
	Port         int    `json:"port"`
	DNS          string `json:"dns"`
	MTU          int    `json:"mtu"`
	Keepalive    int    `json:"keepalive"`
	BlockPrivate bool   `json:"block_private"`
	PeerFree     bool   `json:"unprofiled_free"`
	UpdateCheck  bool   `json:"update_check"`
	IPv6         bool   `json:"ipv6"`
}

func (a *App) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s := a.getSrv()
	c := s.cfg()
	writeJSON(w, http.StatusOK, map[string]any{
		"endpoint": s.Endpoint, "port": s.Port, "dns": c.DNS, "mtu": c.MTU, "keepalive": c.Keepalive,
		"block_private": c.BlockPrivate, "unprofiled_free": c.PeerFree, "update_check": c.UpdateCheck,
		"ipv6": c.IPv6, "ula": c.ULA, "ipv6_tools": haveIP6Tables(), "ipv6_route": func() bool { ok, _ := hostV6Route(); return ok }(),
		"subnet": s.prefix().String(), "iface": s.Iface, "listen": a.listen, "conf_path": s.ConfPath,
		"server_lang": a.srvLang(),
	})
}

func (a *App) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var in settingsIn
	if !decode(w, r, &in) {
		return
	}
	ep, err := validEndpoint(in.Endpoint)
	if err != nil {
		errOf(w, http.StatusBadRequest, err)
		return
	}
	if in.Port < 1 || in.Port > 65535 {
		errCode(w, http.StatusBadRequest, "settings.bad_port", nil)
		return
	}
	dns, err := validDNS(in.DNS)
	if err != nil {
		errOf(w, http.StatusBadRequest, err)
		return
	}
	if in.MTU != 0 && (in.MTU < 1280 || in.MTU > 1500) {
		errCode(w, http.StatusBadRequest, "settings.bad_mtu", nil)
		return
	}
	if in.Keepalive < 0 || in.Keepalive > 120 {
		errCode(w, http.StatusBadRequest, "settings.bad_keepalive", nil)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.getSrv()
	oc := old.cfg()
	ns := old
	ns.Endpoint, ns.Port = ep, in.Port
	nc := Settings{DNS: dns, MTU: in.MTU, Keepalive: in.Keepalive, BlockPrivate: in.BlockPrivate, PeerFree: in.PeerFree, UpdateCheck: in.UpdateCheck, IPv6: in.IPv6, ULA: oc.ULA, Lang: oc.Lang}
	if in.IPv6 {
		if !a.dry && !haveIP6Tables() {
			errCode(w, http.StatusBadRequest, "settings.need_ip6tables", nil)
			return
		}
		if nc.ULA == "" {
			u, err := newULA()
			if err != nil {
				errCode(w, http.StatusInternalServerError, "settings.ula_failed", nil)
				return
			}
			nc.ULA = u
		}
	}
	ns.Settings = &nc

	a.setSrv(ns)
	if err := a.apply(a.peers); err != nil {
		a.setSrv(old)
		a.rollback()
		errCode(w, http.StatusInternalServerError, "apply.failed", map[string]any{"msg": cliErrText(a.reqLang(r), err)})
		return
	}
	if err := a.saveServer(ns); err != nil {
		errCode(w, http.StatusInternalServerError, "apply.not_saved", map[string]any{"msg": err.Error()})
		return
	}

	// Her değişen ayar ayrı bir olay satırıdır: birleşik tek cümle kataloğa sığmaz, her parça izleyenin dilinde yazılır.
	var evs []logEv
	add := func(key string, params map[string]any) { evs = append(evs, logEv{"log.settings." + key, params}) }
	if old.Endpoint != ep {
		add("change_endpoint", nil)
	}
	if old.Port != in.Port {
		add("change_port", nil)
	}
	if oc.DNS != nc.DNS {
		add("change_dns", nil)
	}
	if oc.MTU != nc.MTU {
		add("change_mtu", nil)
	}
	if oc.Keepalive != nc.Keepalive {
		add("change_keepalive", nil)
	}
	if oc.BlockPrivate != nc.BlockPrivate {
		add("change_block_private", nil)
	}
	if oc.PeerFree != nc.PeerFree {
		add("change_unprofiled_free", nil)
	}
	if oc.UpdateCheck != nc.UpdateCheck {
		add("change_update_check", nil)
	}
	if oc.IPv6 != nc.IPv6 {
		if nc.IPv6 {
			add("change_ipv6_on", map[string]any{"ula": nc.ULA})
		} else {
			add("change_ipv6_off", nil)
		}
	}
	if len(evs) == 0 {
		add("nochange", nil)
	}
	a.logReqEvs(r, "settings", evs)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	me := userOf(r)
	if !a.lim.allow(ip, me) { // deneme doğrulamadan önce sayılır (eşzamanlı istekler sınırı aşmasın); başarı sıfırlar
		errCode(w, http.StatusTooManyRequests, "too_many_attempts", nil)
		return
	}
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !decode(w, r, &in) {
		return
	}
	if me == localUser {
		errCode(w, http.StatusBadRequest, "password.local_channel", nil)
		return
	}
	old, _, found := a.lookupUser(me)
	if !found || !old.verify(in.Current) {
		a.logReqT(r, "password_fail", "log.password_fail", nil)
		errCode(w, http.StatusForbidden, "password.wrong_current", nil)
		return
	}
	rec, err := newAdmin(in.New)
	if err != nil {
		errOf(w, http.StatusBadRequest, err)
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	cur, _, _ := a.lookupUser(me)
	rec = rec.withPrefsFrom(cur) // 2FA parola değişince kapanmasın
	if err := a.saveUserRec(me, rec); err != nil {
		errCode(w, http.StatusInternalServerError, "password.save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.lim.succeed(ip, me)
	if c, err := r.Cookie(cookieName); err == nil {
		a.sess.revokeExcept(me, c.Value) // hesabın diğer oturumları düşer
	}
	a.logReqT(r, "password", "log.password", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handlePutServerLang: sunucu varsayılan dili. Güvenlik duvarına dokunmaz, yalnızca server.json'a yazar.
func (a *App) handlePutServerLang(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Lang string `json:"lang"`
	}
	if !decode(w, r, &in) {
		return
	}
	l := normLang(in.Lang)
	if l == "" {
		errCode(w, http.StatusBadRequest, "bad_lang", nil)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ns := a.getSrv()
	c := ns.cfg()
	c.Lang = l
	ns.Settings = &c
	if err := a.saveServer(ns); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.setSrv(ns)
	a.logReqT(r, "settings", "log.settings.lang", map[string]any{"lang": l})
	writeJSON(w, http.StatusOK, map[string]string{"lang": l})
}
