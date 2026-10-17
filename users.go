package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Hesaplar: "admin" (sahip) admin.json'da durur ve silinemez; ek hesaplar users.json'dadır.
// Roller: "admin" her şeyi yapar, "viewer" yalnızca izler (kendi parolası ve 2FA'sı hariç değiştirme yok).
const (
	ownerName  = "admin"
	localUser  = "yerel" // yerel yönetim soketi (kut komutu); rol: admin
	roleAdmin  = "admin"
	roleViewer = "viewer"
)

var userRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,31}$`)

type User struct {
	Name string `json:"name"`
	Role string `json:"role"`
	adminRecord
}

func usersPath(dir string) string { return filepath.Join(dir, "users.json") }

func loadUsers(dir string) ([]User, error) {
	var us []User
	if err := loadJSON(usersPath(dir), &us); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ue("account.users_unreadable", map[string]any{"msg": err.Error()})
	}
	if err := validateAccounts(us); err != nil {
		return nil, err
	}
	return us, nil
}

type userKey struct{}

// userOf: isteği yapan hesap (oturumdan); yerel soket için "yerel".
func userOf(r *http.Request) string {
	if u, ok := r.Context().Value(userKey{}).(string); ok {
		return u
	}
	return ""
}

func withUser(r *http.Request, u string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), userKey{}, u))
}

func normUser(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// lookupUser: hesabın kaydı ve rolü. Boş ad = sahip.
func (a *App) lookupUser(name string) (adminRecord, string, bool) {
	name = normUser(name)
	if name == "" || name == ownerName {
		return a.getAdmin(), roleAdmin, true
	}
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	for _, u := range a.users {
		if u.Name == name {
			return u.adminRecord, u.Role, true
		}
	}
	return adminRecord{}, "", false
}

func (a *App) roleOf(name string) string {
	if name == "" { // kimliksiz istek; lookupUser'ın "boş = sahip" kuralı yalnızca giriş akışı içindir
		return ""
	}
	if name == localUser {
		return roleAdmin
	}
	_, role, ok := a.lookupUser(name)
	if !ok {
		return ""
	}
	return role
}

// saveUserRec: hesabın parola/2FA kaydını kalıcı yazar. Çağıran adminMu'yu tutmalı.
func (a *App) saveUserRec(name string, rec adminRecord) error {
	name = normUser(name)
	if name == "" || name == ownerName {
		if err := saveJSON(adminPath(a.dataDir), rec); err != nil {
			return err
		}
		a.setAdmin(rec)
		return nil
	}
	a.cfgMu.RLock()
	next := slices.Clone(a.users)
	a.cfgMu.RUnlock()
	i := slices.IndexFunc(next, func(u User) bool { return u.Name == name })
	if i < 0 {
		return ue("account.not_found", nil)
	}
	next[i].adminRecord = rec
	return a.setUsers(next)
}

func (a *App) setUsers(next []User) error {
	if next == nil {
		next = []User{}
	}
	if err := saveJSON(usersPath(a.dataDir), next); err != nil {
		return err
	}
	a.cfgMu.Lock()
	a.users = next
	a.cfgMu.Unlock()
	return nil
}

func viewerMayWrite(path string) bool {
	switch path {
	case "/api/logout", "/api/password", "/api/totp/setup", "/api/totp/enable", "/api/totp/disable", "/api/me/lang":
		return true
	}
	return false
}

// adminOnly: yalnızca admin rolü.
func (a *App) adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.roleOf(userOf(r)) != roleAdmin {
			errCode(w, http.StatusForbidden, "auth.admin_required", nil)
			return
		}
		next(w, r)
	}
}

// ownerOnly: yalnızca sahip hesap ya da yerel soket (root). Yedekler tüm hesapların parola özetlerini, TOTP
// sırlarını ve sunucunun özel anahtarını taşır; geri yükleme sahibin parolasını değiştirebilir.
func (a *App) ownerOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if u := userOf(r); u != ownerName && u != localUser {
			errCode(w, http.StatusForbidden, "auth.owner_required", nil)
			return
		}
		next(w, r)
	}
}

// ---- HTTP ----

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	rec, role, _ := a.lookupUser(u)
	if u == localUser {
		role = roleAdmin
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": u, "role": role, "owner": u == ownerName || u == localUser, "totp": rec.TOTPSecret != "", "lang": rec.Lang, "server_lang": a.srvLang()})
}

// handlePutMyLang: oturumdaki hesabın panel dili. Boş dil tercihi siler (tarayıcı diline bırakır).
func (a *App) handlePutMyLang(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Lang string `json:"lang"`
	}
	if !decode(w, r, &in) {
		return
	}
	l := normLang(in.Lang)
	if strings.TrimSpace(in.Lang) != "" && l == "" {
		errCode(w, http.StatusBadRequest, "bad_lang", nil)
		return
	}
	u := userOf(r)
	if u == localUser {
		errCode(w, http.StatusBadRequest, "bad_request", nil)
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	rec, _, ok := a.lookupUser(u)
	if !ok {
		errCode(w, http.StatusUnauthorized, "no_session", nil)
		return
	}
	rec.Lang = l
	if err := a.saveUserRec(u, rec); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"lang": l})
}

func (a *App) handleLoginInfo(w http.ResponseWriter, r *http.Request) {
	a.cfgMu.RLock()
	multi := len(a.users) > 0
	a.cfgMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"users": multi, "server_lang": a.srvLang()})
}

type userView struct {
	Name  string `json:"name"`
	Role  string `json:"role"`
	Owner bool   `json:"owner"`
	TOTP  bool   `json:"totp"`
}

func (a *App) handleListUsers(w http.ResponseWriter, r *http.Request) {
	own := a.getAdmin()
	out := []userView{{Name: ownerName, Role: roleAdmin, Owner: true, TOTP: own.TOTPSecret != ""}}
	a.cfgMu.RLock()
	for _, u := range a.users {
		out = append(out, userView{Name: u.Name, Role: u.Role, TOTP: u.TOTPSecret != ""})
	}
	a.cfgMu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func validRole(r string) bool { return r == roleAdmin || r == roleViewer }

func (a *App) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Password, Role string
	}
	if !decode(w, r, &in) {
		return
	}
	name := normUser(in.Name)
	if !userRe.MatchString(name) || name == ownerName || name == localUser {
		errCode(w, http.StatusBadRequest, "user.bad_name", nil)
		return
	}
	if !validRole(in.Role) {
		errCode(w, http.StatusBadRequest, "user.bad_role", nil)
		return
	}
	rec, err := newAdmin(in.Password)
	if err != nil {
		errOf(w, http.StatusBadRequest, err)
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	if _, _, exists := a.lookupUser(name); exists {
		errCode(w, http.StatusConflict, "user.name_taken", nil)
		return
	}
	a.cfgMu.RLock()
	next := append(slices.Clone(a.users), User{Name: name, Role: in.Role, adminRecord: rec})
	a.cfgMu.RUnlock()
	if err := a.setUsers(next); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.logReqT(r, "user_create", "log.user_create", map[string]any{"name": name, "role": in.Role})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	name := normUser(r.PathValue("name"))
	var in struct {
		Role     *string `json:"role"`
		Password *string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if name == ownerName {
		errCode(w, http.StatusBadRequest, "user.owner_fixed", nil)
		return
	}
	if in.Role != nil && !validRole(*in.Role) {
		errCode(w, http.StatusBadRequest, "user.bad_role", nil)
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	a.cfgMu.RLock()
	next := slices.Clone(a.users)
	a.cfgMu.RUnlock()
	idx := slices.IndexFunc(next, func(u User) bool { return u.Name == name })
	if idx < 0 {
		errCode(w, http.StatusNotFound, "account.not_found", nil)
		return
	}
	params := map[string]any{"name": name}
	roleChanged := in.Role != nil && *in.Role != next[idx].Role
	if roleChanged {
		if name == userOf(r) {
			errCode(w, http.StatusBadRequest, "user.own_role", nil)
			return
		}
		next[idx].Role = *in.Role
		params["role"] = *in.Role
	}
	reset := false
	if in.Password != nil {
		rec, err := newAdmin(*in.Password)
		if err != nil {
			errOf(w, http.StatusBadRequest, err)
			return
		}
		next[idx].adminRecord = rec.withPrefsFrom(next[idx].adminRecord)
		reset = true
	}
	if err := a.setUsers(next); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	if reset || roleChanged {
		a.sess.revokeUser(name) // yeni rol/parola ile yeniden girsin
	}
	key := "log.user_edit"
	switch {
	case roleChanged && reset:
		key += ".role_password"
	case roleChanged:
		key += ".role"
	case reset:
		key += ".password"
	}
	a.logReqT(r, "user_edit", key, params)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := normUser(r.PathValue("name"))
	if name == ownerName {
		errCode(w, http.StatusBadRequest, "user.owner_undeletable", nil)
		return
	}
	if name == userOf(r) {
		errCode(w, http.StatusBadRequest, "user.own_delete", nil)
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	a.cfgMu.RLock()
	cur := a.users
	a.cfgMu.RUnlock()
	next := slices.DeleteFunc(slices.Clone(cur), func(u User) bool { return u.Name == name })
	found := len(next) != len(cur)
	if !found {
		errCode(w, http.StatusNotFound, "account.not_found", nil)
		return
	}
	if err := a.setUsers(next); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.sess.revokeUser(name)
	a.logReqT(r, "user_delete", "log.user_delete", map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleLocalPasswd: yalnızca yerel soketten (root) çağrılır. `kut passwd` servis çalışırken buraya gelir;
// dosyaya doğrudan yazmak bellekteki kaydı eskitir ve sonraki saveUserRec yeni parolayı ezerdi.
func (a *App) handleLocalPasswd(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	name := normUser(in.User)
	if name == "" {
		name = ownerName
	}
	rec, err := newAdmin(in.Password)
	if err != nil {
		errOf(w, http.StatusBadRequest, err)
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	old, _, ok := a.lookupUser(name)
	if !ok {
		errCode(w, http.StatusNotFound, "account.not_found", nil)
		return
	}
	if err := a.saveUserRec(name, rec.withPrefsFrom(old)); err != nil { // 2FA kapanmasın
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.sess.revokeUser(name)
	a.logEventT(localUser, "password", "log.password.local", map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
