package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: RFC 6238 TOTP'nin varsayılanı HMAC-SHA1; doğrulayıcı uygulamalar bunu bekler, HMAC çarpışmadan etkilenmez
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// İki adımlı doğrulama (TOTP, RFC 6238): HMAC-SHA1, 6 hane, 30 sn. Google Authenticator, Aegis, 1Password, Apple Parolalar vb. ile uyumlu.
// Yalnızca standart kütüphane. Kurtarma kodları tek kullanımlıktır ve yalnızca SHA-256 özetleri saklanır.

const (
	totpPeriod   = 30
	totpDigits   = 6
	recoveryN    = 8
	totpPendingT = 10 * time.Minute
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// pendingTOTP: bir hesabın kurulumu süren sırrı.
type pendingTOTP struct {
	secret string
	exp    time.Time
}

// totpPending: kurulumu süren sırlar, hesap başına bir tane; her sır yalnızca kurulumu başlatan hesaba verilir.
// Sıfır değeri kullanıma hazırdır. Süresi geçen girdiler her erişimde süpürülür; harita hesap sayısıyla sınırlı kalır.
type totpPending struct {
	mu sync.Mutex
	m  map[string]pendingTOTP
}

// sweep: süresi geçenleri siler. Çağıran mu'yu tutmalı.
func (p *totpPending) sweep(now time.Time) {
	for u, e := range p.m {
		if now.After(e.exp) {
			delete(p.m, u)
		}
	}
}

func (p *totpPending) set(user, s string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	p.sweep(now)
	if p.m == nil {
		p.m = map[string]pendingTOTP{}
	}
	p.m[user] = pendingTOTP{secret: s, exp: now.Add(totpPendingT)}
}

func (p *totpPending) get(user string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweep(time.Now())
	e, ok := p.m[user]
	if !ok || e.secret == "" {
		return "", false
	}
	return e.secret, true
}

// clear: yalnızca bu hesabın bekleyen kurulumunu siler.
func (p *totpPending) clear(user string) {
	p.mu.Lock()
	delete(p.m, user)
	p.mu.Unlock()
}

func newTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

// totpAt: verilen zaman adımı için kod.
func totpAt(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // G115: step = unix zamanı / 30, hep pozitif
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for range totpDigits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, bin%mod), nil
}

// totpVerify: kodu ±1 adım toleransla denetler. last'tan küçük/eşit adımlar reddedilir (aynı kod ikinci kez kullanılamaz).
func totpVerify(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	var hit int64
	for _, d := range []int64{0, -1, 1} { // sabit sürede hepsini dene
		step := cur + d
		want, err := totpAt(secret, step)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 && step > last && hit == 0 {
			hit = step
		}
	}
	return hit, hit != 0
}

func otpauthURI(user, secret string) string {
	return "otpauth://totp/" + url.PathEscape("Kut:"+user) + "?secret=" + secret + "&issuer=Kut&algorithm=SHA1&digits=6&period=30"
}

func normRecovery(c string) string {
	return strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(c), "-", ""), " ", ""))
}

func hashRecovery(c string) string {
	h := sha256.Sum256([]byte(normRecovery(c)))
	return hex.EncodeToString(h[:])
}

// newRecoveryCodes: düz kodlar (yalnızca bir kez gösterilir) ve özetleri.
func newRecoveryCodes() (plain, hashed []string, err error) {
	for range recoveryN {
		b := make([]byte, 6)
		if _, err = rand.Read(b); err != nil {
			return nil, nil, err
		}
		s := strings.ToLower(b32.EncodeToString(b))[:10]
		c := s[:5] + "-" + s[5:]
		plain = append(plain, c)
		hashed = append(hashed, hashRecovery(c))
	}
	return plain, hashed, nil
}

func looksLikeRecovery(c string) bool {
	n := normRecovery(c)
	return len(n) == 10
}

// ---- Yönetici kaydı yardımcıları ----

// withPrefsFrom: parola değişince hesabın parola dışındaki ayarlarını (2FA, dil tercihi) koru.
func (r adminRecord) withPrefsFrom(old adminRecord) adminRecord {
	r.TOTPSecret, r.TOTPLast, r.Recovery = old.TOTPSecret, old.TOTPLast, old.Recovery
	r.Lang = old.Lang
	return r
}

// checkSecondFactor: açık 2FA için kodu (TOTP ya da kurtarma kodu) denetler ve tüketir. Çağıran adminMu'yu tutmalı.
func (a *App) checkSecondFactor(adm *adminRecord, code string) bool {
	if looksLikeRecovery(code) {
		h := hashRecovery(code)
		for i, x := range adm.Recovery {
			if subtle.ConstantTimeCompare([]byte(x), []byte(h)) == 1 {
				adm.Recovery = slices.Concat(adm.Recovery[:i], adm.Recovery[i+1:])
				return true
			}
		}
		return false
	}
	if step, ok := totpVerify(adm.TOTPSecret, code, time.Now(), adm.TOTPLast); ok {
		adm.TOTPLast = step
		return true
	}
	return false
}

// ---- HTTP ----

func (a *App) handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	adm, _, _ := a.lookupUser(userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"enabled": adm.TOTPSecret != "", "recovery_left": len(adm.Recovery)})
}

func (a *App) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	me := userOf(r)
	if me == localUser {
		errCode(w, http.StatusBadRequest, "totp.panel_only", nil)
		return
	}
	cur, _, _ := a.lookupUser(me)
	if cur.TOTPSecret != "" {
		errCode(w, http.StatusConflict, "totp.already_on_setup", nil)
		return
	}
	sec, err := newTOTPSecret()
	if err != nil {
		errCode(w, http.StatusInternalServerError, "totp.key_failed", nil)
		return
	}
	a.totpPend.set(me, sec)
	uri := otpauthURI(me, sec)
	svg := ""
	if q, err := qrEncode(uri); err == nil {
		svg = q.svg()
	}
	writeJSON(w, http.StatusOK, map[string]any{"secret": sec, "uri": uri, "qr": svg})
}

func (a *App) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	me := userOf(r)
	if !a.lim.allow(ip, me) { // deneme doğrulamadan önce sayılır (eşzamanlı istekler sınırı aşmasın); başarı sıfırlar
		errCode(w, http.StatusTooManyRequests, "too_many_attempts", nil)
		return
	}
	var in struct {
		Code     string `json:"code"`
		Password string `json:"password"` // çalınmış oturum 2FA'yı kendine bağlayıp hesabı kilitleyemesin
	}
	if !decode(w, r, &in) {
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	adm, _, ok := a.lookupUser(me)
	if !ok {
		errCode(w, http.StatusBadRequest, "account.not_found", nil)
		return
	}
	if !adm.verify(in.Password) {
		a.logEventT(ip, "totp_fail", "log.totp_fail.enable", nil)
		errCode(w, http.StatusForbidden, "bad_password", nil)
		return
	}
	if adm.TOTPSecret != "" {
		errCode(w, http.StatusConflict, "totp.already_on", nil)
		return
	}
	sec, ok := a.totpPend.get(me)
	if !ok {
		errCode(w, http.StatusBadRequest, "totp.setup_expired", nil)
		return
	}
	step, ok := totpVerify(sec, in.Code, time.Now(), 0)
	if !ok {
		errCode(w, http.StatusBadRequest, "totp.bad_code", nil)
		return
	}
	plain, hashed, err := newRecoveryCodes()
	if err != nil {
		errCode(w, http.StatusInternalServerError, "totp.recovery_failed", nil)
		return
	}
	adm.TOTPSecret, adm.TOTPLast, adm.Recovery = sec, step, hashed
	if err := a.saveUserRec(me, adm); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.totpPend.clear(me)
	a.lim.succeed(ip, me)
	a.logEventT(ip, "totp_on", "log.totp_on", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "recovery": plain})
}

func (a *App) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	me := userOf(r)
	if !a.lim.allow(ip, me) { // deneme doğrulamadan önce sayılır (eşzamanlı istekler sınırı aşmasın); başarı sıfırlar
		errCode(w, http.StatusTooManyRequests, "too_many_attempts", nil)
		return
	}
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &in) {
		return
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	adm, _, ok := a.lookupUser(me)
	if !ok {
		errCode(w, http.StatusBadRequest, "account.not_found", nil)
		return
	}
	if adm.TOTPSecret == "" {
		errCode(w, http.StatusConflict, "totp.already_off", nil)
		return
	}
	if !adm.verify(in.Password) || !a.checkSecondFactor(&adm, in.Code) {
		a.logEventT(ip, "totp_fail", "log.totp_fail.disable", nil)
		errCode(w, http.StatusForbidden, "totp.bad_password_or_code", nil)
		return
	}
	adm.TOTPSecret, adm.TOTPLast, adm.Recovery = "", 0, nil
	if err := a.saveUserRec(me, adm); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.lim.succeed(ip, me)
	a.logEventT(ip, "totp_off", "log.totp_off", nil)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleLocal2FAOff: yalnızca yerel soketten (root) çağrılır; parolasını/telefonunu kaybeden hesap için.
func (a *App) handleLocal2FAOff(w http.ResponseWriter, r *http.Request) {
	var in struct {
		User string `json:"user"`
	}
	if !decode(w, r, &in) {
		return
	}
	name := normUser(in.User)
	if name == "" {
		name = ownerName
	}
	a.adminMu.Lock()
	defer a.adminMu.Unlock()
	adm, _, ok := a.lookupUser(name)
	if !ok {
		errCode(w, http.StatusNotFound, "account.not_found", nil)
		return
	}
	adm.TOTPSecret, adm.TOTPLast, adm.Recovery = "", 0, nil
	if err := a.saveUserRec(name, adm); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.logEventT(localUser, "totp_off", "log.totp_off.local", map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func cmd2FAOff(args []string) error {
	fs, data := localFlags("2fa-off")
	user := fs.String("user", "", T(argLang(args), "totp.flag_user", nil)) // dil ayrıştırmadan önce: -data ve -lang dahil (diğer komutlar gibi)
	if err := fs.Parse(args); err != nil {
		return err
	}
	name := normUser(*user)
	if name == "" {
		name = ownerName
	}
	if serviceRunning(*data) {
		return newLocalClient(*data, argLang(args)).do("POST", "/api/local/2fa-off", map[string]string{"user": name}, nil)
	}
	return offlineEdit(*data, name, func(r *adminRecord) error {
		if r.TOTPSecret == "" {
			return ue("totp.already_off", nil)
		}
		r.TOTPSecret, r.TOTPLast, r.Recovery = "", 0, nil
		return nil
	})
}

// offlineEdit: servis kapalıyken bir hesabın kaydını diskte değiştirir.
func offlineEdit(dir, name string, f func(*adminRecord) error) error {
	if name == ownerName {
		var rec adminRecord
		if err := loadJSON(adminPath(dir), &rec); err != nil {
			return ue("account.admin_unreadable", map[string]any{"msg": err.Error()})
		}
		if err := f(&rec); err != nil {
			return err
		}
		return saveJSON(adminPath(dir), rec)
	}
	us, err := loadUsers(dir)
	if err != nil {
		return err
	}
	for i := range us {
		if us[i].Name == name {
			if err := f(&us[i].adminRecord); err != nil {
				return err
			}
			return saveJSON(usersPath(dir), us)
		}
	}
	return ue("account.no_such", map[string]any{"name": strconv.Quote(name)})
}
