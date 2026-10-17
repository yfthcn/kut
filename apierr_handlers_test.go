package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Doğrulama ve yetki hataları kodla döner: HTTP durumu değişmez, "code" beklenen, metin iki dilde tam çözülür.
func TestHandlersReturnCodedErrors(t *testing.T) {
	a, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	call := func(c *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
		a.lim = newLimiter() // bu test hata kodlarını sınar; deneme sınırı başka testte
		return rqH(h, method, path, []byte(body), c, nil)
	}
	ok := func(method, path, body string) {
		t.Helper()
		if r := call(owner, method, path, body); r.Code != 200 {
			t.Fatalf("hazırlık %s %s: %d %s", method, path, r.Code, r.Body)
		}
	}
	ok("POST", "/api/policies", `{"name":"Ev","rules":[{"target":"server","proto":"tcp","ports":"80"}]}`)
	ok("POST", "/api/peers", `{"name":"tel"}`)
	ok("POST", "/api/peers", `{"name":"lap"}`)
	ok("POST", "/api/users", `{"name":"bob","password":"bob-long-password","role":"admin"}`)
	ok("POST", "/api/users", `{"name":"vera","password":"vera-long-password","role":"viewer"}`)
	polID, id, id2 := a.pol[0].ID, a.peers[0].ID, a.peers[1].ID
	ok("PATCH", "/api/peers/"+id2, `{"name":"lap","policy":"`+polID+`"}`) // profil kullanımda
	bob, vera := login(h, "bob", "bob-long-password"), login(h, "vera", "vera-long-password")
	long := strings.Repeat("x", maxNoteRunes+1)

	for _, c := range []struct {
		name   string
		who    *http.Cookie
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{"cihaz adı", owner, "POST", "/api/peers", `{"name":"a\nb"}`, 400, "peer.bad_name"},
		{"cihaz notu", owner, "POST", "/api/peers", `{"name":"n","note":"` + long + `"}`, 400, "peer.bad_note"},
		{"aynı ad", owner, "POST", "/api/peers", `{"name":"TEL"}`, 409, "peer.name_taken"},
		{"çok uzun geçerlilik", owner, "POST", "/api/peers", `{"name":"n","expires_minutes":999999999}`, 400, "peer.expiry_too_long"},
		{"grup adı", owner, "POST", "/api/peers", `{"name":"n","group":"!!"}`, 400, "peer.bad_group"},
		{"tür", owner, "POST", "/api/peers", `{"name":"n","kind":"zzz"}`, 400, "peer.bad_kind"},
		{"olmayan profil", owner, "POST", "/api/peers", `{"name":"n","policy":"yok"}`, 400, "policy.not_found"},
		{"ağ dışı IP", owner, "POST", "/api/peers", `{"name":"n","ip":"10.99.0.1"}`, 409, "ip.outside"},
		{"sunucu IP'si", owner, "POST", "/api/peers", `{"name":"n","ip":"10.77.0.1"}`, 409, "ip.is_server"},
		{"kullanımdaki IP", owner, "POST", "/api/peers", `{"name":"n","ip":"` + a.peers[0].IP + `"}`, 409, "ip.in_use"},
		{"günsüz zamanlama", owner, "POST", "/api/peers", `{"name":"n","schedule":{"days":[],"from":"08:00","to":"09:00","scope":"tunnel"}}`, 400, "schedule.no_days"},
		{"olmayan cihaz düzenle", owner, "PATCH", "/api/peers/yok", `{"name":"x"}`, 404, "peer.not_found"},
		{"düzenlemede aynı ad", owner, "PATCH", "/api/peers/" + id, `{"name":"lap"}`, 409, "peer.name_taken"},
		{"düzenlemede olmayan profil", owner, "PATCH", "/api/peers/" + id, `{"name":"tel","policy":"yok"}`, 400, "policy.not_found"},
		{"dondurma süresi", owner, "POST", "/api/peers/" + id + "/freeze", `{"minutes":0}`, 400, "peer.bad_freeze_time"},
		{"olmayan cihazı dondur", owner, "POST", "/api/peers/yok/freeze", `{"minutes":5}`, 404, "peer.not_found"},
		{"olmayan cihazı sil", owner, "DELETE", "/api/peers/yok", ``, 404, "peer.not_found"},
		{"toplu: boş seçim", owner, "POST", "/api/peers/bulk", `{"ids":[],"action":"enable"}`, 400, "bulk.none_selected"},
		{"toplu: olmayan cihaz", owner, "POST", "/api/peers/bulk", `{"ids":["yok"],"action":"enable"}`, 404, "bulk.not_found"},
		{"toplu: bilinmeyen işlem", owner, "POST", "/api/peers/bulk", `{"ids":["` + id + `"],"action":"zz"}`, 400, "bulk.bad_action"},
		{"toplu: dondurma süresi", owner, "POST", "/api/peers/bulk", `{"ids":["` + id + `"],"action":"freeze","minutes":0}`, 400, "peer.bad_freeze_time"},
		{"toplu: olmayan profil", owner, "POST", "/api/peers/bulk", `{"ids":["` + id + `"],"action":"policy","policy":"yok"}`, 400, "policy.not_found"},
		{"profil adı yinelenir", owner, "POST", "/api/policies", `{"name":"ev"}`, 409, "policy.name_taken"},
		{"profil adı geçersiz", owner, "POST", "/api/policies", `{"name":"!!"}`, 400, "policy.bad_name"},
		{"profil kuralı", owner, "POST", "/api/policies", `{"name":"y","rules":[{"target":"server","proto":"tcp","ports":"80"},{"target":"server","proto":"sctp"}]}`, 400, "rule.bad_proto"},
		{"profil grubu", owner, "POST", "/api/policies", `{"name":"y","groups":["a\nb"]}`, 400, "policy.bad_group"},
		{"olmayan profil güncelle", owner, "PUT", "/api/policies/yok", `{"name":"y"}`, 404, "policy.not_found"},
		{"kullanımdaki profil silinmez", owner, "DELETE", "/api/policies/" + polID, ``, 409, "policy.in_use"},
		{"olmayan profil sil", owner, "DELETE", "/api/policies/yok", ``, 404, "policy.not_found"},
		{"kullanıcı adı", owner, "POST", "/api/users", `{"name":"A B","password":"long-enough-pass","role":"admin"}`, 400, "user.bad_name"},
		{"kullanıcı rolü", owner, "POST", "/api/users", `{"name":"x","password":"long-enough-pass","role":"root"}`, 400, "user.bad_role"},
		{"kısa parola", owner, "POST", "/api/users", `{"name":"x","password":"kisa","role":"admin"}`, 400, "password.too_short"},
		{"yinelenen kullanıcı", owner, "POST", "/api/users", `{"name":"bob","password":"long-enough-pass","role":"admin"}`, 409, "user.name_taken"},
		{"sahibin rolü", owner, "PATCH", "/api/users/admin", `{"role":"viewer"}`, 400, "user.owner_fixed"},
		{"olmayan hesap", owner, "PATCH", "/api/users/yok", `{"role":"viewer"}`, 404, "account.not_found"},
		{"olmayan hesabı sil", owner, "DELETE", "/api/users/yok", ``, 404, "account.not_found"},
		{"sahibi sil", owner, "DELETE", "/api/users/admin", ``, 400, "user.owner_undeletable"},
		{"kendini sil", bob, "DELETE", "/api/users/bob", ``, 400, "user.own_delete"},
		{"kendi rolü", bob, "PATCH", "/api/users/bob", `{"role":"viewer"}`, 400, "user.own_role"},
		{"izleyici yönetici işi", vera, "GET", "/api/users", ``, 403, "auth.admin_required"},
		{"izleyici yazamaz", vera, "POST", "/api/peers", `{"name":"q"}`, 403, "viewer_readonly"},
		{"yönetici sahip işi", bob, "POST", "/api/backups", `{}`, 403, "auth.owner_required"},
		{"uç nokta boş", owner, "PUT", "/api/settings", `{"endpoint":"","port":1}`, 400, "settings.endpoint_empty"},
		{"uç nokta portlu", owner, "PUT", "/api/settings", `{"endpoint":"a.example:80","port":1}`, 400, "settings.endpoint_port"},
		{"ayar portu", owner, "PUT", "/api/settings", `{"endpoint":"a.example","port":0}`, 400, "settings.bad_port"},
		{"DNS", owner, "PUT", "/api/settings", `{"endpoint":"a.example","port":1,"dns":"evil.com"}`, 400, "settings.dns_invalid"},
		{"DNS sayısı", owner, "PUT", "/api/settings", `{"endpoint":"a.example","port":1,"dns":"1.1.1.1,8.8.8.8,9.9.9.9,4.4.4.4"}`, 400, "settings.dns_too_many"},
		{"MTU", owner, "PUT", "/api/settings", `{"endpoint":"a.example","port":1,"mtu":100}`, 400, "settings.bad_mtu"},
		{"keepalive", owner, "PUT", "/api/settings", `{"endpoint":"a.example","port":1,"keepalive":999}`, 400, "settings.bad_keepalive"},
		{"yanlış mevcut parola", owner, "POST", "/api/password", `{"current":"yanlis","new":"another-long-password"}`, 403, "password.wrong_current"},
		{"kısa yeni parola", owner, "POST", "/api/password", `{"current":"correct-horse-battery","new":"kisa"}`, 400, "password.too_short"},
		{"2FA kurulumu yok", owner, "POST", "/api/totp/enable", `{"code":"123456","password":"correct-horse-battery"}`, 400, "totp.setup_expired"},
		{"2FA açma: yanlış parola", owner, "POST", "/api/totp/enable", `{"code":"123456","password":"yanlis"}`, 403, "bad_password"},
		{"2FA zaten kapalı", owner, "POST", "/api/totp/disable", `{"password":"correct-horse-battery","code":"123456"}`, 409, "totp.already_off"},
		{"erişim testi protokolü", owner, "GET", "/api/reach?src=" + id + "&dst=server&proto=gre", ``, 400, "reach.bad_proto"},
		{"erişim testi kaynağı", owner, "GET", "/api/reach?src=yok&dst=server&proto=icmp", ``, 404, "reach.src_not_found"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := call(c.who, c.method, c.path, c.body)
			code, params := testErrCode(t, rec.Body.Bytes())
			if rec.Code != c.status || code != c.code {
				t.Fatalf("%d %q (%s), beklenen %d %q", rec.Code, code, rec.Body, c.status, c.code)
			}
			if n, isNum := params["n"].(float64); isNum { // JSON'dan gelen sayı float64; sunucuda int idi
				params["n"] = int(n)
			}
			for _, l := range langs {
				if s := T(l, "err."+code, params); s == "err."+code || strings.ContainsAny(s, "{}") {
					t.Fatalf("%s: çözülmemiş metin %q (params %v)", l, s, params)
				}
			}
			if !strings.Contains(rec.Body.String(), `"error":`) {
				t.Fatalf("eski istemciler için error alanı yok: %s", rec.Body)
			}
		})
	}

	// 2FA zaten açık + kurulum yerel kanaldan olmaz + yerel kanalda parola değişmez
	sec := func(c *http.Cookie) string {
		var s struct{ Secret string }
		rec := call(c, "POST", "/api/totp/setup", `{}`)
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil || s.Secret == "" {
			t.Fatalf("setup: %d %s", rec.Code, rec.Body)
		}
		return s.Secret
	}
	s := sec(owner)
	code, _ := totpAt(s, time.Now().Unix()/30)
	ok("POST", "/api/totp/enable", `{"code":"`+code+`","password":"correct-horse-battery"}`)
	for _, c := range []struct {
		name, method, path, body, code string
		status                         int
	}{
		{"2FA zaten açık (kur)", "POST", "/api/totp/setup", `{}`, "totp.already_on_setup", 409},
		{"2FA zaten açık (aç)", "POST", "/api/totp/enable", `{"code":"123456","password":"correct-horse-battery"}`, "totp.already_on", 409},
		{"2FA kapatma: yanlış kod", "POST", "/api/totp/disable", `{"password":"correct-horse-battery","code":"000000"}`, "totp.bad_password_or_code", 403},
	} {
		rec := call(owner, c.method, c.path, c.body)
		if got, _ := testErrCode(t, rec.Body.Bytes()); rec.Code != c.status || got != c.code {
			t.Errorf("%s: %d %s", c.name, rec.Code, rec.Body)
		}
	}
	a.lim = newLimiter()
	lh := a.handler(true)
	for _, c := range []struct{ path, body, code string }{
		{"/api/password", `{"current":"x","new":"another-long-password"}`, "password.local_channel"},
		{"/api/totp/setup", `{}`, "totp.panel_only"},
		{"/api/local/passwd", `{"user":"yok","password":"another-long-password"}`, "account.not_found"},
		{"/api/local/2fa-off", `{"user":"yok"}`, "account.not_found"},
		{"/api/local/passwd", `{"user":"bob","password":"kisa"}`, "password.too_short"},
	} {
		rec := post(lh, c.path, c.body, nil)
		if got, _ := testErrCode(t, rec.Body.Bytes()); got != c.code {
			t.Errorf("yerel %s: %d %s", c.path, rec.Code, rec.Body)
		}
	}
}
