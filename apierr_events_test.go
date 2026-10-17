package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// evKeys: o ana kadar yazılmış olayların katalog anahtarları (sırayla).
func evKeys(a *App) []string {
	var out []string
	for _, e := range a.act.evs {
		out = append(out, e.Code)
	}
	return out
}

func containsSeq(have []string, want ...string) bool {
	i := 0
	for _, h := range have {
		if i < len(want) && h == want[i] {
			i++
		}
	}
	return i == len(want)
}

// Sunucu işleyicilerinin yazdığı her olay katalog anahtarı + parametre taşır; iki dilde de eksiksiz çözülür ve
// Text sunucu dilindeki karşılığıdır. Çok parçalı işlemler (cihaz düzenleme, ayarlar) parça başına bir satır yazar.
func TestHandlersWriteLocalizedEvents(t *testing.T) {
	a, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	do := func(method, path, body string, want int) {
		t.Helper()
		rec := rqH(h, method, path, []byte(body), c, nil)
		if rec.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
		}
	}
	do("POST", "/api/policies", `{"name":"Ev","rules":[{"target":"server","proto":"tcp","ports":"80"}]}`, 200)
	polID := a.pol[0].ID
	do("POST", "/api/peers", `{"name":"tel","internet":true}`, 200)
	do("POST", "/api/peers", `{"name":"lap"}`, 200)
	id, id2 := a.peers[0].ID, a.peers[1].ID
	if !containsSeq(evKeys(a), "log.login", "log.policy_create", "log.peer_create.internet", "log.peer_create.vpn") {
		t.Fatalf("temel olaylar: %v", evKeys(a))
	}

	// çok parçalı düzenleme: ad değişimi + her alan ayrı satır
	n0 := len(a.act.evs)
	do("PATCH", "/api/peers/"+id, `{"name":"tel2","policy":"`+polID+`","schedule":{"days":[1,2,3],"from":"09:00","to":"18:00","scope":"internet"},"group":"aile","kind":"phone","expires_minutes":30,"internet":false}`, 200)
	got := evKeys(a)[n0:]
	want := []string{"log.peer_edit.rename", "log.peer_edit.policy_set", "log.peer_edit.schedule_internet", "log.peer_edit.group_set", "log.peer_edit.kind_set", "log.peer_edit.expiry_set", "log.peer_edit.internet_off"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("düzenleme olayları\n got %v\nwant %v", got, want)
	}
	sched := a.act.evs[n0+2]
	if sched.Params["days"] != "Pzt,Sal,Çar" { // sunucu dili varsayılan olarak tr
		t.Fatalf("gün listesi sunucu dilinde olmalı: %v", sched.Params)
	}
	if tr := T("tr", sched.Code, sched.Params); !strings.Contains(tr, "Pzt,Sal,Çar 09:00–18:00") || !strings.Contains(tr, "yalnızca internet") {
		t.Fatalf("tr metin: %q", tr)
	}
	if en := T("en", sched.Code, sched.Params); !strings.Contains(en, "Pzt,Sal,Çar 09:00–18:00") || !strings.Contains(en, "internet only") {
		t.Fatalf("en metin: %q", en)
	}
	n0 = len(a.act.evs)
	do("PATCH", "/api/peers/"+id, `{"name":"tel2","policy":"","clear_schedule":true,"group":"","kind":"","expires_minutes":0,"internet":true}`, 200)
	got = evKeys(a)[n0:]
	want = []string{"log.peer_edit", "log.peer_edit.policy_removed", "log.peer_edit.schedule_removed", "log.peer_edit.group_none", "log.peer_edit.kind_other", "log.peer_edit.expiry_removed", "log.peer_edit.internet_on"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("düzenleme olayları (kaldırma)\n got %v\nwant %v", got, want)
	}

	do("POST", "/api/peers/"+id+"/toggle", `{}`, 200)
	do("POST", "/api/peers/"+id+"/toggle", `{}`, 200)
	do("POST", "/api/peers/"+id+"/freeze", `{"minutes":5}`, 200)
	do("POST", "/api/peers/"+id+"/unfreeze", `{}`, 200)
	do("POST", "/api/peers/"+id+"/regenerate", `{"internet":false}`, 200)
	do("POST", "/api/peers/"+id+"/regenerate", `{"internet":true,"ip":"10.77.0.50"}`, 200)
	if !containsSeq(evKeys(a), "log.peer_toggle.off", "log.peer_toggle.on", "log.peer_freeze", "log.peer_unfreeze", "log.peer_regenerate.inet_vpn", "log.peer_regenerate.vpn_inet_ip") {
		t.Fatalf("cihaz olayları: %v", evKeys(a))
	}
	for _, body := range []string{
		`{"action":"enable"}`, `{"action":"disable"}`, `{"action":"enable"}`, `{"action":"freeze","minutes":5}`, `{"action":"unfreeze"}`,
		`{"action":"policy","policy":"` + polID + `"}`, `{"action":"internet","internet":true}`, `{"action":"expires","expires_minutes":60}`,
		`{"action":"group","group":"x"}`, `{"action":"schedule","schedule":{"days":[1],"from":"09:00","to":"10:00","scope":"tunnel"}}`,
	} {
		do("POST", "/api/peers/bulk", strings.Replace(body, "{", `{"ids":["`+id+`","`+id2+`"],`, 1), 200)
	}
	do("POST", "/api/peers/bulk", `{"ids":["`+id2+`"],"action":"delete"}`, 200)
	do("PUT", "/api/policies/"+polID, `{"name":"Ev","rules":[{"target":"server","proto":"tcp","ports":"80"},{"target":"device","device":"`+id+`","proto":"any"}]}`, 200)
	do("DELETE", "/api/peers/"+id, "", 200)
	do("DELETE", "/api/policies/"+polID, "", 200)
	if !containsSeq(evKeys(a), "log.peer_bulk.enable", "log.peer_bulk.disable", "log.peer_bulk.freeze", "log.peer_bulk.unfreeze", "log.peer_bulk.policy",
		"log.peer_bulk.internet", "log.peer_bulk.expires", "log.peer_bulk.group", "log.peer_bulk.schedule", "log.peer_bulk.delete",
		"log.policy_edit", "log.peer_delete.rules", "log.policy_delete") {
		t.Fatalf("toplu/profil olayları: %v", evKeys(a))
	}

	// hesaplar
	do("POST", "/api/users", `{"name":"bob","password":"bob-long-password","role":"viewer"}`, 200)
	do("PATCH", "/api/users/bob", `{}`, 200)
	do("PATCH", "/api/users/bob", `{"role":"admin"}`, 200)
	do("PATCH", "/api/users/bob", `{"password":"bob-another-password"}`, 200)
	do("PATCH", "/api/users/bob", `{"role":"viewer","password":"bob-third-password"}`, 200)
	do("DELETE", "/api/users/bob", "", 200)
	if !containsSeq(evKeys(a), "log.user_create", "log.user_edit", "log.user_edit.role", "log.user_edit.password", "log.user_edit.role_password", "log.user_delete") {
		t.Fatalf("hesap olayları: %v", evKeys(a))
	}
	// kayıtlı metinde ham rol kodu değil, çevrilmiş rol adı olmalı; Params ise ham kalır (arayüz kendi dilinde çevirir)
	for _, e := range a.act.evs {
		if e.Code != "log.user_create" && e.Code != "log.user_edit.role" && e.Code != "log.user_edit.role_password" {
			continue
		}
		role, _ := e.Params["role"].(string)
		if role != "admin" && role != "viewer" {
			t.Errorf("%s: Params.role ham kod olmalı: %v", e.Code, e.Params)
		}
		if !strings.Contains(e.Text, T(a.srvLang(), "settings.users.role_"+role, nil)) {
			t.Errorf("%s: metinde çevrilmiş rol yok: %q", e.Code, e.Text)
		}
	}

	// ayarlar: her değişiklik ayrı satır; değişiklik yoksa tek "nochange"
	n0 = len(a.act.evs)
	do("PUT", "/api/settings", `{"endpoint":"203.0.113.11","port":51821,"dns":"1.1.1.1","mtu":1400,"keepalive":40,"block_private":false,"update_check":true,"ipv6":true}`, 200)
	got = evKeys(a)[n0:]
	for _, k := range []string{"log.settings.change_endpoint", "log.settings.change_port", "log.settings.change_dns", "log.settings.change_mtu", "log.settings.change_keepalive", "log.settings.change_block_private", "log.settings.change_update_check", "log.settings.change_ipv6_on"} {
		if !containsSeq(got, k) {
			t.Fatalf("%s yok: %v", k, got)
		}
	}
	n0 = len(a.act.evs)
	do("PUT", "/api/settings", `{"endpoint":"203.0.113.11","port":51821,"dns":"1.1.1.1","mtu":1400,"keepalive":40,"block_private":false,"update_check":true,"ipv6":true}`, 200)
	if got = evKeys(a)[n0:]; len(got) != 1 || got[0] != "log.settings.nochange" {
		t.Fatalf("değişiklik yok: %v", got)
	}
	do("PUT", "/api/settings", `{"endpoint":"203.0.113.11","port":51821,"dns":"1.1.1.1","mtu":1400,"keepalive":40,"block_private":false,"update_check":true,"ipv6":false}`, 200)
	do("PUT", "/api/settings/lang", `{"lang":"en"}`, 200)

	// parola, 2FA, giriş
	do("POST", "/api/password", `{"current":"yanlis","new":"another-long-password"}`, 403)
	do("POST", "/api/password", `{"current":"correct-horse-battery","new":"another-long-password"}`, 200)
	c = login(h, "", "another-long-password")
	rec := rqH(h, "POST", "/api/totp/setup", []byte(`{}`), c, nil)
	var setup struct{ Secret string }
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil || setup.Secret == "" {
		t.Fatalf("setup: %d %s", rec.Code, rec.Body)
	}
	step := time.Now().Unix() / 30
	code, _ := totpAt(setup.Secret, step)
	do("POST", "/api/totp/enable", `{"code":"000000","password":"yanlis"}`, 403)
	do("POST", "/api/totp/enable", `{"code":"`+code+`","password":"another-long-password"}`, 200)
	post(h, "/api/login", `{"password":"another-long-password","code":"000000"}`, nil)
	post(h, "/api/login", `{"password":"yanlis-parola-xx"}`, nil)
	do("POST", "/api/totp/disable", `{"password":"another-long-password","code":"000000"}`, 403)
	next, _ := totpAt(setup.Secret, step+1)
	do("POST", "/api/totp/disable", `{"password":"another-long-password","code":"`+next+`"}`, 200)
	do("POST", "/api/server/apply", `{}`, 200)
	do("POST", "/api/logout", `{}`, 200)
	lh := a.handler(true)
	post(lh, "/api/local/passwd", `{"user":"admin","password":"third-long-password"}`, nil)
	post(lh, "/api/local/2fa-off", `{"user":"admin"}`, nil)
	a.logEventT("sistem", "start", "log.start", map[string]any{"version": "x"})

	keys := evKeys(a)
	for _, k := range []string{"log.login_fail", "log.login_fail.code", "log.password", "log.password_fail", "log.password.local", "log.totp_on", "log.totp_off", "log.totp_off.local",
		"log.totp_fail.enable", "log.totp_fail.disable", "log.settings.lang", "log.settings.change_ipv6_off", "log.apply", "log.logout"} {
		if !containsSeq(keys, k) {
			t.Errorf("%s olayı yok", k)
		}
	}

	// her olay: kod var, iki dilde tam çözülür, Text sunucu dilinde
	for _, e := range a.act.evs {
		if e.Code == "" {
			t.Errorf("kodsuz olay: %+v", e)
			continue
		}
		for _, l := range langs {
			if s := T(l, e.Code, e.Params); s == e.Code || strings.Contains(s, "{") {
				t.Errorf("%s: %s çözülmedi: %q (%v)", l, e.Code, s, e.Params)
			}
		}
		if e.Text != T("tr", e.Code, textParams("tr", e.Params)) && e.Text != T("en", e.Code, textParams("en", e.Params)) { // sunucu dili testin ortasında tr→en değişir
			t.Errorf("Text sunucu dilinde değil: %q", e.Text)
		}
	}
}
