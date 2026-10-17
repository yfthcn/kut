package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// testErrCode: yanıt gövdesindeki hata kodu ve parametreleri.
func testErrCode(t *testing.T, body []byte) (string, map[string]any) {
	t.Helper()
	var b struct {
		Code   string         `json:"code"`
		Params map[string]any `json:"params"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		t.Fatalf("gövde JSON değil: %v %s", err, body)
	}
	return b.Code, b.Params
}

// apply başarısız olunca yanıt kodlu: "apply.failed" + sistem hatası msg parametresinde.
func TestApplyFailureIsCoded(t *testing.T) {
	a, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	blockFile(t, a.srv.ConfPath)
	rec := post(h, "/api/peers", `{"name":"tel"}`, c)
	code, params := testErrCode(t, rec.Body.Bytes())
	if rec.Code != 500 || code != "apply.failed" || params["msg"] == nil || params["msg"] == "" {
		t.Fatalf("%d %q %v", rec.Code, code, params)
	}
}

// apply.failed'ın msg'si (kodlu iç hata: wg/güvenlik duvarı) isteği yapanın dilinde, referans dile sabit değil.
func TestApplyFailureMessageFollowsRequestLang(t *testing.T) {
	a, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	blockFile(t, a.srv.ConfPath)
	for _, l := range langs {
		rec := rqH(h, "POST", "/api/server/apply", nil, c, map[string]string{"X-Kut-Lang": l})
		code, params := testErrCode(t, rec.Body.Bytes())
		msg, _ := params["msg"].(string)
		prefix, _, _ := strings.Cut(T(l, "err.wg.conf_write_failed", nil), "{")
		if rec.Code != 500 || code != "apply.failed" || prefix == "" || !strings.HasPrefix(msg, prefix) {
			t.Errorf("%s: %d %q msg=%q, beklenen önek %q", l, rec.Code, code, msg, prefix)
		}
	}
}

func errCodeOf(err error) string {
	var ce *codedErr
	if errors.As(err, &ce) {
		return ce.Code
	}
	return ""
}

// testHasKey: anahtar dilde var (çoğul nesnelerde .other).
func testHasKey(lang, key string) bool {
	if _, ok := catalogs[lang][key]; ok {
		return true
	}
	_, ok := catalogs[lang][key+".other"]
	return ok
}

// S1 dosyalarında geçen her hata kodu ve olay/erişim anahtarı iki dilde de kataloğda olmalı (yazım hatası, eksik çeviri).
func TestS1KeysExistInBothLanguages(t *testing.T) {
	files := []string{"server.go", "users.go", "totp.go", "settings.go", "bulk.go", "auth.go", "policy.go", "schedule.go", "crypt.go", "validate.go"}
	codeRe := regexp.MustCompile(`(?:errCode\(w, [A-Za-z.]+, |\bue\()"([a-z_][a-z_0-9.]*[a-z0-9])"`)
	keyRe := regexp.MustCompile(`"((?:log|access)\.[a-z_0-9.]*[a-z0-9])"`)
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range codeRe.FindAllStringSubmatch(string(b), -1) {
			for _, l := range langs {
				if !testHasKey(l, "err."+m[1]) {
					t.Errorf("%s: hata kodu %q için err.%s katalogda yok (%s)", f, m[1], m[1], l)
				}
			}
			n++
		}
		for _, m := range keyRe.FindAllStringSubmatch(string(b), -1) {
			for _, l := range langs {
				if !testHasKey(l, m[1]) {
					t.Errorf("%s: anahtar %q katalogda yok (%s)", f, m[1], l)
				}
			}
			n++
		}
	}
	if n < 100 {
		t.Fatalf("tarama çok az anahtar buldu (%d): düzenli ifade bozulmuş olabilir", n)
	}
	// çalışma anında birleştirilen anahtarlar
	var dyn []string
	for _, act := range []string{"enable", "disable", "freeze", "unfreeze", "delete", "policy", "internet", "expires", "group", "schedule"} {
		dyn = append(dyn, "log.peer_bulk."+act)
	}
	for _, w := range []string{"vpn", "inet"} {
		for _, nw := range []string{"vpn", "inet"} {
			dyn = append(dyn, "log.peer_regenerate."+w+"_"+nw, "log.peer_regenerate."+w+"_"+nw+"_ip")
		}
	}
	for _, c := range []string{"bad_scope", "bad_time", "same_time", "bad_day", "no_days"} {
		dyn = append(dyn, "err.rule.schedule_"+c, "err.schedule."+c)
	}
	for _, k := range append(dyn, "log.peer_edit.schedule_tunnel", "log.peer_edit.schedule_internet", "err.ip.pool_full", "totp.flag_user") {
		for _, l := range langs {
			if !testHasKey(l, k) {
				t.Errorf("anahtar %q katalogda yok (%s)", k, l)
			}
		}
	}
}

// Her kural hatası kendi kodunu ve kural sırasını taşır (metne bağlı değil).
func TestRuleErrorCodes(t *testing.T) {
	peers := []Peer{{ID: "a", Name: "a"}}
	for _, c := range []struct {
		name string
		r    Rule
		code string
	}{
		{"cihaz yalnız device hedefinde", Rule{Target: "server", Device: "a", Proto: "tcp"}, "rule.device_only"},
		{"olmayan cihaz", Rule{Target: "device", Device: "yok", Proto: "tcp"}, "rule.device_missing"},
		{"bilinmeyen hedef", Rule{Target: "x", Proto: "tcp"}, "rule.bad_target"},
		{"both yalnız cihaza", Rule{Target: "server", Proto: "tcp", Both: true}, "rule.both_single"},
		{"icmp portlu", Rule{Target: "server", Proto: "icmp", Ports: "1"}, "rule.ports_tcp_udp_only"},
		{"bilinmeyen protokol", Rule{Target: "server", Proto: "sctp"}, "rule.bad_proto"},
		{"bozuk port", Rule{Target: "server", Proto: "tcp", Ports: "99999"}, "rule.port_bad"},
		{"boş port elemanı", Rule{Target: "server", Proto: "tcp", Ports: "80,,81"}, "rule.port_empty_item"},
		{"çok port", Rule{Target: "server", Proto: "tcp", Ports: strings.Repeat("1,", 20) + "2"}, "rule.port_too_many"},
		{"uzun not", Rule{Target: "server", Proto: "tcp", Note: strings.Repeat("x", maxRuleNote+1)}, "rule.note_invalid"},
		{"zaman: saat", Rule{Target: "server", Proto: "tcp", Schedule: &Schedule{Days: []int{1}, From: "8", To: "09:00"}}, "rule.schedule_bad_time"},
		{"zaman: aynı saat", Rule{Target: "server", Proto: "tcp", Schedule: &Schedule{Days: []int{1}, From: "08:00", To: "08:00"}}, "rule.schedule_same_time"},
		{"zaman: gün", Rule{Target: "server", Proto: "tcp", Schedule: &Schedule{Days: []int{7}, From: "08:00", To: "09:00"}}, "rule.schedule_bad_day"},
		{"zaman: günsüz", Rule{Target: "server", Proto: "tcp", Schedule: &Schedule{From: "08:00", To: "09:00"}}, "rule.schedule_no_days"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := normalizeRule(c.r, peers, 3)
			var ce *codedErr
			if !errors.As(err, &ce) || ce.Code != c.code || ce.Params["n"] != 3 {
				t.Fatalf("hata %v, beklenen kod %q ve n=3", err, c.code)
			}
			for _, l := range langs {
				if s := T(l, "err."+ce.Code, ce.Params); strings.ContainsAny(s, "{}") || s == "err."+ce.Code {
					t.Fatalf("%s: çözülmemiş metin %q", l, s)
				}
			}
		})
	}
	// profil düzeyinde sıra: ikinci kuraldaki hata "2" taşır
	_, err := normalizePolicy(Policy{Name: "x", Rules: []Rule{{Target: "server", Proto: "tcp"}, {Target: "server", Proto: "sctp"}}}, nil)
	var ce *codedErr
	if !errors.As(err, &ce) || ce.Code != "rule.bad_proto" || ce.Params["n"] != 2 {
		t.Fatalf("profil içi kural sırası: %v", err)
	}
}

func TestScheduleErrorCodes(t *testing.T) {
	for code, s := range map[string]*Schedule{
		"schedule.bad_scope": {Days: []int{1}, From: "08:00", To: "09:00", Scope: "x"},
		"schedule.bad_time":  {Days: []int{1}, From: "8", To: "09:00", Scope: "tunnel"},
		"schedule.same_time": {Days: []int{1}, From: "08:00", To: "08:00", Scope: "tunnel"},
		"schedule.bad_day":   {Days: []int{-1}, From: "08:00", To: "09:00", Scope: "tunnel"},
		"schedule.no_days":   {From: "08:00", To: "09:00", Scope: "tunnel"},
	} {
		if _, err := normalizeSchedule(s); errCodeOf(err) != code {
			t.Errorf("%s bekleniyordu, %v", code, err)
		}
	}
}

// Şifreleme ve parola doğrulayıcıları kodlu hata döner; kimlik karşılaştırması (errors.Is) korunur.
func TestCryptAndPasswordCodes(t *testing.T) {
	if errCodeOf(checkPass("kisa")) != "crypt.pass_length" {
		t.Fatal("kısa yedek parolası kodu")
	}
	if _, err := newAdmin("kisa"); errCodeOf(err) != "password.too_short" {
		t.Fatalf("kısa parola: %v", err)
	}
	if errCodeOf(errNeedPass) != "crypt.need_pass" || errCodeOf(errBadPass) != "crypt.bad_pass" {
		t.Fatal("errNeedPass/errBadPass kodu")
	}
	if _, err := decryptBackup([]byte("x"), "parola-123"); errCodeOf(err) != "crypt.bad_format" {
		t.Fatalf("biçim: %v", err)
	}
}

// Gerekçe isteğin dilinde gelir: X-Kut-Lang başlığı → T(lang, ...); hata gövdesi kod taşır.
func TestReachReasonFollowsRequestLanguage(t *testing.T) {
	a, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	a.peers = []Peer{{ID: "a", Name: "a", IP: "10.77.0.2", Enabled: true}}
	get := func(lang string) string {
		rec := rqH(h, "GET", "/api/reach?src=a&dst=nope&proto=tcp&port=80", nil, c, map[string]string{"X-Kut-Lang": lang})
		var v Verdict
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != 200 {
			t.Fatalf("%s: %d %s", lang, rec.Code, rec.Body)
		}
		return v.Reason
	}
	if got, want := get("tr"), T("tr", "access.dst_not_found", nil); got != want {
		t.Fatalf("tr gerekçe %q, beklenen %q", got, want)
	}
	if got, want := get("en"), T("en", "access.dst_not_found", nil); got != want || got == get("tr") {
		t.Fatalf("en gerekçe %q, beklenen %q", got, want)
	}
	rec := rqH(h, "GET", "/api/reach?src=a&dst=server&proto=tcp&port=0", nil, c, nil)
	if code, _ := testErrCode(t, rec.Body.Bytes()); rec.Code != 400 || code != "reach.bad_port" {
		t.Fatalf("reach port: %d %s", rec.Code, rec.Body)
	}
}

// IP denetimi: kod + parametre + isteğin dilinde "message".
func TestIPCheckCodedMessage(t *testing.T) {
	_, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	rec := rqH(h, "GET", "/api/ipcheck?ip=10.99.0.5", nil, c, map[string]string{"X-Kut-Lang": "en"})
	var r struct {
		OK      bool           `json:"ok"`
		Code    string         `json:"code"`
		Params  map[string]any `json:"params"`
		Message string         `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || r.OK || r.Code != "ip.outside" || r.Params["subnet"] != "10.77.0.0/24" {
		t.Fatalf("ipcheck: %s", rec.Body)
	}
	if r.Message != T("en", "err.ip.outside", r.Params) {
		t.Fatalf("message: %q", r.Message)
	}
	rec = rqH(h, "GET", "/api/ipcheck?ip=10.77.0.9", nil, c, map[string]string{"X-Kut-Lang": "tr"})
	r = struct {
		OK      bool           `json:"ok"`
		Code    string         `json:"code"`
		Params  map[string]any `json:"params"`
		Message string         `json:"message"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || !r.OK || r.Message != T("tr", "access.ip_available", nil) {
		t.Fatalf("ipcheck ok: %s", rec.Body)
	}
}

// rqH: rq + ek istek başlıkları (ör. X-Kut-Lang).
func rqH(h http.Handler, method, path string, body []byte, c *http.Cookie, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("X-Kut", "1")
	r.RemoteAddr = "198.51.100.7:4000"
	if c != nil {
		r.AddCookie(c)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}
