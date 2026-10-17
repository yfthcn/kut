package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// httptest sunucuları loopback'te dinler; üretimdeki giden-bağlantı korumasını (dialGuardOff) paket
// düzeyinde kapatırız. Korumayı sınayan testler onu geçici olarak açar (bkz. withDialGuard).
func TestMain(m *testing.M) {
	dialGuardOff = true
	os.Exit(m.Run())
}

func withDialGuard(t *testing.T) {
	t.Helper()
	dialGuardOff = false
	t.Cleanup(func() { dialGuardOff = true })
}

const testTok = "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0"

type hookSrv struct {
	*httptest.Server
	mu   sync.Mutex
	got  []string
	ch   chan string
	code int
}

func newHook(t *testing.T) *hookSrv {
	h := &hookSrv{ch: make(chan string, 32), code: 200}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.got = append(h.got, r.URL.Path+" "+string(b))
		code := h.code
		h.mu.Unlock()
		h.ch <- r.URL.Path + " " + string(b)
		w.WriteHeader(code)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookSrv) wait(t *testing.T) string {
	t.Helper()
	select {
	case s := <-h.ch:
		return s
	case <-time.After(2 * time.Second):
		t.Fatal("bildirim gelmedi")
		return ""
	}
}

func (h *hookSrv) none(t *testing.T) {
	t.Helper()
	select {
	case s := <-h.ch:
		t.Fatalf("bildirim gelmemeliydi: %s", s)
	case <-time.After(150 * time.Millisecond):
	}
}

func notifTestSetup(t *testing.T) (*notifier, *hookSrv) {
	t.Helper()
	retryDelays = []time.Duration{0}
	h := newHook(t)
	n := newNotifier("")
	c := defaultNotify()
	c.Webhook.Enabled, c.Webhook.URL = true, h.URL+"/hook"
	n.set(c)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go n.run(ctx)
	return n, h
}

func TestNotifyClassification(t *testing.T) {
	n, h := notifTestSetup(t)
	// ilk giriş yeni IP → bildirim; aynı IP tekrar → sessiz
	n.onEvent(Event{Kind: "login", IP: "9.9.9.9", User: "admin", Text: "Giriş yapıldı"})
	if s := h.wait(t); !strings.Contains(s, "9.9.9.9") || !strings.Contains(s, `"category":"security"`) {
		t.Fatalf("giriş bildirimi: %s", s)
	}
	n.onEvent(Event{Kind: "login", IP: "9.9.9.9", Text: "Giriş yapıldı"})
	h.none(t)
	// başarısız giriş: 1. ve 2. sessiz, 3. bildirim
	for i := 0; i < 2; i++ {
		n.onEvent(Event{Kind: "login_fail", IP: "6.6.6.6"})
	}
	h.none(t)
	n.onEvent(Event{Kind: "login_fail", IP: "6.6.6.6"})
	if s, want := h.wait(t), T("tr", "notify.failed_logins", map[string]any{"n": 3, "min": 15, "ip": "6.6.6.6"}); !strings.Contains(s, want) {
		t.Fatalf("başarısız giriş: %s, beklenen %q", s, want)
	}
	// ilgisiz olay
	n.onEvent(Event{Kind: "peer_edit", Text: "x"})
	h.none(t)
	// mesaj gizli bir şey içermemeli
	n.onEvent(Event{Kind: "password", IP: "1.1.1.1", User: "admin"})
	if s := h.wait(t); strings.Contains(strings.ToLower(s), "private") {
		t.Fatalf("sızıntı: %s", s)
	}
}

func TestNotifyTogglesQuietDedupeCap(t *testing.T) {
	n, h := notifTestSetup(t)
	c := n.get()
	c.Device = false
	n.set(c)
	n.onEvent(Event{Kind: "peer_first", Text: "Cihaz ilk kez bağlandı: a"})
	h.none(t) // kategori kapalı
	c.Device, c.System = true, true
	// şimdi sessiz saat: her zaman içinde kalan aralık
	now := time.Now()
	c.QuietFrom, c.QuietTo = now.Add(-time.Hour).Format("15:04"), now.Add(time.Hour).Format("15:04")
	n.set(c)
	if inQuiet("00:00", "00:00", now) {
		t.Fatal("aynı saat sessiz sayılmamalı")
	}
	if !inQuiet("22:00", "07:00", time.Date(2026, 1, 1, 23, 30, 0, 0, time.Local)) || !inQuiet("22:00", "07:00", time.Date(2026, 1, 1, 6, 0, 0, 0, time.Local)) || inQuiet("22:00", "07:00", time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)) {
		t.Fatal("gece yarısını aşan aralık yanlış")
	}
	n.onEvent(Event{Kind: "firewall", Text: "kurallar onarıldı"})
	h.none(t) // sessiz saat
	n.onEvent(Event{Kind: "password", IP: "2.2.2.2"})
	h.wait(t) // güvenlik sessiz saatten etkilenmez
	// tekrar eden aynı mesaj elenir
	c.QuietFrom, c.QuietTo = "", ""
	n.set(c)
	n.onEvent(Event{Kind: "firewall", Text: "kurallar onarıldı"})
	h.wait(t)
	n.onEvent(Event{Kind: "firewall", Text: "kurallar onarıldı"})
	h.none(t)
	// saatlik sınır
	old := notifyPerHr
	notifyPerHr = 3
	defer func() { notifyPerHr = old }()
	n.mu.Lock()
	n.sent = nil
	n.mu.Unlock()
	for i := 0; i < 6; i++ {
		n.onEvent(Event{Kind: "start", Text: "başladı " + string(rune('a'+i))})
	}
	for i := 0; i < 4; i++ { // 3 mesaj + 1 sınır uyarısı
		h.wait(t)
	}
	h.none(t)
}

func TestTelegramSendAndTokenScrub(t *testing.T) {
	retryDelays = []time.Duration{0}
	h := newHook(t)
	old := tgBase
	tgBase = h.URL
	defer func() { tgBase = old }()
	n := newNotifier("")
	c := defaultNotify()
	c.Telegram.Enabled, c.Telegram.Token, c.Telegram.ChatID = true, testTok, "42"
	// sahte sunucu Telegram biçiminde yanıt vermiyor → sonuç hata olur; asıl amaç yol ve gövde
	n.deliver(context.Background(), c, notifMsg{Cat: "system", Kind: "test", Text: "merhaba", T: time.Now()}, false)
	got := h.wait(t)
	if !strings.HasPrefix(got, "/bot"+testTok+"/sendMessage ") || !strings.Contains(got, `"chat_id":"42"`) || !strings.Contains(got, "merhaba") {
		t.Fatalf("istek: %s", got)
	}
	// ulaşılamayan sunucu: hata metninde jeton olmamalı
	tgBase = "http://127.0.0.1:1"
	res := n.deliver(context.Background(), c, notifMsg{Cat: "system", Text: "x", T: time.Now()}, false)
	if res[0].err == nil || strings.Contains(res[0].err.Error(), testTok) {
		t.Fatalf("jeton hata metnine sızdı: %v", res[0].err)
	}
}

func TestWebhookNoRedirectAndStatus(t *testing.T) {
	retryDelays = []time.Duration{0}
	target := newHook(t)
	red := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/evil", http.StatusFound)
	}))
	defer red.Close()
	err := webhookCall(context.Background(), red.URL+"/x", "h", notifMsg{Text: "t", T: time.Now()})
	if err == nil {
		t.Fatal("yönlendirme başarı sayılmamalı")
	}
	target.none(t) // yönlendirme izlenmedi
	target.mu.Lock()
	target.code = 500
	target.mu.Unlock()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	err = webhookCall(context.Background(), target.URL+"/ok", "h", notifMsg{Text: "t", T: time.Now()})
	log.SetOutput(os.Stderr)
	if err == nil {
		t.Fatal("500 hata olmalı")
	}
	// HTTP kodu arayüze/last_error'a gitmez (iç ağ servis keşfi sinyali), yalnızca günlüğe
	if !errors.Is(err, errWebhookRejected) || strings.Contains(err.Error(), "500") || strings.Contains(localizedErr("tr", err), "500") {
		t.Errorf("arayüze giden metin genel olmalı: %q", err)
	}
	if !strings.Contains(buf.String(), "500") {
		t.Errorf("HTTP kodu günlüğe yazılmalı: %q", buf.String())
	}
}

func TestNotifyAPI(t *testing.T) {
	a, h := v5App(t)
	a.nf = newNotifier("")
	c := login(h, "", "correct-horse-battery")
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/api/notify", strings.NewReader(body))
		req.Header.Set("X-Kut", "1")
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if r := put(`{"telegram":{"enabled":true,"token":"","chat_id":""},"ev_security":true}`); r.Code != 400 {
		t.Fatalf("jetonsuz açılmamalı: %d", r.Code)
	}
	if r := put(`{"telegram":{"enabled":false,"token":"bozuk"}}`); r.Code != 400 {
		t.Fatalf("bozuk jeton: %d", r.Code)
	}
	if r := put(`{"webhook":{"enabled":true,"url":"ftp://x"}}`); r.Code != 400 {
		t.Fatalf("webhook şeması: %d", r.Code)
	}
	if r := put(`{"quiet_from":"23:00"}`); r.Code != 400 {
		t.Fatalf("tek sessiz saat: %d", r.Code)
	}
	r := put(`{"telegram":{"enabled":true,"token":"` + testTok + `","chat_id":"42"},"ev_security":true,"ev_system":true,"ev_device":false,"quiet_from":"23:00","quiet_to":"07:00"}`)
	if r.Code != 200 {
		t.Fatalf("geçerli kayıt: %d %s", r.Code, r.Body.String())
	}
	if strings.Contains(r.Body.String(), testTok) || strings.Contains(r.Body.String(), "AAHdq") {
		t.Fatalf("yanıtta jeton var: %s", r.Body.String())
	}
	var v notifyView
	json.Unmarshal(r.Body.Bytes(), &v)
	if !v.Telegram.TokenSet || v.Device || v.QuietFrom != "23:00" {
		t.Fatalf("görünüm: %+v", v)
	}
	// boş jeton gönderince mevcut jeton korunur
	if r := put(`{"telegram":{"enabled":true,"token":"","chat_id":"42"},"ev_security":true}`); r.Code != 200 || a.nf.get().Telegram.Token != testTok {
		t.Fatalf("jeton korunmalı: %d", r.Code)
	}
	// Webhook adresi sırdır: kayıttan sonra hiçbir yanıtta yol/anahtar geri dönmez.
	const whSecret = "T000/B000/SECRETXYZ"
	r = put(`{"webhook":{"enabled":true,"url":"https://hooks.example.com/services/` + whSecret + `"}}`)
	if r.Code != 200 {
		t.Fatalf("webhook kaydı: %d %s", r.Code, r.Body.String())
	}
	var raw map[string]any
	_ = json.Unmarshal(r.Body.Bytes(), &raw)
	if strings.Contains(r.Body.String(), "SECRETXYZ") || strings.Contains(r.Body.String(), "/services/") {
		t.Fatalf("PUT yanıtında webhook adresi var: %s", r.Body.String())
	}
	if raw["webhook_set"] != true || raw["webhook_host"] != "https://hooks.example.com/…" {
		t.Fatalf("webhook_set/webhook_host: %v / %v", raw["webhook_set"], raw["webhook_host"])
	}
	greq := httptest.NewRequest(http.MethodGet, "/api/notify", nil)
	greq.AddCookie(c)
	grec := httptest.NewRecorder()
	h.ServeHTTP(grec, greq)
	if grec.Code != 200 || strings.Contains(grec.Body.String(), "SECRETXYZ") || !strings.Contains(grec.Body.String(), `"webhook_set":true`) {
		t.Fatalf("GET: %d %s", grec.Code, grec.Body.String())
	}
	// boş adres gönderince mevcut adres korunur (Telegram jetonu kalıbı)
	if r := put(`{"webhook":{"enabled":true,"url":""}}`); r.Code != 200 || !strings.HasSuffix(a.nf.get().Webhook.URL, whSecret) {
		t.Fatalf("adres korunmalı: %d %q", r.Code, a.nf.get().Webhook.URL)
	}
	// açıkça silme
	if r := put(`{"webhook":{"enabled":false,"url":""},"drop_webhook":true}`); r.Code != 200 || a.nf.get().Webhook.URL != "" {
		t.Fatalf("adres silinmeli: %d %q", r.Code, a.nf.get().Webhook.URL)
	}
	if r := put(`{"webhook":{"enabled":true,"url":""}}`); r.Code != 400 {
		t.Fatalf("adressiz webhook açılmamalı: %d", r.Code)
	}
	// viewer erişemez
	adm := a.nf
	_ = adm
}

func TestTelegramFind(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/getMe"):
			io.WriteString(w, `{"ok":true,"result":{"username":"kut_test_bot"}}`)
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			io.WriteString(w, `{"ok":true,"result":[{"message":{"chat":{"id":7,"type":"private","first_name":"Eski"}}},{"message":{"chat":{"id":99,"type":"private","first_name":"Test","username":"testuser"}}},{"message":{"chat":{"id":-5,"type":"group","first_name":""}}}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	old := tgBase
	tgBase = srv.URL
	defer func() { tgBase = old }()
	a, h := v5App(t)
	a.nf = newNotifier("")
	c := login(h, "", "correct-horse-battery")
	rec := post(h, "/api/notify/telegram-find", `{"token":"`+testTok+`"}`, c)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"chat_id":"99"`) || !strings.Contains(rec.Body.String(), "kut_test_bot") {
		t.Fatalf("find: %d %s", rec.Code, rec.Body.String())
	}
}

func TestWatchOffline(t *testing.T) {
	a := testApp(t)
	a.act = &activity{}
	a.nf = newNotifier("")
	now := time.Now()
	stale := now.Add(-30 * time.Hour).Unix()
	peers := []Peer{{ID: "1", Name: "eski", Enabled: true, LastSeen: stale}}
	a.watchOffline(peers, now) // ilk tur: bilinen sayılır, olay yok
	if len(a.act.evs) != 0 {
		t.Fatal("ilk turda olay olmamalı")
	}
	peers = append(peers, Peer{ID: "2", Name: "yeni", Enabled: true, LastSeen: stale})
	a.watchOffline(peers, now)
	if len(a.act.evs) != 1 || !strings.Contains(a.act.evs[0].Text, "yeni") || a.act.evs[0].Code != "log.peer_offline" || a.act.evs[0].Params["name"] != "yeni" {
		t.Fatalf("olay: %+v", a.act.evs)
	}
	a.watchOffline(peers, now) // tekrar etmez
	if len(a.act.evs) != 1 {
		t.Fatal("tekrarlandı")
	}
}

// Bildirim metinleri sunucu dilinde üretilir (sözleşme 5); zaman damgası da o dilin biçiminde.
func TestNotifyTextsFollowServerLang(t *testing.T) {
	n, h := notifTestSetup(t)
	n.lang = func() string { return "en" }
	n.onEvent(Event{Kind: "login", IP: "9.9.9.9", User: "admin"})
	if s, want := h.wait(t), T("en", "notify.new_ip_login", map[string]any{"who": "admin @ 9.9.9.9"}); !strings.Contains(s, want) || want == "notify.new_ip_login" {
		t.Fatalf("en giriş bildirimi: %s, beklenen %q", s, want)
	}
	n.onEvent(Event{Kind: "totp_off", IP: "1.1.1.1", User: "admin"})
	if s, want := h.wait(t), T("en", "notify.totp_off", map[string]any{"who": "admin @ 1.1.1.1"}); !strings.Contains(s, want) {
		t.Fatalf("en 2FA bildirimi: %s, beklenen %q", s, want)
	}
	m := notifMsg{Cat: "system", Text: "x", T: time.Date(2026, 3, 4, 5, 6, 0, 0, time.Local)}
	if r := n.render(m); !strings.Contains(r, fmtTime("en", m.T, false)) {
		t.Fatalf("en zaman biçimi: %q", r)
	}
	n.lang = func() string { return "tr" }
	if r := n.render(m); !strings.Contains(r, fmtTime("tr", m.T, false)) {
		t.Fatalf("tr zaman biçimi: %q", r)
	}
	for i := 0; i < 3; i++ {
		n.onEvent(Event{Kind: "login_fail", IP: "5.5.5.5"})
	}
	if s, want := h.wait(t), T("tr", "notify.failed_logins", map[string]any{"n": 3, "min": 15, "ip": "5.5.5.5"}); !strings.Contains(s, want) || !strings.Contains(want, "başarısız") {
		t.Fatalf("tr başarısız giriş: %s, beklenen %q", s, want)
	}
}

// Silinen cihazın kimliği offline kümesinde birikmemeli: her tur, listede olmayan kimlikleri budar.
func TestWatchOfflinePrunesDeletedPeers(t *testing.T) {
	a := testApp(t)
	a.act = &activity{}
	a.nf = newNotifier("")
	now := time.Now()
	stale := now.Add(-30 * time.Hour).Unix()
	a.watchOffline([]Peer{{ID: "1", Name: "a", Enabled: true, LastSeen: stale}, {ID: "2", Name: "b", Enabled: true, LastSeen: stale}}, now)
	a.watchOffline([]Peer{{ID: "2", Name: "b", Enabled: true, LastSeen: stale}}, now)
	a.nf.mu.Lock()
	_, kept1 := a.nf.offline["1"]
	n := len(a.nf.offline)
	a.nf.mu.Unlock()
	if kept1 || n != 1 {
		t.Fatalf("silinen cihaz budanmalı: %v", a.nf.offline)
	}
	a.watchOffline(nil, now)
	if len(a.nf.offline) != 0 {
		t.Fatalf("cihaz kalmayınca küme boşalmalı: %v", a.nf.offline)
	}
}

// Telegram'ın beklenmeyen yanıtında HTTP kodu arayüze (test sonucu, last_error) gitmez; yalnızca günlüğe.
func TestTelegramErrorHidesHTTPStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "<html>bad gateway</html>")
	}))
	defer srv.Close()
	old := tgBase
	tgBase = srv.URL
	defer func() { tgBase = old }()
	retryDelays = []time.Duration{0}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	a, h := v5App(t)
	a.nf = newNotifier("")
	c := defaultNotify()
	c.Telegram.Enabled, c.Telegram.Token, c.Telegram.ChatID = true, testTok, "42"
	a.nf.set(c)
	ck := login(h, "", "correct-horse-battery")
	r := post(h, "/api/notify/test", `{}`, ck)
	var res map[string]string
	if json.Unmarshal(r.Body.Bytes(), &res) != nil || r.Code != 200 || res["telegram"] == "" || res["telegram"] == "ok" {
		t.Fatalf("test sonucu: %d %s", r.Code, r.Body)
	}
	if strings.Contains(res["telegram"], "502") || strings.Contains(res["telegram"], "HTTP") {
		t.Errorf("HTTP kodu arayüze gitti: %q", res["telegram"])
	}
	if !strings.Contains(buf.String(), "502") {
		t.Errorf("HTTP kodu günlüğe yazılmalı: %q", buf.String())
	}
	// arka plan teslimi: last_error da genel kalır
	a.nf.handle(context.Background(), notifMsg{Cat: "system", Kind: "test", Text: "x", T: time.Now()})
	g := httptest.NewRequest(http.MethodGet, "/api/notify", nil)
	g.AddCookie(ck)
	gr := httptest.NewRecorder()
	h.ServeHTTP(gr, g)
	var v notifyView
	if json.Unmarshal(gr.Body.Bytes(), &v) != nil || v.LastErr == "" || strings.Contains(v.LastErr, "502") {
		t.Errorf("last_error: %q", v.LastErr)
	}
}

// Bildirim uç noktalarının hataları kodludur (sözleşme 1).
func TestNotifyErrorsAreCoded(t *testing.T) {
	a, h := v5App(t)
	a.nf = newNotifier("")
	c := login(h, "", "correct-horse-battery")
	for _, tc := range []struct{ body, code string }{
		{`{"telegram":{"enabled":false,"token":"bozuk"}}`, "notify.bad_token"},
		{`{"telegram":{"enabled":false,"chat_id":"abc"}}`, "notify.bad_chat_id"},
		{`{"telegram":{"enabled":true,"token":"","chat_id":""}}`, "notify.telegram_incomplete"},
		{`{"webhook":{"enabled":true,"url":"ftp://x"}}`, "notify.bad_webhook_url"},
		{`{"webhook":{"enabled":true,"url":""}}`, "notify.webhook_no_url"},
		{`{"quiet_from":"25:00","quiet_to":"07:00"}`, "notify.bad_quiet_time"},
		{`{"quiet_from":"23:00"}`, "notify.quiet_incomplete"},
	} {
		r := sendAs(h, "PUT", "/api/notify", tc.body, c, nil)
		var b struct{ Code string }
		if json.Unmarshal(r.Body.Bytes(), &b); r.Code != 400 || b.Code != tc.code {
			t.Errorf("%s: %d %s, beklenen %s", tc.body, r.Code, r.Body, tc.code)
		}
	}
	for _, tc := range []struct{ path, body, code string }{
		{"/api/notify/test", `{}`, "notify.no_channel"},
		{"/api/notify/telegram-find", `{"token":""}`, "notify.no_token"},
	} {
		r := post(h, tc.path, tc.body, c)
		var b struct{ Code string }
		if json.Unmarshal(r.Body.Bytes(), &b); r.Code != 400 || b.Code != tc.code {
			t.Errorf("%s: %d %s, beklenen %s", tc.path, r.Code, r.Body, tc.code)
		}
	}
}

func tgRateLimitServer(t *testing.T, retryAfter int, failures int) (*httptest.Server, *[]time.Time) {
	t.Helper()
	var mu sync.Mutex
	var hits []time.Time
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, time.Now())
		n := len(hits)
		mu.Unlock()
		if n <= failures {
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]any{"ok": false, "description": "Too Many Requests", "parameters": map[string]any{"retry_after": retryAfter}})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "result": true})
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestTelegramRetryAfterCappedAt60s(t *testing.T) {
	srv, _ := tgRateLimitServer(t, 3600, 1)
	old := tgBase
	tgBase = srv.URL
	defer func() { tgBase = old }()
	err := tgCall(context.Background(), testTok, "sendMessage", struct{}{}, nil)
	var ra retryAfterErr
	if !errors.As(err, &ra) || ra.after != 60*time.Second {
		t.Fatalf("429 retry_after 60 sn ile sınırlanmalı: %v (%v)", err, ra.after)
	}
}

func TestTelegramRetryHonorsRetryAfter(t *testing.T) {
	srv, hits := tgRateLimitServer(t, 1, 1)
	oldBase, oldDelays := tgBase, retryDelays
	tgBase, retryDelays = srv.URL, []time.Duration{0, 10 * time.Second} // sabit gecikme 10 sn; sunucu 1 sn istiyor
	defer func() { tgBase, retryDelays = oldBase, oldDelays }()
	n := newNotifier("")
	c := defaultNotify()
	c.Telegram.Enabled, c.Telegram.Token, c.Telegram.ChatID = true, testTok, "42"
	start := time.Now()
	res := n.deliver(context.Background(), c, notifMsg{Cat: "system", Kind: "test", Text: "x", T: time.Now()}, true)
	if len(res) != 1 || res[0].err != nil {
		t.Fatalf("ikinci deneme başarılı olmalı: %+v", res)
	}
	if len(*hits) != 2 {
		t.Fatalf("istek sayısı: %d", len(*hits))
	}
	if d := time.Since(start); d < 900*time.Millisecond || d > 5*time.Second {
		t.Fatalf("bekleme retry_after (1 sn) kadar olmalı, ölçülen %v", d)
	}
}

// scrubURL: gerçek http.Client hata yolunda adres, kimlik bilgisi ve yol hiçbir yere sızmamalı.
func TestWebhookErrorsDoNotLeakURL(t *testing.T) {
	retryDelays = []time.Duration{0}
	for _, raw := range []string{
		"HTTPS://127.0.0.1:1/services/SECRETXYZ",
		"https://uuser:ppass@127.0.0.1:1/x",
		"https://127.0.0.1:1/se cret/SECRETXYZ",
	} {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		n := newNotifier("")
		c := defaultNotify()
		c.Webhook.Enabled, c.Webhook.URL = true, raw
		res := n.deliver(context.Background(), c, notifMsg{Cat: "system", Text: "x", T: time.Now()}, false)
		log.SetOutput(os.Stderr)
		if res[0].err == nil {
			t.Fatalf("%q: hata bekleniyordu", raw)
		}
		all := res[0].err.Error() + "\n" + buf.String()
		for _, bad := range []string{"SECRETXYZ", "ppass", "uuser", "se cret", "se%20cret", "/services", "/x"} {
			if strings.Contains(all, bad) {
				t.Errorf("%q: %q sızdı:\n%s", raw, bad, all)
			}
		}
	}
}

func TestBlockedAddr(t *testing.T) {
	own := []netip.Addr{netip.MustParseAddr("10.9.8.7"), netip.MustParseAddr("2001:db8::77")}
	for _, c := range []struct {
		ip      string
		blocked bool
	}{
		{"127.0.0.1", true}, {"127.8.8.8", true}, {"::1", true}, {"::ffff:127.0.0.1", true},
		{"0.0.0.0", true}, {"::", true},
		{"169.254.169.254", true}, {"fe80::1", true}, {"fe80::1%eth0", true},
		{"fd00:ec2::254", true}, {"100.100.100.200", true}, // AWS IPv6 ve Alibaba metadata uçları
		{"fd00:ec2::253", false}, {"100.100.100.201", false}, // komşuları ULA/CGNAT olarak açık kalır
		{"224.0.0.1", true}, {"ff02::1", true},
		{"10.9.8.7", true}, {"::ffff:10.9.8.7", true}, {"2001:db8::77", true}, // sunucunun kendi adresi
		{"10.0.0.5", false}, {"172.16.4.4", false}, {"192.168.1.10", false}, {"fd00::5", false}, // RFC1918/ULA açık
		{"8.8.8.8", false}, {"2001:db8::1", false},
	} {
		if got := blockedAddr(netip.MustParseAddr(c.ip), own); got != c.blocked {
			t.Errorf("blockedAddr(%s) = %v, beklenen %v", c.ip, got, c.blocked)
		}
	}
}

func TestWebhookRejectsLoopbackAndOwnAddr(t *testing.T) {
	withDialGuard(t)
	retryDelays = []time.Duration{0}
	h := newHook(t) // 127.0.0.1'de dinliyor
	check := func(label, target string) {
		t.Helper()
		var buf bytes.Buffer
		log.SetOutput(&buf)
		err := webhookCall(context.Background(), target, "h", notifMsg{Text: "t", T: time.Now()})
		log.SetOutput(os.Stderr)
		if err == nil {
			t.Fatalf("%s: reddedilmeliydi", label)
		}
		if !errors.Is(err, errWebhookUnreachable) || err.Error() != errWebhookUnreachable.Error() {
			t.Errorf("%s: arayüze giden metin genel olmalı: %q", label, err)
		}
		var pe permErr
		if !errors.As(err, &pe) {
			t.Errorf("%s: reddedilen hedef yeniden denenmemeli (permErr)", label)
		}
		if !strings.Contains(buf.String(), errDialBlocked.Error()) {
			t.Errorf("%s: ayrıntı günlüğe yazılmalı: %q", label, buf.String())
		}
	}
	if err := guardDial("tcp4", "127.0.0.1:80", nil); !errors.Is(err, errDialBlocked) {
		t.Fatalf("loopback bağlantı korumasına takılmalı: %v", err)
	}
	check("127.0.0.1", h.URL+"/hook")
	check("localhost (DNS sonrası)", "http://localhost:"+strings.TrimPrefix(h.URL, "http://127.0.0.1:")+"/hook")
	h.none(t) // istek hedefe hiç ulaşmadı

	if l, err := net.Listen("tcp6", "[::1]:0"); err == nil {
		defer l.Close()
		check("[::1]", "http://"+l.Addr().String()+"/hook")
	} else {
		t.Logf("[::1] dinlenemedi, atlandı: %v", err)
	}

	// sunucunun kendi (loopback olmayan) arayüz adresi
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		ip, ok := a.(*net.IPNet)
		if !ok || ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.To4() == nil {
			continue
		}
		l, err := net.Listen("tcp4", ip.IP.String()+":0")
		if err != nil {
			continue
		}
		defer l.Close()
		check("kendi adres "+ip.IP.String(), "http://"+l.Addr().String()+"/hook")
		return
	}
	t.Log("loopback dışı IPv4 arayüz adresi yok; kendi-adres entegrasyonu atlandı (birim testi kapsıyor)")
}

// Sistem vekili kullanılmaz: vekil ortam değişkeni ayarlıyken bağlantı vekile gider ve dial guard yalnızca
// vekilin adresini görürdü (hedef metadata/iç adres olsa bile). Go ortamı süreç başına bir kez okuduğu için
// (http.ProxyFromEnvironment) asıl iddia yapısal: korumalı taşıma vekil işlevi taşımaz.
func TestGuardedTransportIgnoresProxyEnv(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:3128")
	if guardedTransport().Proxy != nil || httpc.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("bildirim taşıması sistem vekilini kullanmamalı")
	}
	withDialGuard(t)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := webhookCall(ctx, "http://169.254.169.254/latest/meta-data/", "h", notifMsg{Text: "t", T: time.Now()})
	if err == nil {
		t.Fatal("metadata hedefi reddedilmeli")
	}
	// permErr yalnızca errors.Is(err, errDialBlocked) iken döner: vekile gidilseydi geçici hata olurdu
	var pe permErr
	if !errors.As(err, &pe) || !strings.Contains(buf.String(), errDialBlocked.Error()) {
		t.Fatalf("hedef bağlantı korumasına takılmalı (vekile gidilmemeli): %v %q", err, buf.String())
	}
}

// Başarısız giriş sayacı IP başına tutulur: çok sayıda farklı IP'den gelen deneme haritayı sınırsız
// büyütmemeli (pencere içindeki 5000 IP dahil); pencereyi geçmiş girdiler yer açılırken süpürülür.
func TestNotifyFailCountersBounded(t *testing.T) {
	n, h := notifTestSetup(t)
	for i := range 5000 {
		n.onEvent(Event{Kind: "login_fail", IP: fmt.Sprintf("198.18.%d.%d", i/256, i%256)})
	}
	n.mu.Lock()
	got := len(n.fails)
	n.mu.Unlock()
	if got > 1024 {
		t.Fatalf("notifier.fails sınırsız büyüyor: %d girdi", got)
	}
	h.none(t) // her IP'den tek deneme: bildirim yok

	// pencereyi geçmiş girdiler: yeni IP'ler geldiğinde hepsi süpürülür
	n.mu.Lock()
	for _, f := range n.fails {
		f.since = time.Now().Add(-nFailWindow - time.Minute)
	}
	n.mu.Unlock()
	for i := range 10 {
		n.onEvent(Event{Kind: "login_fail", IP: fmt.Sprintf("198.19.0.%d", i)})
	}
	n.mu.Lock()
	stale := 0
	for ip := range n.fails {
		if strings.HasPrefix(ip, "198.18.") {
			stale++
		}
	}
	got = len(n.fails)
	n.mu.Unlock()
	if stale != 0 || got != 10 {
		t.Fatalf("süresi geçmiş girdiler süpürülmedi: %d eski, %d toplam", stale, got)
	}

	// sınırdayken de sayaç işler: aynı IP'nin 3. denemesi bildirim üretir
	for range 3 {
		n.onEvent(Event{Kind: "login_fail", IP: "203.0.113.9"})
	}
	if s, want := h.wait(t), T("tr", "notify.failed_logins", map[string]any{"n": 3, "min": 15, "ip": "203.0.113.9"}); !strings.Contains(s, want) {
		t.Fatalf("sınırda başarısız giriş bildirimi: %s, beklenen %q", s, want)
	}
}

// Çalışan panelde (loadApp) bildirimler sunucu dilinde gider; dil Ayarlar'dan değişince sonraki bildirim de.
func TestLoadedAppNotifiesInServerLang(t *testing.T) {
	cliEnv(t, nil)
	retryDelays = []time.Duration{0}
	a, err := loadApp(initDir(t, "-lang", "en"), true)
	if err != nil {
		t.Fatal(err)
	}
	h := newHook(t)
	c := defaultNotify()
	c.Webhook.Enabled, c.Webhook.URL = true, h.URL+"/hook"
	if err := a.nf.set(c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.nf.run(ctx)

	a.act.add(Event{T: time.Now().Unix(), Kind: "login", IP: "9.9.9.9", User: "admin"})
	if s, want := h.wait(t), T("en", "notify.new_ip_login", map[string]any{"who": "admin @ 9.9.9.9"}); !strings.Contains(s, want) {
		t.Fatalf("sunucu dili en: %s, beklenen %q", s, want)
	}
	s := a.getSrv()
	st := s.cfg()
	st.Lang = "tr"
	s.Settings = &st
	a.setSrv(s)
	a.act.add(Event{T: time.Now().Unix(), Kind: "login", IP: "8.8.4.4", User: "admin"})
	if s, want := h.wait(t), T("tr", "notify.new_ip_login", map[string]any{"who": "admin @ 8.8.4.4"}); !strings.Contains(s, want) {
		t.Fatalf("sunucu dili tr: %s, beklenen %q", s, want)
	}
}

// Başarılı giriş yapılan IP'lerin kümesi de sınırlı: çok sayıda farklı IP'den giriş haritayı sınırsız büyütmemeli.
func TestNotifyKnownIPsBounded(t *testing.T) {
	n, _ := notifTestSetup(t)
	for i := range 5000 {
		n.onEvent(Event{Kind: "login", IP: fmt.Sprintf("198.19.%d.%d", i/256, i%256), User: "admin"})
	}
	n.mu.Lock()
	got := len(n.known)
	n.mu.Unlock()
	if got > nFailMaxIPs {
		t.Fatalf("notifier.known sınırsız büyüyor: %d girdi", got)
	}
}
