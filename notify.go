package main

// Bildirimler: yalnızca TEK YÖNLÜ. Kut dışarıya mesaj yollar, dışarıdan hiçbir şey kabul etmez
// (komut yok, webhook dinleme yok, long polling yok). Mesajlarda anahtar, config, QR ya da parola olmaz.

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
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type NotifyCfg struct {
	Telegram struct {
		Enabled bool   `json:"enabled"`
		Token   string `json:"token,omitempty"`
		ChatID  string `json:"chat_id,omitempty"`
	} `json:"telegram"`
	Webhook struct {
		Enabled bool   `json:"enabled"`
		URL     string `json:"url,omitempty"`
	} `json:"webhook"`
	Security  bool   `json:"ev_security"` // giriş, parola, 2FA, hesap değişiklikleri
	System    bool   `json:"ev_system"`   // güvenlik duvarı onarımı, servis başlangıcı
	Device    bool   `json:"ev_device"`   // ilk bağlantı, uzun süre bağlanmayan, süresi dolan cihaz
	QuietFrom string `json:"quiet_from,omitempty"`
	QuietTo   string `json:"quiet_to,omitempty"`
}

func defaultNotify() NotifyCfg { return NotifyCfg{Security: true, System: true, Device: true} }

var (
	tgBase       = "https://api.telegram.org"
	retryDelays  = []time.Duration{0, 3 * time.Second, 10 * time.Second}
	tokenRe      = regexp.MustCompile(`^\d{5,15}:[A-Za-z0-9_-]{30,60}$`)
	chatIDRe     = regexp.MustCompile(`^-?\d{1,20}$`)
	clockRe      = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)
	notifyPerHr  = 30
	nFailWindow  = 15 * time.Minute
	dedupeWindow = time.Minute
)

// nFailMaxIPs: başarısız giriş sayacının tuttuğu en çok IP. Saldırgan çok sayıda adresten deneyince harita
// sınırsız büyümesin (limiter.fails'in toplu süpürme eşiğiyle aynı).
const nFailMaxIPs = 1024

type notifMsg struct {
	Cat, Kind, Text, User string
	T                     time.Time
}

type failCount struct {
	n     int
	since time.Time
}

type notifier struct {
	mu      sync.Mutex
	path    string
	cfg     NotifyCfg
	q       chan notifMsg
	sent    []time.Time
	recent  map[string]time.Time
	fails   map[string]*failCount
	known   map[string]bool // daha önce başarıyla giriş yapmış IP'ler
	offline map[string]bool
	offInit bool
	capWarn time.Time
	lastOK  time.Time
	lastErr error
	host    string
	// lang: bildirim metinlerinin dili (sunucu dili, a.srvLang). nil ise "tr" (srvLang'ın varsayılanı).
	lang func() string
}

// langOf: bildirim metinlerinin dili. n.mu tutulurken çağrılmaz (lang başka kilit alabilir).
func (n *notifier) langOf() string {
	if n.lang != nil {
		if l := normLang(n.lang()); l != "" {
			return l
		}
	}
	return "tr"
}

func newNotifier(path string) *notifier {
	n := &notifier{path: path, cfg: defaultNotify(), q: make(chan notifMsg, 64), recent: map[string]time.Time{}, fails: map[string]*failCount{}, known: map[string]bool{}, offline: map[string]bool{}}
	n.host, _ = os.Hostname()
	if path != "" {
		if b, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: path veri dizininden gelen sabit notify.json yolu
			c := defaultNotify()
			if json.Unmarshal(b, &c) == nil {
				n.cfg = c
			}
		}
	}
	return n
}

func (n *notifier) get() NotifyCfg {
	if n == nil {
		return defaultNotify()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.cfg
}

func (n *notifier) set(c NotifyCfg) error {
	// Diske yazma da kilit altında: iki eşzamanlı kayıtta eski görüntü yenisini ezemez.
	n.mu.Lock()
	defer n.mu.Unlock()
	n.cfg = c
	if n.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(n.path, append(b, '\n'))
}

func (c NotifyCfg) anyChannel() bool { return c.Telegram.Enabled || c.Webhook.Enabled }

// seed: önceki girişlerin IP'lerini "tanıdık" say; yeniden başlatma yüzünden bildirim yağmasın.
func (n *notifier) seed(evs []Event) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, e := range evs {
		if e.Kind == "login" {
			n.rememberIP(e.IP)
		}
	}
}

func inQuiet(from, to string, now time.Time) bool {
	if !clockRe.MatchString(from) || !clockRe.MatchString(to) || from == to {
		return false
	}
	cur := now.Format("15:04")
	if from < to {
		return cur >= from && cur < to
	}
	return cur >= from || cur < to // gece yarısını aşan aralık
}

// pruneFails: n.mu tutulurken, yeni IP'ye yer açar. Önce pencereyi geçmiş sayaçlar silinir; hepsi pencere
// içindeyse (çok sayıda adresten eşzamanlı deneme) en eski sayaç düşer, harita nFailMaxIPs'i aşmaz.
func (n *notifier) pruneFails(now time.Time) {
	for ip, f := range n.fails {
		if now.Sub(f.since) > nFailWindow {
			delete(n.fails, ip)
		}
	}
	for len(n.fails) >= nFailMaxIPs {
		oldest := ""
		for ip, f := range n.fails {
			if oldest == "" || f.since.Before(n.fails[oldest].since) {
				oldest = ip
			}
		}
		delete(n.fails, oldest)
	}
}

// onEvent: günlüğe düşen her olayı süzer; bildirime değer olanı kuyruğa atar. Asla bloklamaz.
func (n *notifier) onEvent(e Event) {
	if n == nil {
		return
	}
	cfg := n.get()
	if !cfg.anyChannel() {
		return
	}
	now := time.Now()
	l := n.langOf()
	var cat, text string
	who := e.IP
	if e.User != "" {
		who = e.User + " @ " + e.IP
	}
	switch e.Kind {
	case "login":
		n.mu.Lock()
		seen := n.known[e.IP]
		n.rememberIP(e.IP)
		n.mu.Unlock()
		if seen {
			return
		}
		cat, text = "security", T(l, "notify.new_ip_login", map[string]any{"who": who})
	case "login_fail", "totp_fail":
		n.mu.Lock()
		f := n.fails[e.IP]
		if f == nil || now.Sub(f.since) > nFailWindow {
			if f == nil && len(n.fails) >= nFailMaxIPs {
				n.pruneFails(now)
			}
			f = &failCount{since: now}
			n.fails[e.IP] = f
		}
		f.n++
		c := f.n
		n.mu.Unlock()
		if c != 3 && c != 10 {
			return
		}
		cat, text = "security", T(l, "notify.failed_logins", map[string]any{"n": c, "min": int(nFailWindow.Minutes()), "ip": e.IP})
	case "password":
		cat, text = "security", T(l, "notify.password_changed", map[string]any{"who": who})
	case "totp_off":
		cat, text = "security", T(l, "notify.totp_off", map[string]any{"who": who})
	case "user_create", "user_delete":
		cat, text = "security", T(l, "notify.account", map[string]any{"text": e.Text, "who": who})
	case "firewall", "start", "backup_fail":
		cat, text = "system", e.Text
	case "peer_first", "peer_offline", "peer_expired":
		cat, text = "device", e.Text
	default:
		return
	}
	if (cat == "security" && !cfg.Security) || (cat == "system" && !cfg.System) || (cat == "device" && !cfg.Device) {
		return
	}
	if cat != "security" && inQuiet(cfg.QuietFrom, cfg.QuietTo, now) {
		return
	}
	n.push(notifMsg{Cat: cat, Kind: e.Kind, Text: text, User: e.User, T: now})
}

func (n *notifier) push(m notifMsg) {
	capText := T(n.langOf(), "notify.cap", nil)
	n.mu.Lock()
	if t, ok := n.recent[m.Text]; ok && m.T.Sub(t) < dedupeWindow {
		n.mu.Unlock()
		return
	}
	for k, t := range n.recent {
		if m.T.Sub(t) > 10*time.Minute {
			delete(n.recent, k)
		}
	}
	keep := n.sent[:0]
	for _, t := range n.sent {
		if m.T.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	n.sent = keep
	if len(n.sent) >= notifyPerHr {
		warn := m.T.Sub(n.capWarn) > time.Hour
		if warn {
			n.capWarn = m.T
		}
		n.mu.Unlock()
		if warn {
			select {
			case n.q <- notifMsg{Cat: "system", Kind: "cap", Text: capText, T: m.T}:
			default:
			}
		}
		return
	}
	// Yalnızca gönderilecek mesaj hatırlanır: sınırı aşan (atılan) mesajlar recent'ı büyütmesin. Böylece recent
	// en çok notifyPerHr kayıt tutar; eskiden her benzersiz metin (ör. 5000 cihazın offline olayı) birikiyordu.
	n.recent[m.Text] = m.T
	n.sent = append(n.sent, m.T)
	n.mu.Unlock()
	select {
	case n.q <- m:
	default: // kuyruk dolu: at
	}
}

var catIcon = map[string]string{"security": "🔐", "system": "⚙️", "device": "📱"}

func (n *notifier) render(m notifMsg) string {
	h := n.host
	if h == "" {
		h = "kut"
	}
	return fmt.Sprintf("%s Kut · %s\n%s\n%s", catIcon[m.Cat], h, m.Text, fmtTime(n.langOf(), m.T, false))
}

func (n *notifier) handle(ctx context.Context, m notifMsg) {
	cfg := n.get()
	var last error
	for _, r := range n.deliver(ctx, cfg, m, true) {
		if r.err != nil {
			last = r.err
		}
	}
	n.mu.Lock()
	if last != nil {
		n.lastErr = last
	} else if cfg.anyChannel() {
		n.lastErr, n.lastOK = nil, time.Now()
	}
	n.mu.Unlock()
}

func (n *notifier) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-n.q:
			// Tek bir mesajdaki panik süreci düşürmesin, döngüyü de bitirmesin.
			safely("notifier", func() { n.handle(ctx, m) })
		}
	}
}

type chResult struct {
	ch  string
	err error
}

func (n *notifier) deliver(ctx context.Context, cfg NotifyCfg, m notifMsg, retry bool) []chResult {
	var out []chResult
	text := n.render(m)
	try := func(f func() error) error {
		var err error
		var wait time.Duration // sunucu retry_after verdiyse sabit gecikme yerine o kullanılır
		for i, d := range retryDelays {
			if !retry && i > 0 {
				break
			}
			if wait > 0 {
				d, wait = wait, 0
			}
			if d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if err = f(); err == nil {
				return nil
			}
			var pe permErr
			if errors.As(err, &pe) {
				break
			}
			var ra retryAfterErr
			if errors.As(err, &ra) {
				wait = ra.after
			}
		}
		return err
	}
	if cfg.Telegram.Enabled {
		err := try(func() error {
			return tgCall(ctx, cfg.Telegram.Token, "sendMessage", map[string]any{"chat_id": cfg.Telegram.ChatID, "text": text, "disable_web_page_preview": true}, nil)
		})
		if err != nil {
			log.Printf("bildirim (telegram): %v", err)
		}
		out = append(out, chResult{"telegram", err})
	}
	if cfg.Webhook.Enabled {
		err := try(func() error { return webhookCall(ctx, cfg.Webhook.URL, n.host, m) })
		if err != nil {
			log.Printf("bildirim (webhook): %v", err)
		}
		out = append(out, chResult{"webhook", err})
	}
	return out
}

var errWebhookUnreachable = ue("notify.webhook_unreachable", nil)

// errWebhookRejected: hedef 2xx dışı yanıt verdi. HTTP kodu yalnızca günlüğe gider (bkz. webhookCall).
var errWebhookRejected = ue("notify.webhook_rejected", nil)

// permErr: yeniden denemenin anlamsız olduğu hata (yanlış jeton, yanlış sohbet, 4xx).
type permErr struct{ error }

// Unwrap: errors.As/Is içteki kodlu hatayı bulsun (errOf, localizedErr, errors.Is(err, errWebhookUnreachable)).
func (e permErr) Unwrap() error { return e.error }

// maxRetryAfter: Telegram'ın 429 yanıtındaki retry_after için üst sınır.
const maxRetryAfter = 60 * time.Second

// retryAfterErr: sunucunun bir sonraki denemeyi ne kadar sonra istediğini taşıyan geçici hata.
type retryAfterErr struct {
	error
	after time.Duration
}

func (e retryAfterErr) Unwrap() error { return e.error }

// dialGuardOff yalnızca testlerde true yapılır (httptest sunucuları loopback'te dinler). Üretimde ona
// yazan hiçbir kod yolu yok: bayrak, ortam değişkeni ya da ayar dosyasıyla kapatılamaz.
var dialGuardOff bool

var errDialBlocked = errors.New("destination address not allowed") // yalnızca günlüğe gider (arayüze errWebhookUnreachable); dilden bağımsız sabit

// metadataNets: link-local dışında kalan bulut metadata uçları (169.254.169.254 link-local kuralına zaten girer).
var metadataNets = []netip.Prefix{
	netip.MustParsePrefix("fd00:ec2::254/128"),  // AWS IMDS (IPv6)
	netip.MustParsePrefix("100.100.100.200/32"), // Alibaba Cloud metadata
}

// blockedAddr: giden bildirim bağlantısının gitmesine izin verilmeyen adresler. Webhook adresini
// yazan yönetici panelin root yetkili sunucusuna loopback/kendi arayüzü üzerinden istek attıramasın
// (SSRF). RFC1918 bilerek AÇIK: kendi sunucundaki ntfy/Gotify yerel öncelik ilkesinin gereği.
func blockedAddr(ip netip.Addr, own []netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast() {
		return true
	}
	for _, p := range metadataNets {
		if p.Contains(ip) {
			return true
		}
	}
	for _, o := range own {
		if o.Unmap().WithZone("") == ip {
			return true
		}
	}
	return false
}

func ownAddrs() ([]netip.Addr, error) {
	ifs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range ifs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip)
			}
		}
	}
	return out, nil
}

// guardDial: net.Dialer.Control, DNS çözümlemesinden SONRA ve bağlanılacak gerçek adresle çağrılır;
// bu yüzden alan adı → 127.0.0.1 çözümlemesi (DNS rebinding dahil) kontrolü atlatamaz. Emin olunamazsa reddeder.
func guardDial(_, address string, _ syscall.RawConn) error {
	if dialGuardOff {
		return nil
	}
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return errDialBlocked
	}
	own, err := ownAddrs()
	if err != nil || blockedAddr(ap.Addr(), own) {
		return errDialBlocked
	}
	return nil
}

func guardedTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second, Control: guardDial}).DialContext
	// Sistem vekili (HTTP_PROXY vb.) kullanılmaz: vekil üzerinden giden bağlantıda guardDial yalnızca vekilin
	// adresini görür, hedefi değil; koruma koşulsuz olsun. Yerel öncelik: vekil desteği gereksinimi yok.
	t.Proxy = nil
	return t
}

var httpc = &http.Client{
	Timeout:       10 * time.Second,
	Transport:     guardedTransport(),
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func scrub(err error, secret string) error {
	if err == nil || secret == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), secret, "***"))
}

// scrubURL: http.Client hataları adresi (kimlik bilgisi, yol, sorgu) metne gömer. Metin değiştirmeyle
// temizlemek büyük/küçük harf, kullanıcı:parola@ ve boşluklu yolda kaçırıyordu; bu yüzden hata
// *url.Error ise adresi taşıyan sarmalayıcı atılır ve yalnızca asıl neden (ue.Err) döner.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// tgCall: Telegram Bot API çağrısı. Hata metinlerinden jeton temizlenir.
func tgCall(ctx context.Context, token, method string, in any, out any) error {
	b, _ := json.Marshal(in)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, tgBase+"/bot"+token+"/"+method, bytes.NewReader(b)) //nolint:gosec // G704: tgBase sabit (api.telegram.org); bağlantı guardDial ile denetlenir
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpc.Do(req) //nolint:gosec // G704: istemci guardedTransport; hedef bağlantıda guardDial ile denetlenir
	if err != nil {
		return ue("notify.telegram_unreachable", map[string]any{"msg": scrub(err, token).Error()})
	}
	defer resp.Body.Close() //nolint:errcheck // yanıt gövdesi okunduktan sonra kapanış hatası işlenemez
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
		Params      struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.Unmarshal(raw, &r) != nil {
		// HTTP kodu yalnızca günlüğe: arayüzde ve last_error'da genel metin (webhookCall ile aynı kural).
		log.Printf("bildirim (telegram): beklenmeyen yanıt, HTTP %d", resp.StatusCode) //nolint:gosec // G706: yalnızca tamsayı durum kodu
		return ue("notify.telegram_bad_response", nil)
	}
	if !r.OK {
		e := ue("notify.telegram_error", map[string]any{"msg": scrub(errors.New(r.Description), token).Error()})
		if resp.StatusCode == http.StatusTooManyRequests && r.Params.RetryAfter > 0 {
			return retryAfterErr{e, min(time.Duration(r.Params.RetryAfter), maxRetryAfter/time.Second) * time.Second}
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return permErr{e}
		}
		return e
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func webhookCall(ctx context.Context, raw, host string, m notifMsg) error {
	b, _ := json.Marshal(map[string]any{"app": "kut", "host": host, "category": m.Cat, "event": m.Kind, "text": m.Text, "user": m.User, "time": m.T.Format(time.RFC3339)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, bytes.NewReader(b)) //nolint:gosec // G704: webhook hedefi bağlantıda guardDial ile denetlenir (loopback/link-local/metadata/kendi adres reddi)
	if err != nil {
		return permErr{ue("notify.webhook_invalid", nil)}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "kut-notify")
	resp, err := httpc.Do(req) //nolint:gosec // G704: istemci guardedTransport; hedef bağlantıda guardDial ile denetlenir
	if err != nil {
		// Ayrıntı (hangi adres/port, reddedildi mi, zaman aşımı mı) yalnızca günlüğe; arayüze ve
		// last_error'a genel metin gider — yoksa webhook, iç servislerin port keşfine dönüşür.
		log.Printf("bildirim (webhook): ulaşılamadı: %v", scrubURL(err))
		if errors.Is(err, errDialBlocked) {
			return permErr{errWebhookUnreachable}
		}
		return errWebhookUnreachable
	}
	defer resp.Body.Close() //nolint:errcheck // yanıt gövdesi okunduktan sonra kapanış hatası işlenemez
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		// HTTP kodu yalnızca günlüğe: arayüzde ve last_error'da iç ağdaki servisleri yoklama sinyaline dönüşmesin.
		log.Printf("bildirim (webhook): hedef HTTP %d döndü", resp.StatusCode) //nolint:gosec // G706: yalnızca tamsayı durum kodu
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return permErr{errWebhookRejected}
		}
		return errWebhookRejected
	}
	return nil
}

// watchOffline: 24 saattir görünmeyen (ve açık) cihazı bir kez bildirir. İlk turda mevcut durum "bilinen" sayılır.
func (a *App) watchOffline(peers []Peer, now time.Time) {
	n := a.nf
	if n == nil {
		return
	}
	var fire []string
	n.mu.Lock()
	// Listede olmayan (silinmiş) cihazların kimlikleri her turda budanır; yoksa küme silinen her cihazla büyür.
	alive := make(map[string]bool, len(peers))
	for _, p := range peers {
		alive[p.ID] = true
	}
	for id := range n.offline {
		if !alive[id] {
			delete(n.offline, id)
		}
	}
	for _, p := range peers {
		stale := p.Enabled && p.LastSeen > 0 && now.Unix()-p.LastSeen > 24*3600
		switch {
		case !n.offInit:
			if stale {
				n.offline[p.ID] = true
			}
		case stale && !n.offline[p.ID]:
			n.offline[p.ID] = true
			fire = append(fire, p.Name)
		case !stale && p.LastSeen > 0 && now.Unix()-p.LastSeen < 3600:
			delete(n.offline, p.ID)
		}
	}
	n.offInit = true
	n.mu.Unlock()
	for _, name := range fire {
		a.logEventT("sistem", "peer_offline", "log.peer_offline", map[string]any{"name": name})
	}
}

// ---- API (yalnızca admin) ----

type notifyView struct {
	Telegram struct {
		Enabled  bool   `json:"enabled"`
		TokenSet bool   `json:"token_set"`
		ChatID   string `json:"chat_id"`
	} `json:"telegram"`
	Webhook struct {
		Enabled bool `json:"enabled"`
	} `json:"webhook"`
	// Webhook adresi (Slack/Discord vb.) bir sırdır: GET'te geri dönmez, yalnızca kayıtlı mı ve hangi sunucu.
	WebhookSet  bool   `json:"webhook_set"`
	WebhookHost string `json:"webhook_host"`
	Security    bool   `json:"ev_security"`
	System      bool   `json:"ev_system"`
	Device      bool   `json:"ev_device"`
	QuietFrom   string `json:"quiet_from"`
	QuietTo     string `json:"quiet_to"`
	LastOK      int64  `json:"last_ok"`
	LastErr     string `json:"last_error"`
}

func (a *App) notif() *notifier {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	if a.nf == nil {
		a.nf = newNotifier("")
	}
	return a.nf
}

func (a *App) handleGetNotify(w http.ResponseWriter, r *http.Request) {
	n := a.notif()
	c := n.get()
	var v notifyView
	v.Telegram.Enabled, v.Telegram.TokenSet, v.Telegram.ChatID = c.Telegram.Enabled, c.Telegram.Token != "", c.Telegram.ChatID
	v.Webhook.Enabled, v.WebhookSet = c.Webhook.Enabled, c.Webhook.URL != ""
	if pu, err := url.Parse(c.Webhook.URL); err == nil && v.WebhookSet {
		v.WebhookHost = pu.Scheme + "://" + pu.Host + "/…"
	}
	v.Security, v.System, v.Device, v.QuietFrom, v.QuietTo = c.Security, c.System, c.Device, c.QuietFrom, c.QuietTo
	n.mu.Lock()
	if !n.lastOK.IsZero() {
		v.LastOK = n.lastOK.Unix()
	}
	lastErr := n.lastErr
	n.mu.Unlock()
	if lastErr != nil {
		v.LastErr = localizedErr(a.reqLang(r), lastErr)
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *App) handlePutNotify(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Telegram struct {
			Enabled bool   `json:"enabled"`
			Token   string `json:"token"` // boş = mevcut jetonu koru
			ChatID  string `json:"chat_id"`
		} `json:"telegram"`
		Webhook struct {
			Enabled bool   `json:"enabled"`
			URL     string `json:"url"`
		} `json:"webhook"`
		Security  bool   `json:"ev_security"`
		System    bool   `json:"ev_system"`
		Device    bool   `json:"ev_device"`
		QuietFrom string `json:"quiet_from"`
		QuietTo   string `json:"quiet_to"`
		DropToken bool   `json:"drop_token"`
		// Webhook adresi GET'te dönmediği için boş gönderim "değiştirme" demektir; silmek için bu alan.
		DropWebhook bool `json:"drop_webhook"`
	}
	if !decodeN(w, r, &in, 4096) {
		return
	}
	n := a.notif()
	c := n.get()
	tok := strings.TrimSpace(in.Telegram.Token)
	switch {
	case in.DropToken:
		c.Telegram.Token = ""
	case tok != "":
		if !tokenRe.MatchString(tok) {
			errCode(w, http.StatusBadRequest, "notify.bad_token", nil)
			return
		}
		c.Telegram.Token = tok
	}
	c.Telegram.ChatID = strings.TrimSpace(in.Telegram.ChatID)
	if c.Telegram.ChatID != "" && !chatIDRe.MatchString(c.Telegram.ChatID) {
		errCode(w, http.StatusBadRequest, "notify.bad_chat_id", nil)
		return
	}
	c.Telegram.Enabled = in.Telegram.Enabled
	if c.Telegram.Enabled && (c.Telegram.Token == "" || c.Telegram.ChatID == "") {
		errCode(w, http.StatusBadRequest, "notify.telegram_incomplete", nil)
		return
	}
	u := strings.TrimSpace(in.Webhook.URL)
	if u != "" {
		pu, err := url.Parse(u)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" || len(u) > 512 {
			errCode(w, http.StatusBadRequest, "notify.bad_webhook_url", nil)
			return
		}
		c.Webhook.URL = u
	} else if in.DropWebhook {
		c.Webhook.URL = ""
	}
	c.Webhook.Enabled = in.Webhook.Enabled
	if c.Webhook.Enabled && c.Webhook.URL == "" {
		errCode(w, http.StatusBadRequest, "notify.webhook_no_url", nil)
		return
	}
	for _, q := range []string{in.QuietFrom, in.QuietTo} {
		if q != "" && !clockRe.MatchString(q) {
			errCode(w, http.StatusBadRequest, "notify.bad_quiet_time", nil)
			return
		}
	}
	if (in.QuietFrom == "") != (in.QuietTo == "") {
		errCode(w, http.StatusBadRequest, "notify.quiet_incomplete", nil)
		return
	}
	c.QuietFrom, c.QuietTo = in.QuietFrom, in.QuietTo
	c.Security, c.System, c.Device = in.Security, in.System, in.Device
	if err := n.set(c); err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.logReqT(r, "settings", "log.settings.notify_changed", nil)
	a.handleGetNotify(w, r)
}

func (a *App) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	n := a.notif()
	c := n.get()
	if !c.anyChannel() {
		errCode(w, http.StatusBadRequest, "notify.no_channel", nil)
		return
	}
	res := map[string]string{}
	m := notifMsg{Cat: "system", Kind: "test", Text: T(n.langOf(), "notify.test", nil), T: time.Now()}
	for _, x := range n.deliver(r.Context(), c, m, false) {
		if x.err != nil {
			res[x.ch] = localizedErr(a.reqLang(r), x.err)
		} else {
			res[x.ch] = "ok"
		}
	}
	writeJSON(w, http.StatusOK, res)
}

// Sohbeti bul: kullanıcı bota /start yazdıktan sonra tek seferlik getUpdates. Sonuç kaydedilmez,
// ekranda "bu sen misin?" diye gösterilir (bota başkası yazdıysa yanlış hesaba bağlanmayı önler).
func (a *App) handleTelegramFind(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !decodeN(w, r, &in, 2048) {
		return
	}
	tok := strings.TrimSpace(in.Token)
	if tok == "" {
		tok = a.notif().get().Telegram.Token
	}
	if !tokenRe.MatchString(tok) {
		errCode(w, http.StatusBadRequest, "notify.no_token", nil)
		return
	}
	ctx := r.Context()
	var me struct {
		Username string `json:"username"`
	}
	if err := tgCall(ctx, tok, "getMe", struct{}{}, &me); err != nil {
		errOf(w, http.StatusBadGateway, err)
		return
	}
	var ups []struct {
		Message struct {
			Chat struct {
				ID        int64  `json:"id"`
				Type      string `json:"type"`
				FirstName string `json:"first_name"`
				Username  string `json:"username"`
			} `json:"chat"`
		} `json:"message"`
	}
	if err := tgCall(ctx, tok, "getUpdates", map[string]any{"limit": 20, "timeout": 0, "allowed_updates": []string{"message"}}, &ups); err != nil {
		errOf(w, http.StatusBadGateway, err)
		return
	}
	for _, up := range slices.Backward(ups) {
		c := up.Message.Chat
		if c.Type == "private" && c.ID != 0 {
			writeJSON(w, http.StatusOK, map[string]any{"bot": me.Username, "chat_id": strconv.FormatInt(c.ID, 10), "name": c.FirstName, "username": c.Username})
			return
		}
	}
	errCode(w, http.StatusNotFound, "notify.no_chat_yet", map[string]any{"bot": me.Username})
}

// rememberIP: başarılı girişin IP'sini "tanıdık" kümesine ekler; küme nFailMaxIPs ile sınırlı. Doluysa rastgele bir
// eski girdi düşer (en kötü ihtimalle o IP'den sonraki girişte fazladan bir "yeni IP" bildirimi gider). n.mu tutulur.
func (n *notifier) rememberIP(ip string) {
	if !n.known[ip] && len(n.known) >= nFailMaxIPs {
		for k := range n.known {
			delete(n.known, k)
			break
		}
	}
	n.known[ip] = true
}
