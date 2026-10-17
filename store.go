package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Settings: panelden değiştirilebilen sunucu ayarları (server.json içinde).
type Settings struct {
	DNS          string `json:"dns"`                       // yalnızca internet çıkışlı profillerin config'ine yazılır
	MTU          int    `json:"mtu"`                       // 0 = WireGuard varsayılanı
	Keepalive    int    `json:"keepalive"`                 // istemci PersistentKeepalive (sn), 0 = kapalı
	BlockPrivate bool   `json:"block_private"`             // internet çıkışlı cihazlar özel ağlara (RFC1918 vb.) erişemesin
	PeerFree     bool   `json:"unprofiled_free,omitempty"` // profili olmayan cihazlar VPN içinde serbest (v0.13 ve öncesi); kapalıyken yalnızca sunucuya
	UpdateCheck  bool   `json:"update_check"`              // isteğe bağlı: günde bir kez GitHub'dan yeni sürüm sorar (varsayılan kapalı)
	IPv6         bool   `json:"ipv6,omitempty"`            // isteğe bağlı çift yığın (varsayılan kapalı)
	ULA          string `json:"ula,omitempty"`             // IPv6 açıldığında üretilen fdXX:XXXX:XXXX::/64 (sonradan değişmez)
	Lang         string `json:"lang,omitempty"`            // sunucu varsayılan dili: bildirim, CLI, doctor (boş = tr; eski kurulumlar)
}

func defaultSettings() Settings {
	return Settings{DNS: "1.1.1.1, 1.0.0.1", Keepalive: 25, BlockPrivate: true}
}

// Server, sunucu tarafı sabit yapılandırma (server.json, 0600).
type Server struct {
	PrivateKey string    `json:"private_key"`
	PublicKey  string    `json:"public_key"`
	Endpoint   string    `json:"endpoint"`
	Port       int       `json:"port"`
	Subnet     string    `json:"subnet"`
	Iface      string    `json:"iface"`
	ConfPath   string    `json:"conf_path"`
	Settings   *Settings `json:"settings,omitempty"`
	Schema     int       `json:"schema,omitempty"` // veri biçimi sürümü (yoksa v0.3 = 1)
}

// currentSchema: 1 = v0.3 (erişim profili yok), 2 = v0.4.
const currentSchema = 2

func (s Server) cfg() Settings {
	if s.Settings == nil {
		return defaultSettings()
	}
	return *s.Settings
}

// srvLang: tarayıcı dışı çıktıların dili (bildirim, CLI, doctor). Boşsa tr: eski kurulumlar Türkçe kalır.
func (a *App) srvLang() string {
	if l := normLang(a.getSrv().cfg().Lang); l != "" {
		return l
	}
	return "tr"
}

// Peer, peers.json içinde saklanır. İstemci özel anahtarı ASLA saklanmaz.
type Peer struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Note         string     `json:"note,omitempty"`
	PublicKey    string     `json:"public_key"`
	PSK          string     `json:"psk"`
	IP           string     `json:"ip"`
	Enabled      bool       `json:"enabled"`                // kalıcı aç/kapa
	Internet     bool       `json:"internet"`               // sunucu izni: cihaz VPN üzerinden internete çıkabilir mi (güvenlik duvarı). İstemci config'inin yönlendirmesi ayrıdır.
	Policy       string     `json:"policy,omitempty"`       // erişim profili kimliği; boş = profil yok (VPN içinde serbest)
	FrozenUntil  *time.Time `json:"frozen_until,omitempty"` // süreli dondurma; dolunca kendiliğinden çözülür
	Kind         string     `json:"kind,omitempty"`         // cihaz türü: phone|tablet|laptop|desktop|tv|server|other ("" = other)
	Group        string     `json:"group,omitempty"`        // düzen için etiket (ör. "Aile", "İş"); filtre ve toplu işlem içindir
	Schedule     *Schedule  `json:"schedule,omitempty"`     // erişim saatleri (boş = her zaman)
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`   // misafir/süreli cihaz: bu andan sonra kendiliğinden kapanır
	Created      time.Time  `json:"created"`
	LastSeen     int64      `json:"last_seen,omitempty"` // son el sıkışma (unix); yeniden başlatmada kaybolmasın diye saklanır
	LastEndpoint string     `json:"last_endpoint,omitempty"`
}

func (p Peer) frozen(now time.Time) bool { return p.FrozenUntil != nil && now.Before(*p.FrozenUntil) }

// expired: bitiş zamanı geçmiş mi (süreli/misafir cihaz).
func (p Peer) expired(now time.Time) bool { return p.ExpiresAt != nil && !now.Before(*p.ExpiresAt) }

// active: peer'ın sunucuda gerçekten tanımlı olup olmadığı (açık, dondurulmamış, süresi dolmamış, saat penceresinde).
func (p Peer) active(now time.Time) bool {
	return p.Enabled && !p.frozen(now) && !p.expired(now) && !p.scheduleOff(now)
}

func (s Server) prefix() netip.Prefix { p, _ := netip.ParsePrefix(s.Subnet); return p.Masked() }
func (s Server) serverIP() netip.Addr { return s.prefix().Addr().Next() }

func (s Server) endpoint() string {
	host := s.Endpoint
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() {
		host = "[" + host + "]"
	}
	return fmt.Sprintf("%s:%d", host, s.Port)
}

// App, tüm uygulama durumunu tutar.
//   - mu: peers ve conf/güvenlik duvarı yazımlarını sıraya sokar
//   - cfgMu: srv ve admin (ayarlar/parola çalışma anında değişebilir)
type App struct {
	mu       sync.Mutex
	cfgMu    sync.RWMutex
	dataDir  string
	dry      bool
	srv      Server
	origConf string // dry-run'da srv.ConfPath ezilir; server.json'a gerçek yol yazılsın diye
	peers    []Peer
	pol      []Policy
	admin    adminRecord
	sess     *sessions
	lim      *limiter
	hist     *history
	ctrs     counterCache // Sunucu sayfasının kural sayaçları (kısa önbellek)
	phist    *peerHistory
	act      *activity
	started  time.Time
	listen   string
	upd      updateState
	streams  atomic.Int32
	inet     inetTracker
	adminMu  sync.Mutex // yönetici kaydı (parola/2FA) yazımları
	totpPend totpPending
	users    []User          // ek hesaplar (users.json); sahip admin.json'dadır
	v6Live   atomic.Bool     // IPv6 kuralları şu an kurulu (kapatılınca temizlenir)
	mt       *maint          // bakım ayarları (maint.json)
	restartF func()          // testlerde yeniden başlatmayı değiştirmek için
	nf       *notifier       // bildirimler (notify.json); nil olabilir (testler)
	schedWas map[string]bool // izleyici: cihaz kimliği → son turdaki saat penceresi durumu (yalnızca zamanlaması olanlar)
	ruleWas  map[string]bool // izleyici: "profil#kural" → son turdaki kural penceresi durumu
}

func (a *App) getSrv() Server {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.srv
}

func (a *App) setSrv(s Server) {
	a.cfgMu.Lock()
	a.srv = s
	a.cfgMu.Unlock()
}

func (a *App) getAdmin() adminRecord {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.admin
}

func (a *App) setAdmin(r adminRecord) {
	a.cfgMu.Lock()
	a.admin = r
	a.cfgMu.Unlock()
}

func serverPath(dir string) string   { return filepath.Join(dir, "server.json") }
func peersPath(dir string) string    { return filepath.Join(dir, "peers.json") }
func policiesPath(dir string) string { return filepath.Join(dir, "policies.json") }
func adminPath(dir string) string    { return filepath.Join(dir, "admin.json") }

func loadJSON(path string, v any) error {
	b, err := os.ReadFile(path) //nolint:gosec // G304: path veri dizini + sabit dosya adından türer (peersPath vb.); HTTP girdisi yok
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func saveJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	// bir önceki iyi sürümü .bak olarak sakla (yanlışlıkla silme / bozulma durumunda elle geri dönülebilsin)
	if old, err := os.ReadFile(path); err == nil && len(old) > 0 { //nolint:gosec // G304: path veri dizinindeki sabit dosya yolu; HTTP girdisi yok
		_ = writeFileAtomic(path+".bak", old)
	}
	return writeFileAtomic(path, append(b, '\n'))
}

func loadApp(dir string, dry bool) (*App, error) {
	var srv Server
	if err := loadJSON(serverPath(dir), &srv); err != nil {
		return nil, ue("store.no_server", map[string]any{"err": err.Error()})
	}
	var peers []Peer
	if err := loadJSON(peersPath(dir), &peers); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ue("store.read_failed", map[string]any{"file": "peers.json", "err": err.Error()})
	}
	var admin adminRecord
	if err := loadJSON(adminPath(dir), &admin); err != nil {
		return nil, ue("store.no_admin", map[string]any{"err": err.Error()})
	}
	users, err := loadUsers(dir)
	if err != nil {
		return nil, err
	}
	var pols []Policy
	if err := loadJSON(policiesPath(dir), &pols); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, ue("store.read_failed", map[string]any{"file": "policies.json", "err": err.Error()})
	}
	if srv.Schema > currentSchema {
		return nil, ue("store.newer_schema", map[string]any{"have": srv.Schema, "max": currentSchema})
	}
	if err := validateState(srv, peers, pols); err != nil {
		return nil, ue("store.invalid_data", map[string]any{"dir": dir, "err": err})
	}
	if !dry {
		if err := checkRealConfPath(srv); err != nil {
			return nil, ue("store.invalid_conf", map[string]any{"dir": dir, "err": err})
		}
	}
	origConf := srv.ConfPath
	if dry {
		// Dry-run asla gerçek /etc/wireguard dosyasına dokunmasın.
		srv.ConfPath = filepath.Join(dir, srv.Iface+".conf")
	}
	app := &App{
		dataDir: dir, dry: dry, srv: srv, origConf: origConf, peers: peers, pol: pols, admin: admin, users: users,
		sess: newSessions(), lim: newLimiter(), hist: &history{}, phist: &peerHistory{}, act: loadActivity(filepath.Join(dir, "activity.jsonl")),
		started: time.Now(),
	}
	app.mt = newMaint(filepath.Join(dir, "maint.json"))
	loadHistory(filepath.Join(dir, "history.json.gz"), app.hist, app.phist, time.Now().Unix())
	app.nf = newNotifier(filepath.Join(dir, "notify.json"))
	app.nf.lang = app.srvLang // bildirimler sunucu dilinde; Ayarlar'dan dil değişince sonraki bildirim de değişir
	app.nf.seed(app.act.evs)
	app.act.onAdd = app.nf.onEvent
	app.v6Live.Store(srv.v6On())
	if err := app.migrate(); err != nil {
		return nil, err
	}
	return app, nil
}

// migrate: eski veri biçimini (v0.3) sessizce yükseltir. Önce dosyaların yedeğini alır, sonra yalnızca ekleme yapar:
// hiçbir mevcut alan silinmez, cihazların IP'leri ve anahtarları aynı kalır.
func (a *App) migrate() error {
	if a.srv.Schema >= currentSchema {
		return nil
	}
	old := a.srv.Schema
	if old == 0 {
		old = 1
	}
	bak := filepath.Join(a.dataDir, fmt.Sprintf("backup-schema%d-%s", old, time.Now().Format("20060102-150405")))
	if err := os.MkdirAll(bak, 0o700); err != nil {
		return ue("store.migrate_backup_create", map[string]any{"err": err.Error()})
	}
	for _, f := range []string{"server.json", "peers.json", "admin.json", "users.json"} {
		b, err := os.ReadFile(filepath.Join(a.dataDir, f)) //nolint:gosec // G304: veri dizini + sabit dosya adı listesi; HTTP girdisi yok
		if err != nil {
			continue
		}
		if err := writeFileAtomic(filepath.Join(bak, f), b); err != nil {
			return ue("store.migrate_backup_write", map[string]any{"err": err.Error()})
		}
	}
	a.srv.Schema = currentSchema
	if a.srv.Settings == nil {
		def := defaultSettings()
		a.srv.Settings = &def
	}
	if err := a.saveServer(a.srv); err != nil {
		return err
	}
	if a.pol == nil {
		a.pol = []Policy{}
	}
	if err := a.savePolicies(a.pol); err != nil {
		return err
	}
	log.Printf("veri biçimi v%d → v%d yükseltildi (yedek: %s)", old, currentSchema, bak)
	return nil
}

// saveServer, ayarları server.json'a yazar (dry-run'da bile gerçek conf yolunu korur).
func (a *App) saveServer(s Server) error {
	if a.dry && a.origConf != "" {
		s.ConfPath = a.origConf
	}
	return saveJSON(serverPath(a.dataDir), s)
}

// nextIP, alt ağdaki ilk boş adresi verir (.1 sunucuya ayrılır).
func (a *App) nextIP(peers []Peer) (string, error) {
	srv := a.getSrv()
	pfx := srv.prefix()
	used := map[netip.Addr]bool{srv.serverIP(): true}
	for _, p := range peers {
		if ip, err := netip.ParseAddr(p.IP); err == nil {
			used[ip] = true
		}
	}
	for ip := srv.serverIP().Next(); pfx.Contains(ip); ip = ip.Next() {
		if !pfx.Contains(ip.Next()) {
			break // yayın (broadcast) adresi
		}
		if !used[ip] {
			return ip.String(), nil
		}
	}
	return "", ue("ip.pool_full", nil)
}

func (a *App) savePolicies(p []Policy) error {
	if p == nil {
		p = []Policy{}
	}
	return saveJSON(policiesPath(a.dataDir), p)
}

// panelPort: panelin dinlediği port (KUT-IN zincirinde profili olmayan cihazlara açılır).
func (a *App) panelPort() int {
	if _, p, err := net.SplitHostPort(a.listen); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			return n
		}
	}
	return 5000
}

func (a *App) savePeers(peers []Peer) error {
	if peers == nil {
		peers = []Peer{}
	}
	return saveJSON(peersPath(a.dataDir), peers)
}
