package main

// Bakım: otomatik yedek, geri yükleme, günlük saklama süresi ve trafik geçmişi kaydı.

import (
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type BackupCfg struct {
	Enabled bool   `json:"enabled"`
	Freq    string `json:"freq"`    // daily | weekly | monthly
	Time    string `json:"time"`    // SS:DD (sunucu saati)
	Weekday int    `json:"weekday"` // 0=Pazar … 6=Cumartesi (haftalıkta)
	Keep    int    `json:"keep"`    // saklanacak otomatik yedek sayısı
	LastRun int64  `json:"last_run"`
	LastErr string `json:"last_error,omitempty"`
	// Pass doluysa yeni yedekler şifrelenir. maint.json (0600) içinde durur; yedeğin kendisine girmez.
	// Amaç diskten/indirilen kopyadan sızmayı önlemek: sunucuda root olan biri zaten canlı anahtara sahiptir.
	Pass string `json:"pass,omitempty"`
}

type MaintCfg struct {
	Backup        BackupCfg `json:"backup"`
	LogDays       int       `json:"log_days"`       // günlükte tutulacak gün; 0 = sınırsız
	LogArchive    bool      `json:"log_archive"`    // süresi dolan olaylar önce aylık arşive yazılsın
	ArchiveMonths int       `json:"archive_months"` // arşivi saklama süresi (ay); 0 = silme
	LastCompact   int64     `json:"last_compact"`
}

func defaultMaint() MaintCfg {
	return MaintCfg{Backup: BackupCfg{Enabled: true, Freq: "daily", Time: "03:30", Weekday: 1, Keep: 7}, LogDays: 90, LogArchive: true, ArchiveMonths: 12}
}

type maint struct {
	mu      sync.Mutex
	path    string
	cfg     MaintCfg
	nextTry time.Time
	histAt  time.Time
}

func newMaint(path string) *maint {
	m := &maint{path: path, cfg: defaultMaint()}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil { //nolint:gosec // G304: path veri dizininden gelen sabit maint.json yolu
			c := defaultMaint()
			if json.Unmarshal(b, &c) == nil {
				m.cfg = c
			}
		}
	}
	return m
}

func (m *maint) get() MaintCfg {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cfg
}

func (m *maint) update(f func(*MaintCfg)) error {
	// Diske yazma da kilit altında: iki eşzamanlı güncellemede eski görüntü yenisini ezemez.
	m.mu.Lock()
	defer m.mu.Unlock()
	f(&m.cfg)
	c := m.cfg
	if m.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return writeFileAtomic(m.path, append(b, '\n'))
}

func (a *App) maintCfg() *maint {
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()
	if a.mt == nil {
		a.mt = newMaint("")
	}
	return a.mt
}

func (a *App) backupDir() string  { return filepath.Join(a.dataDir, "backups") }
func (a *App) archiveDir() string { return filepath.Join(a.dataDir, "logs") }

// ---- Yedek oluşturma / okuma ----

// buildBackup: yedek dosyalarını tek bir tar.gz olarak bellekte üretir.
func buildBackup(dir string) ([]byte, int, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	n := 0
	for _, base := range backupFiles {
		b, err := os.ReadFile(filepath.Join(dir, base)) //nolint:gosec // G304: dir veri dizini, base sabit backupFiles listesinden
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, 0, err
		}
		if err := tw.WriteHeader(&tar.Header{Name: base, Mode: 0o600, Size: int64(len(b)), ModTime: time.Now()}); err != nil {
			return nil, 0, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, 0, err
		}
		n++
	}
	if err := tw.Close(); err != nil {
		return nil, 0, err
	}
	if err := gz.Close(); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), n, nil
}

// parseBackup: yedeği okur ve doğrular; hiçbir şey yazmaz.
func parseBackup(b []byte) (map[string][]byte, error) {
	const (
		maxBackupTotal = 256 << 20 // açılmış arşivin tamamı (sıkıştırma bombasına karşı)
		maxBackupEntry = 64 << 20  // tek bir kayıt
	)
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, nest("backup.unreadable", nil, err)
	}
	allowed := map[string]bool{}
	for _, f := range backupFiles {
		allowed[f] = true
	}
	got := map[string][]byte{}
	tr := tar.NewReader(io.LimitReader(gz, maxBackupTotal))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nest("backup.corrupt", nil, err)
		}
		if h.Typeflag != tar.TypeReg || !allowed[h.Name] {
			return nil, ue("backup.unexpected_entry", map[string]any{"name": strconv.Quote(h.Name)})
		}
		if _, dup := got[h.Name]; dup {
			return nil, ue("backup.duplicate_entry", map[string]any{"name": h.Name})
		}
		d, err := io.ReadAll(io.LimitReader(tr, maxBackupEntry+1))
		if err != nil {
			return nil, err
		}
		if len(d) > maxBackupEntry {
			return nil, ue("backup.entry_too_large", map[string]any{"name": h.Name, "mb": maxBackupEntry >> 20})
		}
		got[h.Name] = d
	}
	for _, need := range []string{"server.json", "admin.json"} {
		if len(got[need]) == 0 {
			return nil, ue("backup.missing_file", map[string]any{"name": need})
		}
	}
	invalid := func(name string) error { return ue("backup.invalid_file", map[string]any{"name": name}) }
	var srv Server
	if json.Unmarshal(got["server.json"], &srv) != nil || srv.PrivateKey == "" || srv.Subnet == "" {
		return nil, invalid("server.json")
	}
	if srv.Schema > currentSchema {
		return nil, ue("backup.newer_version", nil)
	}
	var peers []Peer
	if b := got["peers.json"]; len(b) > 0 {
		if json.Unmarshal(b, &peers) != nil {
			return nil, invalid("peers.json")
		}
	}
	var pols []Policy
	if b := got["policies.json"]; len(b) > 0 {
		if json.Unmarshal(b, &pols) != nil {
			return nil, invalid("policies.json")
		}
	}
	var adm adminRecord
	if json.Unmarshal(got["admin.json"], &adm) != nil {
		return nil, invalid("admin.json")
	}
	if b := got["users.json"]; len(b) > 0 {
		var us []User
		if json.Unmarshal(b, &us) != nil {
			return nil, invalid("users.json")
		}
		if err := validateAccounts(us); err != nil {
			return nil, nest("backup.rejected", nil, err)
		}
	}
	if b := got["notify.json"]; len(b) > 0 {
		var nc NotifyCfg
		if json.Unmarshal(b, &nc) != nil {
			return nil, invalid("notify.json")
		}
		if err := validateNotify(nc); err != nil {
			return nil, nest("backup.rejected", nil, err)
		}
	}
	if err := validateState(srv, peers, pols); err != nil {
		return nil, nest("backup.rejected", nil, err)
	}
	return got, nil
}

// openBackup: yedek şifreliyse çözer (parola boşsa yapılandırılmış parola denenir), sonra doğrular.
func (a *App) openBackup(b []byte, pass string) (map[string][]byte, error) {
	if isEncrypted(b) {
		if pass == "" {
			pass = a.maintCfg().get().Backup.Pass
		}
		if pass == "" {
			return nil, errNeedPass
		}
		plain, err := decryptBackup(b, pass)
		if err != nil {
			return nil, err
		}
		b = plain
	}
	return parseBackup(b)
}

// nestedErr: başka bir hatayı {msg} olarak taşıyan kodlu hata (ör. "yedek reddedildi: <doğrulayıcının hatası>").
// İç hata da kodluysa {msg} okuyanın dilinde yazılır; codedErr'in parametreleri düz değer olduğu için bunu yapamaz.
type nestedErr struct {
	code   string
	params map[string]any
	inner  error
}

func nest(code string, params map[string]any, inner error) error {
	return &nestedErr{code: code, params: params, inner: inner}
}

func (e *nestedErr) Error() string { return localizedErr(refLang, e) }
func (e *nestedErr) Unwrap() error { return e.inner }

func (e *nestedErr) paramsIn(lang string) map[string]any {
	p := make(map[string]any, len(e.params)+1)
	maps.Copy(p, e.params)
	p["msg"] = localizedErr(lang, e.inner)
	return p
}

// localizedErr: hatanın lang dilindeki metni. Kodlu değilse (işletim sistemi, ağ, sıkıştırma) olduğu gibi döner.
func localizedErr(lang string, err error) string {
	var ne *nestedErr
	if errors.As(err, &ne) {
		return T(lang, "err."+ne.code, ne.paramsIn(lang))
	}
	var ce *codedErr
	if errors.As(err, &ce) {
		return T(lang, "err."+ce.Code, ce.Params)
	}
	return err.Error()
}

// maintErrJSON: errOf gibi; iç içe hatada {msg} isteği yapanın dilinde yazılır.
func (a *App) maintErrJSON(w http.ResponseWriter, r *http.Request, status int, err error) {
	var ne *nestedErr
	if errors.As(err, &ne) {
		errCode(w, status, ne.code, ne.paramsIn(a.reqLang(r)))
		return
	}
	errOf(w, status, err)
}

var backupNameRe = regexp.MustCompile(`^kut-(oto|elle|oncesi)-\d{8}-\d{6}\.tar\.gz(\.enc)?$`)

type backupInfo struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // oto | elle | oncesi
	Size int64  `json:"size"`
	T    int64  `json:"t"`
	Enc  bool   `json:"enc"`
}

func (a *App) listBackups() []backupInfo {
	ents, _ := os.ReadDir(a.backupDir())
	var out []backupInfo
	for _, e := range ents {
		if !backupNameRe.MatchString(e.Name()) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, backupInfo{Name: e.Name(), Kind: strings.Split(e.Name(), "-")[1], Size: fi.Size(), T: fi.ModTime().Unix(), Enc: strings.HasSuffix(e.Name(), ".enc")})
	}
	slices.SortFunc(out, func(a, b backupInfo) int { // yeniden eskiye; ad türle (oto/elle/oncesi) başladığı için tarihe bakılır
		if c := cmp.Compare(b.T, a.T); c != 0 {
			return c
		}
		return strings.Compare(b.Name, a.Name)
	})
	return out
}

// makeBackup: kind = oto | elle | oncesi. Dosya kilitli okunur (a.mu) ki yedek tutarlı olsun.
func (a *App) makeBackup(kind string, locked bool) (string, error) {
	if !locked {
		a.mu.Lock()
	}
	b, _, err := buildBackup(a.dataDir)
	if !locked {
		a.mu.Unlock()
	}
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(a.backupDir(), 0o700); err != nil {
		return "", err
	}
	name := "kut-" + kind + "-" + time.Now().Format("20060102-150405") + ".tar.gz"
	if pass := a.maintCfg().get().Backup.Pass; pass != "" {
		if b, err = encryptBackup(b, pass); err != nil {
			return "", err
		}
		name += ".enc"
	}
	if err := writeFileAtomic(filepath.Join(a.backupDir(), name), b); err != nil {
		return "", err
	}
	return name, nil
}

// pruneBackups: otomatik yedeklerden en yeni keep tanesini bırakır; geri yükleme öncesi yedeklerden son 5'i.
func (a *App) pruneBackups(keep int) {
	var oto, once []backupInfo
	for _, b := range a.listBackups() {
		switch b.Kind {
		case "oto":
			oto = append(oto, b)
		case "oncesi":
			once = append(once, b)
		}
	}
	if keep < 1 {
		keep = 1
	}
	for i, b := range oto {
		if i >= keep {
			_ = os.Remove(filepath.Join(a.backupDir(), b.Name))
		}
	}
	for i, b := range once {
		if i >= 5 {
			_ = os.Remove(filepath.Join(a.backupDir(), b.Name))
		}
	}
}

// ---- Zamanlama ----

// lastSlot: now'dan önceki (ya da now'daki) en son planlı yedek zamanı.
func lastSlot(c BackupCfg, now time.Time) time.Time {
	h, m := clockHM(c.Time)
	day := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	switch c.Freq {
	case "weekly":
		t := day.AddDate(0, 0, -((int(now.Weekday()) - c.Weekday + 7) % 7))
		if t.After(now) {
			t = t.AddDate(0, 0, -7)
		}
		return t
	case "monthly":
		t := time.Date(now.Year(), now.Month(), 1, h, m, 0, 0, now.Location())
		if t.After(now) {
			t = t.AddDate(0, -1, 0)
		}
		return t
	}
	if day.After(now) {
		day = day.AddDate(0, 0, -1)
	}
	return day
}

func nextSlot(c BackupCfg, now time.Time) time.Time {
	t := lastSlot(c, now)
	switch c.Freq {
	case "weekly":
		return t.AddDate(0, 0, 7)
	case "monthly":
		return t.AddDate(0, 1, 0)
	}
	return t.AddDate(0, 0, 1)
}

// maintTick: izleyici turunda çağrılır; zamanı gelen yedeği alır, günlüğü temizler, geçmişi diske yazar.
func (a *App) maintTick(now time.Time) {
	m := a.maintCfg()
	c := m.get()
	if c.Backup.Enabled && c.Backup.LastRun < lastSlot(c.Backup, now).Unix() && !now.Before(m.nextTry) {
		name, err := a.makeBackup("oto", false)
		if err != nil {
			m.mu.Lock()
			m.nextTry = now.Add(30 * time.Minute)
			m.mu.Unlock()
			if uerr := m.update(func(c *MaintCfg) { c.Backup.LastErr = err.Error() }); uerr != nil {
				log.Printf("maint.json yazılamadı: %v", uerr)
			}
			log.Printf("otomatik yedek başarısız: %v", err)
			a.logEventT("sistem", "backup_fail", "log.backup_fail", map[string]any{"msg": err.Error()})
		} else {
			if uerr := m.update(func(c *MaintCfg) { c.Backup.LastRun, c.Backup.LastErr = now.Unix(), "" }); uerr != nil {
				log.Printf("maint.json yazılamadı: %v", uerr)
			}
			a.pruneBackups(c.Backup.Keep)
			log.Printf("otomatik yedek alındı: %s", name)
		}
	}
	if now.Unix()-c.LastCompact >= 24*3600 {
		a.compactLogs(now)
	}
	m.mu.Lock()
	due := now.Sub(m.histAt) >= 10*time.Minute
	if due {
		m.histAt = now
	}
	m.mu.Unlock()
	if due {
		if err := saveHistory(filepath.Join(a.dataDir, "history.json.gz"), a.hist, a.phist); err != nil {
			log.Printf("trafik geçmişi yazılamadı: %v", err)
		}
	}
}

func (a *App) compactLogs(now time.Time) {
	m := a.maintCfg()
	c := m.get()
	if c.LogDays > 0 {
		cut := now.AddDate(0, 0, -c.LogDays).Unix()
		if n, err := a.act.compact(cut, a.archiveDir(), c.LogArchive); err != nil {
			log.Printf("günlük temizlenemedi: %v", err)
			// Her turda yeniden denemesin: bir saat sonra tekrar dene.
			if uerr := m.update(func(c *MaintCfg) { c.LastCompact = now.Add(-23 * time.Hour).Unix() }); uerr != nil {
				log.Printf("maint.json yazılamadı: %v", uerr)
			}
			return
		} else if n > 0 {
			log.Printf("günlük: %d eski olay %s", n, map[bool]string{true: "arşive taşındı", false: "silindi"}[c.LogArchive])
		}
	}
	pruneArchives(a.archiveDir(), c.ArchiveMonths, now)
	if err := m.update(func(c *MaintCfg) { c.LastCompact = now.Unix() }); err != nil {
		log.Printf("maint.json yazılamadı: %v", err)
	}
}

// ---- API (yalnızca admin) ----

func dirSize(dir string, match func(string) bool) int64 {
	var n int64
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.IsDir() || (match != nil && !match(e.Name())) {
			continue
		}
		if fi, err := e.Info(); err == nil {
			n += fi.Size()
		}
	}
	return n
}

func (a *App) handleGetMaint(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	c := a.maintCfg().get()
	hasPass := c.Backup.Pass != ""
	c.Backup.Pass = "" // parola arayüze asla geri gönderilmez
	total, oldest := a.act.stats()
	var next int64
	if c.Backup.Enabled {
		next = nextSlot(c.Backup, now).Unix()
		if ls := lastSlot(c.Backup, now); c.Backup.LastRun < ls.Unix() {
			next = now.Unix() // zamanı gelmiş, bir sonraki turda alınır
		}
	}
	bl := a.listBackups()
	if bl == nil {
		bl = []backupInfo{}
	}
	fi, _ := os.Stat(filepath.Join(a.dataDir, "history.json.gz"))
	var hsz int64
	if fi != nil {
		hsz = fi.Size()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"cfg": c, "has_pass": hasPass, "next_run": next, "backups": bl, "dir": a.backupDir(),
		"log":  map[string]any{"total": total, "oldest": oldest, "archive_bytes": dirSize(a.archiveDir(), nil)},
		"disk": map[string]any{"backups": dirSize(a.backupDir(), nil), "history": hsz},
		"dry":  a.dry,
	})
}

func (a *App) handlePutMaint(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Enabled       bool   `json:"enabled"`
		Freq          string `json:"freq"`
		Time          string `json:"time"`
		Weekday       int    `json:"weekday"`
		Keep          int    `json:"keep"`
		LogDays       int    `json:"log_days"`
		LogArchive    bool   `json:"log_archive"`
		ArchiveMonths int    `json:"archive_months"`
		NewPass       string `json:"new_pass"`   // boş = değiştirme
		ClearPass     bool   `json:"clear_pass"` // şifrelemeyi kapat
		OwnerPass     string `json:"owner_password"`
		OwnerCode     string `json:"owner_code"`
	}
	if !decodeN(w, r, &in, 4096) {
		return
	}
	if in.Freq != "daily" && in.Freq != "weekly" && in.Freq != "monthly" {
		errCode(w, http.StatusBadRequest, "maint.bad_freq", nil)
		return
	}
	if !clockRe.MatchString(in.Time) {
		errCode(w, http.StatusBadRequest, "maint.bad_time", nil)
		return
	}
	if in.Weekday < 0 || in.Weekday > 6 || in.Keep < 1 || in.Keep > 60 {
		errCode(w, http.StatusBadRequest, "maint.bad_keep", nil)
		return
	}
	if in.LogDays < 0 || in.LogDays > 3650 || (in.LogDays > 0 && in.LogDays < 7) || in.ArchiveMonths < 0 || in.ArchiveMonths > 120 {
		errCode(w, http.StatusBadRequest, "maint.bad_log_days", nil)
		return
	}
	if in.NewPass != "" {
		if err := checkPass(in.NewPass); err != nil {
			errOf(w, http.StatusBadRequest, err)
			return
		}
	}
	// Yedek parolasını değiştirmek ya da şifrelemeyi kapatmak yedeğin korumasını değiştirir; zamanlama/saklama değil.
	if (in.NewPass != "" || in.ClearPass) && !a.checkOwnerPass(w, r, in.OwnerPass, in.OwnerCode) {
		return
	}
	err := a.maintCfg().update(func(c *MaintCfg) {
		if in.ClearPass {
			c.Backup.Pass = ""
		} else if in.NewPass != "" {
			c.Backup.Pass = in.NewPass
		}
		c.Backup.Enabled, c.Backup.Freq, c.Backup.Time, c.Backup.Weekday, c.Backup.Keep = in.Enabled, in.Freq, in.Time, in.Weekday, in.Keep
		c.LogDays, c.LogArchive, c.ArchiveMonths = in.LogDays, in.LogArchive, in.ArchiveMonths
		c.LastCompact = 0 // yeni süre hemen uygulansın
	})
	if err != nil {
		errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
		return
	}
	switch {
	case in.ClearPass:
		a.logReqT(r, "settings", "log.settings.backup_pass_cleared", nil)
	case in.NewPass != "":
		a.logReqT(r, "settings", "log.settings.backup_pass_set", nil)
	}
	a.logReqT(r, "settings", "log.settings.maint_changed", nil)
	a.handleGetMaint(w, r)
}

func (a *App) handleBackupNow(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OwnerPass string `json:"owner_password"`
		OwnerCode string `json:"owner_code"`
	}
	if !decodeN(w, r, &in, 4096) || !a.checkOwnerPass(w, r, in.OwnerPass, in.OwnerCode) {
		return
	}
	name, err := a.makeBackup("elle", false)
	if err != nil {
		errCode(w, http.StatusInternalServerError, "backup.create_failed", map[string]any{"msg": err.Error()})
		return
	}
	a.logReqT(r, "backup", "log.backup.manual", map[string]any{"name": name})
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func backupName(w http.ResponseWriter, r *http.Request) (string, bool) {
	n := r.PathValue("name")
	if !backupNameRe.MatchString(n) {
		errCode(w, http.StatusBadRequest, "backup.bad_name", nil)
		return "", false
	}
	return n, true
}

func (a *App) handleBackupGet(w http.ResponseWriter, r *http.Request) {
	n, ok := backupName(w, r)
	if !ok {
		return
	}
	// Gövdesiz istek: sahip parolası ve kodu başlıkta, Türkçe karakterler için URL kodlu (bkz. headerDec).
	if !a.checkOwnerPass(w, r, headerDec(r, "X-Kut-Owner-Pass"), headerDec(r, "X-Kut-Owner-Code")) {
		return
	}
	b, err := os.ReadFile(filepath.Join(a.backupDir(), n)) //nolint:gosec // G304: n backupNameRe ile doğrulanmış (yol ayracı içermez)
	if err != nil {
		errCode(w, http.StatusNotFound, "backup.not_found", nil)
		return
	}
	a.logReqT(r, "backup", "log.backup.download", map[string]any{"name": n})
	if strings.HasSuffix(n, ".enc") {
		w.Header().Set("Content-Type", "application/octet-stream")
	} else {
		w.Header().Set("Content-Type", "application/gzip")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+n+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b) //nolint:gosec // G705: indirme attachment + application/gzip|octet-stream + nosniff; sayfa olarak yorumlanmaz
}

func (a *App) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	n, ok := backupName(w, r)
	if !ok {
		return
	}
	if err := os.Remove(filepath.Join(a.backupDir(), n)); err != nil { //nolint:gosec // G703: n backupNameRe ile doğrulanmış (yol ayracı içermez)
		errCode(w, http.StatusNotFound, "backup.not_found", nil)
		return
	}
	a.logReqT(r, "backup", "log.backup.delete", map[string]any{"name": n})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

var (
	restartDelay = 700 * time.Millisecond
)

// restartSelf: servisi yeniden başlatır (systemd Restart=always). Dry-run'da yapılmaz.
func (a *App) restartSelf() {
	if a.dry {
		return
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		log.Printf("yeniden başlatma sinyali gönderilemedi: %v", err)
	}
}

// applyBackupFiles: yedekteki dosyaları veri dizinine yazar. Yedekte olmayan bilinen dosyalar .bak'a taşınır.
// Herhangi bir yazma başarısızsa o ana kadar yazılanları eski içerikleriyle geri koyar.
func applyBackupFiles(dir string, got map[string][]byte) error {
	type prev struct {
		name string
		old  []byte
		had  bool
	}
	var done []prev
	rollback := func() {
		for i := len(done) - 1; i >= 0; i-- {
			p := filepath.Join(dir, done[i].name)
			var err error
			if done[i].had {
				err = writeFileAtomic(p, done[i].old)
			} else {
				err = os.Remove(p) //nolint:gosec // G703: ad backupFiles sabit listesinden
			}
			if err != nil {
				log.Printf("geri yükleme geri alınamadı (%s): %v", done[i].name, err)
			}
		}
	}
	for _, name := range backupFiles {
		d, ok := got[name]
		if !ok {
			continue
		}
		p := filepath.Join(dir, name)
		old, err := os.ReadFile(p) //nolint:gosec // G304: p veri dizini + sabit backupFiles adı
		had := err == nil
		if had {
			_ = writeFileAtomic(p+".bak", old)
		}
		if err := writeFileAtomic(p, d); err != nil {
			rollback()
			return nest("backup.write_failed", map[string]any{"name": name}, err)
		}
		done = append(done, prev{name, old, had})
	}
	for _, name := range backupFiles {
		if _, ok := got[name]; !ok {
			// yedekte olmayan dosya (ör. hiç cihaz yoksa peers.json) eski haliyle kalmasın
			_ = os.Rename(filepath.Join(dir, name), filepath.Join(dir, name+".bak")) //nolint:gosec // G703: ad backupFiles sabit listesinden
		}
	}
	return nil
}

// restore: doğrulanmış yedeği veri dizinine yazar, öncesinde mevcut durumu "oncesi" yedeği olarak saklar.
// Dosyalar yazılırken a.mu tutulur ve süreç yeniden başlayana kadar bırakılmaz: izleyici eski durumu üzerine yazamaz.
// name boşsa yedek yüklenen dosyadır; endpoint doluysa uç nokta değiştirilmiştir (yalnızca günlük için).
func (a *App) restore(r *http.Request, got map[string][]byte, name, endpoint string) (int, bool, error) {
	a.mu.Lock()
	pre, err := a.makeBackup("oncesi", true)
	if err != nil {
		a.mu.Unlock()
		return 0, false, nest("backup.pre_backup_failed", nil, err)
	}
	if err := applyBackupFiles(a.dataDir, got); err != nil {
		a.mu.Unlock()
		return 0, false, nest("backup.restore_failed", map[string]any{"pre": pre}, err)
	}
	key, p := "log.restore.file", map[string]any{"pre": pre}
	if name == "" {
		key = "log.restore.upload"
	} else {
		p["name"] = name
	}
	if endpoint != "" {
		key += "_endpoint"
		p["endpoint"] = endpoint
	}
	a.logReqT(r, "restore", key, p)
	restart := !a.dry
	go func() {
		time.Sleep(restartDelay)
		a.restartFnOrDefault()()
		if a.dry || a.restartF != nil { // test/dry-run: süreç ölmez, kilidi bırak
			a.mu.Unlock()
			return
		}
		// Gerçek modda kilit süreç ölene kadar tutulur: izleyici/işleyici eski belleği diske yazamasın.
		time.Sleep(10 * time.Second)
		log.Printf("SIGTERM sonrası süreç kapanmadı; çıkılıyor")
		os.Exit(0) // systemd Restart=always geri getirir
	}()
	return len(got), restart, nil
}

func (a *App) restartFnOrDefault() func() {
	if a.restartF != nil {
		return a.restartF
	}
	return a.restartSelf
}

// restoreReq: geri yükleme / önizleme isteğinin ortak parametreleri.
type restoreReq struct {
	Pass      string `json:"passphrase"`
	Endpoint  string `json:"endpoint"`       // doluysa yedekteki uç nokta bununla değiştirilir (sunucu taşıma)
	Inspect   bool   `json:"inspect"`        // true: yalnızca önizleme, hiçbir şey yazılmaz
	OwnerPass string `json:"owner_password"` // geri yükleme sahibin mevcut parolasını ister (önizleme istemez)
	OwnerCode string `json:"owner_code"`     // sahipte 2FA açıksa doğrulama ya da kurtarma kodu
}

type backupPreview struct {
	Encrypted    bool   `json:"encrypted"`
	Endpoint     string `json:"endpoint"`
	Port         int    `json:"port"`
	Subnet       string `json:"subnet"`
	Iface        string `json:"iface"`
	Devices      int    `json:"devices"`
	Profiles     int    `json:"profiles"`
	ThisEndpoint string `json:"this_endpoint"`
	ThisPort     int    `json:"this_port"`
	ThisSubnet   string `json:"this_subnet"`
	SameServer   bool   `json:"same_server"` // yedek bu sunucunun kendi anahtarını taşıyor
}

func (a *App) previewOf(got map[string][]byte, enc bool) backupPreview {
	var srv Server
	_ = json.Unmarshal(got["server.json"], &srv)
	var ps []Peer
	_ = json.Unmarshal(got["peers.json"], &ps)
	var pl []Policy
	_ = json.Unmarshal(got["policies.json"], &pl)
	cur := a.getSrv()
	return backupPreview{
		Encrypted: enc, Endpoint: srv.Endpoint, Port: srv.Port, Subnet: srv.Subnet, Iface: srv.Iface,
		Devices: len(ps), Profiles: len(pl),
		ThisEndpoint: cur.Endpoint, ThisPort: cur.Port, ThisSubnet: cur.Subnet,
		SameServer: srv.PrivateKey == cur.PrivateKey,
	}
}

// withEndpoint: server.json içindeki uç noktayı değiştirir (cihaz config'leri bu adresi taşır).
func withEndpoint(got map[string][]byte, ep string) error {
	ep, err := validEndpoint(ep)
	if err != nil {
		return err
	}
	var srv Server
	if err := json.Unmarshal(got["server.json"], &srv); err != nil {
		return err
	}
	srv.Endpoint = ep
	b, err := json.MarshalIndent(srv, "", "  ") //nolint:gosec // G117: server.json özel anahtarı taşır; 0600 yazılır, yedeğin de içeriği budur
	if err != nil {
		return err
	}
	got["server.json"] = append(b, '\n')
	return nil
}

func (a *App) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	n, ok := backupName(w, r)
	if !ok {
		return
	}
	var in restoreReq
	if !decodeN(w, r, &in, 4096) {
		return
	}
	b, err := os.ReadFile(filepath.Join(a.backupDir(), n)) //nolint:gosec // G304: n backupNameRe ile doğrulanmış (yol ayracı içermez)
	if err != nil {
		errCode(w, http.StatusNotFound, "backup.not_found", nil)
		return
	}
	a.finishRestore(w, r, b, n, in)
}

const (
	maxUploadBytes = 64 << 20 // yükleme gövdesinin tamamı (dosya + alanlar)
	maxUploadField = 4096     // tek bir metin alanı (adla geri yüklemedeki JSON gövde sınırıyla aynı)
)

// uploadFields: yükleme gövdesinde kabul edilen alanlar (sözleşme 7). Her biri en çok bir kez.
var uploadFields = map[string]bool{"file": true, "passphrase": true, "endpoint": true, "owner_password": true, "owner_code": true, "inspect": true}

// handleBackupUpload: gövde multipart/form-data. Parolalar gövdede gider: başlıkta (eskiden X-Kut-Pass ve
// X-Kut-Owner-*) vekil/erişim günlüklerine düşebiliyordu.
func (a *App) handleBackupUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	b, f, err := readUpload(r)
	if err != nil {
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			errCode(w, http.StatusRequestEntityTooLarge, "backup.too_large", map[string]any{"mb": maxUploadBytes >> 20})
			return
		}
		errOf(w, http.StatusBadRequest, err)
		return
	}
	in := restoreReq{Pass: f["passphrase"], Endpoint: f["endpoint"], Inspect: f["inspect"] == "1", OwnerPass: f["owner_password"], OwnerCode: f["owner_code"]}
	a.finishRestore(w, r, b, "", in)
}

// readUpload: multipart gövdeyi akışla okur (geçici dosya yok); dosyayı ve metin alanlarını döndürür. Eksik
// dosya, bilinmeyen ya da yinelenen alan reddedilir. Boyut aşımında *http.MaxBytesError sarılı döner.
func readUpload(r *http.Request) ([]byte, map[string]string, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, nil, ue("backup.upload_bad_form", nil)
	}
	bodyErr := func(err error) error {
		if mbe := (*http.MaxBytesError)(nil); errors.As(err, &mbe) {
			return err
		}
		return ue("backup.upload_bad_form", nil)
	}
	var file []byte
	fields := map[string]string{}
	seen := map[string]bool{}
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, bodyErr(err)
		}
		name := p.FormName()
		if !uploadFields[name] {
			if r := []rune(name); len(r) > 64 {
				name = string(r[:64]) + "…"
			}
			return nil, nil, ue("backup.upload_unknown_field", map[string]any{"name": strconv.Quote(name)})
		}
		if seen[name] {
			return nil, nil, ue("backup.upload_duplicate_field", map[string]any{"name": name})
		}
		seen[name] = true
		if name == "file" {
			if file, err = io.ReadAll(p); err != nil {
				return nil, nil, bodyErr(err)
			}
			continue
		}
		v, err := io.ReadAll(io.LimitReader(p, maxUploadField+1))
		if err != nil {
			return nil, nil, bodyErr(err)
		}
		if len(v) > maxUploadField {
			return nil, nil, ue("backup.upload_bad_form", nil)
		}
		fields[name] = string(v)
	}
	if !seen["file"] {
		return nil, nil, ue("backup.upload_no_file", nil)
	}
	if v := fields["inspect"]; v != "" && v != "1" {
		return nil, nil, ue("backup.upload_bad_form", nil)
	}
	return file, fields, nil
}

// headerDec: URL kodlu başlık değeri (Türkçe karakterli parolalar için); çözülemezse olduğu gibi.
func headerDec(r *http.Request, name string) string {
	s := r.Header.Get(name)
	v, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return v
}

// checkOwnerPass: yedek alma/indirme, geri yükleme ve yedek şifrelemesi değişikliği tüm hesapların parola
// özetlerine, TOTP sırlarına ve sunucunun özel anahtarına götürür. Bu yüzden oturum yetmez: sahibin mevcut
// parolası, 2FA açıksa ayrıca kodu istenir (çalınmış oturuma karşı; 2FA kapatmayla aynı çıta). Deneme giriş
// sayacına girer. Yerel soket (root) muaf.
func (a *App) checkOwnerPass(w http.ResponseWriter, r *http.Request, pass, code string) bool {
	me := userOf(r)
	if me == localUser {
		return true
	}
	ip := clientIP(r)
	if !a.lim.allow(ip, me) {
		errCode(w, http.StatusTooManyRequests, "too_many_attempts", nil)
		return false
	}
	if !a.getAdmin().verify(pass) {
		a.logReqT(r, "password_fail", "log.password_fail.backup_owner_pass", nil)
		errCode(w, http.StatusForbidden, "backup.owner_bad_password", nil)
		return false
	}
	a.adminMu.Lock()
	rec := a.getAdmin() // kilit altında en güncel kayıt
	if rec.TOTPSecret != "" {
		if !a.checkSecondFactor(&rec, code) {
			a.adminMu.Unlock()
			a.logReqT(r, "password_fail", "log.password_fail.backup_owner_code", nil)
			c := "backup.owner_bad_code"
			if strings.TrimSpace(code) == "" {
				c = "backup.owner_code_required"
			}
			errCode(w, http.StatusForbidden, c, nil)
			return false
		}
		if err := a.saveUserRec(ownerName, rec); err != nil { // kullanılan adım/kurtarma kodu kalıcı olsun
			a.adminMu.Unlock()
			errCode(w, http.StatusInternalServerError, "save_failed", map[string]any{"msg": err.Error()})
			return false
		}
	}
	a.adminMu.Unlock()
	a.lim.succeed(ip, me)
	return true
}

// finishRestore: önce yedek açılır (şifre çözülür) ve doğrulanır, sahip doğrulaması en sonda: yanlış yedek
// parolası ya da reddedilen yedek, tek kullanımlık 2FA/kurtarma kodunu ve deneme sayacını harcamasın.
// name boşsa yedek yüklenen dosyadır.
func (a *App) finishRestore(w http.ResponseWriter, r *http.Request, b []byte, name string, in restoreReq) {
	enc := isEncrypted(b)
	// Her çözme denemesi bir parola tahminidir (ve PBKDF2 çalıştırır): giriş sayacıyla aynı kalıpta, doğrulamadan
	// önce sayılır; doğru parola sıfırlar. Parola hiç denenmeyecekse (şifresiz yedek, parola yok) sayılmaz.
	ip := clientIP(r)
	tryPass := enc && (in.Pass != "" || a.maintCfg().get().Backup.Pass != "")
	if tryPass && !a.lim.allow(ip, backupPassBucket) {
		errCode(w, http.StatusTooManyRequests, "too_many_attempts", nil)
		return
	}
	got, err := a.openBackup(b, in.Pass)
	if tryPass && err == nil {
		a.lim.succeed(ip, backupPassBucket)
	}
	if err != nil {
		if errors.Is(err, errNeedPass) || errors.Is(err, errBadPass) {
			body := map[string]any{"error": err.Error(), "need_pass": true}
			if ce := (*codedErr)(nil); errors.As(err, &ce) {
				body["code"], body["params"] = ce.Code, ce.Params
			}
			writeJSON(w, http.StatusUnprocessableEntity, body)
			return
		}
		a.maintErrJSON(w, r, http.StatusBadRequest, err)
		return
	}
	if !a.dry {
		// Gerçek kipte yedek, yapılandırmayı /etc/wireguard dışına yazdıramaz (bkz. checkRealConfPath).
		if err := checkBackupConfPath(got); err != nil {
			errOf(w, http.StatusBadRequest, err)
			return
		}
	}
	if in.Inspect {
		writeJSON(w, http.StatusOK, a.previewOf(got, enc))
		return
	}
	if in.Endpoint != "" {
		if err := withEndpoint(got, in.Endpoint); err != nil {
			errOf(w, http.StatusBadRequest, err)
			return
		}
	}
	if !a.checkOwnerPass(w, r, in.OwnerPass, in.OwnerCode) {
		return
	}
	n, restart, err := a.restore(r, got, name, in.Endpoint)
	if err != nil {
		a.maintErrJSON(w, r, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "files": n, "restarting": restart})
}

// handleRestart: Kut servisini yeniden başlatır (systemd Restart=always süreci geri getirir).
// WireGuard arayüzü sunucuda ayakta kalır; cihazların bağlantısı kesilmez, yalnızca panel birkaç saniye yanıt vermez.
func (a *App) handleRestart(w http.ResponseWriter, r *http.Request) {
	a.logReqT(r, "restart", "log.restart.panel", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restarting": !a.dry})
	go func() {
		time.Sleep(restartDelay)
		a.restartFnOrDefault()()
	}()
}
