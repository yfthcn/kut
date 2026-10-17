package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Yerel yönetim istemcisi: `kut add|list|doctor`. Çalışan servisle veri dizinindeki unix soketi üzerinden konuşur.
// Soket 0600 olduğu için yalnızca sahibi (root) erişir; bu yüzden parola istemez. Hiçbir ağ portu açılmaz.

type localClient struct {
	hc   *http.Client
	lang string // CLI dili: sunucuya X-Kut-Lang ile iletilir, hata iletileri bu dilde yazılır
}

func newLocalClient(dataDir, lang string) *localClient {
	sock := filepath.Join(dataDir, socketName)
	return &localClient{lang: lang, hc: &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// Servis yeni başlıyorsa soket birkaç saniye sonra açılır; bağlantı kurulamadıysa
			// istek hiç gitmemiştir, bu yüzden yeniden denemek güvenlidir.
			var d net.Dialer
			var c net.Conn
			var err error
			for range 30 {
				if c, err = d.DialContext(ctx, "unix", sock); err == nil || ctx.Err() != nil {
					break
				}
				if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ECONNREFUSED) {
					break // izin vb. kalıcı hata: beklemek düzeltmez
				}
				select {
				case <-time.After(500 * time.Millisecond):
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return c, err
		}},
	}}
}

func (c *localClient) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "http://kut"+path, body) //nolint:noctx // istemcinin Timeout'u var; CLI'da iptal edilecek bir bağlam yok
	req.Header.Set(csrfHeader, "1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kut-Lang", c.lang) // sunucunun ürettiği metinler (rapor…) CLI dilinde gelsin
	resp, err := c.hc.Do(req)
	if err != nil {
		return errors.New(dialErrText(c.lang, err))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		var e struct {
			Error  string         `json:"error"`
			Code   string         `json:"code"`
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal(raw, &e) // çözülemezse aşağıda resp.Status kullanılır
		if e.Code != "" && hasKey("err."+e.Code) {
			return errors.New(T(c.lang, "err."+e.Code, wholeInts(e.Params)))
		}
		if e.Error == "" {
			e.Error = resp.Status
		}
		return errors.New(e.Error)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// dialErrText: sokete bağlanılamadığında yazılan ileti. İzin hatası (root olmayan kullanıcı, soket 0600) servisin
// çalışıp çalışmadığını sormaz, sudo ister; soket yoksa ya da bağlantı reddedildiyse servisin durumuna yönlendirir.
func dialErrText(lang string, err error) string {
	if errors.Is(err, syscall.EACCES) || errors.Is(err, os.ErrPermission) {
		return T(lang, "cli.no_permission", map[string]any{"err": err.Error()})
	}
	return T(lang, "cli.no_service", map[string]any{"err": err.Error()})
}

// hasKey: anahtar (ya da çoğul biçimi) katalogda var mı. Sunucu daha yeni bir hata kodu gönderirse
// anahtarın kendisini yazmak yerine sunucunun İngilizce metnine düşülür.
func hasKey(key string) bool {
	_, ok := lookup(refLang, key)
	if !ok {
		_, ok = lookup(refLang, key+".other")
	}
	return ok
}

// wholeInts: JSON'dan gelen sayılar float64 olur; T çoğul seçimi için tamsayı bekler.
func wholeInts(p map[string]any) map[string]any {
	out := make(map[string]any, len(p))
	for k, v := range p {
		if f, ok := v.(float64); ok && f == math.Trunc(f) && math.Abs(f) < 1<<53 {
			v = int(f)
		}
		out[k] = v
	}
	return out
}

// qrTerminal: QR'ı terminalde yarım blok karakterleriyle çizer (iki satır = bir karakter satırı).
func qrTerminal(text string) (string, error) {
	q, err := qrEncode(text)
	if err != nil {
		return "", err
	}
	const quiet = 2
	n := q.size + 2*quiet
	dark := func(x, y int) bool {
		x, y = x-quiet, y-quiet
		return x >= 0 && y >= 0 && x < q.size && y < q.size && q.mod[y][x]
	}
	var b strings.Builder
	// Beyaz zemin üzerine siyah modüller: koyu terminallerde de okunur olsun diye ters renk kullanıyoruz.
	for y := 0; y < n; y += 2 {
		for x := range n {
			top, bot := dark(x, y), dark(x, y+1)
			switch {
			case top && bot:
				b.WriteString(" ")
			case top:
				b.WriteString("▄")
			case bot:
				b.WriteString("▀")
			default:
				b.WriteString("█")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

// argValue: ham argümanlardan -ad DEĞER, --ad DEĞER ya da -ad=DEĞER bayrağının değerini bulur ("" = yok).
// Bayraklar ayrıştırılmadan önce (yardım metni, hata iletisi) dili bilmek için gerekir.
func argValue(args []string, name string) string {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			continue
		}
		k, v, hasV := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if k != name {
			continue
		}
		if hasV {
			return v
		}
		if i+1 < len(args) {
			return args[i+1]
		}
		return ""
	}
	return ""
}

// argLang: komutun çıktı dili. -lang verildiyse o; yoksa cliLang (ortam > veri dizinindeki sunucu dili > tr).
func argLang(args []string) string {
	if l := normLang(argValue(args, "lang")); l != "" {
		return l
	}
	return cliLang(cmp.Or(argValue(args, "data"), defaultData))
}

// flagUsage: flag paketinin İngilizce varsayılan yardımı yerine lang dilinde yardım yazar.
func flagUsage(fs *flag.FlagSet, lang string) func() {
	return func() {
		w := fs.Output()
		_, _ = fmt.Fprintln(w, T(lang, "cli.flag.usage_of", map[string]any{"name": fs.Name()}))
		fs.VisitAll(func(f *flag.Flag) {
			typ, usage := flag.UnquoteUsage(f)
			line := "  -" + f.Name
			if typ != "" {
				line += " " + typ
			}
			line += "\n    \t" + strings.ReplaceAll(usage, "\n", "\n    \t")
			if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
				line += " " + T(lang, "cli.flag.default", map[string]any{"v": f.DefValue})
			}
			_, _ = fmt.Fprintln(w, line)
		})
	}
}

// langFlags: lang dilinde yardım metinli bir bayrak kümesi, ortak -data ve -lang bayrakları. -lang'in değeri
// ayrıştırmadan önce argLang ile okunur (yardım metni de o dilde olsun diye); burada yalnızca tanınması sağlanır.
// init aynı bayrağı sunucunun varsayılan dili için de kullanır (fs.Lookup("lang")).
func langFlags(name, lang string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = flagUsage(fs, lang)
	data := fs.String("data", defaultData, T(lang, "cli.flag.data", nil))
	fs.String("lang", "", T(lang, "cli.flag.lang", nil))
	return fs, data
}

// localFlags: langFlags, dili sürecin kendi argümanlarından (os.Args) çıkarır.
func localFlags(name string) (*flag.FlagSet, *string) {
	return langFlags(name, argLang(os.Args[min(2, len(os.Args)):]))
}

func cmdAdd(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("add", lang)
	name := fs.String("name", "", T(lang, "cli.flag.add_name", nil))
	note := fs.String("note", "", T(lang, "cli.flag.add_note", nil))
	internet := fs.Bool("internet", false, T(lang, "cli.flag.add_internet", nil))
	ip := fs.String("ip", "", T(lang, "cli.flag.add_ip", nil))
	policy := fs.String("policy", "", T(lang, "cli.flag.add_policy", nil))
	expires := fs.String("expires", "", T(lang, "cli.flag.add_expires", nil))
	out := fs.String("o", "", T(lang, "cli.flag.add_out", nil))
	noQR := fs.Bool("no-qr", false, T(lang, "cli.flag.add_no_qr", nil))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*name) == "" {
		return errors.New(T(lang, "cli.add.name_required", nil))
	}
	expMins := 0
	if *expires != "" {
		m, err := parseSpan(*expires)
		if err != nil {
			return err
		}
		expMins = m
	}
	c := newLocalClient(*data, lang)
	pid := ""
	if *policy != "" {
		var pl struct {
			Policies []policyView `json:"policies"`
		}
		if err := c.do("GET", "/api/policies", nil, &pl); err != nil {
			return err
		}
		for _, p := range pl.Policies {
			if strings.EqualFold(p.Name, *policy) {
				pid = p.ID
			}
		}
		if pid == "" {
			return errors.New(T(lang, "cli.add.policy_missing", map[string]any{"name": *policy}))
		}
	}
	var resp struct {
		Name, IP, Config string
		Internet         bool
	}
	if err := c.do("POST", "/api/peers", map[string]any{"name": *name, "note": *note, "internet": *internet, "ip": *ip, "policy": pid, "expires_minutes": expMins}, &resp); err != nil {
		return err
	}
	if *out != "" {
		if err := writeFileAtomic(*out, []byte(resp.Config)); err != nil {
			return err
		}
	}
	access := T(lang, "cli.add.access_vpn", nil)
	if resp.Internet {
		access = T(lang, "cli.add.access_inet", nil)
	}
	fmt.Println(T(lang, "cli.add.done", map[string]any{"name": resp.Name, "ip": resp.IP, "access": access}))
	fmt.Println(T(lang, "cli.add.shown_once", nil))
	if !*noQR {
		if q, err := qrTerminal(resp.Config); err == nil {
			fmt.Println()
			fmt.Print(q)
			fmt.Println(T(lang, "cli.add.scan", nil))
		}
	}
	fmt.Println("\n" + T(lang, "cli.add.config_header", nil))
	fmt.Print(resp.Config)
	if *out != "" {
		fmt.Println(T(lang, "cli.add.written", map[string]any{"path": *out}))
	}
	return nil
}

func cmdList(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("list", lang)
	if err := fs.Parse(args); err != nil {
		return err
	}
	var st struct {
		Peers []peerView `json:"peers"`
	}
	c := newLocalClient(*data, lang)
	if err := c.do("GET", "/api/status", nil, &st); err != nil {
		return err
	}
	if len(st.Peers) == 0 {
		fmt.Println(T(lang, "cli.list.empty", nil))
		return nil
	}
	const row = "%-18s %-15s %-11s %-9s %-14s %s\n"
	fmt.Printf(row, T(lang, "cli.list.head.device", nil), T(lang, "cli.list.head.ip", nil), T(lang, "cli.list.head.state", nil),
		T(lang, "cli.list.head.internet", nil), T(lang, "cli.list.head.profile", nil), T(lang, "cli.list.head.seen", nil))
	for _, p := range st.Peers {
		state := ""
		switch {
		case p.Online:
			state = T(lang, "cli.list.state.online", nil)
		case slices.Contains([]string{"active", "disabled", "frozen", "expired", "outside"}, p.State):
			state = T(lang, "cli.list.state."+p.State, nil)
		}
		inet := T(lang, "cli.list.no", nil)
		if p.Internet {
			inet = T(lang, "cli.list.yes", nil)
		}
		pol := p.PolicyName
		if pol == "" {
			pol = "-"
		}
		seen := T(lang, "cli.list.never", nil)
		if p.LastSeen > 0 {
			seen = T(lang, "cli.list.ago", map[string]any{"dur": humanDur(lang, time.Since(time.Unix(p.LastSeen, 0)))})
			if p.Online {
				seen = T(lang, "cli.list.now", nil)
			}
		}
		if p.ExpiresAt > 0 && p.State != "expired" {
			seen += T(lang, "cli.list.guest", map[string]any{"dur": humanDur(lang, time.Until(time.Unix(p.ExpiresAt, 0)))})
		}
		fmt.Printf(row, p.Name, p.IP, state, inet, pol, seen)
	}
	return nil
}

func cmdDoctor(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("doctor", lang)
	asJSON := fs.Bool("json", false, T(lang, "cli.flag.doctor_json", nil))
	if err := fs.Parse(args); err != nil {
		return err
	}
	var rep Report
	c := newLocalClient(*data, lang)
	if err := c.do("GET", "/api/report", nil, &rep); err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		sym := map[string]string{"ok": "✓", "warn": "!", "fail": "✗", "info": "·"}
		for _, c := range rep.Checks {
			fmt.Printf(" %s  %s\n", sym[c.Level], c.Title)
			if c.Detail != "" && c.Level != "ok" {
				fmt.Printf("      %s\n", c.Detail)
			}
			if c.Fix != "" && (c.Level == "warn" || c.Level == "fail") {
				fmt.Printf("      → %s\n", c.Fix)
			}
		}
		fmt.Printf("\n%s, %s, %s\n",
			T(lang, "cli.doctor.ok", map[string]any{"n": rep.Counts["ok"]}),
			T(lang, "cli.doctor.warn", map[string]any{"n": rep.Counts["warn"]}),
			T(lang, "cli.doctor.fail", map[string]any{"n": rep.Counts["fail"]}))
	}
	if rep.Counts["fail"] > 0 {
		os.Exit(1)
	}
	return nil
}

// parseSpan: "90m", "8h", "3d", "2w" → dakika. 1 dakika – 1 yıl. Hatalar kodludur (ue); CLI kendi dilinde yazar.
func parseSpan(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) < 2 {
		return 0, ue("span.invalid", map[string]any{"value": s})
	}
	unit := map[byte]int{'m': 1, 'h': 60, 'd': 1440, 'w': 10080}[s[len(s)-1]]
	n, err := strconv.Atoi(s[:len(s)-1])
	if unit == 0 || err != nil || n < 1 {
		return 0, ue("span.invalid", map[string]any{"value": s})
	}
	if n > maxExpireMins/unit {
		return 0, ue("span.too_long", nil)
	}
	return n * unit, nil
}
