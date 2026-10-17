package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const version = "0.15.4"
const defaultData = "/var/lib/kut"

// Varsayılan VPN ağı: wg-easy/OpenVPN varsayılanı olan 10.8.0.0/24 ile ve yaygın ev ağlarıyla (192.168.x, 10.0.0.x) çakışmasın diye.
const defaultSubnet = "10.77.0.0/24"

var ifaceRe = regexp.MustCompile(`^[a-zA-Z0-9_=+.-]{1,15}$`)

func usage(lang string) {
	fmt.Fprint(os.Stderr, T(lang, "cli.usage", map[string]any{"app": appName, "version": version, "tagline": T(lang, "cli.tagline", nil)}))
}

// cliErrText: komut satırında yazılacak hata metni. Kodlu hatalar (ue) lang dilinde yazılır; içlerindeki
// hata değerli parametreler de aynı dile çevrilir (ör. loadApp'in sardığı doğrulama hatası).
func cliErrText(lang string, err error) string {
	var ne *nestedErr
	if errors.As(err, &ne) { // iç içe hata (ör. geri yüklemede doğrulama): iç hata da aynı dilde {err}'e yazılır
		return T(lang, "err."+ne.code, ne.paramsIn(lang))
	}
	ce, ok := err.(*codedErr) //nolint:errorlint // yalnızca doğrudan kodlu hata çevrilir; sarılmış hatanın metni olduğu gibi kalır
	if !ok {
		return err.Error()
	}
	p := make(map[string]any, len(ce.Params))
	for k, v := range ce.Params {
		if e, isErr := v.(error); isErr {
			v = cliErrText(lang, e)
		}
		p[k] = v
	}
	return T(lang, "err."+ce.Code, p)
}

// commands: geçerli alt komutlar (yazım hatasında öneri için).
var commands = []string{"init", "passwd", "serve", "add", "list", "doctor", "2fa-off", "backup", "restore", "install", "uninstall", "version"}

// unknownCommand: bilinmeyen alt komut iletisi; düzenleme uzaklığı 2 ya da daha az olan bir komut varsa önerir.
func unknownCommand(lang, cmd string) string {
	msg := T(lang, "cli.unknown_command", map[string]any{"cmd": cmd}) + "\n"
	best, bestD := "", 3
	for _, c := range commands {
		if d := editDistance(cmd, c); d < bestD {
			best, bestD = c, d
		}
	}
	if best != "" {
		msg += T(lang, "cli.did_you_mean", map[string]any{"cmd": best}) + "\n"
	}
	return msg + "\n"
}

// editDistance: komşu iki harfin yer değiştirmesini tek düzenleme sayan Levenshtein uzaklığı (optimal string
// alignment; rune bazında): "lsit" → "list" 1'dir, "init" ile eşitlenmez.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

func main() {
	var args []string
	if len(os.Args) > 2 {
		args = os.Args[2:]
	}
	lang := argLang(args)
	if len(os.Args) < 2 {
		usage(lang)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(args)
	case "passwd":
		err = cmdPasswd(args)
	case "serve":
		err = cmdServe(args)
	case "add":
		err = cmdAdd(args)
	case "list":
		err = cmdList(args)
	case "doctor":
		err = cmdDoctor(args)
	case "2fa-off":
		err = cmd2FAOff(args)
	case "backup":
		err = cmdBackup(args)
	case "restore":
		err = cmdRestore(args)
	case "install":
		err = cmdInstall(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "version", "-v", "--version":
		fmt.Println("kut", version)
	default:
		fmt.Fprint(os.Stderr, unknownCommand(lang, os.Args[1]))
		usage(lang)
		os.Exit(2)
	}
	var code exitCode
	if errors.As(err, &code) {
		os.Exit(int(code)) // kurulum betiğinin çıkış kodu; iletisini betik yazdı
	}
	if errors.Is(err, flag.ErrHelp) {
		return // -h: yardım metni bayrak kümesinin Usage'ı ile zaten yazıldı; "flag: help requested" İngilizce sızıntısı olmasın
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, T(lang, "cli.error_prefix", nil), cliErrText(lang, err))
		os.Exit(1)
	}
}

func cmdInit(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("init", lang)
	endpoint := fs.String("endpoint", "", T(lang, "cli.flag.init_endpoint", nil))
	port := fs.Int("port", 51820, T(lang, "cli.flag.init_port", nil))
	subnet := fs.String("subnet", defaultSubnet, T(lang, "cli.flag.init_subnet", nil))
	iface := fs.String("iface", "wg0", T(lang, "cli.flag.init_iface", nil))
	dry := fs.Bool("dry-run", false, T(lang, "cli.flag.init_dry_run", nil))
	force := fs.Bool("force", false, T(lang, "cli.flag.init_force", nil))
	allowOverlap := fs.Bool("allow-overlap", false, T(lang, "cli.flag.init_allow_overlap", nil))
	lf := fs.Lookup("lang")
	lf.Usage = T(lang, "cli.flag.init_lang", nil)
	if err := fs.Parse(args); err != nil {
		return err
	}
	srvLang := normLang(lf.Value.String())
	if lf.Value.String() != "" && srvLang == "" {
		return errors.New(T(lang, "cli.init.bad_lang", nil))
	}
	if srvLang == "" {
		srvLang = lang // bayrak yoksa sunucu dili, kurulumu yapanın çıktı diliyle aynı başlar (sonra Ayarlar'dan değişir)
	}

	ep, err := validEndpoint(*endpoint)
	if err != nil {
		return errors.New(T(lang, "cli.init.bad_endpoint", map[string]any{"err": cliErrText(lang, err)}))
	}
	if *port < 1 || *port > 65535 {
		return errors.New(T(lang, "cli.init.bad_port", nil))
	}
	if !ifaceRe.MatchString(*iface) {
		return errors.New(T(lang, "cli.init.bad_iface", nil))
	}
	pfx, err := netip.ParsePrefix(*subnet)
	if err != nil || !pfx.Addr().Is4() || pfx.Bits() < minSubnetBits || pfx.Bits() > maxSubnetBits || !privateSubnet(pfx.Addr()) {
		return errors.New(T(lang, "cli.init.bad_subnet", map[string]any{"min": minSubnetBits, "max": maxSubnetBits}))
	}
	if pfx.Addr() != pfx.Masked().Addr() {
		return errors.New(T(lang, "cli.init.subnet_not_network", map[string]any{"want": pfx.Masked().String()}))
	}

	if _, err := os.Stat(serverPath(*data)); err == nil {
		return errors.New(T(lang, "cli.init.already", map[string]any{"data": *data}))
	}
	conf := wgConfPath(*iface)
	if *dry {
		conf = filepath.Join(*data, *iface+".conf")
	} else if _, err := os.Stat(conf); err == nil && !*force { //nolint:gosec // G703: -data/-iface root operatörün CLI bayrakları; iface regex ile doğrulanmış
		return errors.New(T(lang, "cli.init.conf_exists", map[string]any{"conf": conf}))
	}

	if lp, bad := overlapLocalExcept(pfx, ""); bad && !*allowOverlap {
		return errors.New(T(lang, "cli.init.overlap", map[string]any{"net": pfx.String(), "local": lp, "example": defaultSubnet}))
	}

	if err := os.MkdirAll(*data, 0o700); err != nil { //nolint:gosec // G703: -data yolu root operatörün CLI bayrağı
		return err
	}
	priv, err := genPrivateKey()
	if err != nil {
		return err
	}
	pub, err := publicKey(priv)
	if err != nil {
		return err
	}
	def := defaultSettings()
	def.Lang = srvLang
	srv := Server{PrivateKey: priv, PublicKey: pub, Endpoint: ep, Port: *port, Subnet: pfx.String(), Iface: *iface, ConfPath: conf, Settings: &def}
	if err := saveJSON(serverPath(*data), srv); err != nil {
		return err
	}
	if _, err := os.Stat(peersPath(*data)); errors.Is(err, os.ErrNotExist) {
		if err := saveJSON(peersPath(*data), []Peer{}); err != nil {
			return err
		}
	}
	if err := writeFileAtomic(conf, []byte(renderServerConf(srv, nil))); err != nil {
		return err
	}
	fmt.Print(T(lang, "cli.init.done", map[string]any{"conf": conf, "data": *data, "ip": srv.serverIP().String(), "key": pub}))
	return nil
}

var stdin = bufio.NewReader(os.Stdin)

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func readSecret(prompt string) (string, error) {
	if isTerminal(os.Stdin) {
		fmt.Fprint(os.Stderr, prompt)
		off := exec.Command("stty", "-echo") //nolint:noctx // stty anında döner; terminal yankısını kapatır
		off.Stdin = os.Stdin
		if off.Run() == nil {
			defer func() {
				on := exec.Command("stty", "echo") //nolint:noctx // stty anında döner; terminal yankısını açar
				on.Stdin = os.Stdin
				_ = on.Run()
				fmt.Fprintln(os.Stderr)
			}()
		}
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func cmdPasswd(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("passwd", lang)
	user := fs.String("user", "", T(lang, "cli.flag.passwd_user", nil))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*data, 0o700); err != nil { //nolint:gosec // G703: -data yolu root operatörün CLI bayrağı
		return err
	}
	pw := os.Getenv("KUT_PASSWORD")
	if pw == "" {
		pw = os.Getenv("WGUI_PASSWORD") // v0.3 uyumluluğu
	}
	if pw == "" {
		var err error
		if pw, err = readSecret(T(lang, "cli.passwd.prompt", nil)); err != nil {
			return err
		}
		if isTerminal(os.Stdin) {
			again, err := readSecret(T(lang, "cli.passwd.again", nil))
			if err != nil {
				return err
			}
			if again != pw {
				return errors.New(T(lang, "cli.passwd.mismatch", nil))
			}
		}
	}
	rec, err := newAdmin(pw)
	if err != nil {
		return err
	}
	if serviceRunning(*data) { // bellekteki kayıt da değişsin; dosyaya yazmak sonraki kayıtta ezilirdi
		name := normUser(*user)
		if name == "" {
			name = ownerName
		}
		if err := newLocalClient(*data, lang).do("POST", "/api/local/passwd", map[string]string{"user": name, "password": pw}, nil); err != nil {
			return err
		}
		fmt.Println(T(lang, "cli.passwd.saved_live", nil))
		return nil
	}
	if name := normUser(*user); name != "" && name != ownerName {
		if err := offlineEdit(*data, name, func(r *adminRecord) error { *r = rec.withPrefsFrom(*r); return nil }); err != nil {
			return err
		}
		fmt.Println(T(lang, "cli.passwd.saved_restart", nil))
		return nil
	}
	var old adminRecord
	if loadJSON(adminPath(*data), &old) == nil {
		rec = rec.withPrefsFrom(old) // 2FA kapanmasın
	}
	if err := saveJSON(adminPath(*data), rec); err != nil {
		return err
	}
	fmt.Println(T(lang, "cli.passwd.saved", nil))
	return nil
}

func cmdServe(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("serve", lang)
	listen := fs.String("listen", "", T(lang, "cli.flag.serve_listen", nil))
	dry := fs.Bool("dry-run", false, T(lang, "cli.flag.serve_dry_run", nil))
	if err := fs.Parse(args); err != nil {
		return err
	}
	app, err := loadApp(*data, *dry)
	if err != nil {
		return err
	}
	addr := *listen
	if addr == "" {
		if *dry {
			addr = "127.0.0.1:5000"
		} else {
			addr = netip.AddrPortFrom(app.srv.serverIP(), 5000).String()
		}
	}
	return app.serve(addr)
}
