package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Durum raporu: kurulumun sağlığını ve yapısını tek yerde gösterir (arayüzde "Rapor", terminalde `kut doctor`).

type Check struct {
	ID     string `json:"id"`
	Group  string `json:"group"` // wireguard | firewall | network | security | devices
	Level  string `json:"level"` // ok | warn | fail | info
	Title  string `json:"title"`
	Detail string `json:"detail,omitempty"`
	Fix    string `json:"fix,omitempty"`
}

type kv struct {
	K string `json:"k"`
	V string `json:"v"`
}

type matrixCell struct {
	Result string `json:"result"` // allow | deny | host | self
	Text   string `json:"text,omitempty"`
}

type Report struct {
	Generated int64            `json:"generated"`
	Health    string           `json:"health"` // ok | warn | fail
	Counts    map[string]int   `json:"counts"`
	Checks    []Check          `json:"checks"`
	Structure []kv             `json:"structure"`
	System    []kv             `json:"system"`
	Devices   []map[string]any `json:"matrix_devices"`
	Matrix    [][]matrixCell   `json:"matrix"` // satır: kaynak cihaz; sütun: hedef cihazlar + son sütun sunucu
}

func firstLine(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // G304: çağıranlar yalnızca sabit /proc yolları verir
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
}

func osPretty() string {
	b, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return runtime.GOOS
	}
	for ln := range strings.SplitSeq(string(b), "\n") {
		if after, ok := strings.CutPrefix(ln, "PRETTY_NAME="); ok {
			return strings.Trim(after, `"`)
		}
	}
	return runtime.GOOS
}

// humanDur: süreyi kısa metne çevirir; birimler kataloğun report.dur.* anahtarlarından (lang dilinde).
func humanDur(lang string, d time.Duration) string {
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return T(lang, "report.dur.days", map[string]any{"d": days, "h": h})
	case h > 0:
		return T(lang, "report.dur.hours", map[string]any{"h": h, "m": m})
	}
	return T(lang, "report.dur.mins", map[string]any{"m": max(m, 0)})
}

func isPrivateAddr(a netip.Addr) bool {
	if a.IsPrivate() || a.IsLinkLocalUnicast() {
		return true
	}
	cg := netip.MustParsePrefix("100.64.0.0/10")
	return a.Is4() && cg.Contains(a)
}

// overlapLocalExcept: alt ağın, verilen arayüz dışındaki bir yerel ağla çakışıp çakışmadığı.
func overlapLocalExcept(pfx netip.Prefix, skip string) (string, bool) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	for _, ifc := range ifs {
		if ifc.Name == skip {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			ip = ip.Unmap()
			if !ip.Is4() {
				continue
			}
			ones, _ := ipn.Mask.Size()
			if lp := netip.PrefixFrom(ip, ones).Masked(); lp.Overlaps(pfx) {
				return fmt.Sprintf("%s (%s)", lp, ifc.Name), true
			}
		}
	}
	return "", false
}

// reportField: rapor satırının bir alanı (title|detail|fix) report.check.<key>.<alan> anahtarından gelir.
// Katalogda olmayan alan boş kalır (ör. çoğu satırın çözümü yoktur). Çoğul alanlar (.one/.other) da sayılır.
func reportField(lang, key, field string, p map[string]any) string {
	k := "report.check." + key + "." + field
	if _, ok := lookup(refLang, k); !ok {
		if _, ok := lookup(refLang, k+".other"); !ok {
			return ""
		}
	}
	return T(lang, k, p)
}

// fwDetail: güvenlik duvarı durumunun gösterim metni. Anahtar varsa (fw.*) istenen dilde, yoksa hazır Detail.
func fwDetail(lang string, st fwState) string {
	if st.Key != "" {
		return T(lang, st.Key, st.Params)
	}
	return st.Detail
}

// buildReport: durum raporunu lang dilinde üretir (arayüz için isteği yapanın dili, `kut doctor` için cliLang).
func (a *App) buildReport(lang string) Report {
	s := a.getSrv()
	peers, pols := a.snapshot()
	now := time.Now()
	var cs []Check
	// add: key, report.check.<key>.{title,detail,fix} satırını p ile doldurur. cmdFix verilirse çözüm
	// dilden bağımsız bir komuttur ve katalogdan okunmaz.
	add := func(group, id, level, key string, p map[string]any, cmdFix ...string) {
		c := Check{ID: id, Group: group, Level: level,
			Title:  reportField(lang, key, "title", p),
			Detail: reportField(lang, key, "detail", p),
			Fix:    reportField(lang, key, "fix", p)}
		if len(cmdFix) > 0 {
			c.Fix = cmdFix[0]
		}
		cs = append(cs, c)
	}
	skip := func(group, id string) {
		cs = append(cs, Check{ID: id, Group: group, Level: "info",
			Title: reportField(lang, id+".skip", "title", nil), Detail: T(lang, "report.skip_dry", nil)})
	}
	stats, up := a.wgDump(peers)
	activeN := 0
	for _, p := range peers {
		if p.active(now) {
			activeN++
		}
	}

	// ---- WireGuard ----
	if a.dry {
		skip("wireguard", "iface")
		skip("wireguard", "tool")
	} else {
		if up {
			add("wireguard", "iface", "ok", "iface.ok", map[string]any{"iface": s.Iface})
		} else {
			add("wireguard", "iface", "fail", "iface.down", map[string]any{"iface": s.Iface}, "sudo systemctl restart wg-quick@"+s.Iface)
		}
		if out, err := run(3*time.Second, "wg", "--version"); err == nil {
			add("wireguard", "tool", "info", "tool.ok", map[string]any{"version": strings.TrimSpace(string(out))})
		} else {
			add("wireguard", "tool", "fail", "tool.missing", nil, "sudo apt install wireguard")
		}
		if up {
			if out, err := run(3*time.Second, "wg", "show", s.Iface, "listen-port"); err == nil {
				if got, _ := strconv.Atoi(strings.TrimSpace(string(out))); got == s.Port {
					add("wireguard", "port", "ok", "port.ok", map[string]any{"port": s.Port})
				} else {
					add("wireguard", "port", "warn", "port.warn", map[string]any{"got": strings.TrimSpace(string(out)), "port": s.Port, "iface": s.Iface})
				}
			}
			if len(stats) == activeN {
				add("wireguard", "kernel", "ok", "kernel.ok", map[string]any{"n": activeN})
			} else {
				add("wireguard", "kernel", "warn", "kernel.warn", map[string]any{"want": activeN, "got": len(stats)})
			}
		}
		if disk, err := os.ReadFile(s.ConfPath); err == nil {
			if string(disk) == renderServerConf(s, peers) {
				add("wireguard", "conf", "ok", "conf.ok", map[string]any{"path": s.ConfPath})
			} else {
				add("wireguard", "conf", "warn", "conf.warn", map[string]any{"path": s.ConfPath})
			}
		} else {
			add("wireguard", "conf", "fail", "conf.fail", map[string]any{"err": err.Error()})
		}
	}

	// ---- Güvenlik duvarı ----
	if a.dry {
		skip("firewall", "rules")
		skip("firewall", "forward")
		skip("firewall", "ufw")
	} else {
		fw := a.fwCheck(s, peers, pols)
		switch fw.State {
		case "ok":
			add("firewall", "rules", "ok", "rules.ok", nil)
		case "down":
			add("firewall", "rules", "info", "rules.down", map[string]any{"detail": fwDetail(lang, fw)})
		case "out-of-sync":
			add("firewall", "rules", "warn", "rules.out_of_sync", map[string]any{"detail": fwDetail(lang, fw)})
		default:
			add("firewall", "rules", "fail", "rules.broken", map[string]any{"detail": fwDetail(lang, fw), "iface": s.Iface})
		}
		if v := firstLine("/proc/sys/net/ipv4/ip_forward"); v == "1" {
			add("firewall", "forward", "ok", "forward.ok", nil)
		} else {
			add("firewall", "forward", "fail", "forward.off", nil, "echo net.ipv4.ip_forward=1 | sudo tee /etc/sysctl.d/99-kut.conf && sudo sysctl --system")
		}
		if s.v6On() {
			if v := firstLine("/proc/sys/net/ipv6/conf/all/forwarding"); v == "1" {
				add("firewall", "forward6", "ok", "forward6.ok", map[string]any{"prefix": s.prefix6().String()})
			} else {
				add("firewall", "forward6", "fail", "forward6.off", nil)
			}
			if ok, _ := hostV6Route(); ok {
				add("firewall", "route6", "ok", "route6.ok", nil)
			} else {
				add("firewall", "route6", "info", "route6.none", nil)
			}
		}
		if out, err := run(3*time.Second, "iptables", "-V"); err == nil {
			add("firewall", "backend", "info", "backend.ok", map[string]any{"version": strings.TrimSpace(string(out))})
		} else {
			add("firewall", "backend", "fail", "backend.missing", nil, "sudo apt install iptables")
		}
		udp := strconv.Itoa(s.Port) + "/udp"
		if _, err := exec.LookPath("ufw"); err != nil {
			add("firewall", "ufw", "info", "ufw.missing", nil)
		} else if out, err := run(5*time.Second, "ufw", "status"); err != nil {
			add("firewall", "ufw", "info", "ufw.unreadable", nil)
		} else {
			switch st := string(out); {
			case !strings.Contains(st, "Status: active"):
				add("firewall", "ufw", "info", "ufw.inactive", nil)
			case strings.Contains(st, udp):
				add("firewall", "ufw", "ok", "ufw.ok", map[string]any{"rule": udp})
			default:
				add("firewall", "ufw", "warn", "ufw.closed", map[string]any{"rule": udp}, "sudo ufw allow "+udp)
			}
		}
	}

	// ---- Ağ ----
	if lp, bad := overlapLocalExcept(s.prefix(), s.Iface); bad {
		add("network", "overlap", "fail", "overlap.fail", map[string]any{"net": s.prefix().String(), "local": lp})
	} else {
		add("network", "overlap", "ok", "overlap.ok", map[string]any{"net": s.prefix().String()})
	}
	if privateSubnet(s.prefix().Addr()) {
		add("network", "subnet", "ok", "subnet.ok", map[string]any{"net": s.prefix().String()})
	} else {
		add("network", "subnet", "warn", "subnet.warn", map[string]any{"net": s.prefix().String()})
	}
	switch addr, err := netip.ParseAddr(s.Endpoint); {
	case err == nil && (addr.IsLoopback() || addr.IsUnspecified()):
		add("network", "endpoint", "fail", "endpoint.local", map[string]any{"endpoint": s.Endpoint})
	case err == nil && isPrivateAddr(addr):
		add("network", "endpoint", "info", "endpoint.private", map[string]any{"endpoint": s.Endpoint})
	case err == nil:
		add("network", "endpoint", "ok", "endpoint.public", map[string]any{"endpoint": s.Endpoint})
	default:
		if hs, e := lookupHost(s.Endpoint); e != nil || len(hs) == 0 {
			add("network", "endpoint", "warn", "endpoint.unresolved", map[string]any{"endpoint": s.Endpoint})
		} else {
			add("network", "endpoint", "ok", "endpoint.resolved", map[string]any{"endpoint": s.Endpoint, "ip": hs[0]})
		}
	}
	host, _, _ := net.SplitHostPort(a.listen)
	switch pa, err := netip.ParseAddr(host); {
	case a.listen == "":
	case err == nil && pa.IsUnspecified():
		add("network", "panel", "fail", "panel.all", map[string]any{"listen": a.listen, "ip": s.serverIP().String()})
	case err == nil && pa.IsLoopback():
		add("network", "panel", "info", "panel.loopback", map[string]any{"listen": a.listen})
	case err == nil && s.prefix().Contains(pa):
		add("network", "panel", "ok", "panel.vpn", map[string]any{"listen": a.listen})
	default:
		add("network", "panel", "warn", "panel.other", map[string]any{"listen": a.listen})
	}

	// ---- Güvenlik ----
	var loose []string
	for _, f := range slices.Concat([]string{""}, backupFiles, []string{"maint.json", "backups"}) {
		fi, err := os.Stat(filepath.Join(a.dataDir, f))
		if err == nil && fi.Mode().Perm()&0o077 != 0 {
			if f == "" {
				f = T(lang, "report.data_dir_name", nil)
			}
			loose = append(loose, f)
		}
	}
	if len(loose) == 0 {
		add("security", "perms", "ok", "perms.ok", nil)
	} else {
		add("security", "perms", "warn", "perms.warn", map[string]any{"list": strings.Join(loose, ", ")}, "sudo chmod -R go-rwx "+a.dataDir)
	}
	var dests []string
	if s.cfg().UpdateCheck {
		dests = append(dests, T(lang, "report.dest.github", nil))
	}
	if nc := a.notif().get(); nc.Telegram.Enabled {
		dests = append(dests, T(lang, "report.dest.telegram", nil))
	}
	if nc := a.notif().get(); nc.Webhook.Enabled {
		h := nc.Webhook.URL
		if u, err := url.Parse(h); err == nil {
			h = u.Host
		}
		dests = append(dests, T(lang, "report.dest.webhook", map[string]any{"host": h}))
	}
	if len(dests) == 0 {
		add("security", "update", "ok", "update.none", nil)
	} else {
		add("security", "update", "info", "update.some", map[string]any{"list": strings.Join(dests, "; ")})
	}
	{
		bc := a.maintCfg().get().Backup
		switch {
		case !bc.Enabled:
			add("security", "backup", "warn", "backup.off", nil)
		case bc.LastErr != "":
			add("security", "backup", "warn", "backup.failed", map[string]any{"err": bc.LastErr, "dir": a.backupDir()})
		case bc.LastRun == 0:
			add("security", "backup", "info", "backup.never", nil)
		default:
			period := map[string]time.Duration{"daily": 24 * time.Hour, "weekly": 7 * 24 * time.Hour, "monthly": 31 * 24 * time.Hour}[bc.Freq]
			last := fmtTime(lang, time.Unix(bc.LastRun, 0), true)
			if time.Since(time.Unix(bc.LastRun, 0)) > 2*period+time.Hour {
				add("security", "backup", "warn", "backup.late", map[string]any{"time": last})
			} else {
				add("security", "backup", "ok", "backup.ok", map[string]any{"time": last, "dir": a.backupDir()})
			}
		}
	}
	if s.cfg().BlockPrivate {
		add("security", "private", "ok", "private.blocked", nil)
	} else {
		add("security", "private", "info", "private.open", nil)
	}

	// ---- Cihazlar ve erişim profilleri ----
	if len(peers) == 0 {
		add("devices", "none", "info", "none.info", nil)
	} else {
		var never, stale []string
		for _, p := range peers {
			if !p.Enabled {
				continue
			}
			ls := max(stats[p.PublicKey].Handshake, p.LastSeen)
			switch {
			case ls == 0:
				never = append(never, p.Name)
			case now.Unix()-ls > 7*86400:
				stale = append(stale, p.Name)
			}
		}
		if len(never) > 0 {
			add("devices", "never", "info", "never.info", map[string]any{"n": len(never), "list": strings.Join(never, ", ")})
		}
		if len(stale) > 0 {
			add("devices", "stale", "info", "stale.info", map[string]any{"n": len(stale), "list": strings.Join(stale, ", ")})
		}
		if len(never) == 0 && len(stale) == 0 {
			add("devices", "seen", "ok", "seen.ok", nil)
		}
	}
	idx := polIndex(pols)
	for _, pol := range pols {
		used := 0
		for _, p := range peers {
			if e, ok := effectivePolicy(p, idx); ok && p.Policy != "" && p.Policy == pol.ID || ok && p.Policy == "" && e.ID == pol.ID {
				used++
			}
		}
		if used > 0 && len(pol.Rules) == 0 {
			add("devices", "emptypol-"+pol.ID, "warn", "emptypol.warn", map[string]any{"name": pol.Name, "n": used})
		}
		if used == 0 {
			add("devices", "unusedpol-"+pol.ID, "info", "unusedpol.info", map[string]any{"name": pol.Name})
		}
	}
	for _, p := range peers {
		if p.Policy != "" {
			if _, ok := idx[p.Policy]; !ok {
				add("devices", "missingpol-"+p.ID, "fail", "missingpol.fail", map[string]any{"name": p.Name})
			}
		}
	}
	// Profilsiz cihazlar kapalıyken her zaman listelenir: yükseltmeden sonra cihazlar arası erişimin neden kesildiği görünsün.
	if len(pols) > 0 || !s.cfg().PeerFree {
		var free []string
		for _, p := range peers {
			if _, has := effectivePolicy(p, idx); !has {
				free = append(free, p.Name)
			}
		}
		if len(free) > 0 {
			key := "nopol.info"
			if s.cfg().PeerFree {
				key = "nopol.free"
			}
			add("devices", "nopol", "info", key, map[string]any{"n": len(free), "list": strings.Join(free, ", ")})
		}
	}

	rep := Report{Generated: now.Unix(), Checks: cs, Counts: map[string]int{"ok": 0, "warn": 0, "fail": 0, "info": 0}, Health: "ok"}
	for _, c := range cs {
		rep.Counts[c.Level]++
	}
	switch {
	case rep.Counts["fail"] > 0:
		rep.Health = "fail"
	case rep.Counts["warn"] > 0:
		rep.Health = "warn"
	}

	// ---- Yapı ----
	inet, withPol := 0, 0
	for _, p := range peers {
		if p.inetOn(now) && p.active(now) {
			inet++
		}
		if p.Policy != "" {
			withPol++
		}
	}
	rep.Structure = []kv{
		{T(lang, "report.structure.network", nil), s.prefix().String()},
		{T(lang, "report.structure.server_addr", nil), fmt.Sprintf("%s/%d", s.serverIP(), s.prefix().Bits())},
		{T(lang, "report.structure.endpoint", nil), s.endpoint()},
		{T(lang, "report.structure.iface", nil), s.Iface},
		{T(lang, "report.structure.panel", nil), a.listen},
		{T(lang, "report.structure.devices", nil), T(lang, "report.structure.devices_v", map[string]any{"n": len(peers), "active": activeN})},
		{T(lang, "report.structure.internet", nil), strconv.Itoa(inet)},
		{T(lang, "report.structure.profiles", nil), T(lang, "report.structure.profiles_n", map[string]any{"n": len(pols)}) + ", " + T(lang, "report.structure.assigned_n", map[string]any{"n": withPol})},
		{T(lang, "report.structure.data_format", nil), T(lang, "report.structure.schema_v", map[string]any{"n": currentSchema})},
	}

	// ---- Sistem ----
	host2, _ := os.Hostname()
	sys := []kv{
		{"Kut", version},
		{T(lang, "report.system.host", nil), host2},
		{T(lang, "report.system.os", nil), osPretty()},
		{T(lang, "report.system.kernel", nil), firstLine("/proc/sys/kernel/osrelease")},
		{T(lang, "report.system.arch", nil), runtime.GOOS + "/" + runtime.GOARCH},
		{"Go", runtime.Version()},
		{T(lang, "report.system.panel_uptime", nil), humanDur(lang, time.Since(a.started))},
	}
	if up := firstLine("/proc/uptime"); up != "" {
		if f, err := strconv.ParseFloat(strings.Fields(up)[0], 64); err == nil {
			sys = append(sys, kv{T(lang, "report.system.uptime", nil), humanDur(lang, time.Duration(f*float64(time.Second)))})
		}
	}
	sys = append(sys, kv{T(lang, "report.system.data_dir", nil), a.dataDir}, kv{T(lang, "report.system.conf", nil), s.ConfPath})
	rep.System = sys

	// ---- Erişim matrisi ----
	ordered := slices.Clone(peers)
	slices.SortStableFunc(ordered, func(a, b Peer) int { return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name)) })
	for _, p := range ordered {
		rep.Devices = append(rep.Devices, map[string]any{"id": p.ID, "name": p.Name, "ip": p.IP, "active": p.active(now)})
	}
	pp := a.panelPort()
	free := s.cfg().PeerFree
	off := T(lang, "report.matrix.off", nil)
	for _, src := range ordered {
		row := make([]matrixCell, 0, len(ordered)+1)
		for _, dst := range ordered {
			if src.ID == dst.ID {
				row = append(row, matrixCell{Result: "self"})
				continue
			}
			if !src.active(now) || !dst.active(now) {
				row = append(row, matrixCell{Result: "deny", Text: off})
				continue
			}
			res, txt := reachSummaryIn(lang, peers, pols, src, dst.ID, pp, free, now)
			row = append(row, matrixCell{Result: res, Text: txt})
		}
		if !src.active(now) {
			row = append(row, matrixCell{Result: "deny", Text: off})
		} else {
			res, txt := reachSummaryIn(lang, peers, pols, src, "server", pp, free, now)
			row = append(row, matrixCell{Result: res, Text: txt})
		}
		rep.Matrix = append(rep.Matrix, row)
	}
	return rep
}

func (a *App) handleReport(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.buildReport(a.reqLang(r)))
}

func lookupHost(h string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupHost(ctx, h)
}
