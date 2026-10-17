package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Gerçek iptables'a karşı testler: her test kendi yalıtılmış ağ ad alanında çalışır (ana makineye dokunmaz).
// Root ve iptables gerekir; yoksa atlanır.
func inNetns(t *testing.T, f func()) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("root gerekir")
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		t.Skip("iptables yok")
	}
	if _, err := exec.LookPath("iptables-restore"); err != nil {
		t.Skip("iptables-restore yok")
	}
	var skip string
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // kilitli bırakılıp çıkılırsa iş parçacığı sonlanır: ad alanı sızmaz
		if err := syscall.Unshare(syscall.CLONE_NEWNET); err != nil {
			skip = "ağ ad alanı açılamadı: " + err.Error()
			return
		}
		f()
	}()
	<-done
	if skip != "" {
		t.Skip(skip)
	}
}

func sh(t *testing.T, script string) string {
	t.Helper()
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		t.Errorf("sh -c %q: %v\n%s", script, err, out)
	}
	return string(out)
}

func fwApp(t *testing.T) *App {
	a := testApp(t)
	a.dry = false
	a.listen = "10.77.0.1:5000"
	return a
}

func testPolicySet() ([]Peer, []Policy) {
	peers := []Peer{
		{ID: "a", Name: "ali", IP: "10.77.0.2", PublicKey: "A", Enabled: true, Internet: true, Policy: "adm"},
		{ID: "b", Name: "veli", IP: "10.77.0.3", PublicKey: "B", Enabled: true, Policy: "gst"},
		{ID: "c", Name: "ayse", IP: "10.77.0.4", PublicKey: "C", Enabled: true},
	}
	pols := []Policy{
		{ID: "adm", Name: "Yönetici", Rules: []Rule{
			{Target: "server", Proto: "tcp", Ports: "22,5000,8000-8100"},
			{Target: "server", Proto: "udp", Ports: "53"},
			{Target: "all", Proto: "any"},
		}},
		{ID: "gst", Name: "Misafir", Rules: []Rule{
			{Target: "server", Proto: "tcp", Ports: "5757"},
			{Target: "device", Device: "c", Proto: "tcp", Ports: "443", Both: true},
			{Target: "device", Device: "a", Proto: "icmp"},
			{Target: "server", Proto: "any"},
		}},
	}
	return peers, pols
}

func TestNetnsSyncAndVerify(t *testing.T) {
	inNetns(t, func() {
		a := fwApp(t)
		peers, pols := testPolicySet()
		if st := skeletonOK(a.srv); st.State == "ok" {
			t.Error("boş ad alanında iskelet olmamalı")
		}
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Errorf("syncFirewall: %v", err)
			return
		}
		if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
			t.Errorf("fwVerify: %+v\n%s", st, sh(t, "iptables -S; iptables -t nat -S"))
		}
		// ikinci kez: yinelenen kural oluşmamalı
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Errorf("ikinci sync: %v", err)
		}
		fw := sh(t, "iptables -S FORWARD")
		for _, j := range []string{"-j KUT-PEERS", "-j KUT-INET"} {
			if strings.Count(fw, j) != 1 {
				t.Errorf("%s tam bir kez olmalı:\n%s", j, fw)
			}
		}
		if u := untag(fw); strings.Count(u, "-i wg0 -j DROP") != 1 || strings.Count(u, "-i wg0 -o wg0 -j DROP") != 1 {
			t.Errorf("DROP kuralları tam birer kez olmalı:\n%s", fw)
		}
		// sıra
		lines := strings.Split(strings.TrimSpace(fw), "\n")
		// Satırlar birebir: iptables-nft'nin -S biçimi (conntrack seçenekleri sabit sırada) skeleton() ile aynı olmalı.
		wantOrder := []string{
			"-P FORWARD ACCEPT",
			`-A FORWARD ! -i wg0 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -m comment --comment "kut:skel:fwd-reply" -j ACCEPT`,
			`-A FORWARD -i wg0 -o wg0 -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m comment --comment "kut:skel:fwd-peer-reply" -j ACCEPT`,
			`-A FORWARD -i wg0 -o wg0 -p icmp -m conntrack --ctstate RELATED -m comment --comment "kut:skel:fwd-icmp" -j KUT-ICMP`,
			`-A FORWARD -i wg0 -o wg0 -m comment --comment "kut:skel:fwd-peers" -j KUT-PEERS`,
			`-A FORWARD -i wg0 -o wg0 -m comment --comment "kut:skel:fwd-peers-drop" -j DROP`,
			`-A FORWARD -i wg0 -m comment --comment "kut:skel:fwd-inet" -j KUT-INET`,
			`-A FORWARD -i wg0 -m comment --comment "kut:skel:fwd-in-drop" -j DROP`,
			`-A FORWARD -o wg0 -m comment --comment "kut:skel:fwd-out-drop" -j DROP`,
		}
		if len(lines) != len(wantOrder) {
			t.Errorf("FORWARD %d satır olmalı:\n%s", len(wantOrder), fw)
		}
		for i, w := range wantOrder {
			if i >= len(lines) || lines[i] != w {
				t.Errorf("FORWARD satır %d %q olmalı:\n%s", i, w, fw)
			}
		}
		if in := sh(t, "iptables -S INPUT"); !strings.Contains(strings.Split(in, "\n")[1], "-j KUT-IN") {
			t.Errorf("INPUT'un ilk kuralı KUT-IN olmalı:\n%s", in)
		}
		if l := strings.Split(sh(t, "iptables -S KUT-IN"), "\n"); len(l) < 2 || l[1] != `-A KUT-IN -m conntrack --ctstate ESTABLISHED --ctdir REPLY -m comment --comment "kut:in:est-reply" -j ACCEPT` {
			t.Errorf("KUT-IN'in ilk kuralı yalnızca yanıt yönünü kabul etmeli:\n%s", strings.Join(l, "\n"))
		} else if len(l) < 3 || l[2] != `-A KUT-IN -p icmp -m conntrack --ctstate RELATED -m comment --comment "kut:in:icmp-related" -j KUT-ICMP` {
			t.Errorf("KUT-IN'in ikinci kuralı akışla ilgili ICMP hatalarını kabul etmeli:\n%s", strings.Join(l, "\n"))
		}
		// beklenen birkaç somut kural gerçekten çekirdekte
		peersChain := untag(sh(t, "iptables -S KUT-PEERS"))
		for _, w := range []string{"-s 10.77.0.3/32 -d 10.77.0.4/32 -p tcp -m tcp --dport 443 -j ACCEPT", "-s 10.77.0.4/32 -d 10.77.0.3/32 -p tcp -m tcp --dport 443 -j ACCEPT"} { // profilsiz c: yalnızca karşılıklı kuralın geri yönü
			if !strings.Contains(peersChain, w) {
				t.Errorf("KUT-PEERS'te %q yok:\n%s", w, peersChain)
			}
		}
		inetOut := sh(t, "iptables -S KUT-INET")
		if strings.Contains(inetOut, "-j ACCEPT") {
			if c := readInetCounters(false); len(c) == 0 {
				t.Errorf("gerçek iptables çıktısından sayaç okunamadı:\n%s", sh(t, "iptables -nvxL KUT-INET"))
			}
		}
		inChain := untag(sh(t, "iptables -S KUT-IN"))
		for _, w := range []string{"--dport 8000:8100 -j ACCEPT", "-p udp -m udp --dport 53 -j ACCEPT", "-s 10.77.0.3/32 -j ACCEPT", "--icmp-type 8"} {
			if !strings.Contains(inChain, w) {
				t.Errorf("KUT-IN'de %q yok:\n%s", w, inChain)
			}
		}
	})
}

func TestNetnsDetectsAndRepairsDrift(t *testing.T) {
	inNetns(t, func() {
		a := fwApp(t)
		peers, pols := testPolicySet()
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Error(err)
			return
		}
		// 1) KUT-PEERS'ten bir kural silinirse uyuşmazlık görülmeli
		sh(t, "iptables -D KUT-PEERS 1")
		if st := a.fwVerify(a.srv, peers, pols); st.State != "out-of-sync" {
			t.Errorf("out-of-sync beklenirdi: %+v", st)
		}
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Error(err)
		}
		if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
			t.Errorf("onarım sonrası ok beklenirdi: %+v", st)
		}
		// 2) başka bir araç (docker gibi) FORWARD'ın en üstüne kural eklerse iskelet bozuk görülmeli, sonra düzelmeli
		sh(t, "iptables -N DOCKER-USER; iptables -I FORWARD 1 -j DOCKER-USER")
		if st := a.fwVerify(a.srv, peers, pols); st.State != "no-jump" {
			t.Errorf("no-jump beklenirdi: %+v", st)
		}
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Error(err)
		}
		if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
			t.Errorf("onarım sonrası ok beklenirdi: %+v\n%s", st, sh(t, "iptables -S FORWARD"))
		}
		fw := sh(t, "iptables -S FORWARD")
		if !strings.Contains(fw, "-j DOCKER-USER") {
			t.Error("yabancı kural silinmemeli")
		}
		if strings.Count(fw, "-j KUT-PEERS") != 1 {
			t.Errorf("KUT-PEERS atlaması çoğalmamalı:\n%s", fw)
		}
		// 3) iskelet silinirse (ör. wg-quick yeniden başladı ama panel kuralları yazmadı)
		sh(t, "iptables -D FORWARD -i wg0 -o wg0 -m comment --comment kut:skel:fwd-peers -j KUT-PEERS")
		if st := a.fwVerify(a.srv, peers, pols); st.State != "no-jump" {
			t.Errorf("no-jump beklenirdi: %+v", st)
		}
	})
}

// İskelet kuralı silinirse (elle `iptables -D`, başka bir aracın temizliği) izleyici bir sonraki turda onarmalı:
// "no-jump" da "out-of-sync" gibi yeniden yazılır. fwCheck arayüzün açık olmasını istediği için ad alanında
// gerçek bir wireguard arayüzü açılır; çekirdek modülü yoksa test atlanır.
func TestNetnsTickRepairsSkeleton(t *testing.T) {
	var noWG string
	inNetns(t, func() {
		if out, err := exec.Command("ip", "link", "add", "wg0", "type", "wireguard").CombinedOutput(); err != nil {
			noWG = "wireguard arayüzü açılamadı: " + strings.TrimSpace(string(out))
			return
		}
		a := fwApp(t)
		a.peers, a.pol = testPolicySet()
		if err := a.syncFirewall(a.srv, a.peers, a.pol); err != nil {
			t.Error(err)
			return
		}
		sh(t, "iptables -D FORWARD 1")
		if st := a.fwCheck(a.srv, a.peers, a.pol); st.State != "no-jump" {
			t.Errorf("iskelet bozukken no-jump beklenirdi: %+v", st)
		}
		a.tick()
		if st := a.fwCheck(a.srv, a.peers, a.pol); st.State != "ok" {
			t.Errorf("izleyici turu sonrası ok beklenirdi: %+v\n%s", st, sh(t, "iptables -S FORWARD"))
		}
		// FORWARD varsayılan politikası bilgi olarak raporlanır (yeni ad alanında ACCEPT).
		sh(t, "iptables -P FORWARD DROP")
		if st := a.fwCheck(a.srv, a.peers, a.pol); st.ForwardPolicy != "DROP" || st.Key != "fw.forward_policy" || st.Params["policy"] != "DROP" {
			t.Errorf("FORWARD politikası okunmalı: %+v", st)
		}
	})
	if noWG != "" {
		t.Skip(noWG)
	}
}

// v0.3'ten yükseltme: eski WGUI-* zincirleri ve "wg0 -> wg0 ACCEPT" kuralı temizlenmeli.
func TestNetnsUpgradeFromV03(t *testing.T) {
	inNetns(t, func() {
		a := fwApp(t)
		sh(t, `iptables -N WGUI-INET; iptables -t nat -N WGUI-NAT
iptables -I FORWARD 1 -i wg0 -j DROP
iptables -I FORWARD 1 -i wg0 -j WGUI-INET
iptables -I FORWARD 1 -i wg0 -o wg0 -j ACCEPT
iptables -I FORWARD 1 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -t nat -I POSTROUTING 1 -s 10.77.0.0/24 -j WGUI-NAT
iptables -A WGUI-INET -s 10.77.0.2/32 -j ACCEPT
iptables -t nat -A WGUI-NAT -s 10.77.0.2/32 ! -o wg0 -j MASQUERADE`)
		peers, pols := testPolicySet()
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Errorf("sync: %v", err)
			return
		}
		fw := sh(t, "iptables -S FORWARD")
		if strings.Contains(fw, "WGUI-") || strings.Contains(fw, "-i wg0 -o wg0 -j ACCEPT") {
			t.Errorf("eski kurallar kalmış:\n%s", fw)
		}
		if all := sh(t, "iptables -S; iptables -t nat -S"); strings.Contains(all, "WGUI-") {
			t.Errorf("eski zincirler kalmış:\n%s", all)
		}
		if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
			t.Errorf("yükseltme sonrası ok beklenirdi: %+v\n%s", st, fw)
		}
	})
}

// Yönsüz kısayollu (--ctdir'siz) eski iskeletten yükseltme, IPv4 ve IPv6: yeni iskelet en üste kurulur, eski
// yönsüz kısayolun FORWARD'daki bütün kopyaları silinir ve KUT-IN'de de yönsüz kural kalmaz. Sonuçta FORWARD
// birebir yeni iskelettir; kurulmuş akışları kabul eden tek kural REPLY yönlü olandır.
func TestNetnsUpgradeFromPreReplySkeleton(t *testing.T) {
	for _, fam := range []struct {
		bin, sub string
		v6       bool
	}{{"iptables", "10.77.0.0/24", false}, {"ip6tables", "fdaa:bbbb:cccc::/64", true}} {
		t.Run(fam.bin, func(t *testing.T) {
			inNetns(t, func() {
				if fam.v6 && !haveIP6Tables() {
					t.Skip("ip6tables yok")
				}
				old := hostSetup6Fn
				hostSetup6Fn = func(Server) error { return nil }
				defer func() { hostSetup6Fn = old }()
				a := fwApp(t)
				if fam.v6 {
					a.srv = v6Server(t)
				}
				undirected := "-o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
				sh(t, strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(`{bin} -N KUT-PEERS; {bin} -N KUT-IN; {bin} -N KUT-INET; {bin} -t nat -N KUT-NAT
{bin} -I FORWARD 1 -i wg0 -j DROP
{bin} -I FORWARD 1 -i wg0 -j KUT-INET
{bin} -I FORWARD 1 -i wg0 -o wg0 -j DROP
{bin} -I FORWARD 1 -i wg0 -o wg0 -j KUT-PEERS
{bin} -I FORWARD 1 -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
{bin} -A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
{bin} -A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED --ctdir REPLY -j ACCEPT
{bin} -A FORWARD -i wg0 -o wg0 -p {icmp} -m conntrack --ctstate RELATED -j ACCEPT
{bin} -A KUT-IN -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
{bin} -I INPUT 1 -i wg0 -j KUT-IN
{bin} -t nat -I POSTROUTING 1 -s {sub} -j KUT-NAT`, "{bin}", fam.bin), "{sub}", fam.sub), "{icmp}", map[bool]string{false: "icmp", true: "ipv6-icmp"}[fam.v6]))
				if n := strings.Count(sh(t, fam.bin+" -S FORWARD"), undirected); n != 2 {
					t.Fatalf("düzenek: eski kısayoldan iki kopya olmalı, %d var", n)
				}
				peers, pols := testPolicySet()
				if err := a.syncFirewall(a.srv, peers, pols); err != nil {
					t.Error(err)
					return
				}
				if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
					t.Errorf("yükseltme sonrası ok beklenirdi: %+v", st)
				}
				fw := sh(t, fam.bin+" -S FORWARD")
				want := []string{"-P FORWARD ACCEPT"}
				for _, r := range skelGroup(skeleton("wg0", fam.sub), "filter", "FORWARD") {
					want = append(want, sLine("FORWARD", r))
				}
				if got := strings.Split(strings.TrimSpace(fw), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
					t.Errorf("FORWARD birebir yeni iskelet olmalı (eski yönsüz kısayol silinmeli):\n%s\n--- beklenen ---\n%s", fw, strings.Join(want, "\n"))
				}
				if in := sh(t, fam.bin+" -S KUT-IN"); strings.Contains(in, "--ctstate RELATED,ESTABLISHED -j ACCEPT") {
					t.Errorf("KUT-IN'de yönsüz kısayol kalmamalı:\n%s", in)
				}
			})
		})
	}
}

// v0.14 (etiketsiz) iskeletten v0.15'e geçiş, IPv4 ve IPv6: sonunda her atlamadan tam bir tane, etiketli, kalır.
func TestNetnsUpgradeFromV014Untagged(t *testing.T) {
	for _, fam := range []struct {
		bin, sub string
		v6       bool
	}{{"iptables", "10.77.0.0/24", false}, {"ip6tables", "fdaa:bbbb:cccc::/64", true}} {
		t.Run(fam.bin, func(t *testing.T) {
			inNetns(t, func() {
				if fam.v6 && !haveIP6Tables() {
					t.Skip("ip6tables yok")
				}
				old := hostSetup6Fn
				hostSetup6Fn = func(Server) error { return nil }
				defer func() { hostSetup6Fn = old }()
				a := fwApp(t)
				if fam.v6 {
					a.srv = v6Server(t)
				}
				sk := skeleton("wg0", fam.sub)
				var b strings.Builder
				for _, c := range filterChains {
					fmt.Fprintf(&b, "%s -N %s\n", fam.bin, c)
				}
				fmt.Fprintf(&b, "%s -t nat -N %s\n", fam.bin, chainNat)
				for _, r := range slices.Backward(sk) { // v0.14'ün PostUp'ı: aynı kurallar, yorumsuz
					fmt.Fprintf(&b, "%s %s-I %s 1 %s\n", fam.bin, tableArgs(r.table), r.chain, strings.Join(stripTag(r.args), " "))
				}
				sh(t, b.String())
				if st := skeletonOKF(map[bool]iptFn{false: ipt, true: ipt6}[fam.v6], sk, "x"); st.State == "ok" {
					t.Fatal("etiketsiz iskelet bozuk sayılmalı (yoksa geçiş hiç tetiklenmez)")
				}
				peers, pols := testPolicySet()
				if err := a.syncFirewall(a.srv, peers, pols); err != nil {
					t.Error(err)
					return
				}
				if st := a.fwVerify(a.srv, peers, pols); st.State != "ok" {
					t.Errorf("geçiş sonrası ok beklenirdi: %+v", st)
				}
				for _, g := range []struct{ table, chain, tflag string }{{"filter", "FORWARD", ""}, {"filter", "INPUT", ""}, {"nat", "POSTROUTING", "-t nat "}} {
					out := sh(t, fam.bin+" "+g.tflag+"-S "+g.chain)
					var want []string
					for _, r := range skelGroup(sk, g.table, g.chain) {
						want = append(want, sLine(g.chain, r))
					}
					var got []string
					for ln := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
						if strings.HasPrefix(ln, "-A ") {
							got = append(got, ln)
						}
					}
					if strings.Join(got, "\n") != strings.Join(want, "\n") {
						t.Errorf("%s birebir etiketli iskelet olmalı (tek kopya):\n%s\n--- beklenen ---\n%s", g.chain, out, strings.Join(want, "\n"))
					}
				}
			})
		})
	}
}

// wg-quick kancaları gerçekten çalıştırılıp idempotentliği ve temizliği doğrulanır.
func TestNetnsPostUpDown(t *testing.T) {
	inNetns(t, func() {
		a := fwApp(t)
		run := func(lines []string) {
			for _, l := range lines {
				sh(t, strings.ReplaceAll(l, "%i", "wg0"))
			}
		}
		run(postUp(a.srv))
		if st := skeletonOK(a.srv); st.State != "ok" {
			t.Errorf("PostUp sonrası iskelet tamam olmalı: %s\n%s", st.Detail, sh(t, "iptables -S FORWARD"))
		}
		run(postUp(a.srv)) // ikinci kez: kopya olmamalı
		if n := strings.Count(sh(t, "iptables -S FORWARD"), "-j KUT-PEERS"); n != 1 {
			t.Errorf("PostUp idempotent olmalı, KUT-PEERS atlaması %d kez", n)
		}
		// panel sonradan kuralları yazar; PostDown hepsini kaldırmalı
		peers, pols := testPolicySet()
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Error(err)
		}
		run(postDown(a.srv))
		all := sh(t, "iptables -S; iptables -t nat -S")
		if strings.Contains(all, "KUT-") {
			t.Errorf("PostDown sonrası Kut kuralı kalmamalı:\n%s", all)
		}
	})
}

// v0.14'ün etiketsiz iskeleti duruyorken (panel henüz geçiş yapmadan) arayüz kapanırsa yeni PostDown onu da kaldırır.
func TestNetnsPostDownRemovesUntagged(t *testing.T) {
	inNetns(t, func() {
		a := fwApp(t)
		for _, l := range postUp(a.srv) {
			sh(t, untag(strings.ReplaceAll(l, "%i", "wg0")))
		}
		if all := sh(t, "iptables -S; iptables -t nat -S"); strings.Contains(all, "kut:") || !strings.Contains(all, "-j KUT-PEERS") {
			t.Fatalf("düzenek: etiketsiz iskelet kurulmalıydı:\n%s", all)
		}
		for _, l := range postDown(a.srv) {
			sh(t, strings.ReplaceAll(l, "%i", "wg0"))
		}
		if all := sh(t, "iptables -S; iptables -t nat -S"); strings.Contains(all, "KUT-") {
			t.Errorf("PostDown sonrası Kut kuralı kalmamalı:\n%s", all)
		}
	})
}

func TestNetnsFailClosedWhenChainsEmpty(t *testing.T) {
	inNetns(t, func() {
		a := fwApp(t)
		for _, l := range postUp(a.srv) {
			sh(t, strings.ReplaceAll(l, "%i", "wg0"))
		}
		// Panel henüz hiçbir şey yazmadı: zincirler boş, cihazlar arası ve internet çıkışı kapalı olmalı.
		// (Kural var mı: wg0'dan gelip wg0'a giden trafik KUT-PEERS'e düşer, orada eşleşme yok, sonra DROP gelir.)
		// Başka arayüzden wg0'a giden yeni trafik de host politikasından bağımsız olarak en sonda düşer.
		fw := untag(sh(t, "iptables -S FORWARD"))
		lines := strings.Split(strings.TrimSpace(fw), "\n")
		if len(lines) < 9 || !strings.Contains(lines[5], "-i wg0 -o wg0 -j DROP") || !strings.Contains(lines[7], "-i wg0 -j DROP") || lines[8] != "-A FORWARD -o wg0 -j DROP" {
			t.Errorf("DROP kuralları beklenen yerde değil:\n%s", fw)
		}
		if n := strings.Count(sh(t, "iptables -S KUT-PEERS"), "-A KUT-PEERS"); n != 0 {
			t.Errorf("KUT-PEERS boş olmalı, %d kural var", n)
		}
		// Boş KUT-ICMP'den dönen ICMP hatası KUT-PEERS'e (boş), oradan DROP'a düşer: erişim açılmaz.
		if n := strings.Count(sh(t, "iptables -S KUT-ICMP"), "-A KUT-ICMP"); n != 0 {
			t.Errorf("KUT-ICMP boş olmalı, %d kural var", n)
		}
		_ = time.Now
	})
}

// ---- Gerçek trafikle davranış testleri ----
//
// Topoloji: testin ad alanı sunucudur (yönlendirici). "wg0" bir köprüdür; her cihaz kendi ad alanında, köprüye
// bağlı bir veth ucunda /32 adresle durur ve her şeyi sunucu üzerinden yönlendirir (cihazdan cihaza trafik de
// -i wg0 -o wg0 olarak FORWARD'dan geçer). iptables -i/-o arayüzü adıyla eşleştiği için köprü WireGuard
// arayüzünün yerini tutar; çekirdek modülü gerekmez. "lan0" arkasında 192.0.2.2 adresli bir dış makine vardır.
// Root yerine `unshare -rn` altında da çalışır.

func needTrafficTools(t *testing.T) {
	t.Helper()
	for _, b := range []string{"unshare", "nsenter", "socat", "ip", "ss", "sysctl"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skip(b + " yok")
		}
	}
}

// nsCmd: pid'in ağ ad alanında komut (pid 0: testin kendi ad alanı).
func nsCmd(pid int, args ...string) *exec.Cmd {
	if pid == 0 {
		return exec.Command(args[0], args[1:]...)
	}
	return exec.Command("nsenter", append([]string{"-t", strconv.Itoa(pid), "-n"}, args...)...)
}

// nsHost: kendi ağ ad alanında bekleyen bir süreç; ad alanına nsCmd ile girilir.
func nsHost(t *testing.T) int {
	cmd := exec.Command("unshare", "-n", "sleep", "120")
	if err := cmd.Start(); err != nil {
		t.Errorf("unshare: %v", err)
		return 0
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	self, _ := os.Readlink("/proc/thread-self/ns/net")
	for range 200 {
		if ns, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", cmd.Process.Pid)); err == nil && ns != self {
			return cmd.Process.Pid
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("unshare ad alanı açmadı")
	return 0
}

// trafficLab: devs (ad → IP) cihazlarını wg0 köprüsüne, "ext" dış makinesini lan0'a bağlar. Dönen: ad → pid.
func trafficLab(t *testing.T, devs map[string]string) map[string]int {
	// Yönlendirme yönlendiricide açık, ICMP yönlendirme (redirect) kapalı: cihazlar birbirine doğrudan gitmesin.
	sh(t, `ip link set lo up
sysctl -q -w net.ipv4.ip_forward=1 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.default.send_redirects=0
ip link add wg0 type bridge && ip addr add 10.77.0.1/24 dev wg0 && ip link set wg0 up
ip link add lan0 type veth peer name lanx && ip addr add 192.0.2.1/24 dev lan0 && ip link set lan0 up`)
	pids := map[string]int{}
	for name, ip := range devs {
		pid := nsHost(t)
		if pid == 0 {
			return nil
		}
		pids[name] = pid
		sh(t, fmt.Sprintf("ip link add v%s type veth peer name eth0 netns %d && ip link set v%s master wg0 up", name, pid, name))
		sh(t, fmt.Sprintf("nsenter -t %d -n sh -c 'ip link set lo up && ip link set eth0 up && ip addr add %s/32 dev eth0 && ip route add 10.77.0.1 dev eth0 && ip route add default via 10.77.0.1'", pid, ip))
	}
	ext := nsHost(t)
	if ext == 0 {
		return nil
	}
	pids["ext"] = ext
	sh(t, fmt.Sprintf("ip link set lanx netns %d", ext))
	sh(t, fmt.Sprintf("nsenter -t %d -n sh -c 'ip link set lo up && ip link set lanx up && ip addr add 192.0.2.2/24 dev lanx && ip route add default via 192.0.2.1'", ext))
	if t.Failed() {
		return nil
	}
	return pids
}

// recvLines: pid'in ad alanında TCP portu dinler; gelen her satır kanala düşer.
func recvLines(t *testing.T, pid, port int) <-chan string {
	return recvLinesOn(t, pid, port, "TCP-LISTEN")
}

// recvLinesOn: recvLines'ın socat adres türü verilebilen hâli (IPv6 için "TCP6-LISTEN").
func recvLinesOn(t *testing.T, pid, port int, listen string) <-chan string {
	ch := make(chan string, 16)
	cmd := nsCmd(pid, "socat", "-u", fmt.Sprintf("%s:%d,reuseaddr", listen, port), "STDOUT")
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		t.Errorf("dinleyici: %v", err)
		close(ch)
		return ch
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			ch <- sc.Text()
		}
	}()
	for range 200 { // dinlemeye başlamadan bağlanılırsa RST gelir
		if o, _ := nsCmd(pid, "ss", "-Hltn", fmt.Sprintf("sport = :%d", port)).Output(); len(strings.TrimSpace(string(o))) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return ch
}

// dialLines: pid'in ad alanından addr:port'a tek bir TCP bağlantısı açar; yazılan her satır aynı akışta,
// ORIGINAL yönde gider.
func dialLines(t *testing.T, pid int, addr string, port int) io.Writer {
	cmd := nsCmd(pid, "socat", "-u", "STDIN", fmt.Sprintf("TCP:%s:%d,connect-timeout=3", addr, port))
	in, err := cmd.StdinPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		t.Errorf("bağlantı: %v", err)
		return io.Discard
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return in
}

func gotLine(ch <-chan string, want string, d time.Duration) bool {
	timeout := time.After(d)
	for {
		select {
		case l, ok := <-ch:
			if !ok {
				return false
			}
			if l == want {
				return true
			}
		case <-timeout:
			return false
		}
	}
}

// Cihazdan cihaza kurulmuş bir akış, profil daraltılınca kesilmeli: ORIGINAL yöndeki sonraki paket
// FORWARD'ın başındaki conntrack kısayolundan geçmemeli, KUT-PEERS'te eşleşmeyip düşmeli.
func TestNetnsRevokedPeerFlowStops(t *testing.T) {
	needTrafficTools(t)
	inNetns(t, func() {
		pids := trafficLab(t, map[string]string{"a": "10.77.0.2", "b": "10.77.0.3"})
		if pids == nil {
			return
		}
		a := fwApp(t)
		peers := []Peer{
			{ID: "a", Name: "a", IP: "10.77.0.2", PublicKey: "A", Enabled: true, Policy: "pa"},
			{ID: "b", Name: "b", IP: "10.77.0.3", PublicKey: "B", Enabled: true, Policy: "pb"},
		}
		open := []Policy{{ID: "pa", Name: "A", Rules: []Rule{{Target: "device", Device: "b", Proto: "tcp", Ports: "7000"}}}, {ID: "pb", Name: "B"}}
		closed := []Policy{{ID: "pa", Name: "A"}, {ID: "pb", Name: "B"}}
		if err := a.syncFirewall(a.srv, peers, open); err != nil {
			t.Error(err)
			return
		}
		rx := recvLines(t, pids["b"], 7000)
		tx := dialLines(t, pids["a"], "10.77.0.3", 7000)
		_, _ = io.WriteString(tx, "1\n")
		if !gotLine(rx, "1", 3*time.Second) {
			t.Errorf("izinli akış kurulamadı (test düzeneği):\n%s", sh(t, "iptables -nvL FORWARD; iptables -nvL KUT-PEERS"))
			return
		}
		if err := a.syncFirewall(a.srv, peers, closed); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.WriteString(tx, "2\n")
		if gotLine(rx, "2", 2*time.Second) {
			t.Errorf("profil daraltıldıktan sonra kurulmuş akış sürmemeli:\n%s", sh(t, "iptables -nvL FORWARD"))
		}
	})
}

// Profili olmayan cihaz varsayılanda yalnızca sunucuya ulaşır: başka bir cihaza yeni bağlantı açamaz. Tek istisna,
// karşı cihazın profilindeki karşılıklı (Both) kuralın geri yönüdür. PeerFree açılınca v0.13 davranışı döner.
func TestNetnsUnprofiledIsolated(t *testing.T) {
	needTrafficTools(t)
	inNetns(t, func() {
		pids := trafficLab(t, map[string]string{"a": "10.77.0.2", "b": "10.77.0.3", "c": "10.77.0.4"})
		if pids == nil {
			return
		}
		a := fwApp(t)
		peers := []Peer{
			{ID: "a", Name: "a", IP: "10.77.0.2", PublicKey: "A", Enabled: true},
			{ID: "b", Name: "b", IP: "10.77.0.3", PublicKey: "B", Enabled: true},
			{ID: "c", Name: "c", IP: "10.77.0.4", PublicKey: "C", Enabled: true, Policy: "pc"},
		}
		pols := []Policy{{ID: "pc", Name: "C", Rules: []Rule{{Target: "device", Device: "a", Proto: "tcp", Ports: "7011", Both: true}}}}
		dump := "iptables -nvL FORWARD; iptables -nvL KUT-PEERS; iptables -nvL KUT-IN"
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Error(err)
			return
		}
		// izinli: sunucu (host güvenlik duvarı karar verir; ad alanında INPUT politikası ACCEPT) ve karşılıklı kuralın geri yönü
		rxS, rxC := recvLines(t, 0, 7012), recvLines(t, pids["c"], 7011)
		_, _ = io.WriteString(dialLines(t, pids["a"], "10.77.0.1", 7012), "s\n")
		_, _ = io.WriteString(dialLines(t, pids["a"], "10.77.0.4", 7011), "r\n")
		if !gotLine(rxS, "s", 3*time.Second) {
			t.Errorf("profilsiz cihaz sunucuya ulaşmalı:\n%s", sh(t, dump))
		}
		if !gotLine(rxC, "r", 3*time.Second) {
			t.Errorf("karşılıklı kuralın geri yönü profilsiz cihaza açık olmalı:\n%s", sh(t, dump))
		}
		// kapalı: profilsizden profilsize ve kural dışı porta
		rxB, rxC2 := recvLines(t, pids["b"], 7010), recvLines(t, pids["c"], 7013)
		_, _ = io.WriteString(dialLines(t, pids["a"], "10.77.0.3", 7010), "x\n")
		_, _ = io.WriteString(dialLines(t, pids["a"], "10.77.0.4", 7013), "y\n")
		if gotLine(rxB, "x", 2*time.Second) {
			t.Errorf("profilsiz cihaz başka bir cihaza ulaşmamalı:\n%s", sh(t, dump))
		}
		if gotLine(rxC2, "y", 300*time.Millisecond) {
			t.Errorf("karşılıklı kural yalnızca kendi portunu açmalı:\n%s", sh(t, dump))
		}
		// PeerFree: profilsiz cihazlar arası serbest
		fc := a.srv.cfg()
		fc.PeerFree = true
		a.srv.Settings = &fc
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Error(err)
			return
		}
		rxB2 := recvLines(t, pids["b"], 7014)
		_, _ = io.WriteString(dialLines(t, pids["a"], "10.77.0.3", 7014), "f\n")
		if !gotLine(rxB2, "f", 3*time.Second) {
			t.Errorf("PeerFree açıkken profilsiz cihazlar birbirine ulaşmalı:\n%s", sh(t, dump))
		}
	})
}

// Cihazdan sunucuya kurulmuş bir akış (SSH gibi), sunucu izni kalkınca kesilmeli (KUT-IN'in başındaki
// kısayol yalnızca yanıt yönünü kabul eder). Sunucunun cihaza açtığı bağlantı ise profil ne olursa olsun
// çalışmalı: cihazın yanıtları REPLY yönündedir.
func TestNetnsRevokedServerFlowStops(t *testing.T) {
	needTrafficTools(t)
	inNetns(t, func() {
		pids := trafficLab(t, map[string]string{"a": "10.77.0.2"})
		if pids == nil {
			return
		}
		a := fwApp(t)
		peers := []Peer{{ID: "a", Name: "a", IP: "10.77.0.2", PublicKey: "A", Enabled: true, Policy: "pa"}}
		open := []Policy{{ID: "pa", Name: "A", Rules: []Rule{{Target: "server", Proto: "tcp", Ports: "7002"}}}}
		closed := []Policy{{ID: "pa", Name: "A"}}
		if err := a.syncFirewall(a.srv, peers, open); err != nil {
			t.Error(err)
			return
		}
		rx := recvLines(t, 0, 7002)
		tx := dialLines(t, pids["a"], "10.77.0.1", 7002)
		_, _ = io.WriteString(tx, "1\n")
		if !gotLine(rx, "1", 3*time.Second) {
			t.Errorf("izinli akış kurulamadı (test düzeneği):\n%s", sh(t, "iptables -nvL INPUT; iptables -nvL KUT-IN"))
			return
		}
		if err := a.syncFirewall(a.srv, peers, closed); err != nil {
			t.Error(err)
			return
		}
		_, _ = io.WriteString(tx, "2\n")
		if gotLine(rx, "2", 2*time.Second) {
			t.Errorf("sunucu izni kalktıktan sonra kurulmuş akış sürmemeli:\n%s", sh(t, "iptables -nvL KUT-IN"))
		}
		// sunucudan cihaza (OUTPUT → cihaz, yanıt INPUT -i wg0): profil kapalıyken de çalışmalı
		rxA := recvLines(t, pids["a"], 7003)
		_, _ = io.WriteString(dialLines(t, 0, "10.77.0.2", 7003), "s\n")
		if !gotLine(rxA, "s", 3*time.Second) {
			t.Errorf("sunucunun cihaza açtığı bağlantı kurulamadı (yanıt yönü kabul edilmeli):\n%s", sh(t, "iptables -nvL KUT-IN"))
		}
	})
}

// Başka bir arayüzden (lan0) wg0'daki cihaza yeni bağlantı, host'un FORWARD politikası ACCEPT olsa da düşmeli.
// İnternet izinli cihazın dışarı açtığı bağlantı (NAT'lı yanıtlarıyla) çalışmaya devam etmeli.
func TestNetnsForwardDropsForeignToWG(t *testing.T) {
	needTrafficTools(t)
	inNetns(t, func() {
		pids := trafficLab(t, map[string]string{"a": "10.77.0.2"})
		if pids == nil {
			return
		}
		a := fwApp(t)
		peers := []Peer{{ID: "a", Name: "a", IP: "10.77.0.2", PublicKey: "A", Enabled: true, Internet: true}}
		if err := a.syncFirewall(a.srv, peers, nil); err != nil {
			t.Error(err)
			return
		}
		if p := forwardPolicyF(ipt); p != "ACCEPT" {
			t.Errorf("test ACCEPT politikasını varsayar, olan %q", p)
		}
		rxExt := recvLines(t, pids["ext"], 7004)
		_, _ = io.WriteString(dialLines(t, pids["a"], "192.0.2.2", 7004), "out\n")
		if !gotLine(rxExt, "out", 3*time.Second) {
			t.Errorf("internet izinli cihaz dışarı çıkabilmeli:\n%s", sh(t, "iptables -nvL FORWARD; iptables -t nat -nvL KUT-NAT"))
		}
		rxA := recvLines(t, pids["a"], 7005)
		_, _ = io.WriteString(dialLines(t, pids["ext"], "10.77.0.2", 7005), "in\n")
		if gotLine(rxA, "in", 3*time.Second) {
			t.Errorf("dış arayüzden wg0'a yeni bağlantı düşmeli:\n%s", sh(t, "iptables -nvL FORWARD"))
		}
	})
}

// ---- ICMP hata paketleri (PMTU) ----

// rawRecv: pid'in ad alanında ICMP (v6'da ICMPv6) ham soketi. Ham soket paketi yerel teslimde, yani INPUT
// süzgecinden geçtikten sonra görür: gelen bayt akışında bir işaretin bulunması paketin güvenlik duvarından
// geçip alıcıya ulaştığının kanıtıdır. Dönen fonksiyon işaretin d süresi içinde görülüp görülmediğini söyler.
func rawRecv(t *testing.T, pid int, v6 bool) func(marker string, d time.Duration) bool {
	addr := "IP4-RECV:1"
	if v6 {
		addr = "IP6-RECV:58"
	}
	cmd := nsCmd(pid, "socat", "-u", addr, "STDOUT")
	out, err := cmd.StdoutPipe()
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		t.Errorf("ham soket: %v", err)
		return func(string, time.Duration) bool { return false }
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	var mu sync.Mutex
	var buf bytes.Buffer
	go func() {
		b := make([]byte, 65536)
		for {
			n, err := out.Read(b)
			mu.Lock()
			buf.Write(b[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	for range 200 { // soket açılmadan gönderilen paket kaçar
		if o, _ := nsCmd(pid, "ss", "-Hwa").Output(); len(strings.TrimSpace(string(o))) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return func(marker string, d time.Duration) bool {
		for end := time.Now().Add(d); ; time.Sleep(20 * time.Millisecond) {
			mu.Lock()
			seen := bytes.Contains(buf.Bytes(), []byte(marker))
			mu.Unlock()
			if seen || time.Now().After(end) {
				return seen
			}
		}
	}
}

// sendICMP: pid'in ad alanından dst'ye ham ICMP/ICMPv6 iletisi (IP başlığını çekirdek yazar; ICMPv6 sağlama
// toplamını da çekirdek doldurur).
func sendICMP(t *testing.T, pid int, dst netip.Addr, msg []byte) {
	addr := fmt.Sprintf("IP4-SENDTO:%s:1", dst)
	if dst.Is6() {
		addr = fmt.Sprintf("IP6-SENDTO:[%s]:58", dst)
	}
	cmd := nsCmd(pid, "socat", "-u", "STDIN", addr)
	cmd.Stdin = bytes.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("ICMP gönderilemedi: %v\n%s", err, out)
	}
}

func inetSum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xffff + s>>16
	}
	return ^uint16(s)
}

// icmpTooBig: src:sport → dst:dport TCP paketine dönen "fragmentation needed" (v4: tip 3 kod 4) ya da
// "packet too big" (v6: tip 2) iletisi; gövdede o paketin IP başlığı + ilk 8 baytı ve sonunda işaret durur.
// conntrack iletiyi gövdedeki paketin akışıyla ilişkilendirir (RELATED).
func icmpTooBig(src, dst netip.Addr, sport, dport uint16, marker string) []byte {
	var inner []byte
	if src.Is4() {
		inner = make([]byte, 20, 28)
		inner[0] = 0x45
		binary.BigEndian.PutUint16(inner[2:], 1420)
		binary.BigEndian.PutUint16(inner[6:], 0x4000) // DF
		inner[8], inner[9] = 64, 6
		copy(inner[12:16], src.AsSlice())
		copy(inner[16:20], dst.AsSlice())
		binary.BigEndian.PutUint16(inner[10:], inetSum(inner))
	} else {
		inner = make([]byte, 40, 48)
		inner[0] = 0x60
		binary.BigEndian.PutUint16(inner[4:], 1400)
		inner[6], inner[7] = 6, 64
		copy(inner[8:24], src.AsSlice())
		copy(inner[24:40], dst.AsSlice())
	}
	inner = binary.BigEndian.AppendUint16(inner, sport)
	inner = binary.BigEndian.AppendUint16(inner, dport)
	inner = append(inner, 0, 0, 0, 1)           // sıra numarası (conntrack yalnızca portlara bakar)
	msg := []byte{3, 4, 0, 0, 0, 0, 0x05, 0x00} // v4: kod 4, sonraki atlama MTU'su 1280
	if src.Is6() {
		msg = []byte{2, 0, 0, 0, 0, 0, 0x05, 0x00} // v6: MTU 1280
	}
	msg = append(append(msg, inner...), marker...)
	if src.Is4() {
		binary.BigEndian.PutUint16(msg[2:], inetSum(msg))
	}
	return msg
}

// icmpEcho: yeni bir ICMP akışı açan echo isteği (v4 tip 8, v6 tip 128), gövdesinde işaret.
func icmpEcho(v6 bool, marker string) []byte {
	if v6 {
		return append([]byte{128, 0, 0, 0, 0x4b, 0x55, 0, 1}, marker...)
	}
	msg := append([]byte{8, 0, 0, 0, 0x4b, 0x55, 0, 1}, marker...)
	binary.BigEndian.PutUint16(msg[2:], inetSum(msg))
	return msg
}

// nsCmdOut: pid'in ad alanında komutu çalıştırıp çıktısını döndürür.
func nsCmdOut(t *testing.T, pid int, args ...string) string {
	out, err := nsCmd(pid, args...).CombinedOutput()
	if err != nil {
		t.Errorf("%v: %v\n%s", args, err, out)
	}
	return string(out)
}

// localPort: pid'in ad alanında peer'e (addr:port) kurulmuş TCP bağlantısının yerel portu.
func localPort(t *testing.T, pid int, peer netip.AddrPort) uint16 {
	out, _ := nsCmd(pid, "ss", "-Htn").Output()
	for ln := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(ln)
		for j := 1; j < len(f); j++ {
			if p, err := netip.ParseAddrPort(f[j]); err == nil && p == peer {
				if l, err := netip.ParseAddrPort(f[j-1]); err == nil {
					return l.Port()
				}
			}
		}
	}
	t.Errorf("%s ile kurulmuş bağlantı bulunamadı:\n%s", peer, out)
	return 0
}

// Kısıtlı bir cihazın kendi başlattığı akışla ilgili gönderdiği ICMP hata paketleri (ORIGINAL yönde RELATED:
// karşı tarafın büyük yanıtına "fragmentation needed" / "packet too big") karşıya ulaşmalı; yoksa yol MTU'su
// keşfi bozulur ve büyük yanıtlar sessizce kaybolur. Cihazdan cihaza (FORWARD) ve cihazdan sunucuya (KUT-IN),
// IPv4 ve IPv6. Bu kapı yeni bir ICMP akışı açmamalı: hiçbir akışla ilgisi olmayan bir hata iletisi ve profilde
// izni olmayan bir echo isteği düşmeli. Akışın tarafı olmayan üçüncü bir cihaz (c, profilsiz ve PeerFree: her yere serbest)
// akışın 5'lisini bilse bile ona sahte hata iletisi gönderememeli: ne başlatana (REPLY yönü), ne yanıtlayana ne de
// sunucuya (ORIGINAL yönü). Yanıtlayan tarafın (b) başlatana gönderdiği gerçek hata ise geçmeli.
func TestNetnsRelatedICMPErrors(t *testing.T) {
	needTrafficTools(t)
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			inNetns(t, func() {
				if v6 && !haveIP6Tables() {
					t.Skip("ip6tables yok")
				}
				if _, err := os.Stat("/proc/sys/net/ipv6"); v6 && err != nil {
					t.Skip("çekirdekte IPv6 yığını yok")
				}
				pids := trafficLab(t, map[string]string{"a": "10.77.0.2", "b": "10.77.0.3", "c": "10.77.0.4"})
				if pids == nil {
					return
				}
				a := fwApp(t)
				srvIP, aIP, bIP := netip.MustParseAddr("10.77.0.1"), netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("10.77.0.3")
				var cIP netip.Addr // yalnızca IPv6 düzeneğinde gerekir (IPv4 adresi trafficLab'de verilir)
				listen, dialFmt := "TCP-LISTEN", "%s"
				if v6 {
					old := hostSetup6Fn
					hostSetup6Fn = func(Server) error { return nil }
					defer func() { hostSetup6Fn = old }()
					a.srv = v6Server(t)
					srvIP, aIP, bIP, cIP = a.srv.ip6Of("10.77.0.1"), a.srv.ip6Of("10.77.0.2"), a.srv.ip6Of("10.77.0.3"), a.srv.ip6Of("10.77.0.4")
					listen, dialFmt = "TCP6-LISTEN", "[%s]"
					sh(t, fmt.Sprintf("sysctl -q -w net.ipv6.conf.all.forwarding=1 && ip -6 addr add %s/64 dev wg0 nodad", srvIP))
					// WireGuard L3'tür, komşu keşfi (NDP) yoktur; köprü düzeneğinde ise NDP iletileri KUT-IN'in cihaz
					// DROP'una takılır. Komşular iki uçta da kalıcı yazılır ki yalnızca sınanan trafik süzgeçten geçsin.
					mac := func(pid int, dev string) string {
						f := strings.Fields(nsCmdOut(t, pid, "ip", "-br", "link", "show", dev))
						if len(f) < 3 {
							t.Fatalf("%s MAC adresi okunamadı: %q", dev, f)
						}
						return f[2]
					}
					srvMAC := mac(0, "wg0")
					for name, ip := range map[string]netip.Addr{"a": aIP, "b": bIP, "c": cIP} {
						sh(t, fmt.Sprintf("nsenter -t %d -n sh -c 'ip -6 addr add %s/128 dev eth0 nodad && ip -6 route add %s dev eth0 && ip -6 route add default via %s && ip -6 neigh replace %s lladdr %s dev eth0 nud permanent'", pids[name], ip, srvIP, srvIP, srvIP, srvMAC))
						sh(t, fmt.Sprintf("ip -6 neigh replace %s lladdr %s dev wg0 nud permanent", ip, mac(pids[name], "eth0")))
					}
				}
				bin := map[bool]string{false: "iptables", true: "ip6tables"}[v6]
				dump := bin + " -nvL FORWARD; " + bin + " -nvL KUT-PEERS; " + bin + " -nvL KUT-IN; " + bin + " -nvL KUT-ICMP"
				peers := []Peer{
					{ID: "a", Name: "a", IP: "10.77.0.2", PublicKey: "A", Enabled: true, Policy: "pa"},
					{ID: "b", Name: "b", IP: "10.77.0.3", PublicKey: "B", Enabled: true, Policy: "pb"},
					{ID: "c", Name: "c", IP: "10.77.0.4", PublicKey: "C", Enabled: true},
				}
				pols := []Policy{{ID: "pa", Name: "A", Rules: []Rule{
					{Target: "device", Device: "b", Proto: "tcp", Ports: "7000"},
					{Target: "server", Proto: "tcp", Ports: "7002"},
				}}, {ID: "pb", Name: "B"}}
				fc := a.srv.cfg() // en kötü durum: saldıran cihazın KUT-PEERS'te her yere izni var
				fc.PeerFree = true
				a.srv.Settings = &fc
				if err := a.syncFirewall(a.srv, peers, pols); err != nil {
					t.Error(err)
					return
				}
				atA, atB, atSrv := rawRecv(t, pids["a"], v6), rawRecv(t, pids["b"], v6), rawRecv(t, 0, v6)
				// a'nın başlattığı iki izinli akış: b'ye ve sunucuya.
				rxB, rxS := recvLinesOn(t, pids["b"], 7000, listen), recvLinesOn(t, 0, 7002, listen)
				_, _ = io.WriteString(dialLines(t, pids["a"], fmt.Sprintf(dialFmt, bIP), 7000), "1\n")
				_, _ = io.WriteString(dialLines(t, pids["a"], fmt.Sprintf(dialFmt, srvIP), 7002), "1\n")
				if !gotLine(rxB, "1", 3*time.Second) || !gotLine(rxS, "1", 3*time.Second) {
					t.Errorf("izinli akışlar kurulamadı (test düzeneği):\n%s", sh(t, dump))
					return
				}
				pB := localPort(t, pids["a"], netip.AddrPortFrom(bIP, 7000))
				pS := localPort(t, pids["a"], netip.AddrPortFrom(srvIP, 7002))
				// Önce düşmesi gerekenler, sonra geçmesi gerekenler: aynı yoldan sonra gönderilen geçtiyse, öncekilerin
				// ulaşmaması gecikmeden değil düşürülmeden kaynaklanır.
				sendICMP(t, pids["a"], bIP, icmpTooBig(bIP, aIP, 7000, pB+1, "kut-unrelated-peer"))
				sendICMP(t, pids["a"], srvIP, icmpTooBig(srvIP, aIP, 7002, pS+1, "kut-unrelated-srv"))
				sendICMP(t, pids["a"], bIP, icmpEcho(v6, "kut-echo-peer"))
				sendICMP(t, pids["c"], bIP, icmpTooBig(bIP, aIP, 7000, pB, "kut-spoof-orig-peer"))
				sendICMP(t, pids["c"], srvIP, icmpTooBig(srvIP, aIP, 7002, pS, "kut-spoof-orig-srv"))
				sendICMP(t, pids["c"], aIP, icmpTooBig(aIP, bIP, pB, 7000, "kut-spoof-reply"))
				sendICMP(t, pids["b"], aIP, icmpTooBig(aIP, bIP, pB, 7000, "kut-related-reply"))
				sendICMP(t, pids["a"], bIP, icmpTooBig(bIP, aIP, 7000, pB, "kut-related-peer"))
				sendICMP(t, pids["a"], srvIP, icmpTooBig(srvIP, aIP, 7002, pS, "kut-related-srv"))
				if !atB("kut-related-peer", 3*time.Second) {
					t.Errorf("akışla ilgili ICMP hata iletisi cihazdan cihaza geçmeli (FORWARD):\n%s", sh(t, dump))
				}
				if !atSrv("kut-related-srv", 3*time.Second) {
					t.Errorf("akışla ilgili ICMP hata iletisi sunucuya ulaşmalı (KUT-IN):\n%s", sh(t, dump))
				}
				if !atA("kut-related-reply", 3*time.Second) {
					t.Errorf("yanıtlayan tarafın hata iletisi başlatana ulaşmalı (REPLY yönü):\n%s", sh(t, dump))
				}
				for _, m := range []struct {
					seen   func(string, time.Duration) bool
					marker string
				}{{atB, "kut-unrelated-peer"}, {atSrv, "kut-unrelated-srv"}, {atB, "kut-echo-peer"},
					{atB, "kut-spoof-orig-peer"}, {atSrv, "kut-spoof-orig-srv"}, {atA, "kut-spoof-reply"}} {
					if m.seen(m.marker, 300*time.Millisecond) {
						t.Errorf("%s düşmeliydi (akışla ilgisiz ya da akışın tarafı olmayandan gelen hata iletisi, ya da izinsiz yeni ICMP):\n%s", m.marker, sh(t, dump))
					}
				}
			})
		})
	}
}

// kut uninstall'un güvenlik duvarı temizliği gerçek iptables'ta: Kut'un her kuralı ve zinciri gider (IPv4+IPv6),
// yabancı kurallar kalır.
func TestNetnsUninstallFirewall(t *testing.T) {
	inNetns(t, func() {
		old := hostSetup6Fn
		hostSetup6Fn = func(Server) error { return nil }
		defer func() { hostSetup6Fn = old }()
		a := fwApp(t)
		a.srv = v6Server(t)
		peers, pols := testPolicySet()
		sh(t, "iptables -N DOCKER-USER; iptables -A FORWARD -j DOCKER-USER; iptables -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE")
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Fatal(err)
		}
		sh(t, "iptables -A FORWARD -i wg0 -j DROP") // v0.14'ten kalmış etiketsiz kopya
		p := planUninstall("/", t.TempDir(), false, time.Now())
		p.Iface, p.Sub, p.Sub6 = "wg0", a.srv.prefix().String(), a.srv.prefix6().String() // server.json'dan gelirdi
		removeKutFirewall(ipt, p.Iface, p.Sub)
		if haveIP6Tables() {
			removeKutFirewall(ipt6, p.Iface, p.Sub6)
		}
		all := sh(t, "iptables -S; iptables -t nat -S; ip6tables -S 2>/dev/null; ip6tables -t nat -S 2>/dev/null")
		if strings.Contains(all, "KUT-") || strings.Contains(all, "kut:") || strings.Contains(all, "wg0") {
			t.Errorf("Kut kuralı kaldı:\n%s", all)
		}
		for _, w := range []string{"-A FORWARD -j DOCKER-USER", "-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE"} {
			if !strings.Contains(all, w) {
				t.Errorf("yabancı kural silindi: %q\n%s", w, all)
			}
		}
	})
}

// Gerçek `iptables -L -v -x -n` çıktısından her Kut kuralının sayacı etiketiyle okunur (IPv4+IPv6).
func TestNetnsRuleCountersByTag(t *testing.T) {
	inNetns(t, func() {
		old := hostSetup6Fn
		hostSetup6Fn = func(Server) error { return nil }
		defer func() { hostSetup6Fn = old }()
		a := fwApp(t)
		a.srv = v6Server(t)
		peers, pols := testPolicySet()
		if err := a.syncFirewall(a.srv, peers, pols); err != nil {
			t.Fatal(err)
		}
		a.dry = false
		got := readRuleCounters(ipt, "ipv4", time.Now().Add(time.Minute))
		if haveIP6Tables() {
			for k, v := range readRuleCounters(ipt6, "ipv6", time.Now().Add(time.Minute)) {
				got[k] = v
			}
		}
		for _, r := range a.fwRules(a.srv, peers, pols, time.Now()) {
			if r.Family == "ipv6" && !haveIP6Tables() {
				continue
			}
			if _, ok := got[r.Key]; !ok {
				t.Errorf("sayaç okunamadı: %s", r.Key)
			}
		}
	})
}
