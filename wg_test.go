package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeWGTools: PATH'in başına sahte wg ve wg-quick koyar. Host'a dokunulmasın diye iptables/ip6tables/ip/sysctl
// de gölgelenir (hepsi başarısız). wg syncconf'un aldığı yol ve okuduğu içerik dir/arg ve dir/in'e yazılır.
func fakeWGTools(t *testing.T, stripScript string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write("wg", `if [ "$1" = show ] && [ "$3" = public-key ]; then echo PUB; exit 0; fi
if [ "$1" = syncconf ]; then printf '%s' "$3" > '`+dir+`/arg'; cat "$3" > '`+dir+`/in'; exit 0; fi
exit 1
`)
	write("wg-quick", stripScript)
	for _, n := range []string{"iptables", "iptables-restore", "ip6tables", "ip6tables-restore", "ip", "sysctl"} {
		write(n, "exit 1\n")
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return dir
}

// Ayıklanmış yapılandırma (özel anahtar dahil) diske geçici dosya olarak inmemeli: wg syncconf stdin'den okur.
func TestApplyFeedsSyncconfFromStdin(t *testing.T) {
	dir := fakeWGTools(t, `[ "$1" = strip ] && grep -v '^PostUp\|^PostDown\|^Address' "$2"
`)
	a := testApp(t)
	a.dry = false
	_ = a.apply([]Peer{{ID: "1", Name: "ali", PublicKey: "KEY", PSK: "PSK", IP: "10.77.0.2", Enabled: true}})
	arg, err := os.ReadFile(filepath.Join(dir, "arg"))
	if err != nil {
		t.Fatalf("wg syncconf çağrılmadı: %v", err)
	}
	if string(arg) != "/dev/stdin" {
		t.Errorf("wg syncconf yolu %q, beklenen /dev/stdin", arg)
	}
	in, _ := os.ReadFile(filepath.Join(dir, "in"))
	if !strings.Contains(string(in), "PrivateKey = x") || !strings.Contains(string(in), "PublicKey = KEY") || strings.Contains(string(in), "PostUp") {
		t.Errorf("syncconf'a giden içerik ayıklanmış yapılandırma değil:\n%s", in)
	}
}

// wg-quick strip başarısız olursa hata metni aracın stderr çıktısını taşımalı ("exit status 1" tek başına teşhis vermez).
func TestApplyStripErrorIncludesStderr(t *testing.T) {
	fakeWGTools(t, "echo \"wg-quick: '$2' does not exist\" >&2\nexit 1\n")
	a := testApp(t)
	a.dry = false
	err := a.apply(nil)
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("hata stderr içermeli: %v", err)
	}
}
