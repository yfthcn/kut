package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// İki hesap aynı anda 2FA kurabilmeli: her biri kendi sırrıyla açar, biri ötekinin kurulumunu ezmez.
func TestTOTPSetupIsPerAccount(t *testing.T) {
	a, h := v5App(t)
	owner := login(h, "", "correct-horse-battery")
	post(h, "/api/users", `{"name":"bob","password":"bob-long-password","role":"admin"}`, owner)
	bob := login(h, "bob", "bob-long-password")

	setup := func(c *http.Cookie) string {
		t.Helper()
		rec := post(h, "/api/totp/setup", `{}`, c)
		var s struct{ Secret string }
		if err := json.Unmarshal(rec.Body.Bytes(), &s); err != nil || rec.Code != 200 || s.Secret == "" {
			t.Fatalf("setup: %d %s", rec.Code, rec.Body)
		}
		return s.Secret
	}
	ownerSec := setup(owner)
	bobSec := setup(bob) // sahibin bekleyen kurulumunu ezmemeli
	if ownerSec == bobSec {
		t.Fatal("iki hesap aynı sırrı aldı")
	}
	enable := func(c *http.Cookie, sec, pw string) int {
		code, _ := totpAt(sec, time.Now().Unix()/30)
		return post(h, "/api/totp/enable", `{"code":"`+code+`","password":"`+pw+`"}`, c).Code
	}
	if got := enable(owner, ownerSec, "correct-horse-battery"); got != 200 {
		t.Fatalf("sahip kendi sırrıyla açamadı: %d", got)
	}
	if got := enable(bob, bobSec, "bob-long-password"); got != 200 {
		t.Fatalf("bob kendi sırrıyla açamadı: %d", got)
	}
	if a.getAdmin().TOTPSecret != ownerSec {
		t.Fatal("sahibin kaydında yanlış sır")
	}
	if rec, _, _ := a.lookupUser("bob"); rec.TOTPSecret != bobSec {
		t.Fatal("bob'un kaydında yanlış sır")
	}
}

// Bir hesabın kurulumu bitince (clear) ya da süresi dolunca yalnızca o hesabın girdisi gider; süresi geçenler süpürülür.
func TestTOTPPendingSweepsExpired(t *testing.T) {
	var p totpPending
	p.set("a", "SA")
	p.set("b", "SB")
	if s, ok := p.get("a"); !ok || s != "SA" {
		t.Fatalf("a: %q %v", s, ok)
	}
	p.clear("a")
	if _, ok := p.get("a"); ok {
		t.Fatal("clear(a) sonrası a durmamalı")
	}
	if s, ok := p.get("b"); !ok || s != "SB" {
		t.Fatalf("clear(a) b'yi silmemeli: %q %v", s, ok)
	}
	// süresi dolan girdi okunmadan da set sırasında süpürülmeli (harita büyümesin)
	p.mu.Lock()
	p.m["gone"] = pendingTOTP{secret: "SG", exp: time.Now().Add(-time.Second)}
	p.m["gone2"] = pendingTOTP{secret: "SG", exp: time.Now().Add(-time.Second)}
	p.mu.Unlock()
	p.set("c", "SC")
	p.mu.Lock()
	n := len(p.m)
	p.mu.Unlock()
	if n != 2 { // b ve c
		t.Fatalf("süresi geçenler süpürülmedi: %d girdi", n)
	}
	if _, ok := p.get("gone"); ok {
		t.Fatal("süresi geçen kurulum kabul edildi")
	}
}

// apply başarısız olunca işleyici 500 döner, bellek değişmez ve geri alma da başarısızsa günlüğe yazılır.
func TestFailedApplyRollsBackAndLogs(t *testing.T) {
	a, h := v5App(t)
	c := login(h, "", "correct-horse-battery")
	blockFile(t, a.srv.ConfPath) // apply conf'u yazamaz; rollback'in apply'ı da aynı sebeple başarısız
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	rec := post(h, "/api/peers", `{"name":"tel"}`, c)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("durum: %d %s", rec.Code, rec.Body)
	}
	if len(a.peers) != 0 {
		t.Fatalf("başarısız apply bellekte iz bırakmamalı: %d cihaz", len(a.peers))
	}
	if !strings.Contains(buf.String(), "geri alma başarısız") {
		t.Fatalf("rollback hatası günlüğe yazılmadı: %q", buf.String())
	}
}

// rollback doğrudan: başarılıysa sessiz, başarısızsa tek satır günlük.
func TestRollbackLogsOnlyOnFailure(t *testing.T) {
	a := testApp(t)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	a.rollback()
	if buf.Len() != 0 {
		t.Fatalf("başarılı geri alma günlük yazmamalı: %q", buf.String())
	}
	blockFile(t, a.srv.ConfPath)
	a.rollback()
	if n := strings.Count(buf.String(), "geri alma başarısız"); n != 1 {
		t.Fatalf("başarısız geri alma tek satır yazmalı: %d\n%s", n, buf.String())
	}
}

// Yerel soketin izni ayarlanamazsa soket kapatılmalı ve dosyası kalmamalı (geniş izinli soket root yönetimini açardı).
func TestLocalSocketChmodFailureClosesSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "kut-sock") // unix soket yolu kısa olmalı: t.TempDir() uzun olabilir
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "k.sock")

	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	orig := chmodSocket
	t.Cleanup(func() { chmodSocket = orig })

	chmodSocket = func(string, os.FileMode) error { return errors.New("izin yok") }
	if ln := listenLocalSocket(sock); ln != nil {
		ln.Close()
		t.Fatal("chmod başarısızken dinleyici dönmemeli")
	}
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("soket dosyası kalmamalı: %v", err)
	}
	if !strings.Contains(buf.String(), "izni ayarlanamadı") {
		t.Fatalf("hata günlüğe yazılmalı: %q", buf.String())
	}

	chmodSocket = orig
	ln := listenLocalSocket(sock)
	if ln == nil {
		t.Fatal("chmod başarılıyken dinleyici dönmeli")
	}
	defer ln.Close()
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("soket izni 0600 olmalı: %v %v", fi, err)
	}
}
