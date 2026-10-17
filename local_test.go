package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Kalıcı bir bağlantı hatası (izin) yeniden denemeyle düzelmez; istemci hemen dönmeli.
func TestLocalClientFailsFastOnPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root izin denetimine takılmaz")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, socketName)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.Chmod(sock, 0); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = newLocalClient(dir, cliLang(dir)).do("GET", "/api/status", nil, nil)
	if err == nil {
		t.Fatal("izinsiz sokete bağlanılmamalı")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("izin hatasında %v beklendi; yeniden denenmemeli", d)
	}
}
