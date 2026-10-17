package main

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

// Olay dosyasına yazılamazsa (disk dolu) satır sayılmamalı ve hata günlüğe düşmeli.
// /dev/full her yazmada ENOSPC döner: gerçek bir yazma hatası.
func TestActivityWriteFailureNotCounted(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Skip("/dev/full yok")
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	l := &activity{path: "/dev/full"}
	l.add(Event{T: 1, IP: "sistem", Kind: "test", Text: "x"})
	if l.lines != 0 {
		t.Errorf("yazılamayan olay sayıldı: lines=%d", l.lines)
	}
	if len(l.evs) != 1 {
		t.Errorf("olay bellekte kalmalı: %d", len(l.evs))
	}
	if !strings.Contains(buf.String(), "no space left on device") {
		t.Errorf("yazma hatası günlüğe yazılmalı, günlük: %q", buf.String())
	}
}
