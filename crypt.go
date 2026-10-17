package main

// Yedek şifreleme: parola → PBKDF2-HMAC-SHA256 → AES-256-GCM. Yalnızca standart kütüphane.
//
// Dosya biçimi:  "KUTENC1\n" | yineleme(4, BE) | tuz(16) | nonce(12) | şifreli veri+etiket
// Başlığın tamamı GCM'de ek doğrulanan veri (AAD) olarak korunur: başlık değiştirilirse çözme başarısız olur.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"unicode/utf8"
)

const (
	encMagic     = "KUTENC1\n"
	encIters     = 600_000
	encMaxIters  = 5_000_000 // bozuk/saldırgan başlığın CPU'yu tüketmesini engeller
	encSaltLen   = 16
	encHeaderLen = len(encMagic) + 4 + encSaltLen + 12
	minPassRunes = 8
	maxPassRunes = 200
)

var errNeedPass = ue("crypt.need_pass", nil)
var errBadPass = ue("crypt.bad_pass", nil)

func isEncrypted(b []byte) bool { return bytes.HasPrefix(b, []byte(encMagic)) }

func checkPass(p string) error {
	if n := utf8.RuneCountInString(p); n < minPassRunes || n > maxPassRunes || strings.ContainsAny(p, "\r\n") {
		return ue("crypt.pass_length", map[string]any{"min": minPassRunes, "max": maxPassRunes})
	}
	return nil
}

func deriveKey(pass string, salt []byte, iters int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pass, salt, iters, 32)
}

func encryptBackup(plain []byte, pass string) ([]byte, error) {
	salt := make([]byte, encSaltLen)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	key, err := deriveKey(pass, salt, encIters)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, 0, encHeaderLen)
	hdr = append(hdr, encMagic...)
	hdr = binary.BigEndian.AppendUint32(hdr, encIters)
	hdr = append(hdr, salt...)
	hdr = append(hdr, nonce...)
	return gcm.Seal(hdr, nonce, plain, hdr[:encHeaderLen-12]), nil
}

func decryptBackup(b []byte, pass string) ([]byte, error) {
	if !isEncrypted(b) || len(b) < encHeaderLen+16 {
		return nil, ue("crypt.bad_format", nil)
	}
	off := len(encMagic)
	iters := int(binary.BigEndian.Uint32(b[off : off+4]))
	if iters < 1000 || iters > encMaxIters {
		return nil, ue("crypt.bad_header", nil)
	}
	salt := b[off+4 : off+4+encSaltLen]
	nonce := b[encHeaderLen-12 : encHeaderLen]
	key, err := deriveKey(pass, salt, iters)
	if err != nil {
		return nil, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, b[encHeaderLen:], b[:encHeaderLen-12])
	if err != nil {
		return nil, errBadPass
	}
	return plain, nil
}
