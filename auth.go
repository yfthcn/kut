package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	pbkdf2Iter  = 600_000
	sessionTTL  = 12 * time.Hour
	maxFails    = 5
	failWindow  = time.Minute
	minPassword = 10
)

// adminRecord: parola PBKDF2-HMAC-SHA256 ile hash'lenir (stdlib, Go 1.24+).
type adminRecord struct {
	Salt string `json:"salt"`
	Hash string `json:"hash"`
	Iter int    `json:"iter"`
	// İki adımlı doğrulama (isteğe bağlı; boş = kapalı)
	TOTPSecret string   `json:"totp_secret,omitempty"`
	TOTPLast   int64    `json:"totp_last,omitempty"` // en son kabul edilen 30 sn'lik adım
	Recovery   []string `json:"recovery,omitempty"`  // kullanılmamış kurtarma kodlarının SHA-256 özetleri
	Lang       string   `json:"lang,omitempty"`      // panel dili tercihi (boş = tarayıcıya bırak)
}

func newAdmin(pw string) (adminRecord, error) {
	if utf8.RuneCountInString(pw) < minPassword {
		return adminRecord{}, ue("password.too_short", map[string]any{"min": minPassword})
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return adminRecord{}, err
	}
	h, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return adminRecord{}, err
	}
	return adminRecord{
		Salt: base64.StdEncoding.EncodeToString(salt),
		Hash: base64.StdEncoding.EncodeToString(h),
		Iter: pbkdf2Iter,
	}, nil
}

func (r adminRecord) verify(pw string) bool {
	salt, err1 := base64.StdEncoding.DecodeString(r.Salt)
	want, err2 := base64.StdEncoding.DecodeString(r.Hash)
	if err1 != nil || err2 != nil || r.Iter < 1000 || r.Iter > 10_000_000 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, r.Iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

// ---- Bellekte oturumlar (yeniden başlatınca hepsi düşer; çıkış hemen geçersiz kılar) ----

type sessEntry struct {
	exp  time.Time
	user string
}

type sessions struct {
	mu      sync.Mutex
	m       map[string]sessEntry
	streams map[string]int // hesap başına açık canlı akış (SSE) sayısı
}

func newSessions() *sessions { return &sessions{m: map[string]sessEntry{}, streams: map[string]int{}} }

func (s *sessions) create(user string) string {
	b := make([]byte, 32)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[tok] = sessEntry{exp: time.Now().Add(sessionTTL), user: user}
	s.mu.Unlock()
	return tok
}

func (s *sessions) user(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range s.m {
		if now.After(e.exp) {
			delete(s.m, k)
		}
	}
	e, ok := s.m[tok]
	return e.user, ok && now.Before(e.exp)
}

func (s *sessions) valid(tok string) bool { _, ok := s.user(tok); return ok }

// revokeUser: hesabın tüm oturumlarını düşürür (silme, rol/parola sıfırlama).
func (s *sessions) revokeUser(name string) {
	s.mu.Lock()
	for k, e := range s.m {
		if e.user == name {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

func (s *sessions) revoke(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// maxStreamsPerUser: hesap başına açık canlı akış sınırı (küresel sınır handleStream'de).
const maxStreamsPerUser = 3

// openStream: hesabın açık akışı sınırın altındaysa sayar ve true döner; her başarılı çağrı closeStream ister.
func (s *sessions) openStream(user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams[user] >= maxStreamsPerUser {
		return false
	}
	s.streams[user]++
	return true
}

func (s *sessions) closeStream(user string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams[user] <= 1 {
		delete(s.streams, user)
	} else {
		s.streams[user]--
	}
}

// revokeExcept: parola değişince hesabın mevcut oturum dışındaki oturumlarını düşürür.
func (s *sessions) revokeExcept(user, keep string) {
	s.mu.Lock()
	for k, e := range s.m {
		if k != keep && e.user == user {
			delete(s.m, k)
		}
	}
	s.mu.Unlock()
}

// ---- Giriş denemesi sınırlama (IP+hesap başına dakikada 5, hesap ve IP başına toplam 20 deneme) ----

type limiter struct {
	mu    sync.Mutex
	fails map[string][]time.Time
}

func newLimiter() *limiter { return &limiter{fails: map[string][]time.Time{}} }

func (l *limiter) prune(ip string) {
	cut := time.Now().Add(-failWindow)
	if len(l.fails) > 1024 { // çok sayıda IP birikti: süresi geçenleri topluca sil
		for k, ts := range l.fails {
			if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
				delete(l.fails, k)
			}
		}
	}
	keep := l.fails[ip][:0]
	for _, t := range l.fails[ip] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		delete(l.fails, ip)
	} else {
		l.fails[ip] = keep
	}
}

// Kova anahtarları: ip|kullanıcı (maxFails), hesabın küresel kovası (farklı IP'lerden aynı hesaba) ve IP'nin
// toplam kovası (aynı IP'den kullanıcı adı değiştirerek sınırsız PBKDF2 doğrulaması yaptırılamasın).
func pairKey(ip, user string) string { return ip + "|" + user }
func acctKey(user string) string     { return "user|" + user }
func ipKey(ip string) string         { return "ip|" + ip }

// backupPassBucket: yedek parolası denemelerinin allow/succeed'deki "kullanıcı" adı (kova ip|#backup-pass).
// '#' hesap adında olamaz (userRe): bir hesabın girişi bu kovayı sıfırlayamaz.
const backupPassBucket = "#backup-pass"

// allow: üç kovadan biri doluysa false; değilse denemeyi doğrulamadan ÖNCE üçüne de sayar (eşzamanlı istekler
// sınırı aşamaz).
func (l *limiter) allow(ip, user string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	p, u, i := pairKey(ip, user), acctKey(user), ipKey(ip)
	l.prune(p)
	l.prune(u)
	l.prune(i)
	if len(l.fails[p]) >= maxFails || len(l.fails[u]) >= maxFails*4 || len(l.fails[i]) >= maxFails*4 {
		return false
	}
	now := time.Now()
	for _, k := range []string{p, u, i} {
		l.fails[k] = append(l.fails[k], now)
	}
	return true
}

// succeed: başarı yalnızca kendi ip|kullanıcı kovasını sıfırlar; IP kovasından bu denemenin kaydını düşer.
// Hesabın küresel kovası zamanla boşalır (başka IP'lerden gelen denemeleri bir başarı silmesin).
func (l *limiter) succeed(ip, user string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, pairKey(ip, user))
	if ts := l.fails[ipKey(ip)]; len(ts) > 0 {
		l.fails[ipKey(ip)] = ts[:len(ts)-1]
	}
}
