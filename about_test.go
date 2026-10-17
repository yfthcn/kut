package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestUpdateCheckViewerForbidden(t *testing.T) {
	_, h, owner := maintApp(t)
	if r := post(h, "/api/users", `{"name":"ayse","password":"ayse-long-password","role":"viewer"}`, owner); r.Code != 200 {
		t.Fatalf("kullanıcı: %d %s", r.Code, r.Body.String())
	}
	v := login(h, "ayse", "ayse-long-password")
	if rc := post(h, "/api/update/check", `{}`, v); rc.Code != 403 {
		t.Fatalf("izleyici dış denetimi tetikleyememeli: %d", rc.Code)
	}
}

// Hakkında yanıtındaki gösterim metinleri (alt başlık, güncelleme denetimi hatası) isteği yapanın dilinde;
// önbellekteki sonuç dilden bağımsız (kod + parametre) saklanır.
func TestAboutTextsFollowRequestLang(t *testing.T) {
	a, h, owner := maintApp(t)
	a.upd.set(updateResult{CheckedAt: 1, Code: "update.http", Params: map[string]any{"status": 503}})
	for _, l := range []string{"en", "tr"} {
		rq := httptest.NewRequest(http.MethodGet, "/api/about", nil)
		rq.AddCookie(owner)
		rq.Header.Set("X-Kut-Lang", l)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, rq)
		var v struct {
			Tagline string
			Update  updateResult
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil || rr.Code != 200 {
			t.Fatalf("%s: %d %s", l, rr.Code, rr.Body)
		}
		if want := T(l, "login.subtitle", nil); v.Tagline != want {
			t.Errorf("%s alt başlık %q, beklenen %q", l, v.Tagline, want)
		}
		if want := T(l, "err.update.http", map[string]any{"status": 503}); v.Update.Error != want || v.Update.Code != "update.http" {
			t.Errorf("%s güncelleme hatası %+v, beklenen %q", l, v.Update, want)
		}
	}
}

func TestUpdateCheckThrottle(t *testing.T) {
	var u updateState
	t0 := time.Now()
	if _, limited := u.throttle(t0); limited {
		t.Fatal("ilk çağrı sınırlanmamalı")
	}
	u.set(updateResult{CheckedAt: t0.Unix(), Latest: "9.9.9"})
	if res, limited := u.throttle(t0.Add(29 * time.Second)); !limited || res.Latest != "9.9.9" {
		t.Fatalf("30 sn içinde önbellek dönmeli: %+v %v", res, limited)
	}
	if _, limited := u.throttle(t0.Add(31 * time.Second)); limited {
		t.Fatal("30 sn sonra yeni denetime izin verilmeli")
	}
}

// Marka dosyaları gömülü web/ altından doğru türle sunulur (nosniff açık; yanlış tür = tarayıcı reddeder).
func TestBrandAssetsContentType(t *testing.T) {
	_, h := v5App(t)
	for path, want := range map[string]string{
		"/favicon.svg":          "image/svg+xml",
		"/apple-touch-icon.png": "image/png",
		"/img/kut-mark.svg":     "image/svg+xml",
		"/img/kut-logo.svg":     "image/svg+xml",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != want {
			t.Errorf("%s: %d %q, beklenen 200 %q", path, rec.Code, rec.Header().Get("Content-Type"), want)
		}
	}
}
