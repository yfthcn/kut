package main

// i18n: kullanıcıya görünen metinler web/locales/<dil>/*.json parçalarından gelir. Dosyalar ikiliye gömülüdür
// (webFS); tarayıcı birleşik kataloğu /locales/<dil>.json adresinden çeker. Tek kaynak, iki kullanıcı.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

const refLang = "en" // referans dil: eksik anahtar buna düşer

var langs = []string{"en", "tr"}

// catalogs: dil → düz anahtar ("login.submit") → metin.
var catalogs = mustLoadCatalogs(webFS)

func mustLoadCatalogs(fsys fs.FS) map[string]map[string]string {
	c, err := loadCatalogs(fsys)
	if err != nil {
		panic(err) // gömülü dosya bozuksa ikili hiç çalışmamalı; testler bunu yakalar
	}
	return c
}

// loadCatalogs: her dil için web/locales/<dil>/*.json parçalarını okuyup tek düz kataloğa birleştirir.
// Parçalar bölüm başına ayrıdır (aynı anda düzenlenebilsin diye); aynı anahtar iki parçada olamaz.
func loadCatalogs(fsys fs.FS) (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	for _, l := range langs {
		dir := "web/locales/" + l
		files, err := fs.Glob(fsys, dir+"/*.json")
		if err != nil {
			return nil, err
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s: katalog dosyası yok", dir)
		}
		flat := map[string]string{}
		for _, f := range files { // fs.Glob sıralı döner: sonuç dosya sırasından bağımsız ve tekrarlanabilir
			b, err := fs.ReadFile(fsys, f)
			if err != nil {
				return nil, err
			}
			var tree map[string]any
			if err := json.Unmarshal(b, &tree); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			part := map[string]string{}
			if err := flatten("", tree, part); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			for k, v := range part {
				if _, dup := flat[k]; dup {
					return nil, fmt.Errorf("%s: %q anahtarı başka bir parçada da var", f, k)
				}
				flat[k] = v
			}
		}
		out[l] = flat
	}
	return out, nil
}

// handleLocale: /locales/<dil>.json — dilin birleşik kataloğu (düz anahtarlar). Giriş ekranı da kullandığı için oturum istemez.
func handleLocale(w http.ResponseWriter, r *http.Request) {
	l := normLang(strings.TrimSuffix(r.PathValue("file"), ".json"))
	if l == "" || !strings.HasSuffix(r.PathValue("file"), ".json") {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, catalogs[l])
}

func flatten(prefix string, m map[string]any, out map[string]string) error {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch x := v.(type) {
		case string:
			out[key] = x
		case map[string]any:
			if err := flatten(key, x, out); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: değer metin ya da nesne olmalı", key)
		}
	}
	return nil
}

// normLang: "tr-TR" → "tr"; desteklenmeyen dil → "".
func normLang(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.IndexAny(s, "-_"); i >= 0 {
		s = s[:i]
	}
	for _, l := range langs {
		if s == l {
			return l
		}
	}
	return ""
}

// pluralCat: en ve tr için CLDR tamsayı kuralı (1 → one, gerisi other).
func pluralCat(n int) string {
	if n == 1 {
		return "one"
	}
	return "other"
}

var placeholderRe = regexp.MustCompile(`\{([a-z_]+)\}`)

// T: anahtarı dile çevirir, {ad} yer tutucularını params ile doldurur. params["n"] (int) varsa
// ve anahtar çoğul nesneyse uygun biçim seçilir. Eksik anahtar anahtarın kendisini döndürür.
func T(lang, key string, params map[string]any) string {
	if n, ok := params["n"].(int); ok {
		if _, plural := lookup(lang, key+".other"); plural {
			key += "." + pluralCat(n)
		}
	}
	s, ok := lookup(lang, key)
	if !ok {
		log.Printf("i18n: eksik anahtar %q", key) //nolint:gosec // G706: anahtar %q ile kaçışlı
		return key
	}
	return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		if v, ok := params[m[1:len(m)-1]]; ok {
			return fmt.Sprint(v)
		}
		return m
	})
}

func lookup(lang, key string) (string, bool) {
	if s, ok := catalogs[normLang(lang)][key]; ok {
		return s, true
	}
	s, ok := catalogs[refLang][key]
	return s, ok
}

// codedErr: kullanıcıya gidecek hata. Metin değil anahtar taşır; istemci err.<Code> anahtarını
// kendi dilinde yazar. Error() referans dilde (en) metin döndürür (günlük ve curl için).
type codedErr struct {
	Code   string
	Params map[string]any
}

func (e *codedErr) Error() string { return T(refLang, "err."+e.Code, e.Params) }

func ue(code string, params map[string]any) error { return &codedErr{Code: code, Params: params} }

// errCode: {"code","params","error"} yazar. "error" eski istemciler ve curl için İngilizce metindir.
func errCode(w http.ResponseWriter, status int, code string, params map[string]any) {
	writeJSON(w, status, map[string]any{"code": code, "params": params, "error": T(refLang, "err."+code, params)})
}

// errOf: err kodlu bir hataysa ({"code","params","error"}) onu, değilse düz metni yazar. Doğrulayıcılar ue(...)
// döndürdükçe işleyiciler errJSON(w, s, err.Error()) yerine bunu çağırır.
func errOf(w http.ResponseWriter, status int, err error) {
	var ce *codedErr
	if errors.As(err, &ce) {
		errCode(w, status, ce.Code, ce.Params)
		return
	}
	errJSON(w, status, err.Error())
}

// reqLang: sunucunun ürettiği ve tarayıcıda gösterilen metinlerin (rapor, erişim testi, önizleme…) dili.
// Arayüz her isteğe o anki dilini X-Kut-Lang ile ekler; yoksa hesap tercihi, o da yoksa sunucu dili.
func (a *App) reqLang(r *http.Request) string {
	if l := normLang(r.Header.Get("X-Kut-Lang")); l != "" {
		return l
	}
	if rec, _, ok := a.lookupUser(userOf(r)); ok {
		if l := normLang(rec.Lang); l != "" {
			return l
		}
	}
	return a.srvLang()
}

// cliLang: komut satırı çıktısının dili. KUT_LANG > LC_ALL > LC_MESSAGES > LANG > sunucu varsayılanı (veri
// dizinindeki server.json) > tr. Yerel ayar "C"/"POSIX" ise atlanır.
func cliLang(dataDir string) string {
	for _, k := range []string{"KUT_LANG", "LC_ALL", "LC_MESSAGES", "LANG"} {
		if l := normLang(os.Getenv(k)); l != "" {
			return l
		}
	}
	var s Server
	if dataDir != "" && loadJSON(serverPath(dataDir), &s) == nil {
		if l := normLang(s.cfg().Lang); l != "" {
			return l
		}
	}
	return "tr"
}

// fmtTime: sunucu tarafında üretilen zaman metni (rapor, bildirim, CLI). İstemci tarafı Intl kullanır.
func fmtTime(lang string, t time.Time, withYear bool) string {
	switch {
	case normLang(lang) == "en" && withYear:
		return t.Format("2006-01-02 15:04")
	case normLang(lang) == "en":
		return t.Format("Jan 2 15:04")
	case withYear:
		return t.Format("02.01.2006 15:04")
	default:
		return t.Format("02.01 15:04")
	}
}

// logReqT / logEventT: olayı katalog anahtarıyla yazar. Text sunucu dilinde üretilir (bildirim, dışa aktarma),
// Code + Params arayüzün olayı izleyenin dilinde göstermesi içindir. key "log." ile başlar.
func (a *App) logReqT(r *http.Request, kind, key string, params map[string]any) {
	a.act.add(Event{T: time.Now().Unix(), IP: clientIP(r), User: userOf(r), Kind: kind, Text: T(a.srvLang(), key, textParams(a.srvLang(), params)), Code: key, Params: params})
}

func (a *App) logEventT(ip, kind, key string, params map[string]any) {
	a.act.add(Event{T: time.Now().Unix(), IP: ip, Kind: kind, Text: T(a.srvLang(), key, textParams(a.srvLang(), params)), Code: key, Params: params})
}

// textParams: kayıtlı Text için ham rol kodunu (admin/viewer) lang dilindeki rol adına çevirir. Params ham kalır;
// arayüz olayı kendi dilinde çevirir.
func textParams(lang string, params map[string]any) map[string]any {
	role, ok := params["role"].(string)
	if !ok || (role != "admin" && role != "viewer") {
		return params
	}
	p := maps.Clone(params)
	p["role"] = T(lang, "settings.users.role_"+role, nil)
	return p
}
