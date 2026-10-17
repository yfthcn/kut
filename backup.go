package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// ---- Panik koruması ----

// recoverer: bir isteğin içindeki beklenmedik panik tüm paneli düşürmesin.
func recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
					panic(v)
				}
				log.Printf("PANİK %s %q: %v\n%s", r.Method, r.URL.Path, v, debug.Stack()) //nolint:gosec // G706: yol %q ile kaçışlı; HTTP ayrıştırıcısı yönteme satır sonu izin vermez
				errCode(w, http.StatusInternalServerError, "maint.panic", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// safely: arka plan döngüsünde panik olursa günlüğe yazıp devam eder.
func safely(name string, f func()) {
	defer func() {
		if v := recover(); v != nil {
			log.Printf("PANİK (%s): %v\n%s", name, v, debug.Stack())
		}
	}()
	f()
}

// ---- Yedek ve geri yükleme ----

// Yedeğe giren dosyalar (sabit liste; geri yüklerken yalnızca bunlar kabul edilir).
var backupFiles = []string{"server.json", "peers.json", "policies.json", "admin.json", "users.json", "notify.json", "activity.jsonl"}

func cmdBackup(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("backup", lang)
	out := fs.String("o", "", T(lang, "cli.flag.backup_out", nil))
	encrypt := fs.Bool("encrypt", false, T(lang, "cli.flag.backup_encrypt", nil))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(serverPath(*data)); err != nil {
		return ue("clibackup.not_data_dir", map[string]any{"data": *data, "err": err.Error()})
	}
	name := *out
	if name == "" {
		name = "kut-yedek-" + time.Now().Format("20060102-150405") + ".tar.gz"
	}
	blob, n, err := buildBackup(*data)
	if err != nil {
		return err
	}
	if *encrypt {
		pass, err := cliBackupPass(lang, true)
		if err != nil {
			return err
		}
		if blob, err = encryptBackup(blob, pass); err != nil {
			return err
		}
		if *out == "" {
			name += ".enc"
		}
	}
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: çıktı yolunu kullanıcı komut satırında kendisi verir
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		_ = os.Remove(name) //nolint:gosec // G703: name kendi oluşturduğumuz geçici dosya (CLI, root)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println(T(lang, "cli.backup.written", map[string]any{"name": name, "n": n}))
	if *encrypt {
		fmt.Println(T(lang, "cli.backup.encrypted_note", nil))
	} else {
		fmt.Println(T(lang, "cli.backup.plain_warning", nil))
	}
	return nil
}

// cliBackupPass: parolayı KUT_BACKUP_PASSWORD'den ya da terminalden (lang dilinde sorarak) alır; confirm=true ise iki kez sorar.
func cliBackupPass(lang string, confirm bool) (string, error) {
	pass := os.Getenv("KUT_BACKUP_PASSWORD")
	if pass == "" {
		var err error
		if pass, err = readSecret(T(lang, "cli.backup.pass_prompt", nil)); err != nil {
			return "", err
		}
		if confirm {
			again, err := readSecret(T(lang, "cli.backup.pass_again", nil))
			if err != nil {
				return "", err
			}
			if again != pass {
				return "", ue("clibackup.pass_mismatch", nil)
			}
		}
	}
	if confirm {
		if err := checkPass(pass); err != nil {
			return "", err
		}
	}
	return pass, nil
}

func serviceRunning(dir string) bool {
	d := net.Dialer{Timeout: time.Second}
	c, err := d.DialContext(context.Background(), "unix", filepath.Join(dir, socketName))
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func cmdRestore(args []string) error {
	lang := argLang(args)
	fs, data := langFlags("restore", lang)
	file := fs.String("f", "", T(lang, "cli.flag.restore_file", nil))
	force := fs.Bool("force", false, T(lang, "cli.flag.restore_force", nil))
	endpoint := fs.String("endpoint", "", T(lang, "cli.flag.restore_endpoint", nil))
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *file == "" {
		return ue("clibackup.need_file", nil)
	}
	if serviceRunning(*data) {
		return ue("clibackup.service_running", nil)
	}
	if _, err := os.Stat(serverPath(*data)); err == nil && !*force {
		return ue("clibackup.not_empty", map[string]any{"data": *data})
	}
	raw, err := os.ReadFile(*file) //nolint:gosec // G703: -f yolu root çalıştıran operatörün CLI bayrağı
	if err != nil {
		return err
	}
	if isEncrypted(raw) {
		pass, err := cliBackupPass(lang, false)
		if err != nil {
			return err
		}
		if raw, err = decryptBackup(raw, pass); err != nil {
			return err
		}
	}
	got, err := parseBackup(raw)
	if err != nil {
		return err
	}
	if *endpoint != "" {
		if err := withEndpoint(got, *endpoint); err != nil {
			return ue("clibackup.bad_endpoint", map[string]any{"err": err}) // iç hata kodluysa cliErrText onu da lang diline çevirir
		}
	}
	if err := checkBackupConfPath(got); err != nil {
		return err
	}
	if err := os.MkdirAll(*data, 0o700); err != nil { //nolint:gosec // G703: -data yolu root çalıştıran operatörün CLI bayrağı
		return err
	}
	if err := applyBackupFiles(*data, got); err != nil {
		return err
	}
	fmt.Print(T(lang, "cli.restore.done", map[string]any{"n": len(got), "data": *data}))
	return nil
}
