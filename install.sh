#!/usr/bin/env bash
# Kut kurulum sihirbazı — Ubuntu / Debian, root olarak.
#   sudo ./install.sh                    # soru-cevap ile kurar
#   sudo ./install.sh --endpoint 203.0.113.10 --yes     # sorusuz
#   sudo ./install.sh --uninstall [--purge] [--yes]      # kaldırır (kut uninstall ile aynı)
# İkili aynı betiği gömülü taşır: sudo ./kut-linux-amd64 install [aynı seçenekler]
# Var olan Kut ya da v0.3 (wireguard-gui) kurulumunun üstüne çalıştırılırsa yükseltir; anahtarlara ve cihazlara dokunmaz.
# Dil: --lang tr|en; verilmezse $LANG'tan (tr* → tr, değilse en). Etkileşimli kurulumda ilk soru dili onaylatır.
set -euo pipefail

ENDPOINT=""; PORT=51820; SUBNET="10.77.0.0/24"; IFACE="wg0"; YES=0; DEVICE=""
HERE="$(cd "$(dirname "$0")" && pwd)"
DATA=/var/lib/kut
OLD_DATA=/var/lib/wireguard-gui
ARCH="$(uname -m)"
case "$ARCH" in x86_64|amd64) A=amd64 ;; aarch64|arm64) A=arm64 ;; *) A="" ;; esac
BIN_SRC="${BIN_SRC:-$HERE/dist/kut-linux-${A}}"

# Kaldırma: mantık ikilidedir (kut uninstall); betik yalnızca uygun ikiliyi bulup çağırır.
if [[ "${1:-}" == "--uninstall" ]]; then
  shift
  if [[ -x /usr/local/bin/kut ]]; then exec /usr/local/bin/kut uninstall "$@"; fi
  if [[ -n "$A" && -f "$BIN_SRC" ]]; then exec "$BIN_SRC" uninstall "$@"; fi
  echo "kut binary not found (/usr/local/bin/kut, $BIN_SRC)" >&2; exit 1
fi

# ---- Dil ----
# KLANG: tüm iletilerin dili. Önce $LANG'tan, --lang verilirse ondan (LANG_SET=1 ilk soruyu atlatır).
case "${LANG:-}" in tr*) KLANG="tr" ;; *) KLANG="en" ;; esac
LANG_SET=0

# msg <anahtar> [değer...]: iletiyi KLANG dilinde yazar ve satır sonu ekler. Değerler yalnızca %s ile biçime girer.
msg() {
  local k="$1" fmt; shift
  case "$KLANG" in
    tr)
      case "$k" in
        usage_head) fmt='Kut kurulum sihirbazı — Ubuntu / Debian, root olarak.\n  sudo ./install.sh                    # soru-cevap ile kurar\n  sudo ./install.sh --endpoint 203.0.113.10 --yes     # sorusuz\nVar olan Kut ya da v0.3 (wireguard-gui) kurulumunun üstüne çalıştırılırsa yükseltir; anahtarlara ve cihazlara dokunmaz.' ;;
        usage_opts) fmt='Seçenekler: --endpoint X --port N --subnet CIDR --iface ADI --device ADI --lang tr|en --yes\nKaldırma: --uninstall [--purge] [--yes] [--dry-run]' ;;
        bad_arg) fmt='bilinmeyen argüman: %s' ;;
        need_root) fmt='root olarak çalıştır: sudo %s' ;;
        debian_only) fmt='Bu betik yalnızca Debian/Ubuntu için.' ;;
        say_install) fmt='Kut kurulumu (%s)' ;;
        ifaces) fmt='Bu makinedeki ağ arayüzleri:' ;;
        endpoint_help1) fmt='Uç nokta: cihazların bu sunucuya bağlanırken kullanacağı genel IP veya alan adı.' ;;
        endpoint_help2) fmt="(Genel IP'ni hosting panelinden öğrenebilirsin. Sanal sunucuda ve yalnızca yerel ağda deniyorsan yukarıdaki yerel IP'yi yaz.)" ;;
        ask_endpoint) fmt='Uç nokta' ;;
        endpoint_required) fmt='Uç nokta gerekli (--endpoint).' ;;
        ask_port) fmt='WireGuard UDP portu' ;;
        net_help) fmt='VPN ağı: cihazlara verilecek özel adres aralığı. Evinizdeki/ofisinizdeki ağlarla çakışmamalı.' ;;
        ask_subnet) fmt='VPN alt ağı' ;;
        ask_iface) fmt='Arayüz adı' ;;
        ask_device) fmt='İlk cihazın adı (boş = sonra eklerim)' ;;
        device_default) fmt='telefon' ;;
        summary) fmt='Özet: uç nokta %s:%s/udp · ağ %s · arayüz %s · ilk cihaz %s' ;;
        none) fmt='yok' ;;
        ask_continue) fmt='Devam edilsin mi? (e/h)' ;;
        yes_default) fmt='e' ;;
        aborted) fmt='Vazgeçildi.' ;;
        migrate_found) fmt='v0.3 (wireguard-gui) kurulumu bulundu. Veriler %s -> %s taşınacak, cihazlar ve anahtarlar korunur.' ;;
        migrate_bak) fmt='Eski veri yedeği olarak %s kalır.' ;;
        upgrade_note) fmt='Mevcut Kut kurulumu yükseltilecek; veri ve anahtarlar korunur.' ;;
        say_packages) fmt='Paketler' ;;
        say_binary) fmt='Çalıştırılabilir dosya' ;;
        no_binary) fmt='Çalıştırılabilir dosya bulunamadı (%s) ve Go kurulu değil.' ;;
        say_migrate) fmt='Veri taşınıyor' ;;
        say_forward) fmt='IP yönlendirme' ;;
        say_server) fmt='Sunucu yapılandırması' ;;
        init_failed) fmt='Başlatılamadı; değerleri düzeltip tekrar dene.' ;;
        say_password) fmt='Yönetici parolası' ;;
        no_password) fmt='Parola yok. Servisi başlatmadan önce çalıştır: sudo kut passwd' ;;
        keep_password) fmt='Mevcut parola korunuyor.' ;;
        say_services) fmt='Servisler' ;;
        bad_iface) fmt="Geçersiz arayüz adı: '%s' (1-15 karakter; harf, rakam ve _ = + . - kullanılabilir)." ;;
        no_start) fmt='kut servisi parola ayarlanana kadar başlatılmadı.' ;;
        say_ufw) fmt='ufw: %s/udp açılıyor' ;;
        say_health) fmt='Sağlık denetimi' ;;
        doctor_warn) fmt='(Yukarıdaki uyarılara bak; panelde Durum raporu sekmesi aynı bilgiyi gösterir.)' ;;
        say_first) fmt='İlk cihaz: %s' ;;
        first_help) fmt='Telefonda WireGuard uygulamasından QR kodu okut. Yapılandırma %s dosyasına da yazıldı.' ;;
        add_failed) fmt='Cihaz eklenemedi; panelden ekleyebilirsin.' ;;
        finished) fmt='\nKurulum tamam.\n\n  Panel:  http://%s:%s   (yalnızca VPN içinden açılır)\n  Kontrol: sudo kut doctor      Cihaz ekle: sudo kut add -name telefon' ;;
        finished_fresh) fmt="\n  Elle yapman gereken tek şey: sağlayıcının panelindeki güvenlik duvarında UDP %s'i aç.\n  (SSH tüneline gerek yok; ilk cihazı yukarıda terminalden ekledik. Bağlanınca panele yukarıdaki adresten girersin.)" ;;
        finished_migrate) fmt='\n  v0.3 verin %s içinde. Eski yedek: %s (her şey çalışıyorsa silebilirsin).\n  Cihazlarda hiçbir değişiklik gerekmez.' ;;
        *) fmt="$k" ;;
      esac ;;
    *)
      case "$k" in
        usage_head) fmt='Kut setup wizard — Ubuntu / Debian, as root.\n  sudo ./install.sh                    # installs interactively\n  sudo ./install.sh --endpoint 203.0.113.10 --yes     # unattended\nRun over an existing Kut or v0.3 (wireguard-gui) installation it upgrades it; keys and devices are left alone.' ;;
        usage_opts) fmt='Options: --endpoint X --port N --subnet CIDR --iface NAME --device NAME --lang tr|en --yes\nUninstall: --uninstall [--purge] [--yes] [--dry-run]' ;;
        bad_arg) fmt='unknown argument: %s' ;;
        need_root) fmt='run as root: sudo %s' ;;
        debian_only) fmt='This script is for Debian/Ubuntu only.' ;;
        say_install) fmt='Kut installation (%s)' ;;
        ifaces) fmt='Network interfaces on this machine:' ;;
        endpoint_help1) fmt='Endpoint: the public IP or domain name devices will use to reach this server.' ;;
        endpoint_help2) fmt="(You can find your public IP in your hosting panel. If you are only trying this on a virtual machine in a local network, enter the local IP shown above.)" ;;
        ask_endpoint) fmt='Endpoint' ;;
        endpoint_required) fmt='An endpoint is required (--endpoint).' ;;
        ask_port) fmt='WireGuard UDP port' ;;
        net_help) fmt='VPN network: the private address range handed out to devices. It must not overlap your home or office networks.' ;;
        ask_subnet) fmt='VPN subnet' ;;
        ask_iface) fmt='Interface name' ;;
        ask_device) fmt='Name of the first device (empty = I will add it later)' ;;
        device_default) fmt='phone' ;;
        summary) fmt='Summary: endpoint %s:%s/udp · network %s · interface %s · first device %s' ;;
        none) fmt='none' ;;
        ask_continue) fmt='Continue? (y/n)' ;;
        yes_default) fmt='y' ;;
        aborted) fmt='Aborted.' ;;
        migrate_found) fmt='Found a v0.3 (wireguard-gui) installation. Data will be moved %s -> %s; devices and keys are kept.' ;;
        migrate_bak) fmt='The old data stays behind as a backup at %s.' ;;
        upgrade_note) fmt='The existing Kut installation will be upgraded; data and keys are kept.' ;;
        say_packages) fmt='Packages' ;;
        say_binary) fmt='Executable' ;;
        no_binary) fmt='Executable not found (%s) and Go is not installed.' ;;
        say_migrate) fmt='Moving data' ;;
        say_forward) fmt='IP forwarding' ;;
        say_server) fmt='Server configuration' ;;
        init_failed) fmt='Could not initialise; fix the values and try again.' ;;
        say_password) fmt='Admin password' ;;
        no_password) fmt='No password set. Run this before starting the service: sudo kut passwd' ;;
        keep_password) fmt='Keeping the existing password.' ;;
        say_services) fmt='Services' ;;
        bad_iface) fmt="Invalid interface name: '%s' (1-15 characters; letters, digits and _ = + . - are allowed)." ;;
        no_start) fmt='The kut service was not started because no password is set yet.' ;;
        say_ufw) fmt='ufw: opening %s/udp' ;;
        say_health) fmt='Health check' ;;
        doctor_warn) fmt='(See the warnings above; the Status report tab in the panel shows the same information.)' ;;
        say_first) fmt='First device: %s' ;;
        first_help) fmt='Scan the QR code with the WireGuard app on your phone. The configuration was also written to %s.' ;;
        add_failed) fmt='Could not add the device; you can add it from the panel.' ;;
        finished) fmt='\nInstallation complete.\n\n  Panel:  http://%s:%s   (reachable only from inside the VPN)\n  Check: sudo kut doctor      Add a device: sudo kut add -name phone' ;;
        finished_fresh) fmt="\n  The only thing left to do by hand: open UDP %s in your provider's firewall panel.\n  (No SSH tunnel needed; the first device was added from the terminal above. Once connected, open the panel at the address above.)" ;;
        finished_migrate) fmt='\n  Your v0.3 data is in %s. Old backup: %s (you can delete it once everything works).\n  No changes are needed on the devices.' ;;
        *) fmt="$k" ;;
      esac ;;
  esac
  # shellcheck disable=SC2059  # fmt yukarıdaki sabit tablodan gelir; kullanıcı girdisi yalnızca %s değerleridir
  printf "$fmt\n" "$@"
}

usage() { msg usage_head; echo; msg usage_opts; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --port)     PORT="$2";     shift 2 ;;
    --subnet)   SUBNET="$2";   shift 2 ;;
    --iface)    IFACE="$2";    shift 2 ;;
    --device)   DEVICE="$2";   shift 2 ;;
    --lang)
      case "${2:-}" in
        tr|en) KLANG="$2"; LANG_SET=1; shift 2 ;;
        *) echo "--lang: tr | en" >&2; exit 2 ;;
      esac ;;
    --yes|-y)   YES=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) msg bad_arg "$1" >&2; usage >&2; exit 2 ;;
  esac
done
# Çağırdığımız kut komutları (init, passwd, doctor, add) çıktılarını aynı dilde yazsın.
export KUT_LANG="$KLANG"

[[ $EUID -eq 0 ]] || { msg need_root "${KUT_INSTALL_CMD:-$0}" >&2; exit 1; }
command -v apt-get >/dev/null || { msg debian_only >&2; exit 1; }
INTERACTIVE=0; [[ -t 0 && $YES -eq 0 ]] && INTERACTIVE=1

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ask()  { # ask "soru" "varsayılan" -> $REPLY
  local d="${2:-}"; read -r -p "$1${d:+ [$d]}: " REPLY || true; REPLY="${REPLY:-$d}"; }

# ---- Kurulum türü ----
MODE=fresh
if [[ -f "$DATA/server.json" ]]; then MODE=upgrade
elif [[ -f "$OLD_DATA/server.json" ]]; then MODE=migrate; fi
# Eski veri yedeği: önceki bir taşımadan kalan .bak varsa üzerine yazılmaz, zaman damgalı ad kullanılır.
OLD_BAK="$OLD_DATA.bak"
[[ -e "$OLD_BAK" ]] && OLD_BAK="$OLD_DATA.bak-$(date +%Y%m%d%H%M%S)"

# İlk soru dili onaylatır (--lang verilmediyse). Anlaşılmayan yanıtta algılanan dil kalır.
if [[ $MODE == fresh ]] && (( INTERACTIVE && ! LANG_SET )); then
  ask "Language / Dil (tr, en)" "$KLANG"
  case "$REPLY" in tr|en) KLANG="$REPLY"; export KUT_LANG="$KLANG" ;; esac
fi

# ---- İkili dosya ----
install_binary() {
  if [[ -n "$A" && -f "$BIN_SRC" ]]; then
    # `sudo kut install` kurulu ikiliden çalıştırıldıysa dosya kendi üstüne kopyalanmaz.
    if [[ -e /usr/local/bin/kut && "$(readlink -f "$BIN_SRC")" == "$(readlink -f /usr/local/bin/kut)" ]]; then return; fi
    install -m 0755 "$BIN_SRC" /usr/local/bin/kut
  elif command -v go >/dev/null; then
    (cd "$HERE" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /usr/local/bin/kut .)
  else
    msg no_binary "$BIN_SRC" >&2; exit 1
  fi
}

say "$(msg say_install "$MODE")"
if [[ $MODE == fresh ]]; then
  msg ifaces; (ip -4 -o addr show scope global 2>/dev/null | awk '{print "   "$2"  "$4}') || true
  if [[ -z "$ENDPOINT" ]]; then
    # Genel IP dışarıdan sorulmaz (üçüncü tarafa sunucu IP'si gitmez); kullanıcı yazar.
    if (( INTERACTIVE )); then
      echo; msg endpoint_help1
      msg endpoint_help2
      ask "$(msg ask_endpoint)" ""; ENDPOINT="$REPLY"
    fi
  fi
  [[ -n "$ENDPOINT" ]] || { msg endpoint_required >&2; exit 1; }
  if (( INTERACTIVE )); then
    ask "$(msg ask_port)" "$PORT"; PORT="$REPLY"
    echo; msg net_help
    ask "$(msg ask_subnet)" "$SUBNET"; SUBNET="$REPLY"
    ask "$(msg ask_iface)" "$IFACE"; IFACE="$REPLY"
    ask "$(msg ask_device)" "$(msg device_default)"; DEVICE="$REPLY"
    echo; msg summary "$ENDPOINT" "$PORT" "$SUBNET" "$IFACE" "${DEVICE:-$(msg none)}"
    ask "$(msg ask_continue)" "$(msg yes_default)"; [[ "$REPLY" =~ ^[eEyY] ]] || { msg aborted; exit 1; }
  fi
elif [[ $MODE == migrate ]]; then
  msg migrate_found "$OLD_DATA" "$DATA"
  msg migrate_bak "$OLD_BAK"
else
  msg upgrade_note
fi

say "$(msg say_packages)"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard iptables

say "$(msg say_binary)"
if [[ $MODE == migrate ]]; then
  systemctl stop wireguard-gui 2>/dev/null || true
  systemctl disable wireguard-gui 2>/dev/null || true
fi
install_binary

if [[ $MODE == migrate ]]; then
  say "$(msg say_migrate)"
  cp -a "$OLD_DATA" "$OLD_BAK"
  mkdir -p "$DATA"; chmod 700 "$DATA"
  cp -a "$OLD_DATA"/. "$DATA"/
  rm -f /etc/systemd/system/wireguard-gui.service /usr/local/bin/wireguard-gui
  rm -f /etc/sysctl.d/99-wireguard-gui.conf
  IFACE="$(sed -n 's/.*"iface": *"\([^"]*\)".*/\1/p' "$DATA/server.json" | head -1 || echo wg0)"
fi
if [[ $MODE == upgrade ]]; then
  IFACE="$(sed -n 's/.*"iface": *"\([^"]*\)".*/\1/p' "$DATA/server.json" | head -1 || echo "$IFACE")"
fi

IFACE="${IFACE:-wg0}"
say "$(msg say_forward)"
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-kut.conf
sysctl -q -w net.ipv4.ip_forward=1

if [[ $MODE == fresh ]]; then
  say "$(msg say_server)"
  while ! kut init -data "$DATA" -endpoint "$ENDPOINT" -port "$PORT" -subnet "$SUBNET" -iface "$IFACE" -lang "$KLANG"; do
    (( INTERACTIVE )) || exit 1
    msg init_failed
    ask "$(msg ask_subnet)" "$SUBNET"; SUBNET="$REPLY"
    ask "$(msg ask_iface)" "$IFACE"; IFACE="$REPLY"
  done
fi

say "$(msg say_password)"
if [[ ! -f "$DATA/admin.json" ]]; then
  if [[ -n "${KUT_PASSWORD:-}" || -t 0 ]]; then kut passwd -data "$DATA"
  else msg no_password >&2; fi
else msg keep_password; fi

say "$(msg say_services)"
# IFACE sed ifadesine ve unit dosyasına girer; server.json'dan okunan değer de dahil, kernel arayüz adı kuralıyla sınırla.
if [[ ! "$IFACE" =~ ^[A-Za-z0-9_=+.-]{1,15}$ ]]; then
  msg bad_iface "$IFACE" >&2; exit 1
fi
sed "s/__IFACE__/${IFACE}/g" "$HERE/kut.service" > /etc/systemd/system/kut.service
systemctl daemon-reload
if [[ $MODE == fresh ]]; then systemctl enable --now "wg-quick@${IFACE}"
else systemctl enable "wg-quick@${IFACE}" >/dev/null 2>&1 || true; systemctl start "wg-quick@${IFACE}" 2>/dev/null || true; fi
if [[ -f "$DATA/admin.json" ]]; then
  systemctl enable kut >/dev/null 2>&1
  rm -f "$DATA/kut.sock"
  systemctl restart kut
else
  msg no_start
fi

if [[ $MODE == fresh ]] && command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  say "$(msg say_ufw "$PORT")"
  # Kural önceden yoksa ekleyen Kut'tur: işaret dosyası kut uninstall'a yalnızca bu kuralı silmesini söyler.
  if ! ufw status | grep -qE "^${PORT}/udp[[:space:]]"; then
    ufw allow "${PORT}/udp" >/dev/null
    echo "$PORT" > "$DATA/ufw-port"; chmod 600 "$DATA/ufw-port"
  fi
fi

SIP="$(awk -F'[ =/]+' '/^Address/{print $2; exit}' "/etc/wireguard/${IFACE}.conf" 2>/dev/null || true)"
PPORT=5000

# ---- Sağlık ve ilk cihaz ----
if systemctl is-active --quiet kut; then
  for _ in 1 2 3 4 5 6 7 8 9 10; do [[ -S "$DATA/kut.sock" ]] && break; sleep 0.5; done
  say "$(msg say_health)"
  kut doctor -data "$DATA" || msg doctor_warn
  if [[ $MODE == fresh && -n "$DEVICE" ]]; then
    say "$(msg say_first "$DEVICE")"
    msg first_help "/root/${DEVICE// /_}.conf"
    kut add -data "$DATA" -name "$DEVICE" -o "/root/${DEVICE// /_}.conf" || msg add_failed
  fi
fi

msg finished "${SIP:-<VPN-IP>}" "$PPORT"
if [[ $MODE == fresh ]]; then
  msg finished_fresh "$PORT"
fi
if [[ $MODE == migrate ]]; then
  msg finished_migrate "$DATA" "${OLD_BAK}"
fi
