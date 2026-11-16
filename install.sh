#!/usr/bin/env bash
# Fayl Audit Paneli - quraşdırma (Kali / Debian / Ubuntu)
# İstifadə: sudo bash install.sh [--watch QOVLUQ]... [--unwatch QOVLUQ]...
#   --watch /var/www     bu qovluğu da izlə (bir neçə dəfə yazmaq olar)
#   --unwatch /root      bu qovluğu izləmədən çıxar
# Yenidən quraşdıranda paneldən və ya --watch ilə seçilmiş qovluqlar saxlanılır.
set -euo pipefail

RULE_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --watch|--unwatch)
      [ $# -ge 2 ] || { echo "$1 üçün qovluq yazın, məsələn: $1 /var/www"; exit 1; }
      RULE_ARGS+=("$1" "$2"); shift 2 ;;
    *) echo "Naməlum seçim: $1  (istifadə: sudo bash install.sh [--watch QOVLUQ] [--unwatch QOVLUQ])"; exit 1 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Bu skripti sudo ilə işlədin:  sudo bash install.sh"
  exit 1
fi

cd "$(dirname "$0")"
for f in fileaudit.py fileaudit.rules fileaudit.service web/index.html; do
  [ -f "$f" ] || { echo "Fayl tapılmadı: $f (zip-i tam açdığınızdan əmin olun)"; exit 1; }
done

echo "[1/4] auditd quraşdırılır..."
if ! command -v auditctl >/dev/null 2>&1; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq auditd >/dev/null
fi
command -v python3 >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null
systemctl enable --now auditd >/dev/null 2>&1 || service auditd start

echo "[2/4] Audit qaydaları yüklənir..."
python3 fileaudit.py --install-rules fileaudit.rules ${RULE_ARGS[@]+"${RULE_ARGS[@]}"}
augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/fileaudit.rules >/dev/null

echo "[3/4] Proqram /opt/fileaudit qovluğuna köçürülür..."
mkdir -p /opt/fileaudit/web /var/lib/fileaudit
install -m 755 fileaudit.py /opt/fileaudit/fileaudit.py
install -m 644 web/index.html /opt/fileaudit/web/index.html
install -m 644 fileaudit.service /etc/systemd/system/fileaudit.service
[ -f /etc/fileaudit.env ] || install -m 600 /dev/null /etc/fileaudit.env
chmod 700 /var/lib/fileaudit

echo "[4/4] Xidmət işə salınır..."
systemctl daemon-reload
systemctl enable fileaudit >/dev/null 2>&1
systemctl restart fileaudit
sleep 2

if systemctl is-active --quiet fileaudit; then
  echo
  echo "Hazırdır! Brauzerdə açın:  http://127.0.0.1:8088"
  echo "İzlənən qovluqlar: $(auditctl -l | grep -oP '(?<=-w )\S+' | tr '\n' ' ')"
else
  echo "Xidmət başlamadı. Səbəbə baxın:  journalctl -u fileaudit -n 30"
  exit 1
fi
