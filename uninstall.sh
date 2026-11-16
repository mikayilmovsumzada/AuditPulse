#!/usr/bin/env bash
# Fayl Audit Paneli - silmək
# İstifadə: sudo bash uninstall.sh   (məlumat bazasını da silmək üçün: sudo bash uninstall.sh --hamisi)
set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Bu skripti sudo ilə işlədin:  sudo bash uninstall.sh"
  exit 1
fi

systemctl disable --now fileaudit >/dev/null 2>&1
rm -f /etc/systemd/system/fileaudit.service
systemctl daemon-reload
rm -f /etc/audit/rules.d/fileaudit.rules
augenrules --load >/dev/null 2>&1
rm -rf /opt/fileaudit
rm -f /etc/fileaudit.env  # panel parolu
[ "${1:-}" = "--hamisi" ] && rm -rf /var/lib/fileaudit

echo "Fayl Audit Paneli silindi. (auditd özü sistemdə qalır)"
