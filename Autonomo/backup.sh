#!/usr/bin/env bash
# Rotina de backup do banco (agendar no cron, ex.: todo dia às 02h).
# Uso: GT_BACKUP_PASSWORD=... ./backup.sh
set -euo pipefail
DESTINO="${GT_BACKUP_DIR:-./backups}"
mkdir -p "$DESTINO"
ARQUIVO="$DESTINO/greythorns_$(date +%F).sql"
MYSQL_PWD="${GT_BACKUP_PASSWORD:?defina GT_BACKUP_PASSWORD}" \
  mysqldump --single-transaction -u gt_backup greythorns > "$ARQUIVO"
chmod 600 "$ARQUIVO"
echo "Backup gravado em $ARQUIVO"
