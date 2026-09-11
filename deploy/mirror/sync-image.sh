#!/usr/bin/env bash
# §mirror: раз в час тянем актуальный образ Ёžika из ghcr и публикуем его
# тарболом (docker save|gzip) в webroot зеркала resource.ecorp.red. bootstrap.sh
# устанавливаемого сервера при недоступности ghcr берёт образ отсюда
# (curl -C - | docker load), sha256 — для сверки целостности.
#
# Ставится на ХОСТ-зеркало (у хоста есть Docker), запускается cron'ом:
#   7 * * * * /opt/hedgehog-mirror/sync-image.sh >> /var/log/hh-mirror.log 2>&1
#
# Публично отдаёт файлы контейнер Caddy (см. Caddyfile), смонтировав OUT_DIR :ro.
set -euo pipefail

IMAGE="${HEDGEHOG_IMAGE:-ghcr.io/illiyanibl/hedgehog:latest}"
OUT_DIR="${MIRROR_DIR:-/srv/hedgehog-mirror}"
NAME="hedgehog-latest.tar.gz"

mkdir -p "$OUT_DIR"
log(){ echo "[$(date -u +%FT%TZ)] $*"; }

log "pull $IMAGE"
docker pull "$IMAGE"

tmp="$(mktemp -p "$OUT_DIR" .hedgehog.XXXXXX)"
trap 'rm -f "$tmp"' EXIT
log "save|gzip → $tmp"
docker save "$IMAGE" | gzip -9 > "$tmp"

sha="$(sha256sum "$tmp" | awk '{print $1}')"
# Атомарная публикация: mv в пределах ФС атомарен. Тарбол — первым, sha — следом
# (клиент при рассинхроне просто не сойдётся по sha и повторит/уйдёт на ghcr).
mv -f "$tmp" "$OUT_DIR/$NAME"
trap - EXIT
printf '%s  %s\n' "$sha" "$NAME" > "$OUT_DIR/$NAME.sha256"
chmod 644 "$OUT_DIR/$NAME" "$OUT_DIR/$NAME.sha256"

# Освобождаем диск от промежуточных слоёв старых образов (маленький VPS).
docker image prune -f >/dev/null 2>&1 || true

log "published $OUT_DIR/$NAME sha256=$sha size=$(du -h "$OUT_DIR/$NAME" | cut -f1)"
