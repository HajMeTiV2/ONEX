#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${ONEX_APP_DIR:-/opt/onex}"
REPO="${ONEX_REPO:-}"
PORT="${PORT:-8000}"
PYTHON="${PYTHON_BIN:-python3}"

if [[ $EUID -ne 0 ]]; then
  echo "Run as root, or set ONEX_APP_DIR to a writable directory." >&2
  exit 1
fi

command -v git >/dev/null || { echo "git is required"; exit 1; }
command -v "$PYTHON" >/dev/null || { echo "python3 is required"; exit 1; }

mkdir -p "$APP_DIR" "$APP_DIR/data" /etc/onex
if ! id onex >/dev/null 2>&1; then
  useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin onex
fi
if [[ -n "$REPO" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git clone --depth 1 "$REPO" "$tmp/src"
  rsync -a --delete --exclude data/ "$tmp/src/" "$APP_DIR/"
fi

cd "$APP_DIR"
"$PYTHON" -m venv .venv
".venv/bin/python" -m pip install --upgrade pip
".venv/bin/pip" install --no-cache-dir -r requirements.txt

cat > "$APP_DIR/.env" <<EOF
PORT=$PORT
DATA_DIR=$APP_DIR/data
PYTHONUNBUFFERED=1
EOF
chmod 600 "$APP_DIR/.env"
cp "$APP_DIR/.env" /etc/onex/onex.env
chown -R onex:onex "$APP_DIR"
install -m 0644 systemd/onex.service /etc/systemd/system/onex.service
systemctl daemon-reload
systemctl enable --now onex.service
systemctl --no-pager --full status onex.service || true
