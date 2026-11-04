#!/usr/bin/env sh
set -eu
url="http://127.0.0.1:${PORT:-8000}/health"
if command -v curl >/dev/null 2>&1; then
  curl --fail --silent --show-error --max-time 5 "$url" >/dev/null
else
  python -c "import urllib.request; urllib.request.urlopen('${url}', timeout=5).read()"
fi
