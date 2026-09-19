from pathlib import Path
import json

ROOT = Path(__file__).resolve().parents[1]
required = [
    ROOT / 'main.py',
    ROOT / 'version.json',
    ROOT / 'requirements.txt',
    ROOT / 'config/news.json',
    ROOT / 'onex/core/native_core.py',
    ROOT / 'onex/core/vless_relay.py',
    ROOT / 'onex/core/xhttp.py',
    ROOT / 'onex/core/traffic_limiter.py',
    ROOT / 'onex/integrations/telegram_bot.py',
    ROOT / 'assets/branding/onex-logo-3d.png',
    ROOT / 'assets/protocols/onex-wb.png',
    ROOT / 'assets/protocols/onex-xhttp.png',
    ROOT / 'assets/protocols/onex-gamig.png',
    ROOT / 'assets/protocols/onex-stream.png',
]
missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
if missing:
    raise SystemExit('Missing required files: ' + ', '.join(missing))
meta = json.loads((ROOT/'version.json').read_text(encoding='utf-8'))
if not isinstance(meta, dict) or not meta.get('version'):
    raise SystemExit('Invalid version.json')
print(f'ONEX structure OK — version {meta["version"]}')
