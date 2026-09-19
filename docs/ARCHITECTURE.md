# ONEX Architecture

## Runtime entrypoint
- `main.py` remains the Railway/FastAPI entrypoint for backward compatibility.
- Core implementation lives under `onex/core/`.
- Telegram integration lives under `onex/integrations/`.

## Layout
- `assets/branding/` — brand artwork.
- `assets/protocols/` — protocol picker artwork.
- `frontend/` — browser-side JavaScript assets.
- `data/` — runtime state and secrets; never commit production contents.
- `archive/legacy/` — historical source kept out of the runtime path.
- Root module shims preserve legacy imports used by deployments and external tooling.
