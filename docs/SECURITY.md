# ONEX Security

- Keep `data/` runtime state and secrets outside source control.
- Keep Railway credentials in environment variables.
- Do not publish `data/pixonpanel_secret.key` from a production instance.
- Compatibility shims contain no secrets and only forward imports to canonical modules.
