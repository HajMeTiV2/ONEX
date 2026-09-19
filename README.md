# ONEX 1.2.0 — Advanced Native Runtime

This build connects the Advanced Configuration UI to the ONEX native `sing-box` runtime without pretending unsupported fields are applied.

## Runtime flow

`Advanced UI → /api/links → persisted state → NativeCore builder → application validation → sing-box check → staged config → runtime start → health check → commit / rollback`

A native change is considered applied only after `sing-box check` succeeds and the new process remains alive. If startup fails, the previous known-good configuration is restored.

## Native protocols

- Trojan
- Shadowsocks
- SOCKS5
- HTTP Proxy
- Hysteria2
- VLESS gRPC Reality

The existing ONEX VLESS WebSocket relay and XHTTP modules remain separate because they are implemented by ONEX itself rather than by native sing-box listeners.

## Advanced settings

The panel stores and validates:

- TLS / SNI / ALPN / TLS versions
- certificate and key paths
- Reality keypair, Short ID and handshake settings
- client fingerprint and randomization metadata
- WebSocket / HTTP / HTTPUpgrade / QUIC / gRPC transport options where the selected native protocol supports them
- multiple ports and listener conflict detection
- listener address, interface, routing mark and network namespace
- TCP Fast Open / MPTCP / keepalive / UDP timeout / reuse address
- sniffing options supported by the installed sing-box version
- final outbound (`direct` or `block` in this build)
- custom transport headers where the selected transport supports them
- Shadowsocks method
- Hysteria2 bandwidth, obfuscation and masquerade

Client-only fields such as fingerprint and `allow_insecure` are never injected into server listeners as fake fields. Fingerprint is represented in generated client links; `allow_insecure` is client metadata.

Reality public/private keys must be supplied together when custom keys are used. If both are empty, ONEX generates and persists a matching keypair with sing-box.

## Native API

- `GET /api/native/status`
- `GET /api/native/config` (redacted by default; `?raw=1` is owner-only)
- `POST /api/native/validate`
- `POST /api/native/reload`
- `GET /api/advanced/capabilities`
- `POST /api/advanced/validate`
- `POST /api/links/{uid}/advanced/reset`

## Environment

- `ONEX_NATIVE_CORE=auto|0|1`
- `ONEX_SINGBOX_BIN=/absolute/path/to/sing-box`
- `ONEX_SINGBOX_VERSION=1.14.1`
- `ONEX_SINGBOX_AUTO_DOWNLOAD=1`
- `ONEX_TLS_CERT=/absolute/path/cert.pem`
- `ONEX_TLS_KEY=/absolute/path/key.pem`
- `ONEX_REALITY_HANDSHAKE=www.cloudflare.com`
- `ONEX_SS_METHOD=aes-256-gcm`

For production, prefer a valid certificate/key or an ACME/certificate-provider setup instead of the generated self-signed fallback.

## Validation

The runtime uses the installed sing-box binary's `check` command before applying a configuration. The current sing-box documentation also provides a JSON Schema and recommends generating a schema matching the installed binary when exact version/build validation is needed.

## Tests

`tests/smoke_native.py` performs offline structural checks for protocol-safe defaults and transport mapping. Full runtime validation still requires a Linux host with the configured sing-box binary and its required privileges/capabilities.

## Security

Secrets, runtime state, generated certificates and Reality key material stay outside source control. The distributed archive does not contain the previous environment's panel secret.
