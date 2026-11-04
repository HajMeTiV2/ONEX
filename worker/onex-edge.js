// ONEX Edge: managed Cloudflare Worker deployed by the ONEX panel.
//
// It is a transparent edge relay in front of the Railway panel: VLESS/Trojan
// WebSocket, XHTTP and subscription traffic enters Cloudflare's network and is
// forwarded to the panel origin, so all ONEX accounting (traffic, IP limit,
// expiry, speed limit) keeps working unchanged.
//
// Bindings injected by the panel at deploy time:
//   ORIGIN  plain_text   the panel's public hostname (e.g. onex.up.railway.app)
//   KEY     secret_text  shared secret, sent to the origin as X-Onex-Edge
//
// Admin routes (login, dashboard, private API, Telegram webhook) are never
// exposed through the edge; they answer with a neutral page instead.

const BLOCKED_PREFIXES = ["/login", "/dashboard", "/api/", "/telegram/", "/docs", "/openapi.json", "/redoc"];
const PUBLIC_API_PREFIXES = ["/api/public/"];
const HOP_HEADERS = ["host", "cf-connecting-ip", "cf-ipcountry", "cf-ray", "cf-visitor", "x-real-ip", "x-forwarded-host", "x-forwarded-proto"];

const DECOY = `<!doctype html><html><head><meta charset="utf-8"><title>Welcome</title>
<meta name="viewport" content="width=device-width,initial-scale=1"><style>body{font-family:system-ui,sans-serif;background:#0f1115;color:#c9d1d9;display:grid;place-items:center;height:100vh;margin:0}</style></head>
<body><div><h1>It works</h1><p>This site is served from the edge.</p></div></body></html>`;

function isBlocked(path) {
  if (path === "/") return true;
  if (PUBLIC_API_PREFIXES.some((p) => path.startsWith(p))) return false;
  return BLOCKED_PREFIXES.some((p) => path === p.replace(/\/$/, "") || path.startsWith(p));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/__onex_ping") {
      return new Response(JSON.stringify({ ok: true, edge: "onex", colo: (request.cf && request.cf.colo) || "" }), {
        headers: { "content-type": "application/json", "cache-control": "no-store" },
      });
    }
    if (!env.ORIGIN) return new Response("edge not configured", { status: 503 });
    if (isBlocked(path)) {
      return new Response(DECOY, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
    }

    const target = new URL(path + url.search, "https://" + env.ORIGIN);
    const headers = new Headers(request.headers);
    for (const name of HOP_HEADERS) headers.delete(name);
    // Cloudflare requires the Upgrade header to survive the relay handshake.
    // Do not rebuild this as a plain fetch init without the original headers.
    const clientIp = request.headers.get("cf-connecting-ip") || "";
    if (clientIp) headers.set("x-forwarded-for", clientIp);
    if (env.KEY) headers.set("x-onex-edge", env.KEY);
    headers.set("host", target.host);

    const method = request.method.toUpperCase();
    const forwarded = new Request(target.toString(), {
      method,
      headers,
      redirect: "manual",
      body: method === "GET" || method === "HEAD" ? undefined : request.body,
    });

    try {
      // The original Upgrade header is retained, allowing Cloudflare to
      // return the origin's 101 WebSocket response instead of downgrading it.
      return await fetch(forwarded);
    } catch (err) {
      return new Response("origin unreachable", { status: 502 });
    }
  },
};
