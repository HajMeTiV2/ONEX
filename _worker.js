
// ONEX Cloudflare Reverse-Proxy Worker
// سازنده: @Mehtif | کانال: @V2rayTun0

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const upgradeHeader = request.headers.get('Upgrade');
    const backendHost = env.BACKEND_HOST || 'onex-production-e81f.up.railway.app';

    if (upgradeHeader === 'websocket') {
      url.hostname = backendHost;
      url.protocol = 'https:';
      url.port = '443';

      const modifiedRequest = new Request(url.toString(), {
        method: request.method,
        headers: request.headers
      });
      modifiedRequest.headers.set('Host', backendHost);

      return fetch(modifiedRequest);
    }

    url.hostname = backendHost;
    url.protocol = 'https:';
    url.port = '443';

    const newRequest = new Request(url.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body
    });
    newRequest.headers.set('Host', backendHost);

    return fetch(newRequest);
  }
};
