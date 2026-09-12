
function generateAllConfigs(user, server) {
  const protocols = JSON.parse(server.protocols);
  const configs = [];
  const uuid = user.id;
  const tag = `ONEX | ${user.username}`;

  // 1. VLESS WS
  if (protocols.includes('vless')) {
    configs.push({
      protocol: 'VLESS',
      name: `${tag} — VLESS WS (TLS)`,
      link: `vless://${uuid}@${server.host}:${server.port}?encryption=none&security=tls&type=ws&host=${encodeURIComponent(server.sni)}&path=%2Fonex-vless#${encodeURIComponent(tag + ' VLESS')}`
    });
  }

  // 2. VLESS REALITY
  if (protocols.includes('reality')) {
    configs.push({
      protocol: 'Reality',
      name: `${tag} — VLESS Reality`,
      link: `vless://${uuid}@${server.host}:${server.port}?encryption=none&security=reality&sni=www.speedtest.net&fp=chrome&pbk=1yH9eXk4z3Q2...&sid=6ba7b810&type=grpc&serviceName=onex-grpc#${encodeURIComponent(tag + ' Reality')}`
    });
  }

  // 3. VMess WS
  if (protocols.includes('vmess')) {
    const vmessObj = {
      v: '2', ps: `${tag} VMess WS`, add: server.host, port: String(server.port),
      id: uuid, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: server.sni,
      path: '/onex-vmess', tls: 'tls', sni: server.sni
    };
    configs.push({
      protocol: 'VMess',
      name: `${tag} — VMess WS CDN`,
      link: `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`
    });
  }

  // 4. Trojan
  if (protocols.includes('trojan')) {
    configs.push({
      protocol: 'Trojan',
      name: `${tag} — Trojan Secure`,
      link: `trojan://${uuid}@${server.host}:${server.port}?security=tls&sni=${server.sni}&type=ws&path=%2Fonex-trojan#${encodeURIComponent(tag + ' Trojan')}`
    });
  }

  // 5. Shadowsocks 2022
  if (protocols.includes('shadowsocks')) {
    const ssKey = Buffer.from(`2022-blake3-aes-128-gcm:${uuid.replace(/-/g, '').slice(0, 16)}`).toString('base64');
    configs.push({
      protocol: 'Shadowsocks',
      name: `${tag} — SS-2022 Turbo`,
      link: `ss://${ssKey}@${server.host}:${server.port}#${encodeURIComponent(tag + ' Shadowsocks')}`
    });
  }

  // 6. Hysteria 2
  if (protocols.includes('hysteria2')) {
    configs.push({
      protocol: 'Hysteria2',
      name: `${tag} — Hysteria 2 (UDP)`,
      link: `hysteria2://${uuid}@${server.host}:${server.port}?insecure=1&sni=${server.sni}#${encodeURIComponent(tag + ' Hysteria2')}`
    });
  }

  return configs;
}

function generateSubList(configs) {
  return configs.map(c => c.link).join('\n');
}

module.exports = { generateAllConfigs, generateSubList };
