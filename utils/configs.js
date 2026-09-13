function generateAllConfigs(client, server) {
  const protocols = JSON.parse(client.protocols);
  const configs = [];
  const uuid = client.uuid;
  const tag = `ONEX-${client.name}`;

  if (protocols.includes('vless')) {
    configs.push({
      protocol: 'VLESS',
      name: `${tag} — VLESS WS`,
      link: `vless://${uuid}@${server.host}:${server.port}?encryption=none&security=tls&type=ws&host=${encodeURIComponent(server.sni)}&path=%2Fonex-vless#${encodeURIComponent(tag + ' VLESS')}`
    });
  }
  if (protocols.includes('reality')) {
    configs.push({
      protocol: 'Reality',
      name: `${tag} — Reality`,
      link: `vless://${uuid}@${server.host}:${server.port}?encryption=none&security=reality&sni=www.speedtest.net&fp=chrome&pbk=onexKeyExample&sid=6ba7b810&type=grpc&serviceName=onex-grpc#${encodeURIComponent(tag + ' Reality')}`
    });
  }
  if (protocols.includes('vmess')) {
    const vmessObj = { v: '2', ps: `${tag} VMess`, add: server.host, port: String(server.port), id: uuid, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: server.sni, path: '/onex-vmess', tls: 'tls', sni: server.sni };
    configs.push({
      protocol: 'VMess',
      name: `${tag} — VMess WS`,
      link: `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`
    });
  }
  if (protocols.includes('trojan')) {
    configs.push({
      protocol: 'Trojan',
      name: `${tag} — Trojan`,
      link: `trojan://${uuid}@${server.host}:${server.port}?security=tls&sni=${server.sni}&type=ws&path=%2Fonex-trojan#${encodeURIComponent(tag + ' Trojan')}`
    });
  }
  if (protocols.includes('shadowsocks')) {
    const ssKey = Buffer.from(`2022-blake3-aes-128-gcm:${uuid.replace(/-/g, '').slice(0, 16)}`).toString('base64');
    configs.push({
      protocol: 'Shadowsocks',
      name: `${tag} — SS-2022`,
      link: `ss://${ssKey}@${server.host}:${server.port}#${encodeURIComponent(tag + ' SS')}`
    });
  }
  if (protocols.includes('hysteria2')) {
    configs.push({
      protocol: 'Hysteria2',
      name: `${tag} — Hysteria2`,
      link: `hysteria2://${uuid}@${server.host}:${server.port}?insecure=1&sni=${server.sni}#${encodeURIComponent(tag + ' HY2')}`
    });
  }
  return configs;
}

function generateSubList(configs) {
  return configs.map(c => c.link).join('\n');
}

module.exports = { generateAllConfigs, generateSubList };
