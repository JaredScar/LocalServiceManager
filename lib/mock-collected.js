'use strict';

// Sample collector output for testing off Windows. Not used on a real server.

function mockCollected() {
  // Documentation address (RFC 5737). config.example.json lists the same IP as trusted.
  const HOME = '203.0.113.10';
  const now = Date.now();
  const iso = (msAgo) => new Date(now - msAgo).toISOString();
  const L = (proto, address, port, pid, process, path, services = []) => ({ proto, address, port, pid, process, path, services });
  const node = 'C:\\Program Files\\nodejs\\node.exe';

  const listeners = [
    L('TCP', '0.0.0.0', 80, 3100, 'caddy.exe', 'C:\\apps\\Caddy\\caddy.exe', ['caddy']),
    L('TCP', '::', 80, 3100, 'caddy.exe', 'C:\\apps\\Caddy\\caddy.exe', ['caddy']),
    L('TCP', '0.0.0.0', 443, 3100, 'caddy.exe', 'C:\\apps\\Caddy\\caddy.exe', ['caddy']),
    L('UDP', '0.0.0.0', 443, 3100, 'caddy.exe', 'C:\\apps\\Caddy\\caddy.exe', ['caddy']),
    L('TCP', '127.0.0.1', 2019, 3100, 'caddy.exe', 'C:\\apps\\Caddy\\caddy.exe', ['caddy']),
    L('TCP', '0.0.0.0', 3389, 1912, 'svchost.exe', 'C:\\Windows\\system32\\svchost.exe', ['TermService']),
    L('UDP', '0.0.0.0', 3389, 1912, 'svchost.exe', 'C:\\Windows\\system32\\svchost.exe', ['TermService']),
    L('TCP', '0.0.0.0', 3306, 2632, 'mariadbd.exe', 'C:\\Program Files\\MariaDB 13.0\\bin\\mariadbd.exe', ['MariaDB']),
    L('TCP', '::', 3020, 3004, 'node.exe', node, []),
    L('TCP', '127.0.0.1', 3030, 2318, 'node.exe', node, []),
    L('TCP', '127.0.0.1', 3000, 2900, 'gitea.exe', 'C:\\apps\\gitea\\gitea.exe', ['gitea']),
    L('TCP', '127.0.0.1', 3090, 2950, 'node.exe', node, []),
    L('TCP', '127.0.0.1', 9000, 7280, 'php-cgi.exe', 'C:\\php\\php-cgi.exe', []),
    L('TCP', '0.0.0.0', 8080, 2284, 'sample-app.exe', 'C:\\apps\\sample-app\\sample-app.exe', []),
    L('TCP', '0.0.0.0', 8443, 1341, 'sample-app.exe', 'C:\\apps\\sample-app\\sample-app.exe', []),
    L('TCP', '::', 445, 4, 'System', null, []),
    L('TCP', '0.0.0.0', 135, 1676, 'svchost.exe', 'C:\\Windows\\system32\\svchost.exe', ['RpcSs']),
    L('TCP', '::', 5985, 4, 'System', null, []),
    L('TCP', '0.0.0.0', 49664, 1216, 'wininit.exe', 'C:\\Windows\\system32\\wininit.exe', []),
    L('UDP', '0.0.0.0', 5353, 1880, 'svchost.exe', 'C:\\Windows\\system32\\svchost.exe', ['Dnscache']),
  ];

  const R = (name, action, ports, extra = {}) => ({
    name,
    action,
    profile: 'Any',
    protocol: 'TCP',
    ports,
    program: 'Any',
    service: 'Any',
    remote: ['Any'],
    ...extra,
  });

  const rules = [
    R('HTTP', 'Allow', ['80']),
    R('HTTPS', 'Allow', ['443']),
    R('HTTP/3', 'Allow', ['443'], { protocol: 'UDP' }),
    R('Remote Desktop - User Mode (TCP-In)', 'Allow', ['3389'], { service: 'TermService', remote: [HOME] }),
    R('Remote Desktop - User Mode (UDP-In)', 'Allow', ['3389'], { protocol: 'UDP', service: 'TermService', remote: [HOME] }),
    R('MariaDB', 'Allow', ['3306']),
    R('Sample app', 'Allow', ['8080']),
    R('Admin UI', 'Allow', ['8443'], { remote: [HOME] }),
    R('Block SMB', 'Block', ['139', '445']),
    R('Block WinRM', 'Block', ['5985']),
    // Windows creates this automatically the first time node.exe listens and someone clicks "Allow"
    R('Node.js JavaScript Runtime', 'Allow', ['Any'], { protocol: 'TCP', program: node, profile: 'Public' }),
    // Built-in rules that look like "allow everything" but are scoped to a packaged app or Wi-Fi Direct
    R('Desktop App Web Viewer', 'Allow', ['Any'], { protocol: 'Any', package: 'S-1-15-2-1910091885-1573563583-1104941280' }),
    R('WFD Driver-only (TCP-In)', 'Allow', ['Any'], { program: 'System', interfaceType: 'Wireless' }),
    R('WFD Driver-only (UDP-In)', 'Allow', ['Any'], { protocol: 'UDP', program: 'System', interfaceType: 'Wireless' }),
  ];

  const attackers = ['192.0.2.10', '192.0.2.21', '198.51.100.15', '198.51.100.44'];
  const users = ['administrator', 'admin', 'Administrator', 'user', 'test', 'backup', 'guest'];
  const failed = [];
  for (let i = 0; i < 260; i++) {
    const ip = attackers[i % 3 === 0 ? 0 : i % 5 === 0 ? 2 : i % 7 === 0 ? 3 : 1];
    const hoursAgo = Math.pow(Math.random(), 1.6) * 23.5;
    failed.push({ t: iso(hoursAgo * 3600e3), user: users[i % users.length], type: 3, ip });
  }
  failed.push({ t: iso(3 * 3600e3), user: 'home-admin', type: 10, ip: HOME }); // trusted address, left out of the attack counts

  return {
    generatedAt: iso(40e3),
    hours: 24,
    listeners,
    firewall: {
      activeProfiles: ['Public'],
      publicInterfaces: [{ alias: 'Ethernet', type: 'Wired' }],
      profiles: [
        { name: 'Domain', enabled: true, defaultInbound: 'Block' },
        { name: 'Private', enabled: true, defaultInbound: 'Block' },
        { name: 'Public', enabled: true, defaultInbound: 'Block' },
      ],
      rules,
    },
    logons: {
      failed,
      success: [
        { t: iso(1.2 * 3600e3), user: 'home-admin', type: 10, ip: HOME },
        { t: iso(1.2 * 3600e3 + 2e3), user: 'home-admin', type: 3, ip: HOME },
        { t: iso(9.5 * 3600e3), user: 'home-admin', type: 10, ip: HOME },
      ],
      lockouts: 2,
      oldestEvent: iso(30 * 3600e3),
      failureAuditing: true,
    },
    errors: [],
  };
}

module.exports = { mockCollected };
