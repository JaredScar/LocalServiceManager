'use strict';

// Exposed ports (listeners + Windows Firewall evaluation) and the attack summary
// (failed Windows logons, MariaDB auth failures, web probes from Caddy logs).

const fsp = require('fs').promises;
const path = require('path');
const { readTailLines, readJson } = require('./util');

const HOURS = 24;

// ---------------- exposed ports ----------------

const isLoopback = (a) => /^127\./.test(a) || a === '::1';

function protoMatches(ruleProto, proto) {
  const p = String(ruleProto || 'Any').toUpperCase();
  if (p === 'ANY') return true;
  return proto === 'TCP' ? p === 'TCP' || p === '6' : p === 'UDP' || p === '17';
}

function portMatches(ports, port) {
  for (const raw of ports || ['Any']) {
    const spec = String(raw);
    if (spec === 'Any') return true;
    if (spec === 'RPCEPMap' && port === 135) return true;
    if (spec === 'RPC' && port >= 49152) return true;
    const m = spec.match(/^(\d+)(?:-(\d+))?$/);
    if (m) {
      const lo = Number(m[1]);
      const hi = m[2] ? Number(m[2]) : lo;
      if (port >= lo && port <= hi) return true;
    }
  }
  return false;
}

function programMatches(ruleProgram, l) {
  const p = String(ruleProgram || 'Any');
  if (p === 'Any') return true;
  if (p === 'System') return l.pid === 4;
  return Boolean(l.path) && p.toLowerCase() === l.path.toLowerCase();
}

function serviceMatches(ruleService, l) {
  const s = String(ruleService || 'Any');
  if (s === 'Any') return true;
  const services = (l.services || []).map((x) => x.toLowerCase());
  if (s === '*') return services.length > 0;
  return services.includes(s.toLowerCase());
}

function profileMatches(ruleProfile, active) {
  const p = String(ruleProfile || 'Any');
  if (p === 'Any') return true;
  return active.some((a) => p.includes(a));
}

// A rule tied to a packaged app's sandbox (AppContainer SID) never applies to normal programs.
function packageMatches(rulePackage) {
  const p = String(rulePackage || '').trim();
  return p === '' || p === 'Any' || p === '*' ? true : !/^S-1-15-/i.test(p);
}

// Rules can be limited to specific interfaces or interface types (e.g. Wi-Fi Direct only).
function interfaceMatches(rule, fw) {
  const pub = Array.isArray(fw.publicInterfaces) ? fw.publicInterfaces : null;
  const aliases = rule.interfaces || ['Any'];
  const type = String(rule.interfaceType || 'Any');
  if (!pub || !pub.length) return true; // older collector output: can't tell, assume it applies
  if (!aliases.includes('Any') && !pub.some((p) => aliases.some((a) => a.toLowerCase() === p.alias.toLowerCase()))) return false;
  if (type !== 'Any' && !pub.some((p) => type.includes(p.type))) return false;
  return true;
}

// Rules with an owner apply only to processes running as that user (per-user app rules).
function ownerMatches(rule) {
  return !rule.owner;
}

function evaluateListener(l, fw) {
  if (!fw) return { verdict: 'unknown', rules: [], remote: [] };

  const active = fw.activeProfiles && fw.activeProfiles.length ? fw.activeProfiles : ['Public'];
  const activeProfiles = (fw.profiles || []).filter((p) => active.includes(p.name));
  if (activeProfiles.some((p) => !p.enabled)) return { verdict: 'firewall-off', rules: [], remote: [] };

  const matching = (fw.rules || []).filter(
    (r) =>
      profileMatches(r.profile, active) &&
      protoMatches(r.protocol, l.proto) &&
      portMatches(r.ports, l.port) &&
      programMatches(r.program, l) &&
      serviceMatches(r.service, l) &&
      packageMatches(r.package) &&
      ownerMatches(r) &&
      interfaceMatches(r, fw)
  );

  const blocks = matching.filter((r) => r.action === 'Block');
  if (blocks.length) return { verdict: 'blocked', rules: blocks.map((r) => r.name), remote: [] };

  const allows = matching.filter((r) => r.action === 'Allow');
  if (allows.length) {
    const open = allows.filter((r) => (r.remote || ['Any']).includes('Any'));
    if (open.length) return { verdict: 'open', rules: open.map((r) => r.name), remote: ['Any'] };
    const remote = [...new Set(allows.flatMap((r) => r.remote || []))];
    return { verdict: 'restricted', rules: allows.map((r) => r.name), remote };
  }

  const defaultAllow = activeProfiles.some((p) => p.defaultInbound === 'Allow');
  return defaultAllow
    ? { verdict: 'open', rules: ['(default inbound action: Allow)'], remote: ['Any'] }
    : { verdict: 'blocked', rules: ['(default inbound action: Block)'], remote: [] };
}

function buildPorts(collected, expected) {
  if (!collected || !Array.isArray(collected.listeners)) return null;
  const fw = collected.firewall;

  // Merge the IPv4 and IPv6 sockets of the same program and port into one row.
  const groups = new Map();
  for (const l of collected.listeners) {
    const key = `${l.proto}|${l.port}|${l.pid}`;
    if (!groups.has(key)) groups.set(key, { ...l, addresses: [] });
    const g = groups.get(key);
    if (!g.addresses.includes(l.address)) g.addresses.push(l.address);
  }

  const rows = [];
  for (const g of groups.values()) {
    const local = g.addresses.every(isLoopback);
    const fwResult = local ? { verdict: 'local', rules: [], remote: [] } : evaluateListener(g, fw);
    const isExpected = expected.has(`${g.port}/${g.proto.toLowerCase()}`);

    let status;
    if (local) status = 'local';
    else if (fwResult.verdict === 'blocked') status = 'blocked';
    else if (fwResult.verdict === 'restricted') status = 'restricted';
    else if (fwResult.verdict === 'unknown') status = 'unknown';
    else status = isExpected ? 'open-expected' : 'open-unexpected';

    rows.push({
      proto: g.proto,
      port: g.port,
      addresses: g.addresses,
      pid: g.pid,
      process: g.process,
      path: g.path,
      services: g.services || [],
      status,
      firewallOff: fwResult.verdict === 'firewall-off',
      rules: fwResult.rules,
      remote: fwResult.remote,
    });
  }

  const order = { 'open-unexpected': 0, unknown: 1, 'open-expected': 2, restricted: 3, blocked: 4, local: 5 };
  rows.sort((a, b) => order[a.status] - order[b.status] || a.port - b.port || a.proto.localeCompare(b.proto));

  const counts = {};
  for (const r of rows) counts[r.status] = (counts[r.status] || 0) + 1;

  return {
    rows,
    counts,
    activeProfiles: fw ? fw.activeProfiles : null,
    firewallProfiles: fw ? fw.profiles : null,
  };
}

// ---------------- attack summary ----------------

const PROBE_RE =
  /\.env|\.git\/|\/\.git|wp-(admin|login|content|includes)|xmlrpc|phpmyadmin|pma\/|\.aws|\/cgi-bin|\.\.\/|\/etc\/passwd|\/vendor\/phpunit|actuator|\/\.ssh|\/config\.(json|php|yml)|\/server-status|\/boaform|\/shell|\.(asp|aspx|jsp)\b/i;

function hourBuckets(now) {
  const end = Math.floor(now / 3600e3) * 3600e3 + 3600e3; // end of the current hour
  const start = end - HOURS * 3600e3;
  return { start, end, labels: Array.from({ length: HOURS }, (_, i) => new Date(start + i * 3600e3).toISOString()) };
}

function bucketIndex(t, b) {
  if (t < b.start || t >= b.end) return -1;
  return Math.floor((t - b.start) / 3600e3);
}

function topBy(map, n) {
  return [...map.values()].sort((a, b) => b.count - a.count || b.last - a.last).slice(0, n);
}

function countNames(arr, n) {
  const m = new Map();
  for (const x of arr) m.set(x, (m.get(x) || 0) + 1);
  return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, n).map(([name, count]) => ({ name, count }));
}

async function parseMariaDb(file, since) {
  const out = { available: false, error: null, events: [] };
  if (!file) return out;
  try {
    const { lines } = await readTailLines(file, 4 * 1024 * 1024);
    out.available = true;
    // 2026-10-11 15:53:46 103 [Warning] Access denied for user 'root'@'64.89.163.176' (using password: YES)
    const denied = /^(\d{4}-\d{2}-\d{2}) +(\d{1,2}:\d{2}:\d{2}) .*Access denied for user '([^']*)'@'([^']*)'/;
    // ... Aborted connection 102 to db: 'unconnected' user: 'unauthenticated' host: '64.89.163.176' (...)
    const aborted = /^(\d{4}-\d{2}-\d{2}) +(\d{1,2}:\d{2}:\d{2}) .*Aborted connection .* user: 'unauthenticated' host: '([^']*)'/;
    for (const line of lines) {
      let m = line.match(denied);
      if (m) {
        const t = new Date(`${m[1]}T${m[2].padStart(8, '0')}`).getTime();
        if (t >= since) out.events.push({ t, ip: m[4], user: m[3], kind: 'denied' });
        continue;
      }
      m = line.match(aborted);
      if (m) {
        const t = new Date(`${m[1]}T${m[2].padStart(8, '0')}`).getTime();
        if (t >= since) out.events.push({ t, ip: m[3], user: null, kind: 'unauthenticated' });
      }
    }
  } catch (e) {
    out.error = e.code === 'EACCES' || e.code === 'EPERM' ? 'No read access to the MariaDB error log.' : e.message;
  }
  return out;
}

async function parseCaddy(dir, since) {
  const out = { available: false, error: null, requests: [] };
  if (!dir) return out;
  let files;
  try {
    files = (await fsp.readdir(dir)).filter((f) => f.toLowerCase().endsWith('.log'));
    out.available = true;
  } catch (e) {
    out.error = e.message;
    return out;
  }
  for (const f of files) {
    try {
      const { lines } = await readTailLines(path.join(dir, f), 8 * 1024 * 1024);
      for (const line of lines) {
        if (line.charAt(0) !== '{') continue;
        let o;
        try {
          o = JSON.parse(line);
        } catch {
          continue;
        }
        if (!o.request || typeof o.status !== 'number') continue;
        const t = typeof o.ts === 'number' ? o.ts * 1000 : Date.parse(o.ts);
        if (!(t >= since)) continue;
        const r = o.request;
        out.requests.push({
          t,
          ip: r.client_ip || r.remote_ip || '?',
          status: o.status,
          host: r.host || '',
          uri: String(r.uri || '').slice(0, 200),
        });
      }
    } catch {
      /* skip unreadable file */
    }
  }
  return out;
}

async function buildAttacks({ collected, collectedError, mariadbLog, caddyLogs, trusted }) {
  const now = Date.now();
  const since = now - HOURS * 3600e3;
  const b = hourBuckets(now);
  const hourly = { windows: new Array(HOURS).fill(0), mariadb: new Array(HOURS).fill(0), web: new Array(HOURS).fill(0) };
  const notes = [];
  const ips = new Set();
  const isTrusted = (ip) => trusted.has(ip);

  // --- Windows logons (from the collector) ---
  const logons = collected && collected.logons;
  const winTop = new Map();
  let windowsTotal = 0;
  const successes = [];
  if (!collected) {
    notes.push({ level: 'warn', text: collectedError || 'Windows logon data not available yet. The collector runs every 2 minutes after install.ps1.' });
  } else if (!logons) {
    notes.push({ level: 'warn', text: 'The collector could not read the Security log.' });
  } else {
    if (logons.failureAuditing === false) {
      notes.push({
        level: 'bad',
        text: 'Failed-logon auditing is off, so failed Windows/RDP logins are not being recorded. Fix: auditpol /set /subcategory:"Logon" /success:enable /failure:enable',
      });
    }
    if (logons.oldestEvent && Date.parse(logons.oldestEvent) > since) {
      notes.push({
        level: 'warn',
        text: `The Security log only goes back to ${new Date(logons.oldestEvent).toLocaleString()}. Increase its size: wevtutil sl Security /ms:1073741824`,
      });
    }
    for (const e of logons.failed || []) {
      const t = Date.parse(e.t);
      if (!(t >= since)) continue;
      const ip = e.ip && e.ip !== '-' ? e.ip : '(no IP)';
      if (isTrusted(ip)) continue;
      windowsTotal++;
      const i = bucketIndex(t, b);
      if (i >= 0) hourly.windows[i]++;
      if (ip !== '(no IP)') ips.add(ip);
      if (!winTop.has(ip)) winTop.set(ip, { ip, count: 0, first: t, last: t, users: [] });
      const g = winTop.get(ip);
      g.count++;
      g.first = Math.min(g.first, t);
      g.last = Math.max(g.last, t);
      g.users.push(e.user || '?');
    }
    for (const s of logons.success || []) {
      successes.push({ t: Date.parse(s.t), user: s.user, type: s.type, ip: s.ip, trusted: isTrusted(s.ip) });
    }
  }

  // --- MariaDB ---
  const maria = await parseMariaDb(mariadbLog, since);
  if (maria.error) notes.push({ level: 'warn', text: `MariaDB log: ${maria.error}` });
  const mariaTop = new Map();
  let mariadbTotal = 0;
  for (const e of maria.events) {
    if (isTrusted(e.ip)) continue;
    mariadbTotal++;
    const i = bucketIndex(e.t, b);
    if (i >= 0) hourly.mariadb[i]++;
    ips.add(e.ip);
    if (!mariaTop.has(e.ip)) mariaTop.set(e.ip, { ip: e.ip, count: 0, denied: 0, first: e.t, last: e.t, users: [] });
    const g = mariaTop.get(e.ip);
    g.count++;
    if (e.kind === 'denied') {
      g.denied++;
      g.users.push(e.user);
    }
    g.first = Math.min(g.first, e.t);
    g.last = Math.max(g.last, e.t);
  }
  if (mariadbTotal > 0) {
    notes.push({
      level: 'bad',
      text: 'Outside IPs are reaching MariaDB. Port 3306 should be closed to the internet (bind-address=127.0.0.1 in my.ini, plus a firewall block).',
    });
  }

  // --- Web probes (Caddy access logs) ---
  const caddy = await parseCaddy(caddyLogs, since);
  if (caddy.error) notes.push({ level: 'warn', text: `Caddy logs: ${caddy.error}` });
  const webTop = new Map();
  let webTotal = 0;
  for (const r of caddy.requests) {
    if (isTrusted(r.ip)) continue;
    const probe = PROBE_RE.test(r.uri);
    if (!(r.status >= 400 && r.status < 500) && !probe) continue;
    webTotal++;
    const i = bucketIndex(r.t, b);
    if (i >= 0) hourly.web[i]++;
    ips.add(r.ip);
    if (!webTop.has(r.ip)) webTop.set(r.ip, { ip: r.ip, count: 0, probes: 0, first: r.t, last: r.t, paths: [], hosts: [] });
    const g = webTop.get(r.ip);
    g.count++;
    if (probe) g.probes++;
    g.paths.push(r.uri);
    g.hosts.push(r.host);
    g.first = Math.min(g.first, r.t);
    g.last = Math.max(g.last, r.t);
  }

  return {
    generatedAt: new Date(now).toISOString(),
    collectorAt: collected ? collected.generatedAt : null,
    hours: HOURS,
    notes,
    totals: { windows: windowsTotal, mariadb: mariadbTotal, web: webTotal, uniqueIps: ips.size, lockouts: logons ? logons.lockouts || 0 : null },
    sources: { windows: Boolean(logons), mariadb: maria.available, web: caddy.available },
    hourly: { labels: b.labels, ...hourly },
    windowsTop: topBy(winTop, 15).map((g) => ({ ...g, users: countNames(g.users, 5) })),
    mariadbTop: topBy(mariaTop, 15).map((g) => ({ ...g, users: countNames(g.users, 5) })),
    webTop: topBy(webTop, 15).map((g) => ({ ...g, paths: countNames(g.paths, 4), hosts: countNames(g.hosts, 3) })),
    successes: successes.sort((a, b2) => b2.t - a.t).slice(0, 30),
  };
}

// ---------------- collector file ----------------

// Two minutes is the schedule. Eight covers a slow run plus a missed one.
const COLLECTOR_STALE_MS = 8 * 60e3;

function collectorProblem(collected) {
  if (!collected) return null;
  if (!collected.generatedAt) return 'The collector data has no usable timestamp. Check the svcdash-collector scheduled task.';
  const age = Date.now() - Date.parse(collected.generatedAt);
  if (Number.isFinite(age) && age <= COLLECTOR_STALE_MS) return null;
  const mins = Number.isFinite(age) ? Math.max(1, Math.round(age / 60e3)) : null;
  return mins
    ? `The collector last wrote ${mins} minute${mins === 1 ? '' : 's'} ago. The scheduled task \\svcdash\\svcdash-collector may have stopped.`
    : 'The collector data has no usable timestamp. Check the svcdash-collector scheduled task.';
}

async function loadCollected(file) {
  try {
    const data = await readJson(file);
    return { data, error: collectorProblem(data) };
  } catch (e) {
    if (e.code === 'ENOENT') return { data: null, error: 'No collector data yet. Run install.ps1 to set up the "svcdash-collector" scheduled task.' };
    if (e.code === 'EACCES' || e.code === 'EPERM') return { data: null, error: 'No read access to collector data. Re-run install.ps1.' };
    return { data: null, error: `Could not read collector data: ${e.message}` };
  }
}

module.exports = { buildPorts, buildAttacks, loadCollected, collectorProblem, COLLECTOR_STALE_MS, evaluateListener, PROBE_RE };
