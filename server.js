'use strict';

// Service Dashboard: status, logs and start/stop/restart for Windows services.
// No dependencies. Runs on Node 18+.

const http = require('http');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { execFile } = require('child_process');
const { readTailLines } = require('./lib/util');
const { createHistory } = require('./lib/history');
const { createSites } = require('./lib/sites');
const { buildPorts, buildAttacks, loadCollected, collectorProblem } = require('./lib/security');
const { createNotify, certBand } = require('./lib/notify');

const CONFIG_PATH = process.env.SVCDASH_CONFIG || path.join(__dirname, 'config.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const AUDIT_LOG = process.env.SVCDASH_AUDIT || path.join(__dirname, 'logs', 'audit.log');
// state: written by the dashboard. collected: written only by the SYSTEM collector task.
const STATE_DIR = process.env.SVCDASH_STATE || path.join(__dirname, 'state');
const COLLECTED_FILE = process.env.SVCDASH_COLLECTED || path.join(__dirname, 'collected', 'security.json');
const IS_WINDOWS = process.platform === 'win32';
const MOCK = process.env.SVCDASH_MOCK === '1' || !IS_WINDOWS;

const log = (msg) => console.log(`${new Date().toISOString()} ${msg}`);

const MAX_TAIL_BYTES = 1024 * 1024; // read at most the last 1 MB of a log
const MAX_LINES = 2000;
const MAX_FILES_PER_DIR = 15;
const STATUS_CACHE_MS = 3000;
const ACTION_TIMEOUT_MS = 120000;
const LOG_EXTENSIONS = new Set(['.log', '.err', '.txt', '.out']);
const ACTIONS = new Set(['start', 'stop', 'restart']);
const NAME_RE = /^[A-Za-z0-9_.-]+$/;

// ---------- config ----------

function loadConfig() {
  const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  if (!Array.isArray(raw.services) || raw.services.length === 0) {
    throw new Error('config.json needs a non-empty "services" array');
  }
  const self = String(raw.self || 'svcdash').toLowerCase();
  for (const s of raw.services) {
    // Names go into PowerShell scripts, so only allow safe characters.
    if (typeof s.name !== 'string' || !NAME_RE.test(s.name)) {
      throw new Error(`Invalid service name in config: ${JSON.stringify(s.name)}`);
    }
    s.label = s.label || s.name;
    s.logs = Array.isArray(s.logs) ? s.logs : [];
    s.isSelf = s.name.toLowerCase() === self;
    s.controllable = raw.allowControl !== false && s.control !== false && !s.isSelf;
    s.confirmNote = typeof s.confirmNote === 'string' ? s.confirmNote : null;
  }
  const sites = (Array.isArray(raw.sites) ? raw.sites : []).filter((s) => {
    try {
      const u = new URL(s.url);
      return s.name && (u.protocol === 'https:' || u.protocol === 'http:');
    } catch {
      throw new Error(`Invalid site URL in config: ${JSON.stringify(s.url)}`);
    }
  });
  const attack = raw.attackSources || {};
  const notify = raw.notify && typeof raw.notify === 'object' ? raw.notify : {};
  const notifyUrl = String(notify.url || '').trim();
  if (notifyUrl) {
    let notifyTarget;
    try {
      notifyTarget = new URL(notifyUrl);
    } catch {
      throw new Error('notify.url is not a valid URL');
    }
    if (notifyTarget.protocol !== 'https:' && notifyTarget.protocol !== 'http:') {
      throw new Error('notify.url must start with https:// or http://');
    }
  }

  return {
    host: raw.host || '127.0.0.1',
    port: Number(raw.port) || 3090,
    allowedHosts: (raw.allowedHosts || []).map((h) => String(h).toLowerCase()),
    services: raw.services,
    trustedIps: new Set((raw.trustedIps || []).map(String)),
    expectedPublicPorts: new Set((raw.expectedPublicPorts || []).map((p) => String(p).toLowerCase())),
    sites,
    mariadbLog: attack.mariadbLog || null,
    caddyLogs: attack.caddyLogs || null,
    notify: { url: notifyUrl, token: String(notify.token || '').trim() },
  };
}

const config = loadConfig();
const serviceByName = new Map(config.services.map((s) => [s.name.toLowerCase(), s]));

// ---------- PowerShell helper ----------

function runPowerShell(script, timeout) {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { timeout, maxBuffer: 4 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        if (err) return reject(new Error((stderr || err.message).trim()));
        const text = stdout.trim();
        try {
          resolve(text ? JSON.parse(text) : null);
        } catch (e) {
          reject(new Error(`Could not parse PowerShell output: ${e.message}`));
        }
      }
    );
  });
}

const psQuote = (s) => `'${String(s).replace(/'/g, "''")}'`;

// ---------- status ----------

function buildStatusScript(names) {
  return `
$ErrorActionPreference = 'SilentlyContinue'
$names = @(${names.map(psQuote).join(',')})
$all = @(Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,WorkingSetSize,CreationDate,KernelModeTime,UserModeTime)
$svcs = @(Get-CimInstance Win32_Service | Where-Object { $names -contains $_.Name })
$out = foreach ($s in $svcs) {
  $procId = [int]$s.ProcessId
  $main = $null
  $children = @()
  if ($procId -gt 0) {
    $main = $all | Where-Object { $_.ProcessId -eq $procId } | Select-Object -First 1
    $children = @($all | Where-Object { $_.ParentProcessId -eq $procId -and $_.Name -ne 'conhost.exe' })
  }
  $mem = 0; $cpu = 0; $pids = @()
  foreach ($p in (@($main) + $children)) {
    if ($p) {
      $mem += [double]$p.WorkingSetSize
      $cpu += [double]$p.KernelModeTime + [double]$p.UserModeTime
      $pids += [int]$p.ProcessId
    }
  }
  $deps = @((Get-Service -Name $s.Name).DependentServices | ForEach-Object { [pscustomobject]@{ name = $_.Name; status = [string]$_.Status } })
  [pscustomobject]@{
    name        = $s.Name
    state       = $s.State
    startMode   = $s.StartMode
    account     = $s.StartName
    pid         = $procId
    pids        = $pids
    process     = if ($children.Count -gt 0) { $children[0].Name } elseif ($main) { $main.Name } else { $null }
    memoryMB    = if ($mem -gt 0) { [math]::Round($mem / 1MB, 1) } else { $null }
    cpuTime     = if ($pids.Count -gt 0) { $cpu } else { $null }
    startedAt   = if ($main -and $main.CreationDate) { $main.CreationDate.ToUniversalTime().ToString('o') } else { $null }
    dependents  = $deps
  }
}
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$load = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$disks = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object {
  [pscustomobject]@{ drive = $_.DeviceID; sizeGB = [math]::Round($_.Size / 1GB, 1); freeGB = [math]::Round($_.FreeSpace / 1GB, 1) }
})
ConvertTo-Json -Compress -Depth 5 -InputObject ([pscustomobject]@{
  services = @($out)
  system = [pscustomobject]@{
    hostname    = $env:COMPUTERNAME
    cpuPercent  = $load
    logicalCpus = [int]$cs.NumberOfLogicalProcessors
    memTotalMB  = [math]::Round($os.TotalVisibleMemorySize / 1KB)
    memFreeMB   = [math]::Round($os.FreePhysicalMemory / 1KB)
    bootTime    = $os.LastBootUpTime.ToUniversalTime().ToString('o')
    disks       = $disks
  }
})
`;
}

// ----- mock data (for testing off Windows) -----

const mock = (() => {
  const now = Date.now();
  const state = new Map();
  const infra = new Set(['caddy', 'mariadb', 'svcdash']);
  const demoStopped = config.services.find((s) => !infra.has(s.name.toLowerCase()));
  config.services.forEach((s, i) => {
    state.set(s.name.toLowerCase(), {
      name: s.name,
      state: demoStopped && s.name === demoStopped.name ? 'Stopped' : 'Running',
      startMode: 'Auto',
      account: `NT SERVICE\\${s.name}`,
      pid: 4100 + i * 37,
      process: i % 2 ? 'node.exe' : `${s.name}.exe`,
      memoryMB: Math.round((40 + i * 23.4) * 10) / 10,
      startedAt: new Date(now - (i + 1) * 3.7 * 3600e3).toISOString(),
      cpuBase: 0.4 + i * 1.7,
    });
  });
  const dependentsOf = (name) =>
    name.toLowerCase() === 'mariadb'
      ? [...state.values()].filter((r) => !infra.has(r.name.toLowerCase())).map((r) => r.name)
      : [];
  return {
    status() {
      const t = Date.now() / 1000;
      const services = [...state.values()].map((r) => {
        const running = r.state === 'Running';
        return {
          ...r,
          pid: running ? r.pid : 0,
          pids: running ? [r.pid] : [],
          memoryMB: running ? r.memoryMB : null,
          startedAt: running ? r.startedAt : null,
          cpuTime: null,
          mockCpu: running ? Math.max(0, r.cpuBase + Math.sin(t / 7 + r.pid) * 1.5) : null,
          dependents: dependentsOf(r.name).map((n) => ({ name: n, status: state.get(n.toLowerCase()).state })),
        };
      });
      return {
        services,
        system: {
          hostname: 'MOCK-SERVER',
          cpuPercent: Math.round(18 + Math.sin(t / 9) * 10),
          logicalCpus: 32,
          memTotalMB: 262144,
          memFreeMB: 171000,
          bootTime: new Date(now - 26.5 * 3600e3).toISOString(),
          disks: [{ drive: 'C:', sizeGB: 1862.9, freeGB: 1210.4 }],
        },
      };
    },
    async control(name, action, force) {
      const key = name.toLowerCase();
      const r = state.get(key);
      const running = dependentsOf(name).filter((d) => state.get(d.toLowerCase()).state === 'Running');
      if (action !== 'start' && running.length && !force) return { ok: false, needsForce: true, dependents: running };
      await new Promise((res) => setTimeout(res, 1200));
      const setState = (k, st) => {
        const s = state.get(k);
        s.state = st;
        if (st === 'Running') s.startedAt = new Date().toISOString();
      };
      if (action === 'start') setState(key, 'Running');
      if (action === 'stop') {
        running.forEach((d) => setState(d.toLowerCase(), 'Stopped'));
        setState(key, 'Stopped');
      }
      if (action === 'restart') {
        setState(key, 'Running');
        running.forEach((d) => setState(d.toLowerCase(), 'Running'));
      }
      return { ok: true, state: r.state, dependents: running };
    },
  };
})();

// ----- live status with caching + CPU deltas -----

let statusCache = { at: 0, data: null, pending: null };
const cpuPrev = new Map(); // service -> { t, cpu, key }

function withCpuPercent(rows, logicalCpus) {
  const now = Date.now();
  for (const r of rows) {
    if (r.mockCpu !== undefined) {
      r.cpuPercent = r.mockCpu === null ? null : Math.round(r.mockCpu * 10) / 10;
      delete r.mockCpu;
      continue;
    }
    const key = (r.pids || []).join(',');
    const prev = cpuPrev.get(r.name);
    let pct = null;
    if (prev && prev.key === key && r.cpuTime !== null && now > prev.t) {
      const cpuMs = (r.cpuTime - prev.cpu) / 1e4; // 100ns units -> ms
      pct = Math.max(0, Math.min(100, (cpuMs / ((now - prev.t) * Math.max(1, logicalCpus))) * 100));
    }
    if (r.cpuTime !== null) cpuPrev.set(r.name, { t: now, cpu: r.cpuTime, key });
    else cpuPrev.delete(r.name);
    r.cpuPercent = pct === null ? null : Math.round(pct * 10) / 10;
  }
  return rows;
}

// One status read at a time, shared by page polls and the history sampler.

async function getStatus(fresh) {
  const now = Date.now();
  if (!fresh && statusCache.data && now - statusCache.at < STATUS_CACHE_MS) return statusCache.data;
  if (statusCache.pending) return statusCache.pending;

  const names = config.services.map((s) => s.name);
  statusCache.pending = (MOCK ? Promise.resolve(mock.status()) : runPowerShell(buildStatusScript(names), 30000))
    .then((data) => {
      const system = data.system || null;
      const rows = withCpuPercent(Array.isArray(data.services) ? data.services : [], system ? system.logicalCpus : 1);
      const result = { byName: new Map(rows.map((r) => [String(r.name).toLowerCase(), r])), system };
      statusCache.data = result;
      statusCache.at = Date.now();
      return result;
    })
    .finally(() => {
      statusCache.pending = null;
    });
  return statusCache.pending;
}

// ---------- service control ----------

function buildControlScript(name, action, force) {
  return `
$ErrorActionPreference = 'Stop'
$name = ${psQuote(name)}
$action = ${psQuote(action)}
$force = ${force ? '$true' : '$false'}
try {
  $svc = Get-Service -Name $name
  $running = @($svc.DependentServices | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name })
  if ($action -ne 'start' -and $running.Count -gt 0 -and -not $force) {
    ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ ok = $false; needsForce = $true; dependents = $running })
    exit 0
  }
  switch ($action) {
    'start'   { Start-Service -Name $name }
    'stop'    { Stop-Service -Name $name -Force }
    'restart' {
      Stop-Service -Name $name -Force
      Start-Service -Name $name
      foreach ($d in $running) { Start-Service -Name $d }
    }
  }
  $svc.Refresh()
  ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ ok = $true; state = [string]$svc.Status; dependents = $running })
} catch {
  ConvertTo-Json -Compress -InputObject ([pscustomobject]@{ ok = $false; error = $_.Exception.Message })
}
`;
}

const busy = new Map(); // service (lowercase) -> action

function friendlyControlError(msg) {
  if (/cannot open|access is denied|permission/i.test(msg)) {
    return `${msg} (Permission denied. Re-run install.ps1 so the dashboard gets control rights for this service.)`;
  }
  return msg;
}

async function audit(entry) {
  try {
    await fsp.mkdir(path.dirname(AUDIT_LOG), { recursive: true });
    await fsp.appendFile(AUDIT_LOG, JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n');
  } catch (e) {
    console.error(new Date().toISOString(), 'Could not write audit log:', e.message);
  }
}

function clientInfo(req) {
  // Only Caddy (on localhost) can reach us, so its forwarding headers are trustworthy.
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return {
    ip: fwd || req.socket.remoteAddress,
    user: req.headers['x-auth-user'] ? String(req.headers['x-auth-user']).slice(0, 64) : null,
  };
}

function readJsonBody(req, limit = 2048) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) {
        reject(new Error('Body too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text ? JSON.parse(text) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

// Blocks cross-site requests: a page on another site can't add a custom header
// or a JSON content type without a CORS preflight, which this server never approves.
function isSameOriginRequest(req) {
  if (req.headers['x-svcdash'] !== '1') return false;
  if (!String(req.headers['content-type'] || '').toLowerCase().startsWith('application/json')) return false;
  const origin = req.headers.origin;
  if (origin) {
    try {
      if (new URL(origin).host.toLowerCase() !== String(req.headers.host || '').toLowerCase()) return false;
    } catch {
      return false;
    }
  }
  return true;
}

async function handleControl(req, res, name, action) {
  if (!isSameOriginRequest(req)) return sendJson(res, 403, { error: 'Request rejected (cross-site check failed).' });

  const svc = serviceByName.get(name.toLowerCase());
  if (!svc) return sendJson(res, 404, { error: 'Unknown service' });
  if (!ACTIONS.has(action)) return sendJson(res, 400, { error: 'Unknown action' });
  if (!svc.controllable) {
    const why = svc.isSelf ? 'The dashboard cannot restart itself; use Windows.' : 'Control is disabled for this service in config.json.';
    return sendJson(res, 403, { error: why });
  }

  let body;
  try {
    body = await readJsonBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: e.message });
  }
  const force = body.force === true;

  const key = svc.name.toLowerCase();
  if (busy.has(key)) return sendJson(res, 409, { error: `Already running "${busy.get(key)}" on this service.` });

  const who = clientInfo(req);
  busy.set(key, action);
  let result;
  try {
    result = MOCK
      ? await mock.control(svc.name, action, force)
      : await runPowerShell(buildControlScript(svc.name, action, force), ACTION_TIMEOUT_MS);
    if (!result) result = { ok: false, error: 'No output from PowerShell' };
  } catch (e) {
    result = { ok: false, error: e.message };
  } finally {
    busy.delete(key);
    statusCache.at = 0; // force a fresh status read
  }

  if (result.needsForce) {
    return sendJson(res, 409, { needsForce: true, dependents: result.dependents || [] });
  }

  await audit({
    action,
    service: svc.name,
    force,
    ok: Boolean(result.ok),
    state: result.state || null,
    dependents: result.dependents || [],
    error: result.error || null,
    ...who,
  });

  if (!result.ok) return sendJson(res, 500, { error: friendlyControlError(result.error || 'Action failed') });
  return sendJson(res, 200, { ok: true, state: result.state, dependents: result.dependents || [] });
}

// ---------- history, sites, security ----------

const history = createHistory({
  file: path.join(STATE_DIR, 'history.json'),
  getStatus,
  serviceNames: config.services.map((s) => s.name),
  log,
});

const sites = createSites({ sites: config.sites, file: path.join(STATE_DIR, 'sites.json'), log });

let maintenanceCache = { at: 0, value: undefined };

async function readCollected() {
  if (MOCK && !fs.existsSync(COLLECTED_FILE)) return { data: require('./lib/mock-collected').mockCollected(), error: null };
  return loadCollected(COLLECTED_FILE);
}

async function getMaintenance() {
  if (maintenanceCache.value !== undefined && Date.now() - maintenanceCache.at < 60e3) return maintenanceCache.value;
  let value = null;
  try {
    const r = await readCollected();
    value = r.data && r.data.maintenance ? r.data.maintenance : null;
  } catch {
    value = null;
  }
  maintenanceCache = { at: Date.now(), value };
  return value;
}

function alertSnapshot(status, siteList, security) {
  const services = {};
  for (const svc of config.services) {
    const row = status.byName.get(svc.name.toLowerCase());
    services[svc.name] = { label: svc.label, state: row ? row.state : 'Not installed' };
  }
  const sitesState = {};
  for (const site of siteList) {
    const up = site.last ? Boolean(site.last.up) : null;
    let detail = null;
    if (site.last && !site.last.up) detail = site.last.error || (site.last.code ? `HTTP ${site.last.code}` : null);
    sitesState[site.name] = { up, band: certBand(site), detail };
  }
  const ports = security && security.ports
    ? security.ports.rows.filter((r) => r.status === 'open-unexpected').map((r) => `${r.port}/${String(r.proto).toLowerCase()}`).sort()
    : [];
  const stale = Boolean(security && security.collectorError && security.collectorAt);
  return {
    services,
    sites: sitesState,
    ports,
    collectorStale: !security || !security.collectorAt || stale,
    collectorDetail: security && security.collectorError ? security.collectorError : null,
  };
}

const notify = createNotify({
  file: path.join(STATE_DIR, 'notify.json'),
  url: config.notify.url,
  token: config.notify.token,
  log,
  observe: async () => {
    const status = await getStatus(false);
    const security = await getSecurity();
    return alertSnapshot(status, sites.summary(), security);
  },
});

let securityCache = { at: 0, data: null, pending: null };

async function getSecurity() {
  if (securityCache.data && Date.now() - securityCache.at < 30e3) return securityCache.data;
  if (securityCache.pending) return securityCache.pending;
  securityCache.pending = (async () => {
    let collected;
    let collectedError = null;
    if (MOCK && !fs.existsSync(COLLECTED_FILE)) {
      collected = require('./lib/mock-collected').mockCollected();
    } else {
      const r = await loadCollected(COLLECTED_FILE);
      collected = r.data;
      collectedError = r.error;
    }
    const attacks = await buildAttacks({
      collected,
      collectedError,
      mariadbLog: config.mariadbLog,
      caddyLogs: config.caddyLogs,
      trusted: config.trustedIps,
    });
    if (collected && Array.isArray(collected.errors)) {
      for (const e of collected.errors) attacks.notes.push({ level: 'warn', text: `Collector: ${e}` });
    }
    const data = {
      generatedAt: new Date().toISOString(),
      collectorAt: collected ? collected.generatedAt : null,
      collectorError: collectedError,
      ports: buildPorts(collected, config.expectedPublicPorts),
      attacks,
      trustedIps: [...config.trustedIps],
    };
    securityCache = { at: Date.now(), data, pending: null };
    return data;
  })().finally(() => {
    securityCache.pending = null;
  });
  return securityCache.pending;
}

// ---------- logs ----------

async function resolveLogs(service) {
  const files = [];
  const seen = new Set();
  const add = (f) => {
    const key = f.path.toLowerCase();
    if (!seen.has(key)) {
      seen.add(key);
      files.push(f);
    }
  };

  for (const entry of service.logs) {
    const p = path.resolve(String(entry));
    let st;
    try {
      st = await fsp.stat(p);
    } catch (e) {
      add({ path: p, name: path.basename(p), missing: true, error: e.code });
      continue;
    }

    if (st.isDirectory()) {
      let names;
      try {
        names = await fsp.readdir(p);
      } catch (e) {
        add({ path: p, name: `${path.basename(p)}/`, missing: true, error: e.code });
        continue;
      }
      const found = [];
      for (const n of names) {
        if (!LOG_EXTENSIONS.has(path.extname(n).toLowerCase())) continue;
        const full = path.join(p, n);
        try {
          const fst = await fsp.stat(full);
          if (fst.isFile()) found.push({ path: full, name: n, size: fst.size, mtime: fst.mtimeMs });
        } catch {
          // skip files we can't stat
        }
      }
      found.sort((a, b) => b.mtime - a.mtime);
      found.slice(0, MAX_FILES_PER_DIR).forEach(add);
    } else if (st.isFile()) {
      add({ path: p, name: path.basename(p), size: st.size, mtime: st.mtimeMs });
    }
  }
  return files;
}

async function tailFile(filePath, wanted) {
  const { size, truncated, lines } = await readTailLines(filePath, MAX_TAIL_BYTES);
  return {
    size,
    totalLinesRead: lines.length,
    truncated: truncated || lines.length > wanted,
    lines: lines.slice(-wanted),
  };
}

// ---------- http ----------

const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/theme.js': ['theme.js', 'text/javascript; charset=utf-8'],
  '/style.css': ['style.css', 'text/css; charset=utf-8'],
  '/charts.js': ['charts.js', 'text/javascript; charset=utf-8'],
  '/pages.js': ['pages.js', 'text/javascript; charset=utf-8'],
};

const SECURITY_HEADERS = {
  'Content-Security-Policy':
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

function send(res, status, body, type) {
  res.writeHead(status, { 'Content-Type': type, ...SECURITY_HEADERS });
  res.end(body);
}

function sendJson(res, status, obj) {
  send(res, status, JSON.stringify(obj), 'application/json; charset=utf-8');
}

function friendlyFsError(code) {
  if (code === 'EACCES' || code === 'EPERM') return 'No read access. Re-run install.ps1 to grant the dashboard read access to this folder.';
  if (code === 'ENOENT') return 'File or folder not found. Check the path in config.json.';
  if (code === 'EBUSY') return 'File is locked by another process.';
  return code || 'Unknown error';
}

async function handleServices(res) {
  let status = { byName: new Map(), system: null };
  let statusError = null;
  let maintenance = null;
  try {
    status = await getStatus(false);
  } catch (e) {
    statusError = e.message;
  }
  try {
    maintenance = await getMaintenance();
  } catch {
    maintenance = null;
  }

  const services = await Promise.all(
    config.services.map(async (s) => {
      const st = status.byName.get(s.name.toLowerCase());
      const logs = await resolveLogs(s);
      const action = busy.get(s.name.toLowerCase()) || null;
      return {
        name: s.name,
        label: s.label,
        installed: Boolean(st),
        state: st ? st.state : statusError ? 'Unknown' : 'Not installed',
        startMode: st ? st.startMode : null,
        account: st ? st.account : null,
        pid: st ? st.pid : null,
        process: st ? st.process : null,
        memoryMB: st ? st.memoryMB : null,
        cpuPercent: st ? st.cpuPercent : null,
        startedAt: st ? st.startedAt : null,
        dependents: st && Array.isArray(st.dependents) ? st.dependents : [],
        controllable: s.controllable && Boolean(st),
        isSelf: s.isSelf,
        confirmNote: s.confirmNote,
        busy: action,
        logs: logs.map((f, i) => ({
          id: i,
          name: f.name,
          path: f.path,
          size: f.size ?? null,
          mtime: f.mtime ?? null,
          missing: Boolean(f.missing),
          error: f.error ? friendlyFsError(f.error) : null,
        })),
      };
    })
  );

  sendJson(res, 200, {
    generatedAt: new Date().toISOString(),
    mock: MOCK,
    statusError,
    system: status.system,
    maintenance,
    services,
  });
}

async function handleLog(res, serviceName, index, url) {
  const service = serviceByName.get(String(serviceName).toLowerCase());
  if (!service) return sendJson(res, 404, { error: 'Unknown service' });

  const files = await resolveLogs(service);
  const file = files[index];
  if (!file) return sendJson(res, 404, { error: 'Unknown log file' });
  if (file.missing) return sendJson(res, 404, { error: friendlyFsError(file.error), path: file.path });

  const requested = parseInt(url.searchParams.get('lines') || '500', 10);
  const wanted = Math.min(Math.max(Number.isFinite(requested) ? requested : 500, 10), MAX_LINES);

  try {
    const result = await tailFile(file.path, wanted);
    sendJson(res, 200, { name: file.name, path: file.path, mtime: file.mtime, ...result });
  } catch (e) {
    sendJson(res, e.code === 'ENOENT' ? 404 : 500, { error: friendlyFsError(e.code), path: file.path });
  }
}

async function handleStatic(res, pathname) {
  const entry = STATIC[pathname];
  if (!entry) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
  try {
    const body = await fsp.readFile(path.join(PUBLIC_DIR, entry[0]));
    send(res, 200, body, entry[1]);
  } catch {
    send(res, 500, 'Missing static file', 'text/plain; charset=utf-8');
  }
}

const server = http.createServer(async (req, res) => {
  try {
    // Reject unexpected Host headers (blocks DNS-rebinding tricks).
    const host = String(req.headers.host || '').toLowerCase();
    if (config.allowedHosts.length && !config.allowedHosts.includes(host)) {
      return send(res, 421, 'Misdirected request', 'text/plain; charset=utf-8');
    }

    const url = new URL(req.url, 'http://localhost');
    const p = url.pathname;

    if (req.method === 'POST') {
      const c = p.match(/^\/api\/services\/([A-Za-z0-9_.-]+)\/(start|stop|restart)$/);
      if (c) return await handleControl(req, res, c[1], c[2]);
      if (p === '/api/sites/check') {
        if (!isSameOriginRequest(req)) return sendJson(res, 403, { error: 'Request rejected (cross-site check failed).' });
        await sites.checkNow();
        return sendJson(res, 200, { generatedAt: new Date().toISOString(), sites: sites.summary() });
      }
      return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      return send(res, 405, 'Method not allowed', 'text/plain; charset=utf-8');
    }

    if (p === '/api/services') return await handleServices(res);
    if (p === '/api/history') return sendJson(res, 200, { mock: MOCK, ...history.snapshot() });
    if (p === '/api/sites') return sendJson(res, 200, { generatedAt: new Date().toISOString(), sites: sites.summary() });
    if (p === '/api/security') return sendJson(res, 200, { mock: MOCK, ...(await getSecurity()) });

    const m = p.match(/^\/api\/logs\/([A-Za-z0-9_.-]+)\/(\d{1,3})$/);
    if (m) return await handleLog(res, m[1], parseInt(m[2], 10), url);

    if (p === '/healthz') return send(res, 200, 'ok', 'text/plain; charset=utf-8');

    return await handleStatic(res, p);
  } catch (e) {
    console.error(new Date().toISOString(), 'Request error:', e);
    if (!res.headersSent) sendJson(res, 500, { error: 'Internal error' });
  }
});

server.listen(config.port, config.host, () => {
  log(`Service dashboard on http://${config.host}:${config.port}` + (MOCK ? ' (mock status data)' : ''));
  history.start().catch((e) => log(`History failed to start: ${e.message}`));
  sites.start().catch((e) => log(`Site checks failed to start: ${e.message}`));
  notify.start().catch((e) => log(`Notifications failed to start: ${e.message}`));
});

function shutdown() {
  history.stop();
  sites.stop();
  notify.stop();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 3000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
