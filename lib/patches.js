'use strict';

// Compares installed runtimes with the current patch in their release line.
// Version commands are a fixed list, run with execFile (never a shell). An exe
// path comes from that search or from a config path that passed isSafeExe.
// Release data is fetched only from endoflife.date, nodejs.org, and api.github.com.

const fs = require('fs');
const { execFile } = require('child_process');
const path = require('path');
const https = require('https');
const { readJson, writeJsonAtomic } = require('./util');

const LOCAL_TTL_MS = 10 * 60 * 1000;
const FEED_TTL_MS = 6 * 60 * 60 * 1000;
const FEED_HOSTS = new Set(['endoflife.date', 'www.endoflife.date', 'nodejs.org', 'api.github.com']);
const NOTES_HOSTS = new Set([
  'github.com',
  'nodejs.org',
  'php.net',
  'www.php.net',
  'mariadb.com',
  'www.mariadb.com',
  'mariadb.org',
  'www.mariadb.org',
  'go.dev',
  'nginx.org',
  'www.nginx.org',
  'www.postgresql.org',
  'python.org',
  'www.python.org',
  'redis.io',
  'caddyserver.com',
  'endoflife.date',
]);

const CATALOG = [
  { id: 'nodejs', label: 'Node.js', source: 'endoflife', product: 'nodejs', securityFeed: true, args: ['--version'] },
  { id: 'php', label: 'PHP', source: 'endoflife', product: 'php', args: ['--version'] },
  { id: 'mariadb', label: 'MariaDB', source: 'endoflife', product: 'mariadb', args: ['--version'] },
  { id: 'mysql', label: 'MySQL', source: 'endoflife', product: 'mysql', args: ['--version'] },
  { id: 'caddy', label: 'Caddy', source: 'endoflife', product: 'caddy', args: ['version'] },
  { id: 'gitea', label: 'Gitea', source: 'github', repo: 'go-gitea/gitea', args: ['--version'] },
  { id: 'python', label: 'Python', source: 'endoflife', product: 'python', args: ['--version'] },
  { id: 'go', label: 'Go', source: 'endoflife', product: 'go', args: ['version'] },
  { id: 'nginx', label: 'nginx', source: 'endoflife', product: 'nginx', args: ['-v'] },
  { id: 'postgresql', label: 'PostgreSQL', source: 'endoflife', product: 'postgresql', args: ['--version'] },
  { id: 'redis', label: 'Redis', source: 'endoflife', product: 'redis', args: ['--version'] },
];

const BY_ID = new Map(CATALOG.map((p) => [p.id, p]));

function isSafeExe(p) {
  if (typeof p !== 'string') return false;
  if (p.length < 7 || p.length > 260) return false;
  // execFile does not use a shell, but reject metacharacters so a path cannot
  // be mistaken for a command line if this is ever invoked differently.
  if (/[\0\r\n"<>|*?&;%`]/.test(p)) return false;
  if (/(^|[\\/])\.\.([\\/]|$)/.test(p)) return false;
  return /^[A-Za-z]:[\\/][^:*?"<>|\r\n&;%`]+\.exe$/i.test(p);
}

function normalizePatchConfig(value) {
  if (value === undefined || value === null) return { explicit: false, items: [] };
  if (!Array.isArray(value)) throw new Error('config.json "patches" must be an array');
  const items = [];
  const seen = new Set();
  for (const entry of value) {
    const id = typeof entry === 'string' ? entry : entry && entry.id;
    if (!BY_ID.has(id)) {
      throw new Error(`Unknown patch product in config: ${JSON.stringify(id)}. Known: ${CATALOG.map((p) => p.id).join(', ')}`);
    }
    if (seen.has(id)) throw new Error(`Duplicate patch product in config: ${id}`);
    seen.add(id);
    let exe = null;
    if (entry && typeof entry === 'object' && entry.exe != null && String(entry.exe).trim() !== '') {
      exe = String(entry.exe).trim();
      if (!isSafeExe(exe)) throw new Error(`Invalid exe path for ${id} in config.json`);
    }
    items.push({ id, exe });
  }
  return { explicit: true, items };
}

function parseVersion(text) {
  const s = String(text == null ? '' : text);
  let m = /(?:^|[^0-9])(\d{1,4})\.(\d{1,4})\.(\d{1,4})(?!\d)/.exec(s);
  if (m) {
    const parts = [Number(m[1]), Number(m[2]), Number(m[3])];
    if (parts.every((n) => n === 0)) return null;
    return { text: parts.join('.'), parts };
  }
  m = /(?:^|[^0-9])(\d{1,4})\.(\d{1,4})(?!\.\d)(?!\d)/.exec(s);
  if (!m) return null;
  const major = Number(m[1]);
  const minor = Number(m[2]);
  if (major === 0 && minor === 0) return null;
  return { text: `${major}.${minor}`, parts: [major, minor, 0] };
}

function compareVersions(a, b) {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const d = (a[i] || 0) - (b[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

function cycleParts(name) {
  const m = String(name == null ? '' : name).trim().match(/^(\d+)(?:\.(\d+))?$/);
  if (!m) return null;
  return m[2] === undefined ? [Number(m[1])] : [Number(m[1]), Number(m[2])];
}

function pickCycle(parts, cycles) {
  let best = null;
  let bestLen = 0;
  for (const cycle of cycles || []) {
    const cp = cycleParts(cycle.name);
    if (!cp || cp.length > parts.length || cp.length <= bestLen) continue;
    let ok = true;
    for (let i = 0; i < cp.length; i++) if (cp[i] !== parts[i]) ok = false;
    if (ok) {
      best = cycle;
      bestLen = cp.length;
    }
  }
  return best;
}

function dateOnly(value) {
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(String(value || ''));
  return m ? m[1] : null;
}

function safeNotesUrl(raw) {
  if (!raw) return null;
  let url;
  try {
    url = new URL(String(raw));
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.username || url.password) return null;
  if (!NOTES_HOSTS.has(url.hostname.toLowerCase())) return null;
  return url.toString();
}

function newestMaintained(cycles, exceptName) {
  const mine = exceptName ? cycleParts(exceptName) : null;
  let best = null;
  for (const cycle of cycles) {
    if (cycle.eol || cycle.name === exceptName) continue;
    const cp = cycleParts(cycle.name);
    if (!cp) continue;
    if (mine && compareVersions(cp, mine) <= 0) continue;
    if (!best || compareVersions(cp, cycleParts(best.name)) > 0) best = cycle;
  }
  return best;
}

function securityReleaseCount(list, installed) {
  let n = 0;
  for (const rel of list) {
    const parsed = parseVersion(rel.version);
    if (!parsed || parsed.parts[0] !== installed[0]) continue;
    if (compareVersions(parsed.parts, installed) > 0) n++;
  }
  return n;
}

function newerLineOf(cycle) {
  if (!cycle) return null;
  return { label: cycle.label || cycle.name, latest: cycle.latest };
}

// feed.cycles are endoflife lines, or for Gitea the recent GitHub minors.
// The two newest Gitea minors are marked maintained; older ones are eol.
function assessFeed(versionText, feed, securityList) {
  const installed = parseVersion(versionText);
  const base = {
    version: installed ? installed.text : null,
    latest: null,
    latestDate: null,
    notesUrl: null,
    line: null,
    lineLabel: null,
    lts: false,
    supportLabel: (feed && feed.supportLabel) || 'Security support',
    supportUntil: null,
    supportEnded: false,
    activeSupportLabel: (feed && feed.activeLabel) || null,
    activeSupportEnded: null,
    securityReleases: null,
    newerLine: null,
    unmatched: false,
    error: null,
  };
  if (!installed) return { ...base, status: 'error', error: 'Could not read a version number' };
  const cycles = (feed && feed.cycles) || [];
  const cycle = pickCycle(installed.parts, cycles);
  if (!cycle && cycles.length) {
    const newest = newestMaintained(cycles) || [...cycles].sort((a, b) => compareVersions(cycleParts(b.name) || [0], cycleParts(a.name) || [0]))[0];
    const newestParts = newest && parseVersion(newest.latest);
    if (newestParts && compareVersions(installed.parts, newestParts.parts) < 0) {
      if (Array.isArray(securityList)) base.securityReleases = securityReleaseCount(securityList, installed.parts);
      return {
        ...base,
        status: 'eol',
        latest: newest.latest,
        latestDate: newest.latestDate || null,
        notesUrl: safeNotesUrl(newest.link),
        supportEnded: true,
        unmatched: true,
      };
    }
  }
  if (!cycle) return { ...base, status: 'current', latest: installed.text };
  const latest = parseVersion(cycle.latest) || installed;
  const cmp = compareVersions(installed.parts, latest.parts);
  let status = 'current';
  if (cycle.eol) status = 'eol';
  else if (cmp < 0) status = 'behind';
  if (Array.isArray(securityList)) base.securityReleases = securityReleaseCount(securityList, installed.parts);
  return {
    ...base,
    status,
    latest: latest.text,
    latestDate: cycle.latestDate || null,
    notesUrl: safeNotesUrl(cycle.link),
    line: cycle.name,
    lineLabel: cycle.label || cycle.name,
    lts: Boolean(cycle.lts),
    supportUntil: cycle.eolFrom || null,
    supportEnded: Boolean(cycle.eol),
    activeSupportEnded: !cycle.eol && cycle.eoas && cycle.eoasFrom ? cycle.eoasFrom : null,
    newerLine: newerLineOf(newestMaintained(cycles, cycle.name)),
  };
}

function normalizeCycles(body) {
  const releases = body && body.result && Array.isArray(body.result.releases) ? body.result.releases : null;
  if (!releases) throw new Error('Unexpected release feed');
  const labels = body.result.labels || {};
  const cycles = [];
  for (const row of releases) {
    if (!row || row.latest == null || row.latest.name == null) continue;
    const latest = parseVersion(row.latest.name);
    if (!latest || !cycleParts(row.name)) continue;
    cycles.push({
      name: String(row.name),
      label: row.label ? String(row.label) : String(row.name),
      lts: Boolean(row.isLts),
      eol: Boolean(row.isEol),
      eolFrom: dateOnly(row.eolFrom),
      eoas: Boolean(row.isEoas),
      eoasFrom: dateOnly(row.eoasFrom),
      latest: latest.text,
      latestDate: dateOnly(row.latest.date),
      link: row.latest.link || null,
    });
  }
  if (!cycles.length) throw new Error('Release feed had no versions');
  return {
    supportLabel: labels.eol ? String(labels.eol) : 'Security support',
    activeLabel: labels.eoas ? String(labels.eoas) : 'Active support',
    cycles,
  };
}

function cyclesFromReleases(releases) {
  if (!Array.isArray(releases)) throw new Error('Unexpected release list');
  const map = new Map();
  for (const row of releases) {
    if (!row || row.draft || row.prerelease) continue;
    const tag = String(row.tag_name || '');
    if (/-(rc|alpha|beta|preview|dev)\d*$/i.test(tag)) continue;
    const parsed = parseVersion(tag);
    if (!parsed) continue;
    const key = `${parsed.parts[0]}.${parsed.parts[1]}`;
    const prev = map.get(key);
    if (prev && compareVersions(parsed.parts, prev.parts) <= 0) continue;
    map.set(key, {
      name: key,
      label: key,
      lts: false,
      latest: parsed.text,
      latestDate: dateOnly(row.published_at),
      link: row.html_url || null,
      parts: parsed.parts,
    });
  }
  const cycles = [...map.values()].sort((a, b) => compareVersions(b.parts, a.parts));
  if (!cycles.length) throw new Error('Release list had no versions');
  const maintained = new Set(cycles.slice(0, 2).map((c) => c.name));
  for (const cycle of cycles) {
    cycle.eol = !maintained.has(cycle.name);
    cycle.eolFrom = null;
    cycle.eoas = false;
    cycle.eoasFrom = null;
    delete cycle.parts;
  }
  return { supportLabel: 'Supported release', activeLabel: null, cycles };
}

function normalizeSecurityReleases(list) {
  if (!Array.isArray(list)) throw new Error('Unexpected Node.js release index');
  const out = [];
  for (const row of list) {
    if (!row || !row.security) continue;
    const parsed = parseVersion(row.version);
    if (!parsed) continue;
    out.push({ version: parsed.text, date: dateOnly(row.date) });
  }
  return out;
}

function fetchJson(url, options = {}) {
  const redirectsLeft = options.redirectsLeft == null ? 3 : options.redirectsLeft;
  const maxBytes = options.maxBytes || 2 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(url);
    } catch (e) {
      reject(e);
      return;
    }
    if (target.protocol !== 'https:' || !FEED_HOSTS.has(target.hostname)) {
      reject(new Error('Unexpected release feed host'));
      return;
    }
    const headers = { 'User-Agent': 'svcdash', Accept: 'application/json', ...options.headers };
    const req = https.request(target, { method: 'GET', headers, timeout: 12000 }, (res) => {
      const code = res.statusCode || 0;
      if (code >= 300 && code < 400 && res.headers.location) {
        res.resume();
        if (redirectsLeft <= 0) {
          reject(new Error('Too many redirects'));
          return;
        }
        let next;
        try {
          next = new URL(res.headers.location, target);
        } catch (e) {
          reject(e);
          return;
        }
        fetchJson(next, { ...options, redirectsLeft: redirectsLeft - 1, maxBytes }).then(resolve, reject);
        return;
      }
      if (code < 200 || code >= 300) {
        res.resume();
        reject(new Error(`HTTP ${code}`));
        return;
      }
      const chunks = [];
      let size = 0;
      let settled = false;
      const fail = (err) => {
        if (settled) return;
        settled = true;
        reject(err);
      };
      res.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxBytes) {
          fail(new Error('Response too large'));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        if (settled) return;
        settled = true;
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
        } catch {
          reject(new Error('Could not parse the release feed'));
        }
      });
      res.on('error', fail);
    });
    req.on('timeout', () => req.destroy(new Error('Timed out')));
    req.on('error', reject);
    req.end();
  });
}

function clip(text) {
  return String(text || 'Unknown error').replace(/\s+/g, ' ').trim().slice(0, 240);
}

function runPowerShell(script, timeout) {
  return new Promise((resolve, reject) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
      { timeout, maxBuffer: 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        if (err) {
          reject(new Error(clip(stderr || err.message)));
          return;
        }
        try {
          resolve(JSON.parse(String(stdout).replace(/^\uFEFF/, '').trim() || 'null'));
        } catch {
          reject(new Error('Could not parse version discovery'));
        }
      }
    );
  });
}

const DISCOVER_SCRIPT = [
  "$ErrorActionPreference = 'SilentlyContinue'",
  "$ProgressPreference = 'SilentlyContinue'",
  "$result = [ordered]@{",
  "  nodejs = $null; php = $null; mariadb = $null; mysql = $null; caddy = $null; gitea = $null",
  "  python = $null; go = $null; nginx = $null; postgresql = $null; redis = $null",
  "}",
  "function Test-Exe([string]$path) {",
  "  if (-not $path) { return $false }",
  "  if (-not $path.ToLower().EndsWith('.exe')) { return $false }",
  "  if ($path -match '\\\\WindowsApps\\\\') { return $false }",
  "  return Test-Path -LiteralPath $path",
  "}",
  "function Get-QuotedOrFirst([string]$raw) {",
  "  if (-not $raw) { return $null }",
  "  if ($raw.StartsWith([char]34)) {",
  "    $end = $raw.IndexOf([char]34, 1)",
  "    if ($end -gt 1) { return $raw.Substring(1, $end - 1) }",
  "    return $null",
  "  }",
  "  return ($raw -split '\\s+', 2)[0]",
  "}",
  "function Get-CommandExe([string]$name) {",
  "  $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1",
  "  if ($cmd -and (Test-Exe ([string]$cmd.Source))) { return [string]$cmd.Source }",
  "  return $null",
  "}",
  "function Get-VersionKey([string]$name) {",
  "  $m = [regex]::Match($name, '(\\d+)(?:\\.(\\d+))?')",
  "  if (-not $m.Success) { return 0 }",
  "  $minor = 0",
  "  if ($m.Groups[2].Success) { $minor = [int]$m.Groups[2].Value }",
  "  return [int]$m.Groups[1].Value * 1000 + $minor",
  "}",
  "function Get-ServiceExe([string]$pattern, [string]$exclude) {",
  "  foreach ($svc in $services) {",
  "    $raw = [string]$svc.PathName",
  "    if (-not $raw) { continue }",
  "    if ($exclude -and $raw -match $exclude) { continue }",
  "    if ($raw -notmatch $pattern) { continue }",
  "    $exe = Get-QuotedOrFirst $raw",
  "    if (Test-Exe $exe) { return $exe }",
  "  }",
  "  return $null",
  "}",
  "function Get-Highest([string]$root, [string]$filter, [string]$leaf) {",
  "  if (-not (Test-Path -LiteralPath $root)) { return $null }",
  "  $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Filter $filter -ErrorAction SilentlyContinue)",
  "  $dirs = @($dirs | Sort-Object { Get-VersionKey $_.Name } -Descending)",
  "  foreach ($dir in $dirs) {",
  "    $exe = Join-Path $dir.FullName $leaf",
  "    if (Test-Exe $exe) { return $exe }",
  "  }",
  "  return $null",
  "}",
  "try {",
  "  $services = @(Get-CimInstance Win32_Service)",
  "  $nodeReg = @(",
  "    (Get-ItemProperty 'HKLM:\\SOFTWARE\\Node.js' -ErrorAction SilentlyContinue).InstallPath,",
  "    (Get-ItemProperty 'HKLM:\\SOFTWARE\\WOW6432Node\\Node.js' -ErrorAction SilentlyContinue).InstallPath",
  "  )",
  "  foreach ($dir in $nodeReg) {",
  "    if (-not $dir) { continue }",
  "    $exe = Join-Path ([string]$dir) 'node.exe'",
  "    if (Test-Exe $exe) { $result.nodejs = $exe; break }",
  "  }",
  "  if (-not $result.nodejs) { $result.nodejs = Get-CommandExe 'node' }",
  "  if (-not $result.nodejs) {",
  "    $known = Join-Path $env:ProgramFiles 'nodejs\\node.exe'",
  "    if (Test-Exe $known) { $result.nodejs = $known }",
  "  }",
  "  foreach ($candidate in @('C:\\php\\php.exe', (Join-Path $env:ProgramFiles 'PHP\\php.exe'))) {",
  "    if (Test-Exe $candidate) { $result.php = $candidate; break }",
  "  }",
  "  if (-not $result.php) { $result.php = Get-Highest (Join-Path $env:ProgramFiles 'PHP') '*' 'php.exe' }",
  "  if (-not $result.php) { $result.php = Get-CommandExe 'php' }",
  "  $result.mariadb = Get-ServiceExe 'mariadbd\\.exe' ''",
  "  if (-not $result.mariadb) { $result.mariadb = Get-ServiceExe 'MariaDB.*mysqld\\.exe' '' }",
  "  if (-not $result.mariadb) {",
  "    $exe = Get-Highest $env:ProgramFiles 'MariaDB*' 'bin\\mariadbd.exe'",
  "    if (-not $exe) { $exe = Get-Highest $env:ProgramFiles 'MariaDB*' 'bin\\mysqld.exe' }",
  "    $result.mariadb = $exe",
  "  }",
  "  if (-not $result.mariadb) { $result.mariadb = Get-CommandExe 'mariadbd' }",
  "  $result.mysql = Get-ServiceExe 'mysqld\\.exe' 'MariaDB'",
  "  if (-not $result.mysql) { $result.mysql = Get-Highest (Join-Path $env:ProgramFiles 'MySQL') '*' 'bin\\mysqld.exe' }",
  "  if (-not $result.mysql) {",
  "    $cmd = Get-CommandExe 'mysqld'",
  "    if ($cmd -and $cmd -notmatch 'MariaDB') { $result.mysql = $cmd }",
  "  }",
  "  $result.caddy = Get-ServiceExe 'caddy\\.exe' ''",
  "  if (-not $result.caddy -and (Test-Exe 'C:\\apps\\Caddy\\caddy.exe')) { $result.caddy = 'C:\\apps\\Caddy\\caddy.exe' }",
  "  if (-not $result.caddy) { $result.caddy = Get-CommandExe 'caddy' }",
  "  $result.gitea = Get-ServiceExe 'gitea\\.exe' ''",
  "  if (-not $result.gitea -and (Test-Exe 'C:\\apps\\gitea\\gitea.exe')) { $result.gitea = 'C:\\apps\\gitea\\gitea.exe' }",
  "  if (-not $result.gitea) { $result.gitea = Get-CommandExe 'gitea' }",
  "  $result.python = Get-CommandExe 'py'",
  "  if (-not $result.python) { $result.python = Get-CommandExe 'python' }",
  "  if (-not $result.python) { $result.python = Get-Highest $env:ProgramFiles 'Python*' 'python.exe' }",
  "  if (-not $result.python) { $result.python = Get-Highest 'C:\\' 'Python*' 'python.exe' }",
  "  $go = Join-Path $env:ProgramFiles 'Go\\bin\\go.exe'",
  "  if (Test-Exe $go) { $result.go = $go } else { $result.go = Get-CommandExe 'go' }",
  "  $result.nginx = Get-ServiceExe 'nginx\\.exe' ''",
  "  if (-not $result.nginx -and (Test-Exe 'C:\\nginx\\nginx.exe')) { $result.nginx = 'C:\\nginx\\nginx.exe' }",
  "  if (-not $result.nginx) { $result.nginx = Get-CommandExe 'nginx' }",
  "  $result.postgresql = Get-ServiceExe 'postgres\\.exe' ''",
  "  if (-not $result.postgresql) { $result.postgresql = Get-Highest (Join-Path $env:ProgramFiles 'PostgreSQL') '*' 'bin\\postgres.exe' }",
  "  $result.redis = Get-ServiceExe 'redis-server\\.exe' ''",
  "  if (-not $result.redis -and (Test-Exe (Join-Path $env:ProgramFiles 'Redis\\redis-server.exe'))) { $result.redis = Join-Path $env:ProgramFiles 'Redis\\redis-server.exe' }",
  "  if (-not $result.redis) { $result.redis = Get-Highest (Join-Path $env:ProgramFiles 'Redis') '*' 'redis-server.exe' }",
  "  if (-not $result.redis) { $result.redis = Get-CommandExe 'redis-server' }",
  "} catch { }",
  "ConvertTo-Json -Compress -InputObject ([pscustomobject]$result)",
].join('\n');

function versionArgs(product, exe) {
  if (product.id === 'python' && path.basename(exe).toLowerCase() === 'py.exe') return ['-3', '--version'];
  return product.args;
}

function readVersion(product, exe) {
  if (product.id === 'nodejs' && path.resolve(exe) === path.resolve(process.execPath)) {
    const parsed = parseVersion(process.version);
    if (parsed) return Promise.resolve({ missing: false, version: parsed.text, path: exe, error: null });
  }
  return new Promise((resolve) => {
    execFile(exe, versionArgs(product, exe), {
      cwd: path.dirname(exe),
      timeout: 8000,
      windowsHide: true,
      maxBuffer: 256 * 1024,
    }, (err, stdout, stderr) => {
      const parsed = parseVersion(`${stdout || ''}\n${stderr || ''}`);
      if (parsed) resolve({ missing: false, version: parsed.text, path: exe, error: null });
      else resolve({ missing: false, version: null, path: exe, error: clip(err ? err.message : 'No version number in the output') });
    });
  });
}

function dashboardNodeExe() {
  const exe = process.execPath;
  const base = path.basename(exe).toLowerCase();
  if (base !== 'node' && base !== 'node.exe') return null;
  if (!isSafeExe(exe) || !fs.existsSync(exe)) return null;
  return exe;
}

async function discoverInstalled() {
  if (process.platform !== 'win32') return {};
  const found = await runPowerShell(DISCOVER_SCRIPT, 20000);
  const out = {};
  if (!found || typeof found !== 'object' || Array.isArray(found)) return out;
  for (const product of CATALOG) {
    const candidate = found[product.id];
    if (typeof candidate === 'string' && isSafeExe(candidate) && fs.existsSync(candidate)) out[product.id] = candidate;
  }
  return out;
}

async function probeOne(product, configuredExe, found, discoverError) {
  if (configuredExe) {
    if (!fs.existsSync(configuredExe)) return { missing: true, version: null, path: configuredExe, error: null };
    return readVersion(product, configuredExe);
  }
  if (found && found[product.id]) return readVersion(product, found[product.id]);
  if (product.id === 'nodejs') {
    const exe = dashboardNodeExe();
    if (exe) return readVersion(product, exe);
  }
  if (discoverError) return { missing: false, version: null, path: null, error: discoverError, searchFailed: true };
  return { missing: true, version: null, path: null, error: null };
}

function blank(product, extra) {
  return {
    id: product.id,
    label: product.label,
    status: 'missing',
    version: null,
    path: null,
    latest: null,
    latestDate: null,
    notesUrl: null,
    line: null,
    lineLabel: null,
    lts: false,
    supportLabel: 'Security support',
    supportUntil: null,
    supportEnded: false,
    activeSupportLabel: null,
    activeSupportEnded: null,
    securityReleases: null,
    newerLine: null,
    unmatched: false,
    error: null,
    stale: false,
    feedAt: null,
    alsoRunning: null,
    ...extra,
  };
}

function compose(product, local, feedEntry) {
  if (!local || local.missing) return blank(product, { path: local ? local.path : null });
  if (!local.version) {
    return blank(product, {
      status: 'error',
      path: local.path,
      error: local.error || 'Could not read the version',
      searchFailed: Boolean(local.searchFailed),
    });
  }
  let alsoRunning = null;
  if (product.id === 'nodejs' && local.path && dashboardNodeExe()) {
    const dash = parseVersion(process.version);
    if (dash && path.resolve(local.path) !== path.resolve(process.execPath) && dash.text !== local.version) alsoRunning = dash.text;
  }
  if (!feedEntry || !feedEntry.feed) {
    const why = feedEntry && feedEntry.error ? feedEntry.error : 'no response';
    return blank(product, {
      status: 'error',
      version: local.version,
      path: local.path,
      alsoRunning,
      error: `Couldn't reach the release feed (${why})`,
    });
  }
  const assessed = assessFeed(local.version, feedEntry.feed, product.securityFeed ? feedEntry.security : null);
  return blank(product, {
    ...assessed,
    path: local.path,
    stale: Boolean(feedEntry.stale),
    feedAt: feedEntry.at || null,
    alsoRunning,
  });
}

async function fetchFeed(product) {
  if (product.source === 'github') {
    if (!/^[\w.-]+\/[\w.-]+$/.test(product.repo)) throw new Error('Unexpected repository');
    const body = await fetchJson(`https://api.github.com/repos/${product.repo}/releases?per_page=50`, {
      headers: { Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' },
    });
    return cyclesFromReleases(body);
  }
  const body = await fetchJson(`https://endoflife.date/api/v1/products/${product.product}`);
  return normalizeCycles(body);
}

async function fetchNodeSecurity() {
  const body = await fetchJson('https://nodejs.org/dist/index.json');
  return normalizeSecurityReleases(body);
}

function sampleProducts() {
  return [
    {
      id: 'nodejs',
      label: 'Node.js',
      status: 'behind',
      version: '22.20.0',
      path: 'C:\\Program Files\\nodejs\\node.exe',
      latest: '22.23.5',
      latestDate: '2026-11-11',
      notesUrl: 'https://github.com/nodejs/node/blob/main/doc/changelogs/CHANGELOG_V22.md#22.23.5',
      line: '22',
      lineLabel: '22 (LTS)',
      lts: true,
      supportLabel: 'Security support',
      supportUntil: '2027-04-30',
      supportEnded: false,
      activeSupportLabel: 'Active support',
      activeSupportEnded: '2025-10-21',
      securityReleases: 2,
      newerLine: { label: '26 (LTS)', latest: '26.13.1' },
      error: null,
      stale: false,
      feedAt: null,
      alsoRunning: null,
    },
    {
      id: 'php',
      label: 'PHP',
      status: 'eol',
      version: '8.1.34',
      path: 'C:\\php\\php.exe',
      latest: '8.1.34',
      latestDate: '2025-12-18',
      notesUrl: 'https://www.php.net/ChangeLog-8.php#8.1.34',
      line: '8.1',
      lineLabel: '8.1',
      lts: false,
      supportLabel: 'Security support',
      supportUntil: '2025-12-31',
      supportEnded: true,
      activeSupportLabel: 'Active support',
      activeSupportEnded: null,
      securityReleases: null,
      newerLine: { label: '8.6', latest: '8.6.0' },
      error: null,
      stale: false,
      feedAt: null,
      alsoRunning: null,
    },
    {
      id: 'mariadb',
      label: 'MariaDB',
      status: 'behind',
      version: '11.4.9',
      path: 'C:\\Program Files\\MariaDB 11.4\\bin\\mariadbd.exe',
      latest: '11.4.14',
      latestDate: '2026-11-13',
      notesUrl: 'https://mariadb.com/docs/release-notes/community-server/changelogs/11.4/11.4.14',
      line: '11.4',
      lineLabel: '11.4 (LTS)',
      lts: true,
      supportLabel: 'Community support',
      supportUntil: '2029-05-29',
      supportEnded: false,
      activeSupportLabel: null,
      activeSupportEnded: null,
      securityReleases: null,
      newerLine: { label: '13.0', latest: '13.0.2' },
      error: null,
      stale: false,
      feedAt: null,
      alsoRunning: null,
    },
    {
      id: 'caddy',
      label: 'Caddy',
      status: 'current',
      version: '2.11.9',
      path: 'C:\\apps\\Caddy\\caddy.exe',
      latest: '2.11.9',
      latestDate: '2026-11-04',
      notesUrl: 'https://github.com/caddyserver/caddy/releases/tag/v2.11.9',
      line: '2',
      lineLabel: '2',
      lts: false,
      supportLabel: 'Security support',
      supportUntil: null,
      supportEnded: false,
      activeSupportLabel: null,
      activeSupportEnded: null,
      securityReleases: null,
      newerLine: null,
      error: null,
      stale: false,
      feedAt: null,
      alsoRunning: null,
    },
    {
      id: 'gitea',
      label: 'Gitea',
      status: 'eol',
      version: '1.27.3',
      path: 'C:\\apps\\gitea\\gitea.exe',
      latest: '1.27.3',
      latestDate: '2026-08-29',
      notesUrl: 'https://github.com/go-gitea/gitea/releases/tag/v1.27.3',
      line: '1.27',
      lineLabel: '1.27',
      lts: false,
      supportLabel: 'Supported release',
      supportUntil: null,
      supportEnded: true,
      activeSupportLabel: null,
      activeSupportEnded: null,
      securityReleases: null,
      newerLine: { label: '28.4', latest: '28.4.0' },
      error: null,
      stale: false,
      feedAt: null,
      alsoRunning: null,
    },
  ];
}

function createPatches({ items, explicit, file, mock, log }) {
  const wanted = explicit ? items : CATALOG.map((p) => ({ id: p.id, exe: null }));
  let cache = { localAt: null, local: {}, feeds: {} };
  let loaded = false;
  let tail = Promise.resolve();
  let timer = null;
  let lastSummary = '';

  function mockSummary() {
    const now = Date.now();
    return {
      generatedAt: new Date(now).toISOString(),
      mock: true,
      explicit: false,
      error: null,
      localAt: new Date(now - 2 * 60 * 1000).toISOString(),
      feedsAt: new Date(now - 3 * 3600 * 1000).toISOString(),
      products: sampleProducts(),
    };
  }

  async function load() {
    if (loaded || mock) {
      loaded = true;
      return;
    }
    loaded = true;
    try {
      const data = await readJson(file);
      if (data && data.local && data.feeds) cache = { localAt: data.localAt || null, local: data.local, feeds: data.feeds };
    } catch {
      cache = { localAt: null, local: {}, feeds: {} };
    }
  }

  async function save() {
    if (mock) return;
    try {
      await writeJsonAtomic(file, cache);
    } catch (e) {
      log(`Patch cache could not be saved: ${e.message}`);
    }
  }

  function feedsAtOf(products) {
    const times = products.map((p) => Date.parse(p.feedAt)).filter((t) => Number.isFinite(t));
    if (!times.length) return null;
    return new Date(Math.min(...times)).toISOString();
  }

  async function build(force) {
    await load();
    let discoverError = null;
    const localFresh = cache.localAt && Date.now() - Date.parse(cache.localAt) < LOCAL_TTL_MS;
    if (force || !localFresh) {
      let found = {};
      const needsSearch = wanted.some((item) => !item.exe);
      if (needsSearch) {
        try {
          found = await discoverInstalled();
        } catch (e) {
          discoverError = e.message;
        }
      }
      const local = {};
      await Promise.all(wanted.map(async (item) => {
        const product = BY_ID.get(item.id);
        local[item.id] = await probeOne(product, item.exe, found, discoverError);
      }));
      cache.local = local;
      cache.localAt = new Date().toISOString();
      await save();
    } else {
      discoverError = Object.values(cache.local).map((row) => (row && row.searchFailed ? row.error : null)).find(Boolean) || null;
    }

    const feedJobs = [];
    for (const item of wanted) {
      const local = cache.local[item.id];
      if (!local || !local.version) continue;
      const prev = cache.feeds[item.id];
      const fresh = prev && prev.feed && !prev.error && prev.at && Date.now() - Date.parse(prev.at) < FEED_TTL_MS;
      if (!force && fresh) continue;
      feedJobs.push((async () => {
        const product = BY_ID.get(item.id);
        try {
          const feed = await fetchFeed(product);
          let security = prev ? prev.security : null;
          if (product.securityFeed) {
            try {
              security = await fetchNodeSecurity();
            } catch (e) {
              log(`${product.label} security index: ${e.message}`);
            }
          }
          cache.feeds[item.id] = { at: new Date().toISOString(), feed, security: security || null, error: null, stale: false };
        } catch (e) {
          if (prev && prev.feed) cache.feeds[item.id] = { ...prev, error: e.message, stale: true };
          else cache.feeds[item.id] = { at: new Date().toISOString(), feed: null, security: null, error: e.message, stale: false };
          log(`${product.label} release feed: ${e.message}`);
        }
      })());
    }
    if (feedJobs.length) {
      await Promise.all(feedJobs);
      await save();
    }

    let products = wanted.map((item) => compose(BY_ID.get(item.id), cache.local[item.id], cache.feeds[item.id]));
    if (!explicit) products = products.filter((p) => p.status !== 'missing' && !p.searchFailed);
    products = products.map(({ searchFailed, ...rest }) => rest);
    return {
      generatedAt: new Date().toISOString(),
      mock: false,
      explicit,
      error: discoverError ? `Couldn't search this server for installed programs. ${discoverError}` : null,
      localAt: cache.localAt,
      feedsAt: feedsAtOf(products),
      products,
    };
  }

  function summary(force) {
    const run = tail.then(() => (mock ? mockSummary() : build(Boolean(force))));
    tail = run.then(() => undefined, () => undefined);
    return run;
  }

  function note(payload) {
    if (!payload || payload.mock) return;
    const behind = payload.products.filter((p) => p.status === 'behind').length;
    const eol = payload.products.filter((p) => p.status === 'eol').length;
    const line = `${behind} behind, ${eol} unsupported`;
    if (line === lastSummary) return;
    lastSummary = line;
    log(`Patch check: ${line}`);
  }

  function start() {
    if (mock) return;
    const arm = setTimeout(() => {
      summary(false).then(note).catch((e) => log(`Patch check failed: ${e.message}`));
    }, 5000);
    if (arm.unref) arm.unref();
    timer = setInterval(() => {
      summary(false).then(note).catch((e) => log(`Patch check failed: ${e.message}`));
    }, LOCAL_TTL_MS);
  }

  function stop() {
    clearInterval(timer);
    timer = null;
  }

  return { start, stop, summary };
}

module.exports = {
  createPatches,
  normalizePatchConfig,
  parseVersion,
  compareVersions,
  assessFeed,
  normalizeCycles,
  cyclesFromReleases,
  securityReleaseCount,
  safeNotesUrl,
  isSafeExe,
};
