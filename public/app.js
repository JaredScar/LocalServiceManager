'use strict';

// Service dashboard UI. Log content is untrusted (it contains request URLs and
// user input), so everything is rendered with textContent, never innerHTML.

const SERVICES_REFRESH_MS = 10000;
const FAST_REFRESH_MS = 2000;
const LOG_REFRESH_MS = 5000;

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = text;
  return n;
};

const state = {
  services: [],
  system: null,
  maintenance: null,
  selected: null, // service name
  fileId: null,
  lastLines: [],
  lastFileName: '',
  logTimer: null,
  svcTimer: null,
  fastUntil: 0,
  logGen: 0,
  pending: new Map(), // service name -> action started from this browser
  online: true,
};

// ---------- prefs (per-browser, optional) ----------

const prefs = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem('svcdash.' + key);
      return v === null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem('svcdash.' + key, JSON.stringify(value));
    } catch {
      /* storage unavailable */
    }
  },
};

// ---------- formatting ----------

function fmtDuration(iso) {
  if (!iso) return '—';
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  return `${m}m`;
}

function fmtBytes(n) {
  if (n === null || n === undefined) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

const fmtGB = (mb) => `${(mb / 1024).toFixed(mb >= 10240 ? 0 : 1)} GB`;
const fmtTime = (ms) => (ms ? new Date(ms).toLocaleString() : '');

function stateClass(s) {
  if (s === 'Running') return 'ok';
  if (s === 'Stopped') return 'bad';
  if (s === 'Not installed' || s === 'Unknown') return 'dim';
  return 'warn'; // Start Pending, Stop Pending, Paused…
}

const ACTION_VERB = { start: 'Starting…', stop: 'Stopping…', restart: 'Restarting…' };
const ACTION_DONE = { start: 'started', stop: 'stopped', restart: 'restarted' };
const ACTION_TITLE = { start: 'Start', stop: 'Stop', restart: 'Restart' };

// ---------- toasts ----------

function toast(text, kind = '') {
  const t = el('div', 'toast' + (kind ? ' ' + kind : ''), text);
  $('toasts').append(t);
  setTimeout(() => t.remove(), kind === 'bad' ? 12000 : 6000);
}

// ---------- API ----------

async function api(path, options) {
  const res = await fetch(path, { cache: 'no-store', ...options });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body.error || `HTTP ${res.status}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return body;
}

function postJson(path, body) {
  return api(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-SvcDash': '1' },
    body: JSON.stringify(body || {}),
  });
}

function postAction(name, action, force) {
  return postJson(`/api/services/${encodeURIComponent(name)}/${action}`, { force });
}

function numText(v) {
  const n = Math.round(Number(v) * 10) / 10;
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}

let usageHistory = null;
let usageLoading = null;
let deck = null;
function loadDeck() {
  if (deck) return Promise.resolve(deck);
  if (!usageLoading) {
    usageLoading = Promise.all([
      api('/api/history').catch(() => null),
      api('/api/sites').catch(() => null),
      api('/api/security').catch(() => null),
    ]).then(([history, sites, security]) => {
      deck = { history, sites, security };
      usageHistory = history;
      return deck;
    });
  }
  return usageLoading;
}
function loadUsage() {
  return loadDeck().then((d) => (d && d.history) || null);
}

function stoppedSince(name) {
  const row = usageHistory && usageHistory.services && usageHistory.services[name];
  if (!row || !row.cpu) return null;
  for (let i = row.cpu.length - 1; i > 0; i--) {
    if (typeof row.cpu[i] !== 'number' && typeof row.cpu[i - 1] === 'number') return usageHistory.times[i];
  }
  return null;
}

function siteHosts() {
  const sites = (deck && deck.sites && deck.sites.sites) || [];
  return sites.map((s) => {
    try { return new URL(s.url).host; } catch { return s.name; }
  });
}

function portsFor(name) {
  const rows = deck && deck.security && deck.security.ports ? deck.security.ports.rows : [];
  const ports = [];
  for (const r of rows) {
    if (r.status !== 'open-expected' && r.status !== 'open-unexpected') continue;
    if (!(r.services || []).some((n) => String(n).toLowerCase() === String(name).toLowerCase())) continue;
    if (!ports.includes(r.port)) ports.push(r.port);
  }
  return ports.sort((a, b) => a - b);
}

function fourthTile(s) {
  const web = portsFor(s.name).filter((p) => p === 80 || p === 443);
  if (web.length) {
    const hosts = siteHosts();
    return ['Connected to', hosts.length ? hosts.join(' and ') : 'the sites on this server', `public on ${web.map((p) => `:${p}`).join(' and ')}`];
  }
  const users = (s.dependents || []).filter((d) => d.status === 'Running').map((d) => {
    const found = state.services.find((x) => x.name.toLowerCase() === String(d.name).toLowerCase());
    return found ? found.label : d.name;
  });
  if (users.length) return ['Used by', users.join(', '), `needs ${s.label}`];
  return ['Account', s.account ? s.account.replace(/\\/g, '\\\u200b') : '—', s.startMode === 'Auto' ? 'starts automatically' : s.startMode || ''];
}

function storyFor(s) {
  if (!s || state.selected !== s.name || s.state !== 'Running') return;
  const parts = [];
  const web = portsFor(s.name).some((p) => p === 80 || p === 443);
  const hosts = siteHosts();
  if (web && hosts.length) parts.push(`Serving ${hosts.join(' and ')}.`);
  const row = usageHistory && usageHistory.services && usageHistory.services[s.name];
  const cpu = row && seriesPeakAt(row.cpu);
  if (cpu && cpu.peak >= 15 && usageHistory.times[cpu.at]) {
    const when = new Date(usageHistory.times[cpu.at]).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    parts.push(`Its busiest moment today was ${when}, when it hit ${numText(cpu.peak)}% CPU.`);
  }
  if (web) {
    const scans = (state.lastLines || []).filter((line) => SCAN_RE.test(line)).length;
    if (scans) parts.push(`${scans === 1 ? 'One scanner' : `${scans} scanners`} tried to fetch a sensitive path and were refused.`);
  }
  if (parts.length) $('v-sentence').textContent = parts.join(' ');
}

function seriesPeakAt(values) {
  let peak = null;
  let at = -1;
  (values || []).forEach((v, i) => {
    if (typeof v === 'number' && (peak === null || v > peak)) {
      peak = v;
      at = i;
    }
  });
  return { peak, at };
}

// ---------- services ----------

async function loadServices() {
  try {
    const data = await api('/api/services');
    state.services = data.services;
    state.system = data.system;
    state.maintenance = data.maintenance || null;
    if (!state.online) toast('Connection restored.', 'ok');
    state.online = true;
    renderBanner(data);
    renderSystem();
    renderServices();
    $('updated').textContent = 'updated ' + new Date(data.generatedAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    if (state.selected) renderFileTabs();
    notifyServices();
  } catch (e) {
    if (state.online) showBanner(`Lost connection to the dashboard (${e.message}). Retrying…`);
    state.online = false;
  }
}

const serviceListeners = new Set();

function notifyServices() {
  for (const fn of serviceListeners) {
    try {
      fn();
    } catch (e) {
      console.error(e);
    }
  }
}

function renderBanner(data) {
  if (data.statusError) showBanner(`Service status unavailable: ${data.statusError}`);
  else hideBanner();
  const dot = $('host-dot');
  if (dot) dot.className = 'dot ' + (data.statusError ? 'bad' : 'ok');
  const host = $('hostname');
  if (host) host.textContent = (data.system && data.system.hostname) || (data.mock ? 'sample' : 'this server');
}

function showBanner(text) {
  const b = $('banner');
  b.textContent = text;
  b.hidden = false;
}

function hideBanner() {
  $('banner').hidden = true;
}

function statTile(label, value, sub, pct, level) {
  const t = el('div', 'stat' + (level ? ' ' + level : ''));
  t.append(el('div', 'stat-label', label), el('div', 'stat-value', value));
  if (sub) t.append(el('div', 'stat-sub', sub));
  if (pct !== null && pct !== undefined) {
    const m = el('div', 'meter');
    const fill = el('span');
    fill.style.width = `${Math.max(0, Math.min(100, pct))}%`;
    m.append(fill);
    t.append(m);
  }
  return t;
}

const levelFor = (pct, warn, bad) => (pct >= bad ? 'bad' : pct >= warn ? 'warn' : '');

function renderSystem() {
  const sys = state.system;
  const box = $('system');
  if (!box || !sys) {
    if (box) box.hidden = true;
    return;
  }
  box.hidden = false;
  box.replaceChildren();

  const cpu = Number(sys.cpuPercent) || 0;
  box.append(statTile('CPU', `${Math.round(cpu)}%`, `${sys.logicalCpus} threads`, cpu, levelFor(cpu, 70, 90)));

  if (sys.memTotalMB) {
    const used = sys.memTotalMB - sys.memFreeMB;
    const pct = (used / sys.memTotalMB) * 100;
    box.append(
      statTile('Memory', `${Math.round(pct)}%`, `${fmtGB(used)} of ${fmtGB(sys.memTotalMB)}`, pct, levelFor(pct, 80, 92))
    );
  }

  for (const d of sys.disks || []) {
    const pct = d.sizeGB ? ((d.sizeGB - d.freeGB) / d.sizeGB) * 100 : 0;
    box.append(
      statTile(`Disk ${d.drive}`, `${Math.round(d.freeGB)} GB free`, `of ${Math.round(d.sizeGB)} GB`, pct, levelFor(pct, 85, 95))
    );
  }

  box.append(statTile('Uptime', fmtDuration(sys.bootTime), sys.hostname || '', null, ''));

  const m = state.maintenance;
  if (m) {
    const updates = m.updates;
    if (updates) {
      const count = typeof updates.count === 'number' ? updates.count : null;
      const failed = count === null;
      const titles = Array.isArray(updates.titles) ? updates.titles.filter(Boolean) : [];
      const sub = failed ? updates.error || 'Could not check' : count ? titles[0] || 'pending' : 'None pending';
      const tile = statTile('Updates', failed ? 'Unknown' : count ? String(count) : 'None', sub, null, failed || count ? 'warn' : '');
      if (titles.length) tile.title = titles.join('\n');
      box.append(tile);
    }
    if (typeof m.rebootPending === 'boolean') {
      box.append(
        statTile('Reboot', m.rebootPending ? 'Needed' : 'Not needed', m.rebootPending ? 'Finish installing updates' : 'No reboot pending', null, m.rebootPending ? 'warn' : '')
      );
    }
  }
}

let svcQuery = '';
let svcFilter = 'all';

function serviceBusy(s) {
  return state.pending.get(s.name) || s.busy || null;
}

function renderSvcFilters(running, stopped) {
  const box = $('svc-filters');
  if (!box) return;
  box.replaceChildren();
  const choices = [
    ['all', `All ${state.services.length}`],
    ['running', `Running ${running}`],
    ['stopped', `Stopped ${stopped}`],
  ];
  for (const [id, label] of choices) {
    const b = el('button', svcFilter === id ? 'on' : '', label);
    b.type = 'button';
    b.setAttribute('aria-pressed', String(svcFilter === id));
    b.addEventListener('click', () => {
      svcFilter = id;
      renderServices();
    });
    box.append(b);
  }
}

function serviceSentence(s) {
  if (s.state === 'Stopped') {
    const how = s.startMode === 'Auto'
      ? 'It is set to start automatically, but it has not come back on its own.'
      : 'It stays stopped until you start it.';
    return `${s.label} is stopped. ${how}`;
  }
  if (s.state !== 'Running') return `${s.label} is ${String(s.state).toLowerCase()}.`;
  const bits = [];
  if (s.cpuPercent !== null && s.cpuPercent !== undefined) bits.push(`CPU is ${s.cpuPercent}%`);
  if (s.memoryMB !== null) bits.push(`memory is ${s.memoryMB} MB`);
  if (s.startedAt) bits.push(`up ${fmtDuration(s.startedAt)}`);
  return bits.length ? `${bits.join(', ')}.` : `${s.label} is running.`;
}

function renderDetail() {
  const s = state.services.find((x) => x.name === state.selected);
  const viewer = $('viewer');
  if (!viewer) return;
  if (!s) {
    viewer.hidden = true;
    return;
  }
  viewer.hidden = false;
  $('v-title').textContent = s.label;
  const busy = serviceBusy(s);
  const badge = $('v-state');
  badge.className = 'pill ' + (busy ? 'warn' : stateClass(s.state));
  badge.textContent = busy ? ACTION_VERB[busy] || 'Working…' : s.state === 'Running' ? 'Running' : s.state;

  const bits = [s.name];
  if (s.process) bits.push(s.pid ? `${s.process} (${s.pid})` : s.process);
  if (s.account) bits.push(s.account);
  if (s.startMode === 'Auto') bits.push('starts automatically');
  else if (s.startMode) bits.push(`start ${s.startMode}`);
  $('v-meta-line').textContent = bits.join(' · ');
  $('v-sentence').textContent = serviceSentence(s);

  const stats = $('v-stats');
  stats.replaceChildren();
  const mini = (label, value, sub) => {
    const t = el('div', 'mini');
    t.append(el('span', null, label), el('strong', null, value));
    if (sub) t.append(el('em', null, sub));
    return t;
  };
  const running = s.state === 'Running';
  stats.append(
    mini('CPU', running && s.cpuPercent !== null && s.cpuPercent !== undefined ? `${numText(s.cpuPercent)}%` : '—', running ? 'right now' : ''),
    mini('Memory', s.memoryMB !== null ? `${numText(s.memoryMB)} MB` : '—', ''),
    mini('Uptime', running ? fmtDuration(s.startedAt) : '—', running && s.startedAt ? `since ${new Date(s.startedAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}` : ''),
    (() => {
      const tile = fourthTile(s);
      return mini(tile[0], tile[1], tile[2]);
    })()
  );
  const selected = s.name;
  loadUsage().then((d) => {
    if (!d || state.selected !== selected) return;
    const row = d.services && d.services[s.name];
    const tiles = [...stats.children];
    const setSub = (tile, text) => {
      if (!tile) return;
      let em = tile.querySelector('em');
      if (!em) tile.append((em = el('em', null, '')));
      em.textContent = text;
    };
    if (row) {
      const cpu = seriesPeakAt(row.cpu);
      const mem = seriesPeakAt(row.mem);
      if (cpu.peak !== null) setSub(tiles[0], `peak ${numText(cpu.peak)}% today`);
      if (mem.peak !== null) setSub(tiles[1], `peak ${numText(mem.peak)} MB today`);
    }
    const tile = fourthTile(s);
    if (tiles[3]) {
      tiles[3].replaceChildren(el('span', null, tile[0]), el('strong', null, tile[1]));
      if (tile[2]) tiles[3].append(el('em', null, tile[2]));
    }
    storyFor(s);
  });

  const actions = $('detail-actions');
  actions.replaceChildren();
  if (!s.controllable) {
    actions.append(el('span', 'muted small', s.isSelf ? 'Restart from Windows' : s.installed ? 'Read-only' : 'Not installed'));
    return;
  }
  const stoppedState = s.state === 'Stopped';
  const mk = (action, enabled, cls) => {
    const b = el('button', 'btn' + (cls ? ' ' + cls : ''), ACTION_TITLE[action]);
    b.type = 'button';
    b.disabled = Boolean(busy) || !enabled;
    b.addEventListener('click', () => runAction(s.name, action));
    return b;
  };
  if (stoppedState) actions.append(mk('start', true, 'btn-primary'));
  else if (running) actions.append(mk('restart', true), mk('stop', true));
  else actions.append(mk('start', false), mk('restart', false), mk('stop', false));
}

function renderServices() {
  const list = $('services');
  if (!list) return;
  list.replaceChildren();

  let running = 0;
  let stopped = 0;
  for (const s of state.services) {
    if (s.state === 'Running') running++;
    else if (s.state === 'Stopped') stopped++;
  }
  renderSvcFilters(running, stopped);

  const q = svcQuery.trim().toLowerCase();
  const visible = state.services.filter((s) => {
    if (q && !`${s.label} ${s.name}`.toLowerCase().includes(q)) return false;
    if (svcFilter === 'running' && s.state !== 'Running') return false;
    if (svcFilter === 'stopped' && s.state !== 'Stopped') return false;
    return true;
  });

  for (const s of visible) {
    const row = el('button', 'svc-row' + (s.name === state.selected ? ' on' : '') + (s.state === 'Stopped' ? ' down' : ''));
    row.type = 'button';
    const grow = el('span', 'grow');
    const sub = [];
    if (s.state === 'Running') {
      if (s.cpuPercent !== null && s.cpuPercent !== undefined) sub.push(`${s.cpuPercent}%`);
      if (s.memoryMB !== null) sub.push(`${s.memoryMB} MB`);
      if (s.startedAt) sub.push(`up ${fmtDuration(s.startedAt)}`);
    } else if (s.state === 'Stopped') {
      const at = stoppedSince(s.name);
      sub.push(at ? `down since ${new Date(at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}` : 'down');
    }
    else sub.push(s.state);
    grow.append(el('strong', null, s.label), el('span', 'sub', sub.join(' · ')));
    row.append(el('span', 'dot ' + (s.state === 'Running' ? 'ok' : s.state === 'Stopped' ? 'bad' : 'dim')), grow);
    if (s.state === 'Stopped') row.append(el('span', 'pill bad', 'Stopped'));
    else if (serviceBusy(s)) row.append(el('span', 'pill warn', 'Working'));
    row.addEventListener('click', () => selectService(s.name));
    list.append(row);
  }
  if (!visible.length) list.append(el('p', 'muted small', state.services.length ? 'No services match.' : 'No services configured.'));
  if (!deck) loadDeck().then(() => renderServices());

  const down = state.services.filter((s) => s.state === 'Stopped');
  const headline = $('services-headline');
  if (headline) {
    if (!state.services.length) headline.textContent = 'No services configured.';
    else if (down.length === 1) headline.textContent = `${running} of ${state.services.length} running. ${down[0].label} is down.`;
    else if (down.length) headline.textContent = `${running} of ${state.services.length} running. ${down.length} are down.`;
    else headline.textContent = `All ${state.services.length} services are running.`;
  }
  document.title = down.length ? `(${down.length}) svcdash` : 'svcdash';
  updateServicesBadge(state.services);
  renderDetail();
}

function updateServicesBadge(services) {
  const badge = $('nav-services-badge');
  if (!badge) return;
  const down = services.filter((s) => s.state === 'Stopped' || s.state === 'Not installed');
  badge.hidden = down.length === 0;
  badge.classList.remove('warn');
  badge.textContent = String(down.length);
  badge.title = down.map((s) => `${s.label} is ${s.state.toLowerCase()}`).join(', ');
}

// ---------- actions ----------

function depLabel(name) {
  const s = state.services.find((x) => x.name === name || x.name.toLowerCase() === String(name).toLowerCase());
  return s ? s.label : name;
}

function confirmAction(svc, action, dependents) {
  return new Promise((resolve) => {
    const dlg = $('confirm');
    $('confirm-title').textContent = `${ACTION_TITLE[action]} ${svc.label}?`;
    $('confirm-body').textContent =
      action === 'start'
        ? `This starts ${svc.label}.`
        : action === 'stop'
          ? 'It stays stopped until you start it again.'
          : 'It stops and starts again. Open connections drop for a moment.';

    const showDeps = action !== 'start' && dependents.length > 0;
    $('confirm-deps').hidden = !showDeps;
    $('confirm-deps-kicker').textContent = action === 'stop' ? 'This also stops' : 'This also restarts';
    $('confirm-deps-list').replaceChildren(
      ...dependents.map((d) => {
        const li = el('li');
        li.append(el('strong', null, depLabel(d)), el('span', null, `because it needs ${svc.label}`));
        return li;
      })
    );

    const note = action !== 'start' ? svc.confirmNote : null;
    $('confirm-note').hidden = !note;
    $('confirm-note').textContent = note || '';

    const count = 1 + (showDeps ? dependents.length : 0);
    const ok = $('confirm-ok');
    ok.textContent =
      action === 'stop' && count > 1 ? `Stop ${count} services` : action === 'restart' && count > 1 ? `Restart ${count} services` : ACTION_TITLE[action];
    ok.className = 'btn ' + (action === 'start' ? 'btn-primary' : 'btn-danger');

    dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok'), { once: true });
    dlg.returnValue = '';
    dlg.showModal();
    ok.focus();
  });
}

async function runAction(name, action) {
  const svc = state.services.find((s) => s.name === name);
  if (!svc || serviceBusy(svc)) return;

  let deps = (svc.dependents || []).filter((d) => d.status === 'Running').map((d) => d.name);
  if (!(await confirmAction(svc, action, deps))) return;

  state.pending.set(name, action);
  renderServices();

  try {
    let result;
    try {
      result = await postAction(name, action, deps.length > 0);
    } catch (e) {
      // Dependents changed since the page loaded: confirm again with the real list.
      if (e.status === 409 && e.body && e.body.needsForce) {
        deps = e.body.dependents || [];
        if (!(await confirmAction(svc, action, deps))) return;
        result = await postAction(name, action, true);
      } else {
        throw e;
      }
    }
    const extra = result.dependents && result.dependents.length ? ` (with ${result.dependents.join(', ')})` : '';
    toast(`${svc.label} ${ACTION_DONE[action]}${extra}.`, 'ok');
  } catch (e) {
    if (e.status === undefined) {
      // Network error: expected when restarting Caddy, since this page goes through it.
      toast(`Lost connection while running "${action}" on ${svc.label}. Checking status…`, 'warn');
    } else {
      toast(`${ACTION_TITLE[action]} ${svc.label} failed: ${e.message}`, 'bad');
    }
  } finally {
    state.pending.delete(name);
    state.fastUntil = Date.now() + 15000; // poll quickly for a bit to show the new state
    await loadServices();
    if (state.selected === name) loadLog(false);
  }
}

// ---------- selection ----------

function selectService(name, fileId) {
  const svc = state.services.find((s) => s.name === name);
  if (!svc) return;

  state.selected = name;
  const chosen = fileId != null ? svc.logs.find((f) => f.id === fileId) : null;
  const firstOk = svc.logs.find((f) => !f.missing);
  state.fileId = chosen ? chosen.id : firstOk ? firstOk.id : svc.logs[0] ? svc.logs[0].id : null;

  history.replaceState(null, '', `#/services/${encodeURIComponent(name)}/${state.fileId ?? ''}`);
  renderServices();
  renderFileTabs();
  loadLog(true);
}

function renderFileTabs() {
  const svc = state.services.find((s) => s.name === state.selected);
  const tabs = $('v-files');
  tabs.replaceChildren();
  if (!svc) return;

  if (!svc.logs.length) {
    tabs.append(el('span', 'muted small', 'No log paths configured'));
    return;
  }

  for (const f of svc.logs) {
    const t = el('button', 'tab' + (f.id === state.fileId ? ' active' : '') + (f.missing ? ' missing' : ''), f.name);
    t.type = 'button';
    t.setAttribute('role', 'tab');
    t.setAttribute('aria-selected', String(f.id === state.fileId));
    t.title = f.missing
      ? `${f.path}\n${f.error || 'Missing'}`
      : `${f.path}\n${fmtBytes(f.size)} · modified ${fmtTime(f.mtime)}`;
    t.addEventListener('click', () => {
      state.fileId = f.id;
      history.replaceState(null, '', `#/services/${encodeURIComponent(state.selected)}/${f.id}`);
      renderFileTabs();
      loadLog(true);
    });
    tabs.append(t);
  }
}

// ---------- logs ----------

async function loadLog(reset) {
  const logEl = $('log');
  const service = state.selected;
  const fileId = state.fileId;
  const gen = ++state.logGen;
  if (service === null) return;

  if (fileId === null) {
    state.lastLines = [];
    logEl.replaceChildren(el('div', 'log-note', 'This service has no log files configured in config.json.'));
    $('v-meta').textContent = '';
    return;
  }

  if (reset) logEl.replaceChildren(el('div', 'log-note', 'Loading…'));

  const lines = $('lines').value;
  try {
    const data = await api(
      `/api/logs/${encodeURIComponent(service)}/${encodeURIComponent(fileId)}?lines=${encodeURIComponent(lines)}`
    );
    if (gen !== state.logGen) return;
    state.lastLines = data.lines;
    state.lastFileName = data.name;
    renderLog(reset);
    const note = data.truncated ? ` · showing last ${data.lines.length}` : '';
    const updated = new Date().toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    $('v-meta').textContent = `${data.name} · ${fmtBytes(data.size)}${note} · updated ${updated}`;
  } catch (e) {
    if (gen !== state.logGen) return;
    state.lastLines = [];
    const msg = e.body && e.body.path ? `${e.message}\n${e.body.path}` : e.message;
    logEl.replaceChildren(el('div', 'log-note bad', msg));
    $('v-meta').textContent = '';
  }
}

const LEVEL_PATTERNS = [
  ['error', /\b(error|fatal|exception|failed|failure|panic|critical)\b|\[(E|F|C)\]|PHP (Fatal|Parse) error/i],
  ['warn', /\b(warn|warning|deprecated)\b|\[W\]|PHP Warning/i],
  ['debug', /\b(debug|verbose|trace)\b|\[(D|T)\]/i],
];

function detectLevel(text) {
  for (const [level, re] of LEVEL_PATTERNS) if (re.test(text)) return level;
  return '';
}

const SCAN_RE = /\.env|\.git|wp-(admin|login)|xmlrpc|phpmyadmin|\.\.\/|\/etc\/passwd/i;

function parseLine(line, raw) {
  if (!raw && line.charAt(0) === '{') {
    try {
      const o = JSON.parse(line);
      let ts = '';
      const asTime = (value) => {
        const d = new Date(value);
        return Number.isNaN(d.getTime()) ? '' : d.toLocaleTimeString();
      };
      if (typeof o.ts === 'number') ts = asTime(o.ts * 1000);
      else if (typeof o.ts === 'string') ts = asTime(o.ts) || o.ts;

      let level = String(o.level || '').toLowerCase();
      if (level === 'warning') level = 'warn';
      if (level === 'info') level = '';
      let text;

      if (o.request) {
        // Caddy access log
        const r = o.request;
        const status = o.status ?? '';
        const dur = typeof o.duration === 'number' ? `${Math.round(o.duration * 1000)}ms` : '';
        text = [status, r.method, (r.host || '') + (r.uri || ''), r.client_ip || r.remote_ip || '', dur]
          .filter((x) => x !== '' && x !== undefined)
          .join('  ');
        if (status >= 500) level = 'error';
        else if (status >= 400) level = 'warn';
        const target = (r.host || '') + (r.uri || '');
        return {
          ts,
          level,
          text,
          access: {
            status,
            method: r.method || '',
            target,
            ip: r.client_ip || r.remote_ip || '',
            dur,
            scanner: SCAN_RE.test(target),
          },
        };
      } else if (o.action && o.service) {
        // Dashboard audit log
        const who = [o.user, o.ip].filter(Boolean).join(' @ ');
        text = `${o.ok ? 'OK' : 'FAILED'}  ${o.action} ${o.service}${o.dependents && o.dependents.length ? ` (+ ${o.dependents.join(', ')})` : ''}${who ? `  by ${who}` : ''}${o.error ? `  — ${o.error}` : ''}`;
        level = o.ok ? '' : 'error';
      } else {
        const extra = [];
        if (o.logger) extra.push(`[${o.logger}]`);
        extra.push(o.msg || '');
        if (o.error) extra.push(`— ${o.error}`);
        if (o.identifier) extra.push(`(${o.identifier})`);
        text = extra.join(' ');
      }
      return { ts, level, text };
    } catch {
      /* not JSON after all */
    }
  }
  return { ts: '', level: detectLevel(line), text: line };
}

function appendHighlighted(container, text, needle) {
  if (!needle) {
    container.textContent = text;
    return;
  }
  const lower = text.toLowerCase();
  let i = 0;
  while (i < text.length) {
    const hit = lower.indexOf(needle, i);
    if (hit === -1) {
      container.append(document.createTextNode(text.slice(i)));
      break;
    }
    if (hit > i) container.append(document.createTextNode(text.slice(i, hit)));
    container.append(el('mark', null, text.slice(hit, hit + needle.length)));
    i = hit + needle.length;
  }
}

function syncLogMode() {
  const on = prefs.get('errorsOnly', false);
  const all = $('log-all');
  const problems = $('log-problems');
  if (!all || !problems) return;
  all.classList.toggle('on', !on);
  problems.classList.toggle('on', on);
  all.setAttribute('aria-pressed', String(!on));
  problems.setAttribute('aria-pressed', String(on));
}

function codeClass(status) {
  const n = Number(status);
  if (n >= 500) return 'c5';
  if (n >= 400) return 'c4';
  if (n >= 200) return 'c2';
  return '';
}

function renderLog(forceBottom) {
  const logEl = $('log');
  const raw = $('raw').checked;
  const needle = $('filter').value.trim().toLowerCase();
  const errorsOnly = prefs.get('errorsOnly', false);
  syncLogMode();

  const nearBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
  const prevTop = logEl.scrollTop;

  const frag = document.createDocumentFragment();
  let shown = 0;
  let problems = 0;

  for (const line of state.lastLines) {
    const parsed = parseLine(line, raw);
    if (parsed.level === 'error' || parsed.level === 'warn') problems++;
    if (needle && !line.toLowerCase().includes(needle)) continue;
    if (errorsOnly && parsed.level !== 'error' && parsed.level !== 'warn') continue;

    const row = el('div', 'line' + (parsed.access ? ' access' : '') + (parsed.level ? ' ' + parsed.level : ''));
    row.append(el('span', 'ts', parsed.ts));
    if (parsed.access) {
      row.append(el('span', 'code ' + codeClass(parsed.access.status), String(parsed.access.status)));
      const msg = el('span', 'msg');
      appendHighlighted(msg, `${parsed.access.method} ${parsed.access.target}`.trim(), needle);
      if (parsed.access.scanner) msg.append(el('span', 'tag tag-warn', 'scanner'));
      row.append(msg);
      const meta = [parsed.access.ip, parsed.access.dur].filter(Boolean).join(' · ');
      if (meta) row.append(el('span', 'meta', meta));
    } else {
      const msg = el('span', 'msg');
      appendHighlighted(msg, parsed.text, needle);
      row.append(msg);
    }
    frag.append(row);
    shown++;
  }

  if (!shown) {
    const note = state.lastLines.length ? 'No lines match the current filter.' : 'This log is empty.';
    frag.append(el('div', 'log-note', note));
  }

  logEl.replaceChildren(frag);
  const count = $('problem-count');
  if (count) count.textContent = problems ? String(problems) : '';
  const shownEl = $('v-shown');
  if (shownEl) shownEl.textContent = state.lastLines.length ? `${shown} of ${state.lastLines.length} lines` : '';

  if ($('follow').checked && (forceBottom || nearBottom)) logEl.scrollTop = logEl.scrollHeight;
  else logEl.scrollTop = prevTop;
  const current = state.services.find((x) => x.name === state.selected);
  if (current) storyFor(current);
}

function downloadLog() {
  if (!state.lastLines.length) {
    toast('Nothing to download yet.', 'warn');
    return;
  }
  const blob = new Blob([state.lastLines.join('\r\n') + '\r\n'], { type: 'text/plain' });
  const a = el('a');
  a.href = URL.createObjectURL(blob);
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  a.download = `${state.selected}-${state.lastFileName || 'log'}-${stamp}.txt`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

// ---------- timers ----------

function scheduleLogRefresh() {
  clearInterval(state.logTimer);
  if ($('auto').checked) {
    state.logTimer = setInterval(() => {
      if (!document.hidden && state.selected !== null) loadLog(false);
    }, LOG_REFRESH_MS);
  }
}

function scheduleServiceRefresh() {
  clearTimeout(state.svcTimer);
  const tick = async () => {
    if (!document.hidden) await loadServices();
    const fast = Date.now() < state.fastUntil || !state.online || state.services.some((s) => s.busy);
    state.svcTimer = setTimeout(tick, fast ? FAST_REFRESH_MS : SERVICES_REFRESH_MS);
  };
  state.svcTimer = setTimeout(tick, SERVICES_REFRESH_MS);
}

// ---------- wiring ----------

function restorePrefs() {
  $('lines').value = String(prefs.get('lines', 500));
  $('auto').checked = prefs.get('auto', true);
  $('follow').checked = prefs.get('follow', true);
  $('raw').checked = prefs.get('raw', false);
  syncLogMode();
}

function wire() {
  $('refresh').addEventListener('click', () => {
    loadServices();
    if (currentPage === 'services') {
      if (state.selected !== null) loadLog(false);
    } else if (pages[currentPage] && pages[currentPage].refresh) {
      pages[currentPage].refresh();
    }
  });

  // Keep the selected service when returning to the Services page.
  document.querySelector('[data-nav="services"]').addEventListener('click', (e) => {
    if (state.selected !== null) {
      e.preventDefault();
      location.hash = `#/services/${encodeURIComponent(state.selected)}/${state.fileId ?? ''}`;
    }
  });

  $('svc-search').addEventListener('input', () => {
    svcQuery = $('svc-search').value;
    renderServices();
  });

  const setProblems = (on) => {
    prefs.set('errorsOnly', on);
    syncLogMode();
    renderLog(true);
  };
  $('log-all').addEventListener('click', () => setProblems(false));
  $('log-problems').addEventListener('click', () => setProblems(true));

  let filterTimer;
  $('filter').addEventListener('input', () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => renderLog(true), 120);
  });
  $('filter').addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $('filter').value = '';
      renderLog(true);
      $('filter').blur();
    }
  });

  document.addEventListener('keydown', (e) => {
    const tag = (e.target && e.target.tagName) || '';
    if (e.key === '/' && currentPage === 'services' && !['INPUT', 'TEXTAREA', 'SELECT'].includes(tag) && !$('viewer').hidden && !$('confirm').open) {
      e.preventDefault();
      $('filter').focus();
    }
  });

  $('lines').addEventListener('change', () => {
    prefs.set('lines', Number($('lines').value));
    loadLog(true);
  });

  $('raw').addEventListener('change', () => {
    prefs.set('raw', $('raw').checked);
    renderLog(true);
  });

  $('follow').addEventListener('change', () => {
    prefs.set('follow', $('follow').checked);
    if ($('follow').checked) $('log').scrollTop = $('log').scrollHeight;
  });

  $('auto').addEventListener('change', () => {
    prefs.set('auto', $('auto').checked);
    scheduleLogRefresh();
  });

  $('download').addEventListener('click', downloadLog);

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      loadServices();
      if (state.selected !== null) loadLog(false);
    }
  });
}

// ---------- pages & routing ----------
// URLs: #/overview, #/services[/name/fileId], #/history, #/sites, #/patches, #/security

const pages = {};
let currentPage = null;

function registerPage(name, impl) {
  pages[name] = impl;
}

function parseHash() {
  const h = decodeURIComponent(location.hash.slice(1));
  if (!h || h === '/') return { page: 'overview', rest: [] };
  if (h.startsWith('/')) {
    const parts = h.slice(1).split('/');
    return { page: parts[0] || 'overview', rest: parts.slice(1) };
  }
  return { page: 'services', rest: h.split('/') };
}

function applyServicesRoute([name, file]) {
  if (!name || !state.services.some((s) => s.name === name)) return;
  const fileId = file ? String(file) : undefined;
  if (name === state.selected && (fileId === undefined || fileId === state.fileId)) return;
  selectService(name, fileId);
}

function route() {
  const { page, rest } = parseHash();
  const name = page === 'services' || pages[page] ? page : 'overview';
  if (name !== currentPage) {
    if (currentPage && pages[currentPage] && pages[currentPage].hide) pages[currentPage].hide();
    document.querySelectorAll('[data-page]').forEach((p) => {
      p.hidden = p.dataset.page !== name;
    });
    document.querySelectorAll('[data-nav]').forEach((a) => {
      if (a.dataset.nav === name) a.setAttribute('aria-current', 'page');
      else a.removeAttribute('aria-current');
    });
    currentPage = name;
    if (pages[name] && pages[name].show) pages[name].show();
  }
  if (name === 'services') {
    applyServicesRoute(rest);
    if (!state.selected && state.services.length) {
      const down = state.services.find((s) => s.state === 'Stopped') || state.services[0];
      selectService(down.name);
    }
  }
}

async function init() {
  restorePrefs();
  wire();
  await loadServices();
  route();
  window.addEventListener('hashchange', route);

  scheduleServiceRefresh();
  scheduleLogRefresh();
}

// Shared with pages.js, which calls SD.init() once its pages are registered.
window.SD = {
  $,
  el,
  api,
  postJson,
  toast,
  prefs,
  fmtDuration,
  fmtBytes,
  registerPage,
  init,
  runAction,
  onServices(fn) {
    serviceListeners.add(fn);
    return () => serviceListeners.delete(fn);
  },
  get services() {
    return state.services;
  },
  get system() {
    return state.system;
  },
  get maintenance() {
    return state.maintenance;
  },
};
