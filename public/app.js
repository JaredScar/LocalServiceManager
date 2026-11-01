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
  loadingLog: false,
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

// ---------- theme ----------

const THEMES = ['dark', 'light', 'auto'];
const THEME_LABEL = { dark: 'Dark', light: 'Light', auto: 'Auto' };

function currentTheme() {
  const t = document.documentElement.getAttribute('data-theme');
  return THEMES.includes(t) ? t : 'dark';
}

function setTheme(mode) {
  document.documentElement.setAttribute('data-theme', mode);
  try {
    localStorage.setItem('svcdash.theme', mode);
  } catch {
    /* storage unavailable */
  }
  $('theme').textContent = `Theme: ${THEME_LABEL[mode]}`;
}

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
    $('updated').textContent = 'Updated ' + new Date(data.generatedAt).toLocaleTimeString();
    if (state.selected) renderFileTabs();
  } catch (e) {
    if (state.online) showBanner(`Lost connection to the dashboard (${e.message}). Retrying…`);
    state.online = false;
  }
}

function renderBanner(data) {
  if (data.statusError) showBanner(`Service status unavailable: ${data.statusError}`);
  else if (data.mock) showBanner('Mock mode: status and actions are simulated (not running on Windows).');
  else hideBanner();
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
  if (!sys) {
    box.hidden = true;
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

function serviceBusy(s) {
  return state.pending.get(s.name) || s.busy || null;
}

function renderServices() {
  const grid = $('services');
  grid.replaceChildren();

  let running = 0;
  let stopped = 0;
  let other = 0;

  for (const s of state.services) {
    if (s.state === 'Running') running++;
    else if (s.state === 'Stopped') stopped++;
    else other++;

    const busy = serviceBusy(s);
    const card = el('div', 'card' + (s.name === state.selected ? ' selected' : ''));

    const select = el('button', 'card-select', s.label);
    select.type = 'button';
    select.setAttribute('aria-pressed', String(s.name === state.selected));
    select.title = `Show ${s.label} logs`;
    select.addEventListener('click', () => selectService(s.name));

    const pill = busy
      ? el('span', 'pill warn busy', ACTION_VERB[busy] || 'Working…')
      : el('span', 'pill ' + stateClass(s.state), s.state);

    const head = el('div', 'card-head');
    head.append(select, pill);

    const facts = el('dl', 'facts');
    const add = (k, v, cls) => {
      const dd = el('dd', cls || null, v ?? '—');
      dd.title = v ?? '';
      facts.append(el('dt', null, k), dd);
    };
    const isRunning = s.state === 'Running';
    add('Service', s.name);
    add('Start', s.startMode);
    add('Account', s.account);
    add('Process', s.pid ? `${s.process || '?'} (${s.pid})` : '—');
    add(
      'CPU',
      isRunning ? (s.cpuPercent === null ? '…' : `${s.cpuPercent}%`) : '—',
      isRunning && s.cpuPercent >= 50 ? 'hot' : ''
    );
    add('Memory', s.memoryMB !== null ? `${s.memoryMB} MB` : '—');
    add('Uptime', isRunning ? fmtDuration(s.startedAt) : '—');

    card.append(head, facts, renderActions(s, busy));
    grid.append(card);
  }

  const parts = [`${running} running`];
  if (stopped) parts.push(`${stopped} stopped`);
  if (other) parts.push(`${other} other`);
  $('summary').textContent = `${state.services.length} services · ${parts.join(' · ')}`;
  document.title = stopped ? `(${stopped} down) Service Dashboard` : 'Service Dashboard';
  updateServicesBadge(state.services);
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

function renderActions(s, busy) {
  const bar = el('div', 'card-actions');
  if (!s.controllable) {
    const why = s.isSelf ? 'Restart from Windows' : s.installed ? 'Read-only' : 'Not installed';
    bar.append(el('span', 'note-inline', why));
    return bar;
  }
  const running = s.state === 'Running';
  const stoppedState = s.state === 'Stopped';
  const mk = (action, enabled) => {
    const b = el('button', 'btn btn-sm', ACTION_TITLE[action]);
    b.type = 'button';
    b.disabled = Boolean(busy) || !enabled;
    b.addEventListener('click', () => runAction(s.name, action));
    return b;
  };
  bar.append(mk('start', stoppedState), mk('stop', running), mk('restart', running));
  return bar;
}

// ---------- actions ----------

function confirmAction(svc, action, dependents) {
  return new Promise((resolve) => {
    const dlg = $('confirm');
    $('confirm-title').textContent = `${ACTION_TITLE[action]} ${svc.label}?`;
    $('confirm-body').textContent =
      action === 'start'
        ? `This starts the ${svc.name} service.`
        : action === 'stop'
          ? `This stops the ${svc.name} service until you start it again.`
          : `This stops and starts the ${svc.name} service.`;

    const showDeps = action !== 'start' && dependents.length > 0;
    $('confirm-deps').hidden = !showDeps;
    $('confirm-deps-verb').textContent = action === 'stop' ? 'stopped' : 'restarted';
    $('confirm-deps-list').replaceChildren(...dependents.map((d) => el('li', null, d)));

    const note = action !== 'start' ? svc.confirmNote : null;
    $('confirm-note').hidden = !note;
    $('confirm-note').textContent = note || '';

    const ok = $('confirm-ok');
    ok.textContent = ACTION_TITLE[action];
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
  const firstOk = svc.logs.find((f) => !f.missing);
  state.fileId = fileId !== undefined ? fileId : firstOk ? firstOk.id : svc.logs[0] ? svc.logs[0].id : null;

  history.replaceState(null, '', `#/services/${encodeURIComponent(name)}/${state.fileId ?? ''}`);
  $('viewer').hidden = false;
  $('empty-hint').hidden = true;
  $('v-title').textContent = svc.label;

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
  if (state.selected === null) return;

  if (state.fileId === null) {
    state.lastLines = [];
    logEl.replaceChildren(el('div', 'log-note', 'This service has no log files configured in config.json.'));
    $('v-meta').textContent = '';
    return;
  }
  if (state.loadingLog) return;
  state.loadingLog = true;

  if (reset) logEl.replaceChildren(el('div', 'log-note', 'Loading…'));

  const lines = $('lines').value;
  try {
    const data = await api(
      `/api/logs/${encodeURIComponent(state.selected)}/${state.fileId}?lines=${encodeURIComponent(lines)}`
    );
    state.lastLines = data.lines;
    state.lastFileName = data.name;
    renderLog(reset);
    const note = data.truncated ? ` · showing last ${data.lines.length}` : '';
    $('v-meta').textContent = `${data.name} · ${fmtBytes(data.size)}${note} · ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    state.lastLines = [];
    const msg = e.body && e.body.path ? `${e.message}\n${e.body.path}` : e.message;
    logEl.replaceChildren(el('div', 'log-note bad', msg));
    $('v-meta').textContent = '';
  } finally {
    state.loadingLog = false;
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

function parseLine(line, raw) {
  if (!raw && line.charAt(0) === '{') {
    try {
      const o = JSON.parse(line);
      let ts = '';
      if (typeof o.ts === 'number') ts = new Date(o.ts * 1000).toLocaleString();
      else if (typeof o.ts === 'string') ts = new Date(o.ts).toLocaleString();

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

function renderLog(forceBottom) {
  const logEl = $('log');
  const raw = $('raw').checked;
  const needle = $('filter').value.trim().toLowerCase();
  const errorsOnly = $('errorsOnly').checked;

  const nearBottom = logEl.scrollHeight - logEl.scrollTop - logEl.clientHeight < 40;
  const prevTop = logEl.scrollTop;

  const frag = document.createDocumentFragment();
  let shown = 0;

  for (const line of state.lastLines) {
    if (needle && !line.toLowerCase().includes(needle)) continue;
    const p = parseLine(line, raw);
    if (errorsOnly && p.level !== 'error' && p.level !== 'warn') continue;

    const row = el('div', 'line' + (p.level ? ' ' + p.level : ''));
    row.append(el('span', 'ts', p.ts));
    const msg = el('span', 'msg');
    appendHighlighted(msg, p.text, needle);
    row.append(msg);
    frag.append(row);
    shown++;
  }

  if (!shown) {
    const note = state.lastLines.length ? 'No lines match the current filter.' : 'This log is empty.';
    frag.append(el('div', 'log-note', note));
  }

  logEl.replaceChildren(frag);

  if ($('follow').checked && (forceBottom || nearBottom)) logEl.scrollTop = logEl.scrollHeight;
  else logEl.scrollTop = prevTop;
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
  $('errorsOnly').checked = prefs.get('errorsOnly', false);
  $('theme').textContent = `Theme: ${THEME_LABEL[currentTheme()]}`;
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

  $('theme').addEventListener('click', () => {
    const next = THEMES[(THEMES.indexOf(currentTheme()) + 1) % THEMES.length];
    setTheme(next);
  });

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

  for (const id of ['raw', 'errorsOnly']) {
    $(id).addEventListener('change', () => {
      prefs.set(id, $(id).checked);
      renderLog(true);
    });
  }

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
// URLs: #/services[/name/fileId], #/history, #/sites, #/security (old #name/fileId still works)

const pages = {};
let currentPage = null;

function registerPage(name, impl) {
  pages[name] = impl;
}

function parseHash() {
  const h = decodeURIComponent(location.hash.slice(1));
  if (h.startsWith('/')) {
    const parts = h.slice(1).split('/');
    return { page: parts[0] || 'services', rest: parts.slice(1) };
  }
  return { page: 'services', rest: h ? h.split('/') : [] };
}

function applyServicesRoute([name, file]) {
  if (!name || !state.services.some((s) => s.name === name)) return;
  const id = file !== undefined && file !== '' ? Number(file) : undefined;
  const fileId = Number.isInteger(id) ? id : undefined;
  if (name === state.selected && (fileId === undefined || fileId === state.fileId)) return;
  selectService(name, fileId);
}

function route() {
  const { page, rest } = parseHash();
  const name = page === 'services' || pages[page] ? page : 'services';
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
  if (name === 'services') applyServicesRoute(rest);
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
  get services() {
    return state.services;
  },
};
