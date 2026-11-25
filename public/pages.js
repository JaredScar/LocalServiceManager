'use strict';

// History, Sites and Security pages. Shares helpers from app.js via window.SD.
// Everything from the server (IPs, paths, usernames, URLs) is untrusted text:
// it is only ever inserted with textContent.

(() => {
  const { $, el, api, postJson, toast, prefs, fmtDuration } = SD;
  const SERIES = ['#3d6cf5', '#e08a3c', '#3aaa6d'];
  const MEM_COLOR = '#d0893e';

  // ---------- shared helpers ----------

  function ago(t) {
    if (!t) return '—';
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  }

  const clock = (t) => new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const n = (v) => (typeof v === 'number' ? v.toLocaleString() : '—');

  function svgIcon(pathD, size) {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', String(size));
    svg.setAttribute('height', String(size));
    svg.setAttribute('aria-hidden', 'true');
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('fill', 'currentColor');
    path.setAttribute('d', pathD);
    svg.append(path);
    return svg;
  }

  function globeIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('aria-hidden', 'true');
    const add = (tag, attrs) => {
      const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
      for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
      svg.append(node);
    };
    add('circle', { cx: '12', cy: '12', r: '8.25', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6' });
    add('ellipse', { cx: '12', cy: '12', rx: '3.4', ry: '8.25', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6' });
    add('path', { d: 'M4 12h16M5.2 8.2h13.6M5.2 15.8h13.6', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6' });
    return svg;
  }

  function lockIcon() {
    return svgIcon('M12 2.5a4 4 0 0 0-4 4V9H7a1.5 1.5 0 0 0-1.5 1.5v8A1.5 1.5 0 0 0 7 20h10a1.5 1.5 0 0 0 1.5-1.5v-8A1.5 1.5 0 0 0 17 9h-1V6.5a4 4 0 0 0-4-4zm-2 6.5V6.5a2 2 0 1 1 4 0V9h-4z', 14);
  }

  function table(headers, rows, emptyText) {
    const t = el('table', 'table');
    const thead = el('thead');
    const tr = el('tr');
    headers.forEach((h) => tr.append(el('th', h.num ? 'num' : null, h.label || h)));
    thead.append(tr);
    const tbody = el('tbody');
    if (!rows.length) {
      const r = el('tr');
      const td = el('td', 'empty', emptyText || 'Nothing to show.');
      td.colSpan = headers.length;
      r.append(td);
      tbody.append(r);
    }
    for (const cells of rows) {
      const r = el('tr');
      cells.forEach((c, i) => {
        const td = el('td', headers[i] && headers[i].num ? 'num' : null);
        if (c instanceof Node) td.append(c);
        else td.textContent = c ?? '—';
        r.append(td);
      });
      tbody.append(r);
    }
    t.append(thead, tbody);
    return t;
  }

  function pill(text, cls) {
    return el('span', `pill ${cls}`, text);
  }

  function stat(label, value, sub, level) {
    const t = el('div', 'stat' + (level ? ' ' + level : ''));
    t.append(el('div', 'stat-label', label), el('div', 'stat-value', value));
    if (sub) t.append(el('div', 'stat-sub', sub));
    return t;
  }

  const IP_RE = /^[0-9a-fA-F:.]{3,45}$/;

  async function copy(text, what) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copied ${what}. Paste it into an admin PowerShell on the server.`, 'ok');
    } catch {
      window.prompt('Copy this command:', text);
    }
  }

  function ipCell(ip, { trusted } = {}) {
    const wrap = el('span', 'ip-cell');
    wrap.append(el('code', null, ip));
    if (trusted) wrap.append(el('span', 'tag tag-ok', 'you'));
    if (!trusted && IP_RE.test(ip)) {
      const b = el('button', 'btn btn-xs', 'Copy block rule');
      b.type = 'button';
      b.title = 'Copies a PowerShell command that blocks this IP in Windows Firewall';
      b.addEventListener('click', () =>
        copy(`New-NetFirewallRule -DisplayName "Block ${ip}" -Direction Inbound -RemoteAddress ${ip} -Action Block`, `block rule for ${ip}`)
      );
      wrap.append(b);
    }
    return wrap;
  }

  function namesList(items) {
    return items && items.length ? items.map((x) => (x.count > 1 ? `${x.name} (${x.count})` : x.name)).join(', ') : '—';
  }

  function labelFor(name) {
    const s = SD.services.find((x) => x.name === name);
    return s ? s.label : name;
  }

  function pageError(container, e) {
    container.replaceChildren(el('div', 'log-note bad', `Could not load: ${e.message}`));
  }

  // ================= Overview =================

  (() => {
    let timer = null;
    let unsub = null;
    let shown = false;
    const cache = { security: null, sites: null, history: null, patches: null };
    const DB_PORTS = new Set([1433, 3306, 5432, 6379, 9200, 11211, 27017]);

    const partOfDay = (t) => {
      const h = new Date(t).getHours();
      if (h < 12) return 'This morning';
      if (h < 17) return 'This afternoon';
      return 'Tonight';
    };

    function runningBits(s) {
      const bits = [];
      if (s.cpuPercent !== null && s.cpuPercent !== undefined) bits.push(`${s.cpuPercent}%`);
      if (s.memoryMB !== null) bits.push(`${s.memoryMB} MB`);
      if (s.startedAt) bits.push(`up ${fmtDuration(s.startedAt)}`);
      return bits.join(' · ');
    }

    function findService(names) {
      const want = (names || []).map((n) => String(n).toLowerCase());
      return SD.services.find((s) => want.includes(s.name.toLowerCase())) || null;
    }

    function baseName(p) {
      if (!p) return '';
      const parts = String(p).split(/[/\\]/);
      return parts[parts.length - 1] || '';
    }

    function flowBox(kind, title, sub) {
      const box = el('div', 'flow-box ' + kind);
      box.append(el('strong', null, title));
      if (sub) box.append(el('span', null, sub));
      return box;
    }

    function stoppedAt(name) {
      const hist = cache.history;
      const row = hist && hist.services && hist.services[name];
      if (!row || !row.cpu) return null;
      for (let i = row.cpu.length - 1; i > 0; i--) {
        if (typeof row.cpu[i] !== 'number' && typeof row.cpu[i - 1] === 'number') return hist.times[i];
      }
      return null;
    }

    function serviceNode(s, tone) {
      const stopped = s.state === 'Stopped';
      const node = el('div', 'node' + (stopped || tone === 'bad' ? ' bad' : '') + (stopped ? ' dim' : ''));
      const title = el('strong');
      title.append(el('i', 'dot ' + (stopped || tone === 'bad' ? 'bad' : 'ok')));
      title.append(document.createTextNode(s.label));
      node.append(title);
      let sub = '';
      if (stopped) {
        const at = stoppedAt(s.name);
        sub = at ? `stopped since ${clock(at)}` : 'stopped';
      } else {
        sub = runningBits(s);
        if (s.isSelf) sub = sub ? `${sub} · this app` : 'this app';
      }
      if (sub) node.append(el('span', null, sub));
      return node;
    }

    function renderMap() {
      const host = $('traffic-map');
      host.replaceChildren();
      const sec = cache.security;
      const ports = sec && sec.ports;
      if (!ports) {
        host.append(el('p', 'muted', sec && sec.collectorError ? sec.collectorError : 'Port data is not available yet.'));
        return;
      }
      const attacks = sec.attacks;
      const failed = attacks ? (attacks.totals.windows || 0) + (attacks.totals.mariadb || 0) + (attacks.totals.web || 0) : 0;
      const ips = attacks ? attacks.totals.uniqueIps || 0 : 0;
      const youIp = (sec.trustedIps && sec.trustedIps[0]) || '';

      const dedupe = (list) => {
        const out = [];
        for (const r of list) {
          if (out.some((m) => m.port === r.port && m.status === r.status)) continue;
          out.push(r);
        }
        return out;
      };
      const expected = dedupe(ports.rows.filter((r) => r.status === 'open-expected'));
      const unexpected = dedupe(ports.rows.filter((r) => r.status === 'open-unexpected'));
      const restricted = dedupe(ports.rows.filter((r) => r.status === 'restricted'));
      const shown = new Set();
      const internet = [];
      const you = [];

      const pipeFor = (portsList, note, kind) => ({
        kind,
        text: `${[...new Set(portsList)].map((p) => `:${p}`).join(' · ')} ${note}`,
      });

      if (expected.length) {
        const svc = findService(expected.flatMap((r) => r.services));
        const expectedPorts = expected.map((r) => r.port).sort((a, b) => Number(b === 443) - Number(a === 443) || a - b);
        internet.push({
          pipe: pipeFor(expectedPorts, 'open, expected', 'ok'),
          node: svc ? serviceNode(svc, 'ok') : flowBox('ok', expected[0].process || 'Public', ''),
          linkDown: false,
        });
        if (svc) shown.add(svc.name);
      }

      const named = new Set();
      for (const r of unexpected.concat(restricted)) for (const name of r.services || []) named.add(String(name).toLowerCase());
      const fronted = SD.services.filter((s) => s.state === 'Running' && !s.isSelf && !shown.has(s.name) && !named.has(s.name.toLowerCase()));
      if (fronted.length && internet.length) internet[0].linkDown = true;
      for (const s of fronted) {
        internet.push({ pipe: null, node: serviceNode(s, 'ok') });
        shown.add(s.name);
      }

      const managed = new Map();
      const unmanaged = [];
      for (const r of unexpected) {
        const svc = findService(r.services);
        if (!svc) {
          unmanaged.push(r);
          continue;
        }
        const cur = managed.get(svc.name) || { svc, ports: [] };
        if (!cur.ports.includes(r.port)) cur.ports.push(r.port);
        managed.set(svc.name, cur);
      }
      for (const { svc, ports: svcPorts } of managed.values()) {
        internet.push({ pipe: pipeFor(svcPorts, 'should be closed', 'bad'), node: serviceNode(svc, 'bad') });
        shown.add(svc.name);
      }

      for (const s of SD.services) {
        if (shown.has(s.name)) continue;
        internet.push({ pipe: null, node: serviceNode(s, s.state === 'Stopped' ? 'bad' : 'ok') });
        shown.add(s.name);
      }

      if (unmanaged.length) {
        const procs = [...new Set(unmanaged.map((r) => baseName(r.path) || r.process).filter(Boolean))];
        const node = el('div', 'node dim');
        const title = el('strong');
        title.append(el('i', 'dot warn'), document.createTextNode('Not a managed service'));
        node.append(title, el('span', null, procs.join(' · ') || 'listening publicly'));
        internet.push({ pipe: pipeFor(unmanaged.map((r) => r.port), 'open unexpectedly', 'bad'), node });
      }

      const youGroups = new Map();
      for (const r of restricted) {
        const key = r.port === 3389 ? 'rdp' : String(r.port);
        const cur = youGroups.get(key) || { ports: [], row: r };
        if (!cur.ports.includes(r.port)) cur.ports.push(r.port);
        youGroups.set(key, cur);
      }
      for (const { ports: youPorts, row } of youGroups.values()) {
        const svc = findService(row.services);
        const node = svc
          ? serviceNode(svc, 'ok')
          : (() => {
            const box = el('div', 'node');
            const title = el('strong');
            title.append(el('i', 'dot ok'), document.createTextNode(row.port === 3389 ? 'Remote Desktop' : baseName(row.path) || row.process || `Port ${row.port}`));
            box.append(title);
            if (row.process) box.append(el('span', null, row.process));
            return box;
          })();
        you.push({ pipe: pipeFor(youPorts, 'only your IP', 'ok'), node });
      }

      if (!internet.length && !you.length) {
        host.append(el('p', 'muted', 'No listeners to draw.'));
        return;
      }

      const map = el('div', 'tmap2');
      const head = el('div', 'tmap-head');
      ['Internet', 'Firewall', 'This server'].forEach((label, i) => {
        const s = el('span', null, label);
        s.style.gridColumn = String(i + 1);
        s.style.gridRow = '1';
        head.append(s);
      });
      map.append(head);
      const place = (node, col, row, span) => {
        node.style.gridColumn = String(col);
        node.style.gridRow = span > 1 ? `${row} / span ${span}` : String(row);
        map.append(node);
      };
      const chip = (pipe) => {
        const elPipe = el('div', 'pipe ' + pipe.kind);
        elPipe.append(el('span', null, pipe.text));
        return elPipe;
      };
      const paint = (group, start, source) => {
        group.forEach((row, i) => {
          if (row.pipe) place(chip(row.pipe), 2, start + i, 1);
          if (row.linkDown) row.node.classList.add('linked');
          place(row.node, 3, start + i, 1);
        });
        if (group.length && source) place(source, 1, start, group.length);
      };

      const net = el('div', 'flow-box bad internet');
      const netTitle = el('strong', 'net-title');
      netTitle.append(globeIcon(), document.createTextNode('The internet'));
      net.append(netTitle);
      if (failed) net.append(el('div', 'big-num', n(failed)));
      net.append(el('span', null, failed ? `failed attempts today${ips ? ` from ${n(ips)} IPs` : ''}` : 'Public traffic'));
      const lines = [];
      if (attacks && attacks.totals.windows) lines.push(`${n(attacks.totals.windows)} stopped at the firewall`);
      if (attacks && attacks.totals.mariadb) lines.push(`${n(attacks.totals.mariadb)} reached the database`);
      if (attacks && attacks.totals.web) lines.push(`${n(attacks.totals.web)} scanned the web`);
      if (lines.length) {
        const ul = el('ul', 'net-lines');
        lines.forEach((text) => ul.append(el('li', null, text)));
        net.append(ul);
      }
      paint(internet, 2, internet.length ? net : null);
      paint(you, 2 + internet.length, you.length ? flowBox('you', 'You', youIp || 'a trusted address') : null);
      host.append(map);
    }

    function needCard(kicker, title, body, actions) {
      const card = el('article', 'need-card');
      const kick = el('p', 'need-kicker' + (kicker === 'Worth a look' ? ' warn' : ''), kicker);
      card.append(kick, el('h3', null, title));
      if (body) card.append(el('p', null, body));
      if (actions) card.append(actions);
      return card;
    }

    function renderNeeds() {
      const needs = $('needs-you');
      const worth = $('worth');
      needs.replaceChildren();
      worth.replaceChildren();
      const items = [];

      for (const s of SD.services) {
        if (s.state !== 'Stopped') continue;
        const actions = el('div', 'need-actions');
        if (s.controllable) {
          const start = el('button', 'btn btn-primary', `Start ${s.label}`);
          start.type = 'button';
          start.addEventListener('click', () => SD.runAction(s.name, 'start'));
          actions.append(start);
        }
        const logs = el('a', 'btn', 'View logs');
        logs.href = `#/services/${encodeURIComponent(s.name)}`;
        actions.append(logs);
        const how = s.startMode === 'Auto' ? 'It is set to start automatically, but it has not come back on its own.' : 'It stays stopped until you start it.';
        const at = stoppedAt(s.name);
        items.push(needCard('Service down', at ? `${s.label} stopped at ${clock(at)}` : `${s.label} stopped`, how, actions));
      }

      const rows = cache.security && cache.security.ports ? cache.security.ports.rows : [];
      const unexpected = rows.filter((r) => r.status === 'open-unexpected');
      const primary = unexpected.find((r) => DB_PORTS.has(r.port)) || unexpected[0];
      const rest = unexpected.filter((r) => r !== primary);
      if (primary) {
        const svc = findService(primary.services);
        const name = svc ? svc.label : baseName(primary.path) || primary.process || `Port ${primary.port}`;
        const maria = cache.security.attacks && primary.port === 3306 ? cache.security.attacks.totals.mariadb : 0;
        const fromIps = cache.security.attacks ? cache.security.attacks.totals.uniqueIps : 0;
        const body = maria
          ? `${n(maria)} login attempts${fromIps ? ` from ${n(fromIps)} IPs` : ''} today. Bind it to 127.0.0.1 and block port ${primary.port}.`
          : `It is listening on 0.0.0.0:${primary.port}. Bind it to 127.0.0.1, or block the port.`;
        const actions = el('div', 'need-actions');
        const fix = el('a', 'btn btn-primary', 'Show me the fix');
        fix.href = '#/security';
        const see = el('a', 'btn', 'See attempts');
        see.href = '#/security';
        actions.append(fix, see);
        items.push(needCard('Exposed', `${name} is open to the internet`, body, actions));
      }

      const sites = (cache.sites && cache.sites.sites) || [];
      for (const site of sites) {
        if (!site.last || site.last.up !== false) continue;
        items.push(needCard('Site down', `${site.name} is not responding`, site.last.error || `Last check returned ${site.last.code || 'no response'}.`));
      }

      const behind = ((cache.patches && cache.patches.products) || []).filter((p) => p.status === 'behind' || p.status === 'eol');
      if (behind.length) {
        const actions = el('div', 'need-actions');
        const link = el('a', 'btn', 'Review patches');
        link.href = '#/patches';
        actions.append(link);
        const names = behind.map((p) => p.label).slice(0, 3).join(', ');
        items.push(needCard('Patch', behind.length === 1 ? `${behind[0].label} is behind` : `${behind.length} programs are behind a patch`, names, actions));
      }

      if (!items.length) needs.append(needCard('', 'Nothing is waiting on you', 'Services, sites, and the firewall look settled.'));
      else needs.append(...items);

      const looks = [];
      if (rest.length) {
        const names = [...new Set(rest.map((r) => baseName(r.path) || r.process).filter(Boolean))];
        looks.push({
          swatch: 'warn',
          title: rest.map((r) => `:${r.port}`).join(' and ') + (rest.length === 1 ? ' is open' : ' are open'),
          body: `${names.join(' and ') || 'These listeners'} ${names.length === 1 ? 'is' : 'are'} public, and not in the expected list.`,
          href: '#/security',
          link: 'Review',
        });
      }
      const updates = SD.maintenance && SD.maintenance.updates;
      if (updates && updates.count) {
        const titles = Array.isArray(updates.titles) ? updates.titles.filter(Boolean) : [];
        looks.push({ swatch: 'dim', title: 'Windows update ready', body: titles[0] || `${updates.count} pending` });
      } else if (SD.maintenance && SD.maintenance.rebootPending) {
        looks.push({ swatch: 'dim', title: 'A reboot is pending', body: 'Windows is waiting to finish installing updates.' });
      }
      for (const site of sites) {
        const days = site.cert && site.cert.daysLeft;
        if (typeof days === 'number' && days <= 14 && site.cert.authorized !== false) {
          looks.push({
            swatch: days < 0 ? 'bad' : 'warn',
            title: `${site.name} certificate`,
            body: days < 0 ? 'The certificate has expired.' : `Expires in ${days} day${days === 1 ? '' : 's'}.`,
          });
        }
      }
      if (!looks.length) looks.push({ swatch: 'dim', title: 'Nothing else standing out', body: 'No pending updates or certificates due soon.' });
      const lookCard = el('article', 'look-card');
      for (const item of looks) {
        const row = el('div', 'look-row');
        const text = el('div');
        const heading = el('h3');
        heading.append(el('i', 'swatch ' + item.swatch), document.createTextNode(item.title));
        text.append(heading);
        if (item.body) text.append(el('p', null, item.body));
        row.append(text);
        if (item.href) {
          const link = el('a', 'text-link', item.link || 'Review');
          link.href = item.href;
          row.append(link);
        }
        lookCard.append(row);
      }
      worth.append(lookCard);

      const stopped = SD.services.filter((s) => s.state === 'Stopped').length;
      const running = SD.services.filter((s) => s.state === 'Running').length;
      const total = SD.services.length;
      const sitesDown = sites.filter((s) => s.last && s.last.up === false).length;
      const count = items.length;
      const headline = $('overview-headline');
      if (!total && !cache.security) headline.textContent = 'Loading the server…';
      else if (count === 0) headline.textContent = 'Everything that this dashboard watches is running fine.';
      else if (count === 1) headline.textContent = 'One thing needs you. Everything else is running fine.';
      else headline.textContent = `${count === 2 ? 'Two' : count} things need you. Everything else is running fine.`;

      const sys = SD.system;
      const bits = [];
      if (total) bits.push(`${running} of ${total} service${total === 1 ? '' : 's'} up`);
      if (sites.length) bits.push(sitesDown ? `${sites.length - sitesDown} of ${sites.length} sites up` : sites.length === 1 ? 'site up' : 'sites up');
      if (sys && typeof sys.cpuPercent === 'number') bits.push(`CPU ${Math.round(sys.cpuPercent)}%`);
      if (sys && sys.memTotalMB) bits.push(`memory ${Math.round(((sys.memTotalMB - sys.memFreeMB) / sys.memTotalMB) * 100)}%`);
      if (sys && sys.disks && sys.disks[0] && sys.disks[0].sizeGB) {
        const d = sys.disks[0];
        bits.push(`disk ${Math.round(((d.sizeGB - d.freeGB) / d.sizeGB) * 100)}% used`);
      }
      if (sys && sys.bootTime) bits.push(`up ${fmtDuration(sys.bootTime)}`);
      $('overview-sub').textContent = bits.join(' · ');
      $('overview-when').textContent = `${partOfDay(Date.now())}, ${clock(Date.now())}`;
      if (stopped) document.title = `(${stopped}) svcdash`;
    }

    function pushEvent(list, t, title, detail, level) {
      if (!t || Number.isNaN(t)) return;
      list.push({ t, title, detail: detail || '', level: level || 'ok' });
    }

    function renderTimeline() {
      const box = $('timeline');
      box.replaceChildren();
      const events = [];
      const hist = cache.history;
      if (hist && hist.times && hist.times.length) {
        const spike = findSpike(hist.times, hist.system.cpu);
        if (spike) pushEvent(events, spike.t, `CPU spiked to ${Math.round(spike.v)}%`, 'The busiest moment in this window.', 'warn');
        for (const name of Object.keys(hist.services || {})) {
          const values = hist.services[name].cpu;
          for (let i = 1; i < values.length; i++) {
            const prev = typeof values[i - 1] === 'number';
            const cur = typeof values[i] === 'number';
            if (prev === cur) continue;
            pushEvent(events, hist.times[i], `${labelFor(name)} ${cur ? 'restarted' : 'stopped'}`, '', cur ? 'ok' : 'bad');
          }
        }
      }
      const attacks = cache.security && cache.security.attacks;
      if (attacks) {
        const latestWin = (attacks.windowsTop || []).reduce((m, g) => Math.max(m, g.last || 0), 0);
        if (attacks.totals.windows) {
          pushEvent(events, latestWin || Date.now(), `${n(attacks.totals.windows)} failed Windows logins`, attacks.totals.uniqueIps ? `From ${n(attacks.totals.uniqueIps)} addresses, not counting yours.` : '', 'bad');
        }
        const latestDb = (attacks.mariadbTop || []).reduce((m, g) => Math.max(m, g.last || 0), 0);
        if (attacks.totals.mariadb) pushEvent(events, latestDb || Date.now(), `MariaDB refused ${n(attacks.totals.mariadb)} login${attacks.totals.mariadb === 1 ? '' : 's'}`, '', 'bad');
        const web = (attacks.webTop || [])[0];
        if (web && web.paths && web.paths[0]) pushEvent(events, web.last, `Requests for ${web.paths[0].name}`, `${n(web.count)} from ${web.ip}`, 'warn');
        for (const s of attacks.successes || []) {
          const how = s.type === 10 ? 'Remote Desktop' : s.type === 3 ? 'the network' : 'a remote sign-in';
          pushEvent(events, s.t, s.trusted ? `You signed in over ${how}` : `Sign-in over ${how}`, s.user || '', s.trusted ? 'ok' : 'warn');
        }
      }
      events.sort((a, b) => b.t - a.t);
      const top = events.slice(0, 12);
      if (!top.length) {
        box.append(el('p', 'muted', 'Nothing recorded in the last day yet. History fills in as the dashboard keeps running.'));
      }
      let group = '';
      for (const ev of top) {
        const g = partOfDay(ev.t);
        if (g !== group) {
          group = g;
          box.append(el('div', 'tl-group', g));
        }
        const row = el('div', 'tl');
        row.append(el('span', 'tl-time', clock(ev.t)), el('span', 'dot ' + (ev.level === 'bad' ? 'bad' : ev.level === 'warn' ? 'warn' : 'ok')));
        const text = el('div');
        text.append(el('strong', null, ev.title));
        if (ev.detail) text.append(el('p', 'muted small', ev.detail));
        row.append(text);
        box.append(row);
      }
      const a = attacks;
      const rdpLocked = cache.security && cache.security.ports && cache.security.ports.rows.some((r) => r.port === 3389 && r.status === 'restricted');
      const day = [];
      if (a && a.totals.windows) {
        day.push(`${n(a.totals.windows)} failed Windows logins${a.totals.uniqueIps ? ` from ${n(a.totals.uniqueIps)} IPs` : ''}${a.totals.lockouts ? ` and ${n(a.totals.lockouts)} account lockouts` : ''}`);
      }
      if (rdpLocked) day.push('Remote Desktop only accepts your IP, so none got through');
      $('timeline-sub').textContent = day.length ? `All day: ${day.join('. ')}.` : '';
    }

    function meterRow(label, right, pct, sub) {
      const row = el('div', 'meter-row');
      const lab = el('div', 'meter-label');
      lab.append(el('strong', null, label), el('span', null, right));
      const bar = el('div', 'meter');
      const fill = el('span');
      fill.style.width = `${Math.max(0, Math.min(100, pct || 0))}%`;
      bar.append(fill);
      row.append(lab, bar);
      if (sub) row.append(el('p', 'muted small', sub));
      return row;
    }

    function renderSide() {
      const server = $('overview-server');
      const sitesBox = $('overview-sites');
      server.replaceChildren();
      sitesBox.replaceChildren();
      server.append(el('h3', null, 'Server'));
      const sys = SD.system;
      if (!sys) server.append(el('p', 'muted', 'No sample yet.'));
      else {
        const cpu = Number(sys.cpuPercent) || 0;
        const hist = cache.history;
        let peak = null;
        if (hist && hist.system && hist.system.cpu) {
          const nums = hist.system.cpu.filter((v) => typeof v === 'number');
          if (nums.length) peak = Math.max(...nums);
        }
        const cpuRight = peak !== null ? `${Math.round(cpu)}% · peak ${Math.round(peak)}%` : `${Math.round(cpu)}%`;
        server.append(meterRow('CPU', cpuRight, cpu));
        if (sys.memTotalMB) {
          const used = sys.memTotalMB - sys.memFreeMB;
          const pct = (used / sys.memTotalMB) * 100;
          server.append(meterRow('Memory', `${(used / 1024).toFixed(0)} / ${(sys.memTotalMB / 1024).toFixed(0)} GB`, pct));
        }
        for (const d of sys.disks || []) {
          const pct = d.sizeGB ? ((d.sizeGB - d.freeGB) / d.sizeGB) * 100 : 0;
          server.append(meterRow(`Disk ${d.drive}`, `${Math.round(d.freeGB).toLocaleString()} GB free`, pct));
        }
        if (sys.bootTime) server.append(el('p', 'muted small', `${sys.logicalCpus || ''} threads · up ${fmtDuration(sys.bootTime)}`.replace(/^ threads/, '').trim()));
      }

      sitesBox.append(el('h3', null, 'Sites'));
      const sites = (cache.sites && cache.sites.sites) || [];
      if (!sites.length) sitesBox.append(el('p', 'muted', 'No sites configured.'));
      let soonest = null;
      for (const s of sites) {
        const row = el('div', 'site-mini');
        const up = s.last && s.last.up;
        row.append(el('span', 'dot ' + (!s.last ? 'dim' : up ? 'ok' : 'bad')));
        const grow = el('span', 'grow');
        let hostName = s.name;
        try { hostName = new URL(s.url).host; } catch { /* keep the configured name */ }
        grow.append(el('strong', null, hostName));
        const days = s.cert && typeof s.cert.daysLeft === 'number' ? s.cert.daysLeft : null;
        if (days !== null && (soonest === null || days < soonest)) soonest = days;
        row.append(grow);
        const right = el('span', 'muted small', s.last && typeof s.last.ms === 'number' ? `${s.last.ms} ms` : '—');
        row.append(right, el('span', 'muted small', s.uptimePct !== null && s.uptimePct !== undefined ? `${s.uptimePct}%` : ''));
        sitesBox.append(row);
      }
      if (soonest !== null) {
        const soon = sites.find((s) => s.cert && s.cert.daysLeft === soonest && s.cert.validTo);
        const when = soon ? new Date(soon.cert.validTo).toLocaleDateString([], { month: 'short', day: 'numeric' }) : '';
        sitesBox.append(el('p', 'muted small', soonest < 0 ? 'A certificate has expired.' : when ? `Certificates expire ${when}, in ${soonest} days.` : `Certificates expire in ${soonest} days at the soonest.`));
      }
    }

    function render() {
      renderMap();
      renderNeeds();
      renderTimeline();
      renderSide();
    }

    async function load() {
      const [security, sites, history, patches] = await Promise.all([
        api('/api/security').catch(() => null),
        api('/api/sites').catch(() => null),
        api('/api/history').catch(() => null),
        api('/api/patches').catch(() => null),
      ]);
      cache.security = security;
      cache.sites = sites;
      cache.history = history;
      cache.patches = patches;
      if (shown) render();
    }

    SD.registerPage('overview', {
      show() {
        shown = true;
        render();
        load();
        unsub = SD.onServices(() => shown && render());
        timer = setInterval(() => !document.hidden && load(), 60e3);
      },
      hide() {
        shown = false;
        clearInterval(timer);
        timer = null;
        if (unsub) unsub();
        unsub = null;
      },
      refresh: load,
    });
  })();

  // ================= History =================

  (() => {
    let timer = null;
    let charts = [];
    let last = null;
    let rangeH = Number(prefs.get('historyRange', 24)) || 24;
    if (![1, 6, 24].includes(rangeH)) rangeH = 24;
    const destroy = () => {
      charts.forEach((c) => c.destroy());
      charts = [];
    };
    const pct = (v) => (typeof v === 'number' ? `${Math.round(v)}%` : '—');
    const mb = (v) => (v >= 1024 ? `${(v / 1024).toFixed(1)} GB` : `${Math.round(v)} MB`);

    function peakAndNow(values) {
      const nums = (values || []).filter((v) => typeof v === 'number');
      if (!nums.length) return { now: null, peak: null, avg: null };
      const now = [...values].reverse().find((v) => typeof v === 'number');
      return { now, peak: Math.max(...nums), avg: nums.reduce((a, b) => a + b, 0) / nums.length };
    }

    function take(times, arr, from) {
      const outT = [];
      const outV = [];
      times.forEach((t, i) => {
        if (t >= from) {
          outT.push(t);
          outV.push(arr ? arr[i] : null);
        }
      });
      return { times: outT, values: outV };
    }

    function findSpike(times, values) {
      const pts = [];
      values.forEach((v, i) => {
        if (typeof v === 'number') pts.push({ t: times[i], v });
      });
      if (pts.length < 8) return null;
      const peak = pts.reduce((a, b) => (b.v > a.v ? b : a));
      const sorted = pts.map((p) => p.v).sort((a, b) => a - b);
      const med = sorted[Math.floor(sorted.length / 2)];
      if (peak.v >= 50 && peak.v >= med * 1.8) return peak;
      return null;
    }

    function metrics(id, rows) {
      const box = $(id);
      box.replaceChildren();
      for (const [label, value] of rows) {
        const d = el('div');
        d.append(el('span', null, label), el('strong', null, value));
        box.append(d);
      }
    }

    function pins(container, events, from, to) {
      container.replaceChildren();
      const span = Math.max(1, to - from);
      const sorted = events.filter((e) => e.t >= from && e.t <= to).sort((a, b) => a.t - b.t);
      const placed = [];
      let maxLane = 0;
      for (const ev of sorted) {
        const pctPos = ((ev.t - from) / span) * 100;
        const end = pctPos > 78;
        const start = pctPos < 12;
        const width = Math.min(36, 8 + String(ev.label).length * 0.42);
        const left = end ? pctPos - width : pctPos;
        const right = end ? pctPos : Math.min(100, pctPos + width);
        let lane = 0;
        while (placed.some((p) => p.lane === lane && left < p.right && right > p.left)) lane += 1;
        placed.push({ lane, left, right });
        maxLane = Math.max(maxLane, lane);
        const pin = el('div', 'pin ' + (ev.kind || '') + (end ? ' end' : start ? ' start' : ''));
        pin.style.left = `${pctPos}%`;
        pin.style.top = `${lane * 22}px`;
        pin.append(el('span', 'pin-dot'), el('span', 'pin-label', ev.label));
        container.append(pin);
      }
      container.style.height = sorted.length ? `${20 + maxLane * 22}px` : '0px';
    }

    function draw(d) {
      destroy();
      last = d;
      const to = Date.now();
      const from = to - rangeH * 3600e3;
      document.querySelectorAll('#history-range button').forEach((b) => b.classList.toggle('on', Number(b.dataset.range) === rangeH));
      const label = rangeH === 1 ? 'Last hour' : rangeH === 6 ? 'Last 6 hours' : 'Last 24 hours';
      $('history-window-label').textContent = label;

      const cpu = take(d.times, d.system.cpu, from);
      const mem = take(d.times, d.system.mem, from);
      const cpuStats = peakAndNow(cpu.values);
      const memStats = peakAndNow(mem.values);
      const spike = findSpike(cpu.times, cpu.values);
      const down = SD.services.find((s) => s.state === 'Stopped');
      let headline = rangeH === 1 ? 'A quiet hour.' : rangeH === 6 ? 'A quiet few hours.' : 'A quiet day.';
      if (spike) headline = `A quiet ${rangeH === 1 ? 'hour' : 'day'}, apart from one CPU spike at ${clock(spike.t)}.`;
      else if (down) headline = `${down.label} is down. The rest of this ${rangeH === 1 ? 'hour' : 'stretch'} was quiet.`;
      $('history-headline').textContent = headline;

      const since = d.collectingSince;
      $('history-meta').textContent = since > from + 10 * 60e3
        ? `Collecting since ${new Date(since).toLocaleString()}. The chart fills in over 24 hours.`
        : 'Server and per-service usage, sampled every minute.';

      const threads = SD.system && SD.system.logicalCpus;
      $('cpu-sub').textContent = threads ? `${threads} threads · events from the timeline are pinned below the chart` : 'Events from the timeline are pinned below the chart';
      metrics('cpu-metrics', [['Now', pct(cpuStats.now)], ['Peak', pct(cpuStats.peak)], ['Average', pct(cpuStats.avg)]]);
      charts.push(Charts.line($('chart-cpu'), {
        times: cpu.times,
        series: [{ name: 'CPU', values: cpu.values, color: SERIES[0] }],
        from, to, yMax: 100, format: pct, height: 220, area: true,
        ariaLabel: `Server CPU. Now ${pct(cpuStats.now)}, peak ${pct(cpuStats.peak)}.`,
      }));
      const callout = $('cpu-callout');
      if (spike) {
        const pos = ((spike.t - from) / Math.max(1, to - from));
        callout.hidden = false;
        callout.textContent = `Spiked to ${Math.round(spike.v)}% at ${clock(spike.t)}`;
        callout.style.left = `calc(36px + (100% - 48px) * ${pos})`;
      } else callout.hidden = true;

      const pinEvents = [];
      for (const name of Object.keys(d.services)) {
        const values = d.services[name].cpu;
        for (let i = 1; i < values.length; i++) {
          const prev = typeof values[i - 1] === 'number';
          const cur = typeof values[i] === 'number';
          if (prev === cur || d.times[i] < from) continue;
          const when = clock(d.times[i]);
          const words = `${labelFor(name)} ${cur ? 'restarted' : 'stopped'}`;
          const pctPos = ((d.times[i] - from) / Math.max(1, to - from)) * 100;
          pinEvents.push({
            t: d.times[i],
            kind: cur ? 'ok' : 'bad',
            label: pctPos > 78 ? `${when} ${words}` : `${words} ${when}`,
          });
        }
      }
      pins($('cpu-pins'), pinEvents, from, to);

      const sys = SD.system;
      let memSub = '';
      if (sys && sys.memTotalMB && typeof memStats.now === 'number') {
        const used = (memStats.now / 100) * sys.memTotalMB;
        memSub = `${(used / 1024).toFixed(0)} of ${(sys.memTotalMB / 1024).toFixed(0)} GB`;
      }
      $('mem-sub').textContent = memSub;
      metrics('mem-metrics', [['', memStats.now !== null ? `${memStats.now.toFixed(1)}%` : '—'], ['', memStats.peak !== null ? `peak ${memStats.peak.toFixed(1)}%` : '']]);
      $('mem-metrics').classList.add('hero');
      charts.push(Charts.line($('chart-mem'), {
        times: mem.times,
        series: [{ name: 'Memory', values: mem.values, color: SERIES[0] }],
        from, to, yMax: 100, format: pct, height: 150, area: true,
        ariaLabel: `Memory. Now ${pct(memStats.now)}.`,
      }));

      const drives = Object.keys(d.system.disk || {});
      const diskSeries = drives.map((drive, i) => ({ name: drive, values: take(d.times, d.system.disk[drive], from).values, color: SERIES[i % SERIES.length] }));
      const diskValues = diskSeries.flatMap((s) => s.values).filter((v) => typeof v === 'number');
      const diskNow = drives.map((drive) => {
        const vals = take(d.times, d.system.disk[drive], from).values;
        const nowV = [...vals].reverse().find((v) => typeof v === 'number');
        return nowV == null ? null : nowV;
      }).filter((v) => v != null);
      const diskPeak = diskValues.length ? Math.max(...diskValues) : null;
      const drive = (sys && sys.disks && sys.disks[0]) || null;
      $('disk-title').textContent = drive ? `Disk ${drive.drive}` : drives[0] ? `Disk ${drives[0]}` : 'Disk';
      $('disk-sub').textContent = drive ? `${Math.round(drive.freeGB).toLocaleString()} GB free of ${Math.round(drive.sizeGB).toLocaleString()} GB` : '';
      metrics('disk-metrics', [['', diskNow.length ? `${diskNow[0].toFixed(1)}%` : '—'], ['', diskPeak !== null ? `peak ${diskPeak.toFixed(1)}%` : '']]);
      $('disk-metrics').classList.add('hero');
      const diskTimes = take(d.times, drives[0] ? d.system.disk[drives[0]] : [], from).times;
      charts.push(Charts.line($('chart-disk'), {
        times: diskTimes.length ? diskTimes : cpu.times,
        series: diskSeries.length ? diskSeries : [{ name: 'Disk', values: [], color: SERIES[0] }],
        from, to, yMax: 100, format: pct, height: 150, area: true,
        ariaLabel: 'Disk use.',
      }));

      const table = el('table', 'svc-table');
      const thead = el('thead');
      const hr = el('tr');
      ['Service', 'CPU', 'Now / peak', 'Memory', 'Now / peak'].forEach((h) => hr.append(el('th', null, h)));
      thead.append(hr);
      const tbody = el('tbody');
      for (const name of Object.keys(d.services)) {
        const cpuS = take(d.times, d.services[name].cpu, from);
        const memS = take(d.times, d.services[name].mem, from);
        const c = peakAndNow(cpuS.values);
        const m = peakAndNow(memS.values);
        const live = SD.services.find((s) => s.name === name);
        const stopped = live && live.state === 'Stopped';
        const tr = el('tr');
        const nameCell = el('td', 'name' + (stopped ? ' down' : ''));
        nameCell.append(el('strong', null, labelFor(name)));
        let stoppedAtTs = null;
        let restartedAt = null;
        for (let i = 1; i < cpuS.values.length; i++) {
          const prevOn = typeof cpuS.values[i - 1] === 'number';
          const curOn = typeof cpuS.values[i] === 'number';
          if (prevOn && !curOn) stoppedAtTs = cpuS.times[i];
          if (!prevOn && curOn) restartedAt = cpuS.times[i];
        }
        const busy = c.peak !== null && c.now !== null && c.peak > (c.avg || 0) * 2 && c.peak >= 20;
        let note = '';
        if (stopped) note = stoppedAtTs ? `stopped at ${clock(stoppedAtTs)}` : 'stopped';
        else if (busy) note = `busiest at ${clock(cpuS.times[cpuS.values.indexOf(c.peak)] || from)}`;
        else if (restartedAt) note = `restarted at ${clock(restartedAt)}`;
        if (note) nameCell.append(el('span', null, note));
        tr.append(nameCell);

        const cpuCell = el('td');
        if (c.peak === null) cpuCell.append(el('span', 'muted', '—'));
        else {
          const box = el('div', 'spark');
          cpuCell.append(box);
          charts.push(Charts.line(box, {
            times: cpuS.times, series: [{ name: 'CPU', values: cpuS.values, color: SERIES[0] }],
            from, to, yMax: Math.max(5, (c.peak || 1) * 1.2), height: 36, compact: true, area: true,
            ariaLabel: `${labelFor(name)} CPU`,
          }));
        }
        const cpuNum = el('td', 'num-stack');
        cpuNum.append(el('strong', null, c.now !== null ? `${c.now}%` : '—'), el('span', null, c.peak !== null ? `peak ${c.peak}%` : ''));
        const memCell = el('td');
        if (m.peak === null) memCell.append(el('span', 'muted', '—'));
        else {
          const box = el('div', 'spark');
          memCell.append(box);
          charts.push(Charts.line(box, {
            times: memS.times, series: [{ name: 'Memory', values: memS.values, color: MEM_COLOR }],
            from, to, yMax: Math.max(1, (m.peak || 1) * 1.2), format: mb, height: 36, compact: true, area: true,
            ariaLabel: `${labelFor(name)} memory`,
          }));
        }
        const memNum = el('td', 'num-stack');
        memNum.append(el('strong', null, m.now !== null ? mb(m.now) : '—'), el('span', null, m.peak !== null ? `peak ${mb(m.peak)}` : ''));
        tr.append(cpuCell, cpuNum, memCell, memNum);
        tbody.append(tr);
      }
      table.append(thead, tbody);
      $('history-services').replaceChildren(table);
    }

    async function load() {
      try {
        draw(await api('/api/history'));
      } catch (e) {
        pageError($('history-services'), e);
      }
    }

    document.querySelectorAll('#history-range button').forEach((b) => {
      b.addEventListener('click', () => {
        rangeH = Number(b.dataset.range);
        prefs.set('historyRange', rangeH);
        if (last) draw(last);
      });
    });

    SD.registerPage('history', {
      show() {
        load();
        timer = setInterval(() => !document.hidden && load(), 60e3);
      },
      hide() {
        clearInterval(timer);
        destroy();
      },
      refresh: load,
    });
  })();

  function findSpike(times, values) {
    const pts = [];
    values.forEach((v, i) => {
      if (typeof v === 'number') pts.push({ t: times[i], v });
    });
    if (pts.length < 8) return null;
    const peak = pts.reduce((a, b) => (b.v > a.v ? b : a));
    const sorted = pts.map((p) => p.v).sort((a, b) => a - b);
    const med = sorted[Math.floor(sorted.length / 2)];
    if (peak.v >= 50 && peak.v >= med * 1.8) return peak;
    return null;
  }

  // ================= Sites =================

  (() => {
    let timer = null;
    let charts = [];
    const destroy = () => {
      charts.forEach((c) => c.destroy());
      charts = [];
    };

    function certBanner(site) {
      const isHttps = site.url.startsWith('https:');
      const box = el('div', 'cert-banner');
      if (!isHttps) {
        box.classList.add('warn');
        box.append(el('strong', null, 'No HTTPS'), el('span', null, 'This check is plain HTTP.'));
        return box;
      }
      const c = site.cert;
      if (!c) {
        box.classList.add(site.last ? 'bad' : 'warn');
        box.append(el('strong', null, site.last ? 'No certificate received' : 'Not checked yet'));
        return box;
      }
      if (!c.authorized) {
        box.classList.add('bad');
        box.append(el('strong', null, 'Certificate is not trusted'), el('span', null, c.authError || 'The chain did not verify.'));
        return box;
      }
      const days = c.daysLeft;
      const when = c.validTo ? new Date(c.validTo).toLocaleDateString([], { month: 'short', day: 'numeric', year: 'numeric' }) : '';
      const issuer = c.issuer ? ` · issued by ${c.issuer}` : '';
      const level = days === null ? '' : days <= 7 ? 'bad' : days <= 14 ? 'warn' : '';
      if (level) box.classList.add(level);
      const titleText = days === null ? 'Certificate present' : days < 0 ? 'Certificate has expired' : `Certificate valid for ${days} more day${days === 1 ? '' : 's'}`;
      const title = el('strong');
      title.append(lockIcon(), document.createTextNode(titleText));
      box.append(title, el('span', null, `Expires ${when}${issuer}`));
      return box;
    }

    function updateSitesBadge(list) {
      const badge = $('nav-sites-badge');
      if (!badge) return;
      const problems = (list || []).map(siteProblem).filter(Boolean);
      const bad = problems.some((level) => level === 'bad');
      badge.hidden = problems.length === 0;
      badge.classList.toggle('warn', problems.length > 0 && !bad);
      badge.textContent = String(problems.length);
      badge.title = bad ? `${problems.length} site${problems.length === 1 ? '' : 's'} down or with a certificate due` : `${problems.length} certificate${problems.length === 1 ? '' : 's'} expiring within 14 days`;
    }

    function siteProblem(site) {
      if (site.last && site.last.up === false) return 'bad';
      const cert = site.cert;
      if (cert && cert.authorized === false) return 'bad';
      if (cert && typeof cert.daysLeft === 'number' && cert.daysLeft <= 7) return 'bad';
      if (cert && typeof cert.daysLeft === 'number' && cert.daysLeft <= 14) return 'warn';
      return null;
    }

    function render(data) {
      destroy();
      const list = $('sites-list');
      list.replaceChildren();
      const sites = data.sites || [];
      const down = sites.filter((s) => s.last && s.last.up === false);
      const days = sites.map((s) => (s.cert && s.cert.authorized !== false && typeof s.cert.daysLeft === 'number' ? s.cert.daysLeft : null)).filter((d) => d !== null);
      const minDays = days.length ? Math.min(...days) : null;
      let headline = 'Sites';
      if (!sites.length) headline = 'No sites configured.';
      else if (down.length === 1) headline = `${down[0].name} is down.`;
      else if (down.length) headline = `${down.length} sites are down.`;
      else if (sites.length === 2 && minDays !== null) headline = `Both sites are up. Certificates are good for ${minDays} more days.`;
      else if (minDays !== null) headline = `${sites.length === 1 ? sites[0].name + ' is up' : `All ${sites.length} sites are up`}. Certificates are good for ${minDays} more days.`;
      else headline = sites.length === 1 ? `${sites[0].name} is up.` : `All ${sites.length} sites are up.`;
      $('sites-headline').textContent = headline;
      const lastT = sites.map((s) => s.last && s.last.t).filter(Boolean).sort((a, b) => b - a)[0];
      $('sites-meta').textContent = lastT ? `Checked every minute from this server. Last check ${ago(lastT)}.` : 'Checked every minute from this server.';

      if (!sites.length) {
        list.append(el('div', 'log-note', 'No sites configured. Add a "sites" list to config.json.'));
        updateSitesBadge([]);
        return;
      }

      const to = Date.now();
      const from = to - 24 * 3600e3;
      for (const s of sites) {
        const card = el('section', 'card site-card');
        const head = el('div', 'site-head');
        const title = el('div');
        let host = s.url;
        try { host = new URL(s.url).host; } catch { /* keep the raw url */ }
        const link = el('a', 'site-url', host);
        link.href = s.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        title.append(el('h3', null, s.name), link);
        const last = s.last;
        const status = !last ? pill('Pending', 'dim') : last.up ? pill(`Up · ${last.code}`, 'ok') : pill(last.code ? `Down · ${last.code}` : 'Down', 'bad');
        head.append(title, status);
        card.append(head);

        const facts = el('div', 'mini-stats');
        const fact = (label, value, level) => {
          const f = el('div', 'mini' + (level ? ' ' + level : ''));
          f.append(el('span', null, label), el('strong', null, value));
          facts.append(f);
        };
        fact('Response now', last && typeof last.ms === 'number' ? `${last.ms} ms` : '—');
        fact('24h average', s.avgMs !== null && s.avgMs !== undefined ? `${s.avgMs} ms` : '—');
        const upLevel = s.uptimePct === null || s.uptimePct === undefined ? '' : s.uptimePct >= 99 ? 'ok' : 'bad';
        fact('Uptime, 24h', s.uptimePct !== null && s.uptimePct !== undefined ? `${s.uptimePct}%` : '—', upLevel);
        card.append(facts);

        const times = (s.points || []).map((p) => p[0]);
        const values = (s.points || []).map((p) => (p[2] ? p[1] : null));
        if (times.length && times[0] - from > 2 * 60e3) {
          times.unshift(from);
          values.unshift(values[0]);
        }
        const nums = values.filter((v) => typeof v === 'number');
        const slow = nums.length ? Math.max(...nums) : null;
        const cap = el('div', 'chart-caption');
        cap.append(el('span', null, 'Response time, last 24 hours'), el('span', null, slow !== null ? `slowest ${Math.round(slow)} ms` : ''));
        card.append(cap);
        const sparkBox = el('div', 'spark');
        card.append(sparkBox, certBanner(s));
        if (last && !last.up && last.error) card.append(el('p', 'site-error', last.error));
        list.append(card);
        charts.push(Charts.line(sparkBox, {
          times, series: [{ name: 'Response time', values, color: SERIES[0] }],
          from, to, format: (v) => `${Math.round(v)} ms`, height: 110, compact: true, xLabels: true, area: true,
          gapMs: 24 * 3600e3,
          ariaLabel: `${s.name} response time, last 24 hours`,
        }));
      }
      updateSitesBadge(sites);
    }

    async function load() {
      try {
        render(await api('/api/sites'));
      } catch (e) {
        pageError($('sites-list'), e);
      }
    }

    $('sites-check').addEventListener('click', async () => {
      const b = $('sites-check');
      b.disabled = true;
      b.textContent = 'Checking…';
      try {
        render(await postJson('/api/sites/check'));
        toast('Sites checked.', 'ok');
      } catch (e) {
        toast(`Check failed: ${e.message}`, 'bad');
      } finally {
        b.disabled = false;
        b.textContent = 'Check now';
      }
    });

    const badgeTick = async () => {
      if (!document.hidden && !timer) {
        try { updateSitesBadge((await api('/api/sites')).sites); } catch { /* ignore */ }
      }
    };
    setTimeout(badgeTick, 1500);
    setInterval(badgeTick, 60e3);

    SD.registerPage('sites', {
      show() {
        load();
        timer = setInterval(() => !document.hidden && load(), 30e3);
      },
      hide() {
        clearInterval(timer);
        timer = null;
        destroy();
      },
      refresh: load,
    });
  })();

  // ================= Security =================

  (() => {
    let timer = null;
    let chart = null;
    let last = null;
    let portFilter = 'all';

    const PORT_STATUS = {
      'open-unexpected': ["Shouldn't be open", 'bad'],
      'open-expected': ['Open', 'ok'],
      restricted: ['Only you', 'ok'],
      blocked: ['Blocked', 'dim'],
      local: ['Local only', 'dim'],
      unknown: ['Unknown', 'warn'],
    };

    function blockCmd(port, proto) {
      return `New-NetFirewallRule -DisplayName "Block ${port}/${proto}" -Direction Inbound -LocalPort ${port} -Protocol ${proto} -Action Block`;
    }

    function commandRow(cmd) {
      const row = el('div', 'cmd');
      row.append(el('code', null, cmd));
      const b = el('button', 'btn btn-xs', 'Copy');
      b.type = 'button';
      b.addEventListener('click', () => copy(cmd, 'the firewall command'));
      row.append(b);
      return row;
    }

    function updateBadge(data) {
      const badge = $('nav-security-badge');
      const bad = data && data.ports ? data.ports.counts['open-unexpected'] || 0 : 0;
      badge.hidden = !bad;
      badge.textContent = String(bad);
      badge.title = `${bad} port${bad === 1 ? '' : 's'} open to the internet unexpectedly`;
    }

    function renderNotes(data) {
      const box = $('security-notes');
      box.replaceChildren();
      const notes = [...(data.attacks ? data.attacks.notes : [])];
      for (const nt of notes) box.append(el('div', `notice ${nt.level}`, nt.text));
      if (data.collectorError) box.prepend(el('div', 'notice bad', data.collectorError));
      if (data.ports && data.ports.rows.some((r) => r.firewallOff)) {
        box.prepend(el('div', 'notice bad', 'Windows Firewall is turned off for the active network profile. Every listening port is reachable.'));
      }
    }

    function exposureName(row) {
      const svc = row.services && row.services[0] ? labelFor(row.services[0]) : '';
      if (svc && svc !== row.services[0]) return svc;
      if (row.services && row.services[0]) return row.services[0];
      return row.process || `port ${row.port}`;
    }

    function copyChip(label, text) {
      const b = el('button', 'btn btn-sm', label);
      b.type = 'button';
      b.addEventListener('click', () => copy(text, 'the firewall command'));
      return b;
    }

    function renderActions(data) {
      const box = $('security-actions');
      box.replaceChildren();
      const rows = data.ports ? data.ports.rows.filter((r) => r.status === 'open-unexpected') : [];
      if (!rows.length) {
        const card = el('section', 'card fix-card');
        card.append(el('p', 'kicker', 'Clear'), el('h3', null, 'Nothing is open that should not be'));
        card.append(el('p', null, 'Every public listener is either expected or limited to specific addresses.'));
        box.append(card);
        return;
      }
      const seen = new Set();
      const unique = [];
      for (const r of rows) {
        if (seen.has(r.port)) continue;
        seen.add(r.port);
        unique.push(r);
      }
      const primary = unique.find((r) => [1433, 3306, 5432, 6379, 9200, 27017].includes(r.port)) || unique[0];
      const rest = unique.filter((r) => r !== primary);
      const name = exposureName(primary);
      const attempts = data.attacks && primary.port === 3306 ? data.attacks.totals.mariadb : 0;
      const fromIps = data.attacks ? data.attacks.totals.uniqueIps : 0;
      const card = el('section', 'card fix-card');
      card.append(el('p', 'kicker bad', 'Fix first'));
      card.append(el('h3', null, `Close ${name} on the internet`));
      card.append(el('p', null, attempts
        ? `${n(attempts)} login attempts${fromIps ? ` from ${n(fromIps)} IPs` : ''} reached it today. Two changes close it for good.`
        : `${name} is reachable on port ${primary.port}. Two changes close that.`));
      const steps = el('ol', 'steps');
      const one = el('li');
      one.append(el('strong', null, `1. If ${name} should only be used on this server, bind it to 127.0.0.1, then restart it.`));
      one.append(commandRow('bind-address = 127.0.0.1'));
      const two = el('li');
      two.append(el('strong', null, '2. Block the port in Windows Firewall (PowerShell, as admin).'));
      two.append(commandRow(blockCmd(primary.port, primary.proto)));
      steps.append(one, two);
      card.append(steps);
      const svcName = primary.services && primary.services[0];
      if (svcName) {
        const go = el('a', 'btn', `Go to ${labelFor(svcName)}`);
        go.href = `#/services/${encodeURIComponent(svcName)}`;
        card.append(go);
      }
      box.append(card);

      const other = el('section', 'card fix-card');
      if (rest.length) {
        const procs = [...new Set(rest.map((r) => r.process).filter(Boolean))];
        other.append(el('p', 'kicker muted', 'Then'));
        other.append(el('h3', null, `${rest.map((r) => ':' + r.port).join(' and ')} ${rest.length === 1 ? 'is' : 'are'} open too`));
        other.append(el('p', null, `${procs.join(' and ') || 'These programs'} listen where they should not. Bind them to 127.0.0.1, or block the ports.`));
        const actions = el('div', 'need-actions');
        rest.forEach((r) => actions.append(copyChip(`Copy block rule for :${r.port}`, blockCmd(r.port, r.proto))));
        other.append(actions);
      }
      const blocked = data.ports.rows.filter((r) => r.status === 'blocked');
      const rdp = data.ports.rows.find((r) => r.port === 3389 && r.status === 'restricted');
      if (rdp || blocked.length || (data.attacks && data.attacks.totals.windows)) {
        const hold = el('div', 'holding');
        hold.append(el('strong', null, 'Holding up well'));
        const bits = [];
        if (data.attacks && data.attacks.totals.windows) bits.push(`${n(data.attacks.totals.windows)} Windows login attempts today, all stopped`);
        if (rdp) bits.push(`Remote Desktop only accepts ${(data.trustedIps || []).join(', ') || 'your IP'}`);
        if (blocked.length) bits.push(`${[...new Set(blocked.map((r) => r.port))].slice(0, 4).join(', ')} are blocked`);
        hold.append(el('p', null, `${bits.join('. ')}.`));
        other.append(hold);
      }
      if (other.childNodes.length) box.append(other);
    }

    function renderPorts(data) {
      const tableBox = $('ports-table');
      const filters = $('port-filters');
      filters.replaceChildren();
      if (!data.ports) {
        tableBox.replaceChildren();
        filters.append(el('span', 'muted small', data.collectorError || 'No port data yet.'));
        return;
      }
      const choices = [
        ['all', 'All'],
        ['open-unexpected', "Shouldn't be open"],
        ['open-expected', 'Open'],
        ['restricted', 'Only you'],
        ['blocked', 'Blocked'],
      ];
      for (const [id, label] of choices) {
        const b = el('button', portFilter === id ? 'on' : '', label);
        b.type = 'button';
        b.addEventListener('click', () => {
          portFilter = id;
          renderPorts(data);
        });
        filters.append(b);
      }
      const localCount = data.ports.rows.filter((r) => r.status === 'local').length;
      $('ports-note').textContent = `From Windows Firewall rules. A firewall at your hosting provider isn't visible from here.${localCount ? ` ${localCount} local-only listener${localCount === 1 ? '' : 's'} hidden.` : ''}`;
      const rows = data.ports.rows.filter((r) => r.status !== 'local' && (portFilter === 'all' || r.status === portFilter));
      tableBox.replaceChildren(table(
        ['Status', 'Port', 'Listening on', 'Program', 'Firewall'],
        rows.map((r) => {
          const [label, cls] = PORT_STATUS[r.status] || [r.status, 'warn'];
          const prog = el('span');
          prog.append(document.createTextNode(r.process || `PID ${r.pid}`));
          if (r.services.length) prog.append(el('span', 'muted small', ' ' + r.services.join(', ')));
          const fw = el('span');
          fw.append(document.createTextNode(r.rules.join(', ') || '—'));
          if (r.status === 'restricted' && r.remote.length) fw.append(el('span', 'muted small', ` from ${r.remote.join(', ')}`));
          if (r.status === 'open-unexpected') fw.append(commandRow(blockCmd(r.port, r.proto)));
          return [el('span', 'status-text ' + cls, label), el('code', null, `${r.port}/${String(r.proto).toLowerCase()}`), r.addresses.join(', '), prog, fw];
        }),
        'Nothing in this filter.'
      ));
    }

    function mergeKnock(attacks) {
      const map = new Map();
      const add = (list, where, usersOf) => {
        for (const g of list || []) {
          const cur = map.get(g.ip) || { ip: g.ip, count: 0, where: [], users: [], last: 0 };
          cur.count += g.count || 0;
          if (!cur.where.includes(where)) cur.where.push(where);
          for (const u of usersOf(g)) {
            const prev = cur.users.find((x) => x.name === u.name);
            if (prev) prev.count += u.count || 1;
            else cur.users.push({ name: u.name, count: u.count || 1 });
          }
          cur.last = Math.max(cur.last, g.last || 0);
          map.set(g.ip, cur);
        }
      };
      add(attacks.windowsTop, 'Windows', (g) => g.users || []);
      add(attacks.mariadbTop, 'MariaDB', (g) => g.users || []);
      add(attacks.webTop, 'Web', (g) => g.paths || []);
      return [...map.values()].sort((a, b) => b.count - a.count).slice(0, 12);
    }

    function renderAttacks(data) {
      const a = data.attacks;
      if (!a) return;
      const stats = $('attack-stats');
      const stat = (value, label, sub, tone) => {
        const t = el('div', 'stat');
        const num = el('div', 'stat-value' + (tone ? ' ' + tone : ''), value);
        const lab = el('div', 'stat-label');
        lab.append(el('i', 'swatch ' + (tone || 'dim')), document.createTextNode(label));
        t.append(num, lab);
        if (sub) t.append(el('div', 'stat-sub', sub));
        return t;
      };
      stats.replaceChildren(
        stat(n(a.totals.windows), 'Windows logins refused', a.totals.lockouts ? `${n(a.totals.lockouts)} account lockouts` : 'Windows and Remote Desktop', 'blue'),
        stat(n(a.totals.mariadb), 'MariaDB login attempts', a.sources.mariadb ? 'reached the database' : 'MariaDB log not readable', 'warn'),
        stat(n(a.totals.web), 'Web probes', a.sources.web ? 'scanner paths' : 'Caddy logs not readable', 'ok'),
        stat(n(a.totals.uniqueIps), 'Hostile IPs', 'not counting your own', '')
      );

      const series = [
        { name: 'Windows', values: a.hourly.windows, color: SERIES[0], total: a.totals.windows },
        { name: 'MariaDB', values: a.hourly.mariadb, color: SERIES[1], total: a.totals.mariadb },
        { name: 'Web', values: a.hourly.web, color: SERIES[2], total: a.totals.web },
      ];
      const legend = $('attack-legend');
      legend.replaceChildren();
      for (const se of series) {
        const item = el('span', 'legend-item');
        const sw = el('span', 'legend-swatch');
        sw.style.background = se.color;
        item.append(sw, el('span', null, se.name), el('strong', null, n(se.total)));
        legend.append(item);
      }
      if (chart) chart.destroy();
      chart = Charts.stackedBars($('attack-chart'), {
        labels: a.hourly.labels,
        bucketMs: 3600e3,
        series,
        ariaLabel: `Failed attempts per hour: ${series.map((s) => `${s.name} ${s.total}`).join(', ')}.`,
      });

      const knock = mergeKnock(a);
      const max = knock.reduce((m, g) => Math.max(m, g.count), 1);
      $('knock-table').replaceChildren(table(
        ['Source', 'Attempts', 'Where', 'What they tried', 'Last seen'],
        knock.map((g) => {
          const bar = el('span');
          const track = el('span', 'bar-track');
          const fill = el('span', 'bar-fill');
          fill.style.width = `${Math.round((g.count / max) * 100)}%`;
          track.append(fill);
          bar.append(track, document.createTextNode(n(g.count)));
          return [ipCell(g.ip), bar, g.where.join(', '), namesList(g.users), ago(g.last)];
        }),
        'No failed attempts in the last 24 hours.'
      ));

      $('success-note').textContent = a.sources.windows ? '' : 'Collector data unavailable.';
      $('table-success').replaceChildren(table(
        ['When', 'User', 'Type', 'From'],
        (a.successes || []).map((s) => [
          new Date(s.t).toLocaleString(),
          s.user,
          s.type === 10 ? 'Remote Desktop' : s.type === 3 ? 'Network' : `Type ${s.type}`,
          ipCell(s.ip || '—', { trusted: s.trusted }),
        ]),
        'No remote sign-ins in the last 24 hours.'
      ));
    }

    function render(data) {
      last = data;
      updateBadge(data);
      renderNotes(data);
      const bad = data.ports ? data.ports.counts['open-unexpected'] || 0 : 0;
      const rdp = data.ports && data.ports.rows.find((r) => r.port === 3389 && r.status === 'restricted');
      let headline = bad
        ? `${bad} port${bad === 1 ? ' is' : 's are'} open that shouldn't be.`
        : 'Nothing is open that shouldn\'t be.';
      if (rdp) headline += ' Remote Desktop is locked to your IP.';
      $('security-headline').textContent = headline;
      const parts = [];
      if (data.collectorAt) parts.push(`Windows data from ${clock(Date.parse(data.collectorAt))}, collected every 2 minutes`);
      else if (data.collectorError) parts.push(data.collectorError);
      if (data.mock) parts.push('sample data');
      $('security-meta').textContent = parts.join(' · ');
      renderActions(data);
      renderPorts(data);
      renderAttacks(data);
    }

    async function load() {
      try {
        render(await api('/api/security'));
      } catch (e) {
        pageError($('security-notes'), e);
      }
    }

    $('security-refresh').addEventListener('click', load);

    const badgeTick = async () => {
      if (!document.hidden && !timer) {
        try { updateBadge(await api('/api/security')); } catch { /* ignore */ }
      }
    };
    setTimeout(badgeTick, 1500);
    setInterval(badgeTick, 5 * 60e3);

    SD.registerPage('security', {
      show() {
        load();
        timer = setInterval(() => !document.hidden && load(), 60e3);
      },
      hide() {
        clearInterval(timer);
        timer = null;
        if (chart) chart.destroy();
        chart = null;
      },
      refresh: load,
    });
  })();

  // ================= Patches =================

  (() => {
    let timer = null;
    let last = null;

    const PATCH_PILL = {
      current: ['Up to date', 'ok'],
      behind: ['Patch available', 'bad'],
      eol: ['Unsupported', 'bad'],
      missing: ['Not installed', 'dim'],
      error: ["Couldn't check", 'warn'],
    };

    function day(iso) {
      const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || '');
      if (!m) return null;
      return new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).toLocaleDateString();
    }

    function daysUntil(iso) {
      const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso || '');
      if (!m) return null;
      const then = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]));
      const now = new Date();
      const today = Date.UTC(now.getFullYear(), now.getMonth(), now.getDate());
      return Math.round((then - today) / 86400000);
    }

    function notesLink(url) {
      let parsed;
      try {
        parsed = new URL(url);
      } catch {
        return null;
      }
      if (parsed.protocol !== 'https:') return null;
      const a = el('a', 'site-url', 'Release notes');
      a.href = parsed.href;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      return a;
    }

    function patchDetail(p) {
      if (p.status === 'missing') return 'Not found. Set an exe path under patches in config.json if it is installed somewhere else.';
      if (p.status === 'error') return p.error || 'Could not check this program.';
      if (p.unmatched) return `${p.version} does not match a published release line. The newest release is ${p.latest}.`;
      if (p.status === 'behind') return `${p.version} is behind ${p.latest}.`;
      if (p.status === 'eol') {
        const ended = p.supportUntil
          ? `${p.supportLabel || 'Security support'} ended ${day(p.supportUntil)}.`
          : `${p.lineLabel || 'This release'} is no longer a supported release.`;
        if (p.latest && p.version && p.version !== p.latest) {
          return `${p.version} is behind the last release in this line (${p.latest}). ${ended}`;
        }
        return ended;
      }
      const line = p.lineLabel ? ` in line ${p.lineLabel}` : '';
      return `On ${p.version}, the latest patch${line}.`;
    }

    function detailLevel(p) {
      if (p.status === 'behind' || p.status === 'eol') return 'bad';
      if (p.status === 'error') return 'warn';
      if (p.status === 'current') return 'ok';
      return '';
    }

    function updateBadge(data) {
      const badge = $('nav-patches-badge');
      const list = data && data.products ? data.products : [];
      const n = list.filter((p) => p.status === 'behind' || p.status === 'eol').length;
      badge.hidden = n === 0;
      badge.textContent = String(n);
      badge.title = `${n} program${n === 1 ? '' : 's'} behind a patch or out of support`;
    }

    function render(data) {
      last = data;
      updateBadge(data);
      const notes = $('patches-notes');
      notes.replaceChildren();
      if (data.error) notes.append(el('div', 'notice warn', data.error));
      if ((data.products || []).some((p) => p.stale)) {
        notes.append(el('div', 'notice warn', 'A release feed could not be refreshed. Cards marked stale are showing the last copy.'));
      }

      const counts = { current: 0, behind: 0, eol: 0, error: 0 };
      for (const p of data.products || []) if (counts[p.status] != null) counts[p.status] += 1;
      const sum = $('patches-summary');
      sum.replaceChildren();
      const chip = (count, text, cls) => count && sum.append(el('span', `chip ${cls}`, `${count} ${text}`));
      chip(counts.behind, counts.behind === 1 ? 'patch available' : 'patches available', 'bad');
      chip(counts.eol, 'unsupported', 'bad');
      chip(counts.current, 'up to date', 'ok');
      chip(counts.error, "couldn't check", 'warn');

      const hideMissing = $('patches-hide-missing').checked;
      const list = (data.products || []).filter((p) => !(hideMissing && p.status === 'missing'));
      const box = $('patches-list');
      box.replaceChildren();
      if (!list.length) {
        const empty = data.products && data.products.length
          ? 'Nothing to show. Not-installed programs are hidden.'
          : 'None of the tracked programs were found. Add a patches list to config.json to point at an exe, or install one of the programs this page knows.';
        box.append(el('div', 'log-note', empty));
      }

      for (const p of list) {
        const card = el('section', 'panel site');
        const head = el('div', 'site-head');
        const title = el('div');
        title.append(el('h3', null, p.label));
        const [pillText, pillCls] = PATCH_PILL[p.status] || [p.status, 'warn'];
        head.append(title, pill(pillText, pillCls));
        card.append(head);

        const facts = el('div', 'site-facts patch-facts');
        const fact = (label, value, node) => {
          const f = el('div', 'site-fact');
          f.append(el('span', 'muted small', label));
          if (node) f.append(node);
          else f.append(el('strong', null, value || '—'));
          facts.append(f);
        };
        fact('Installed', p.version);
        fact('Latest', p.latest);
        const line = el('strong', 'line-label');
        line.append(document.createTextNode(p.lineLabel || '—'));
        if (p.lts && !/lts/i.test(p.lineLabel || '')) line.append(el('span', 'tag tag-ok', 'LTS'));
        fact('Line', null, line);
        fact('Released', p.latestDate ? day(p.latestDate) : null);
        card.append(facts);

        const detail = el('p', `site-cert ${detailLevel(p)}`);
        detail.append(el('span', null, patchDetail(p)));
        card.append(detail);

        const extra = el('div', 'patch-extra');
        const add = (text, cls) => extra.append(el('p', cls || 'muted small', text));
        if (typeof p.securityReleases === 'number' && p.securityReleases > 0) {
          add(
            `${p.securityReleases} security release${p.securityReleases === 1 ? '' : 's'} since this version.`,
            'site-cert bad'
          );
        }
        if (p.supportUntil && !p.supportEnded && p.status !== 'eol') {
          const days = daysUntil(p.supportUntil);
          const when = day(p.supportUntil);
          const label = p.supportLabel || 'Security support';
          const ended = days != null && days < 0;
          add(ended ? `${label} ended ${when}.` : `${label} until ${when}.`, days != null && days <= 60 ? 'site-cert warn' : 'muted small');
        }
        if (p.activeSupportEnded && !p.supportEnded) {
          add(`${p.activeSupportLabel || 'Active support'} ended ${day(p.activeSupportEnded)}.`);
        }
        if (p.newerLine && p.newerLine.latest) add(`Newer line ${p.newerLine.label} (latest ${p.newerLine.latest}).`);
        if (p.alsoRunning) add(`This dashboard is running ${p.alsoRunning}.`);
        if (p.stale) add(`Release information is the last copy (${ago(Date.parse(p.feedAt))}).`, 'site-cert warn');
        if (p.path) add(p.path, 'muted small patch-path');
        const link = notesLink(p.notesUrl);
        if (link) extra.append(link);
        if (extra.childNodes.length) card.append(extra);
        box.append(card);
      }

      const bits = [];
      if (data.localAt) bits.push(`versions ${ago(Date.parse(data.localAt))}`);
      if (data.feedsAt) bits.push(`release feeds ${ago(Date.parse(data.feedsAt))}`);
      if (data.mock) bits.push('sample data');
      $('patches-meta').textContent = bits.join(' · ');
    }

    async function load() {
      try {
        render(await api('/api/patches'));
      } catch (e) {
        pageError($('patches-list'), e);
      }
    }

    $('patches-hide-missing').checked = prefs.get('hideUninstalled', true);
    $('patches-hide-missing').addEventListener('change', () => {
      prefs.set('hideUninstalled', $('patches-hide-missing').checked);
      if (last) render(last);
    });

    $('patches-check').addEventListener('click', async () => {
      const b = $('patches-check');
      b.disabled = true;
      b.textContent = 'Checking…';
      try {
        render(await postJson('/api/patches/check'));
        toast('Patch check finished.', 'ok');
      } catch (e) {
        toast(`Check failed: ${e.message}`, 'bad');
      } finally {
        b.disabled = false;
        b.textContent = 'Check now';
      }
    });

    const badgeTick = async () => {
      if (!document.hidden && !timer) {
        try {
          updateBadge(await api('/api/patches'));
        } catch {
          /* ignore */
        }
      }
    };
    setTimeout(badgeTick, 1500);
    setInterval(badgeTick, 60e3);

    SD.registerPage('patches', {
      show() {
        load();
        timer = setInterval(() => !document.hidden && load(), 60e3);
      },
      hide() {
        clearInterval(timer);
        timer = null;
      },
      refresh: load,
    });
  })();

  SD.init();
})();
