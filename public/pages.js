'use strict';

// History, Sites and Security pages. Shares helpers from app.js via window.SD.
// Everything from the server (IPs, paths, usernames, URLs) is untrusted text:
// it is only ever inserted with textContent.

(() => {
  const { $, el, api, postJson, toast, prefs } = SD;
  const SERIES = ['var(--series-1)', 'var(--series-2)', 'var(--series-3)'];

  // ---------- shared helpers ----------

  function ago(t) {
    if (!t) return '—';
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 60) return `${s}s ago`;
    if (s < 3600) return `${Math.round(s / 60)}m ago`;
    if (s < 86400) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  }

  const clock = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const n = (v) => (typeof v === 'number' ? v.toLocaleString() : '—');

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

  // ================= History =================

  (() => {
    let timer = null;
    let charts = [];
    const destroy = () => {
      charts.forEach((c) => c.destroy());
      charts = [];
    };
    const pct = (v) => `${Math.round(v)}%`;
    const mb = (v) => (v >= 1024 ? `${(v / 1024).toFixed(1)} GB` : `${Math.round(v)} MB`);

    function peakAndNow(values) {
      const nums = values.filter((v) => typeof v === 'number');
      if (!nums.length) return { now: null, peak: null, avg: null };
      return { now: values[values.length - 1], peak: Math.max(...nums), avg: nums.reduce((a, b) => a + b, 0) / nums.length };
    }

    async function load() {
      let d;
      try {
        d = await api('/api/history');
      } catch (e) {
        pageError($('history-services'), e);
        return;
      }
      destroy();
      const to = Date.now();
      const from = to - d.windowMs;

      const since = d.collectingSince;
      $('history-meta').textContent =
        since > from + 10 * 60e3
          ? `Sampled every minute. Collecting since ${new Date(since).toLocaleString()}; the charts fill in over 24 hours.`
          : 'Sampled every minute.';

      const cpu = peakAndNow(d.system.cpu);
      const mem = peakAndNow(d.system.mem);
      charts.push(
        Charts.line($('chart-cpu'), {
          times: d.times,
          series: [{ name: 'CPU', values: d.system.cpu, color: SERIES[0] }],
          from,
          to,
          yMax: 100,
          format: pct,
          ariaLabel: `Server CPU over the last 24 hours. Now ${cpu.now ?? '—'}%, peak ${cpu.peak ?? '—'}%.`,
        })
      );
      charts.push(
        Charts.line($('chart-mem'), {
          times: d.times,
          series: [{ name: 'Memory used', values: d.system.mem, color: SERIES[0] }],
          from,
          to,
          yMax: 100,
          format: pct,
          ariaLabel: `Server memory over the last 24 hours. Now ${mem.now ?? '—'}%, peak ${mem.peak ?? '—'}%.`,
        })
      );
      $('chart-cpu').dataset.summary = cpu.now !== null ? `Now ${pct(cpu.now)} · peak ${pct(cpu.peak)} · avg ${pct(cpu.avg)}` : '';
      $('chart-mem').dataset.summary = mem.now !== null ? `Now ${mem.now.toFixed(1)}% · peak ${mem.peak.toFixed(1)}%` : '';
      for (const id of ['chart-cpu', 'chart-mem']) {
        const box = $(id).parentElement;
        let sum = box.querySelector('.chart-summary');
        if (!sum) {
          sum = el('p', 'chart-summary muted small');
          box.append(sum);
        }
        sum.textContent = $(id).dataset.summary;
      }

      const grid = $('history-services');
      grid.replaceChildren();
      for (const name of Object.keys(d.services)) {
        const sv = d.services[name];
        const c = peakAndNow(sv.cpu);
        const m = peakAndNow(sv.mem);
        const card = el('section', 'panel multiple');
        card.append(el('h4', null, labelFor(name)));

        const rowCpu = el('div', 'spark-row');
        const cpuBox = el('div', 'spark');
        rowCpu.append(
          el('span', 'spark-label', 'CPU'),
          cpuBox,
          el('span', 'spark-value', c.now !== null ? `${c.now}%` : '—'),
          el('span', 'spark-peak muted', c.peak !== null ? `peak ${c.peak}%` : '')
        );
        const rowMem = el('div', 'spark-row');
        const memBox = el('div', 'spark');
        rowMem.append(
          el('span', 'spark-label', 'Memory'),
          memBox,
          el('span', 'spark-value', m.now !== null ? mb(m.now) : '—'),
          el('span', 'spark-peak muted', m.peak !== null ? `peak ${mb(m.peak)}` : '')
        );
        card.append(rowCpu, rowMem);
        grid.append(card);

        charts.push(
          Charts.line(cpuBox, {
            times: d.times,
            series: [{ name: 'CPU', values: sv.cpu, color: SERIES[0] }],
            from,
            to,
            yMax: Math.max(5, Charts.niceMax((c.peak || 0) * 1.1)),
            format: (v) => `${Math.round(v * 10) / 10}%`,
            height: 40,
            compact: true,
            ariaLabel: `${labelFor(name)} CPU, last 24 hours`,
          })
        );
        charts.push(
          Charts.line(memBox, {
            times: d.times,
            series: [{ name: 'Memory', values: sv.mem, color: SERIES[0] }],
            from,
            to,
            yMax: Charts.niceMax((m.peak || 1) * 1.1),
            format: mb,
            height: 40,
            compact: true,
            ariaLabel: `${labelFor(name)} memory, last 24 hours`,
          })
        );
      }
    }

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

  // ================= Sites =================

  (() => {
    let timer = null;
    let charts = [];
    const destroy = () => {
      charts.forEach((c) => c.destroy());
      charts = [];
    };

    function certInfo(site) {
      const isHttps = site.url.startsWith('https:');
      if (!isHttps) return { text: 'No HTTPS', level: 'warn' };
      const c = site.cert;
      if (!c) return { text: site.last ? 'No certificate received' : 'Not checked yet', level: site.last ? 'bad' : '' };
      if (!c.authorized) return { text: `Untrusted certificate: ${c.authError || 'unknown reason'}`, level: 'bad' };
      const when = c.validTo ? new Date(c.validTo).toLocaleDateString() : '?';
      const days = c.daysLeft;
      const level = days === null ? '' : days <= 7 ? 'bad' : days <= 14 ? 'warn' : 'ok';
      const issuer = c.issuer ? ` · ${c.issuer}` : '';
      return { text: `Expires in ${days} day${days === 1 ? '' : 's'} (${when})${issuer}`, level };
    }

    function render(data) {
      destroy();
      const list = $('sites-list');
      list.replaceChildren();
      if (!data.sites.length) {
        list.append(el('div', 'log-note', 'No sites configured. Add a "sites" list to config.json.'));
        return;
      }
      const to = Date.now();
      const from = to - 24 * 3600e3;
      for (const s of data.sites) {
        const card = el('section', 'panel site');
        const head = el('div', 'site-head');
        const title = el('div');
        const link = el('a', 'site-url', s.url);
        link.href = s.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        title.append(el('h3', null, s.name), link);
        const last = s.last;
        const status = !last ? pill('Pending', 'dim') : last.up ? pill(`Up · ${last.code}`, 'ok') : pill(last.code ? `Down · ${last.code}` : 'Down', 'bad');
        head.append(title, status);
        card.append(head);

        const facts = el('div', 'site-facts');
        const fact = (label, value, level) => {
          const f = el('div', 'site-fact' + (level ? ' ' + level : ''));
          f.append(el('span', 'muted small', label), el('strong', null, value));
          facts.append(f);
        };
        fact('Response', last && typeof last.ms === 'number' ? `${last.ms} ms` : '—');
        fact('Avg (24h)', s.avgMs !== null ? `${s.avgMs} ms` : '—');
        const upLevel = s.uptimePct === null ? '' : s.uptimePct >= 99.9 ? '' : s.uptimePct >= 99 ? 'warn' : 'bad';
        fact('Uptime (24h)', s.uptimePct !== null ? `${s.uptimePct}%` : '—', upLevel);
        fact('Checked', last ? ago(last.t) : '—');
        card.append(facts);

        const cert = certInfo(s);
        const certLine = el('p', 'site-cert ' + cert.level);
        certLine.append(el('span', 'muted small', 'Certificate '), el('span', null, cert.text));
        card.append(certLine);

        if (last && !last.up && last.error) card.append(el('p', 'site-error', last.error));

        const sparkBox = el('div', 'spark spark-wide');
        card.append(sparkBox);
        list.append(card);

        const times = s.points.map((p) => p[0]);
        const values = s.points.map((p) => (p[2] ? p[1] : null));
        charts.push(
          Charts.line(sparkBox, {
            times,
            series: [{ name: 'Response time', values, color: SERIES[0] }],
            from,
            to,
            format: (v) => `${Math.round(v)} ms`,
            height: 44,
            compact: true,
            ariaLabel: `${s.name} response time, last 24 hours`,
          })
        );
      }
      $('sites-meta').textContent = `Checked every minute from this server · updated ${clock(Date.parse(data.generatedAt))}`;
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

    SD.registerPage('sites', {
      show() {
        load();
        timer = setInterval(() => !document.hidden && load(), 30e3);
      },
      hide() {
        clearInterval(timer);
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

    const PORT_STATUS = {
      'open-unexpected': ['Open · unexpected', 'bad'],
      'open-expected': ['Open', 'ok'],
      restricted: ['Restricted', 'ok'],
      blocked: ['Blocked', 'dim'],
      local: ['Local only', 'dim'],
      unknown: ['Unknown', 'warn'],
    };

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
      if (data.ports && data.ports.rows.some((r) => r.firewallOff)) {
        box.prepend(el('div', 'notice bad', 'Windows Firewall is turned off for the active network profile. Every listening port is reachable.'));
      }
    }

    function renderPorts(data) {
      const sum = $('ports-summary');
      const tableBox = $('ports-table');
      sum.replaceChildren();
      if (!data.ports) {
        tableBox.replaceChildren();
        sum.append(el('span', 'muted small', data.collectorError || 'No port data yet.'));
        return;
      }
      const c = data.ports.counts;
      const chip = (count, text, cls) => count && sum.append(el('span', `chip ${cls}`, `${count} ${text}`));
      chip(c['open-unexpected'], 'open unexpectedly', 'bad');
      chip(c['open-expected'], 'open (expected)', 'ok');
      chip(c.restricted, 'restricted to specific IPs', 'ok');
      chip(c.blocked, 'blocked by firewall', 'dim');
      chip(c.local, 'local only', 'dim');
      chip(c.unknown, 'unknown', 'warn');

      const hideLocal = $('ports-hide-local').checked;
      const rows = data.ports.rows.filter((r) => !(hideLocal && r.status === 'local'));

      const t = table(
        ['Status', 'Port', 'Listening on', 'Program', 'Firewall'],
        rows.map((r) => {
          const [label, cls] = PORT_STATUS[r.status] || [r.status, 'warn'];
          const statusCell = el('span', 'cell-stack');
          statusCell.append(pill(label, cls));

          const prog = el('span', 'cell-stack');
          prog.append(el('span', null, r.process || `PID ${r.pid}`));
          if (r.services.length) prog.append(el('span', 'muted small', r.services.join(', ')));
          if (r.path) prog.title = r.path;

          const fw = el('span', 'cell-stack');
          if (r.status === 'local') fw.append(el('span', 'muted', 'Not reachable from outside'));
          else {
            fw.append(el('span', null, r.rules.join(', ') || '—'));
            if (r.status === 'restricted') fw.append(el('span', 'muted small', `Allowed from: ${r.remote.join(', ')}`));
          }
          if (r.status === 'open-unexpected') {
            const fix = el('span', 'row-actions');
            const b = el('button', 'btn btn-xs', 'Copy block rule');
            b.type = 'button';
            b.addEventListener('click', () =>
              copy(
                `New-NetFirewallRule -DisplayName "Block ${r.port}/${r.proto}" -Direction Inbound -LocalPort ${r.port} -Protocol ${r.proto} -Action Block`,
                `block rule for port ${r.port}`
              )
            );
            fix.append(b, el('span', 'muted small', 'or bind the app to 127.0.0.1'));
            fw.append(fix);
          }
          return [statusCell, el('code', null, `${r.port}/${r.proto}`), r.addresses.join(', '), prog, fw];
        }),
        'No listening ports to show.'
      );
      tableBox.replaceWith(t);
      t.id = 'ports-table';
    }

    function renderAttacks(data) {
      const a = data.attacks;
      const stats = $('attack-stats');
      stats.replaceChildren(
        stat('Windows / RDP failed logins', n(a.totals.windows), a.sources.windows ? `${n(a.totals.lockouts)} account lockouts` : 'collector data unavailable', a.totals.windows > 100 ? 'warn' : ''),
        stat('MariaDB login attempts', n(a.totals.mariadb), a.sources.mariadb ? 'from outside IPs' : 'log not readable', a.totals.mariadb > 0 ? 'bad' : ''),
        stat('Web probes', n(a.totals.web), a.sources.web ? '4xx and scanner paths' : 'Caddy logs not readable'),
        stat('Unique source IPs', n(a.totals.uniqueIps), 'excluding your trusted IPs')
      );

      // Legend + chart
      const series = [
        { name: 'Windows / RDP', values: a.hourly.windows, color: SERIES[0], total: a.totals.windows },
        { name: 'MariaDB', values: a.hourly.mariadb, color: SERIES[1], total: a.totals.mariadb },
        { name: 'Web probes', values: a.hourly.web, color: SERIES[2], total: a.totals.web },
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
        ariaLabel: `Failed attempts per hour over the last 24 hours: ${series.map((s) => `${s.name} ${s.total}`).join(', ')}.`,
      });

      // Hourly table view
      $('attack-hourly-table').replaceChildren(
        table(
          ['Hour', { label: 'Windows / RDP', num: true }, { label: 'MariaDB', num: true }, { label: 'Web probes', num: true }, { label: 'Total', num: true }],
          a.hourly.labels.map((l, i) => {
            const w = a.hourly.windows[i];
            const m = a.hourly.mariadb[i];
            const wb = a.hourly.web[i];
            return [new Date(l).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' }), n(w), n(m), n(wb), n(w + m + wb)];
          })
        )
      );

      $('table-windows').replaceChildren(
        table(
          ['Source IP', { label: 'Attempts', num: true }, 'Usernames tried', 'Last seen'],
          a.windowsTop.map((g) => [ipCell(g.ip), n(g.count), namesList(g.users), ago(g.last)]),
          a.sources.windows ? 'No failed Windows logins in the last 24 hours.' : 'Collector data unavailable.'
        )
      );
      $('table-mariadb').replaceChildren(
        table(
          ['Source IP', { label: 'Connections', num: true }, { label: 'Wrong password', num: true }, 'Users tried', 'Last seen'],
          a.mariadbTop.map((g) => [ipCell(g.ip), n(g.count), n(g.denied), namesList(g.users), ago(g.last)]),
          a.sources.mariadb ? 'No outside connections to MariaDB in the last 24 hours.' : 'MariaDB log not configured or not readable.'
        )
      );
      $('table-web').replaceChildren(
        table(
          ['Source IP', { label: 'Requests', num: true }, { label: 'Scanner paths', num: true }, 'Most requested', 'Sites', 'Last seen'],
          a.webTop.map((g) => [ipCell(g.ip), n(g.count), n(g.probes), namesList(g.paths), namesList(g.hosts), ago(g.last)]),
          a.sources.web ? 'No probes in the last 24 hours.' : 'Caddy logs not configured or not readable.'
        )
      );
      $('table-success').replaceChildren(
        table(
          ['When', 'User', 'Type', 'From'],
          a.successes.map((s) => [
            new Date(s.t).toLocaleString(),
            s.user,
            s.type === 10 ? 'RDP' : s.type === 3 ? 'Network' : `Type ${s.type}`,
            (() => {
              const c = ipCell(s.ip || '—', { trusted: s.trusted });
              if (!s.trusted) c.append(el('span', 'tag tag-warn', 'not your IP'));
              return c;
            })(),
          ]),
          a.sources.windows ? 'No remote logins in the last 24 hours.' : 'Collector data unavailable.'
        )
      );
    }

    function render(data) {
      last = data;
      updateBadge(data);
      renderNotes(data);
      renderPorts(data);
      renderAttacks(data);
      const parts = [];
      if (data.collectorAt) parts.push(`Windows data from ${clock(Date.parse(data.collectorAt))} (collected every 2 minutes)`);
      else if (data.collectorError) parts.push(data.collectorError);
      if (data.mock) parts.push('sample data');
      $('security-meta').textContent = parts.join(' · ');
    }

    async function load() {
      try {
        render(await api('/api/security'));
      } catch (e) {
        pageError($('security-notes'), e);
      }
    }

    $('ports-hide-local').checked = prefs.get('hideLocal', true);
    $('ports-hide-local').addEventListener('change', () => {
      prefs.set('hideLocal', $('ports-hide-local').checked);
      if (last) renderPorts(last);
    });
    $('attack-table-toggle').addEventListener('change', () => {
      const on = $('attack-table-toggle').checked;
      $('attack-hourly-table').hidden = !on;
      $('attack-chart').hidden = on;
    });

    // Keep the nav badge current even when the page isn't open.
    const badgeTick = async () => {
      if (!document.hidden && !timer) {
        try {
          updateBadge(await api('/api/security'));
        } catch {
          /* ignore */
        }
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

  SD.init();
})();
