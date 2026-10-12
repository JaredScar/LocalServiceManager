'use strict';

// Tiny SVG chart helpers: a time-series line chart (with crosshair tooltip and
// keyboard support) and a stacked bar chart (with per-bar tooltips).
// All labels are set with textContent.

const Charts = (() => {
  const NS = 'http://www.w3.org/2000/svg';

  function s(tag, attrs, parent) {
    const n = document.createElementNS(NS, tag);
    for (const k in attrs) n.setAttribute(k, attrs[k]);
    if (parent) parent.append(n);
    return n;
  }

  function h(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function niceMax(v) {
    if (!(v > 0)) return 1;
    const exp = Math.pow(10, Math.floor(Math.log10(v)));
    const f = v / exp;
    const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10;
    return nice * exp;
  }

  const fmtClock = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const fmtHour = (t) => new Date(t).toLocaleTimeString([], { hour: 'numeric' });

  function hourTicks(from, to, everyHours) {
    const step = everyHours * 3600e3;
    const ticks = [];
    for (let t = Math.ceil(from / step) * step; t <= to; t += step) ticks.push(t);
    return ticks;
  }

  // Re-render when the container's width changes.
  function responsive(container, render) {
    let lastW = 0;
    const ro = new ResizeObserver(() => {
      const w = Math.round(container.clientWidth);
      if (w && w !== lastW) {
        lastW = w;
        render(w);
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }

  // ---------------- line chart ----------------
  // opts: { times, series:[{name, values, color}], from, to, yMax, format, height, compact, gapMs, ariaLabel }
  function line(container, opts) {
    container.classList.add('chart');
    const height = opts.height || 170;
    const compact = Boolean(opts.compact);
    const fmt = opts.format || ((v) => String(v));
    const times = opts.times || [];
    const series = opts.series || [];
    const from = opts.from ?? times[0] ?? Date.now() - 3600e3;
    const to = opts.to ?? times[times.length - 1] ?? Date.now();
    const gapMs = opts.gapMs || 150e3;

    let dataMax = 0;
    for (const se of series) for (const v of se.values) if (typeof v === 'number' && v > dataMax) dataMax = v;
    const yMax = opts.yMax || niceMax(dataMax * 1.1 || 1);

    const render = (W) => {
      container.replaceChildren();
      const pad = compact ? { l: 2, r: 2, t: 4, b: 4 } : { l: 40, r: 10, t: 10, b: 22 };
      const pw = Math.max(10, W - pad.l - pad.r);
      const ph = height - pad.t - pad.b;
      const x = (t) => pad.l + ((t - from) / Math.max(1, to - from)) * pw;
      const y = (v) => pad.t + ph - (Math.max(0, Math.min(v, yMax)) / yMax) * ph;

      const svg = s('svg', { width: W, height, viewBox: `0 0 ${W} ${height}`, role: 'img', tabindex: '0' });
      svg.setAttribute('aria-label', opts.ariaLabel || series.map((x2) => x2.name).join(', '));

      // grid + y labels
      const ticks = compact ? [0] : [0, yMax / 2, yMax];
      for (const tv of ticks) {
        s('line', { x1: pad.l, x2: pad.l + pw, y1: y(tv), y2: y(tv), class: tv === 0 ? 'axis' : 'grid' }, svg);
        if (!compact) {
          const label = s('text', { x: pad.l - 6, y: y(tv) + 4, 'text-anchor': 'end', class: 'tick' }, svg);
          label.textContent = fmt(tv);
        }
      }
      // x labels
      if (!compact) {
        const span = to - from;
        const every = span > 12 * 3600e3 ? 6 : span > 4 * 3600e3 ? 2 : 1;
        for (const t of hourTicks(from, to, every)) {
          const tx = x(t);
          if (tx < pad.l + 12 || tx > pad.l + pw - 12) continue;
          const label = s('text', { x: tx, y: height - 6, 'text-anchor': 'middle', class: 'tick' }, svg);
          label.textContent = fmtHour(t);
        }
      }

      // lines (broken at nulls and at time gaps)
      for (const se of series) {
        let d = '';
        let prevT = null;
        se.values.forEach((v, i) => {
          const t = times[i];
          if (typeof v !== 'number' || t < from) {
            prevT = null;
            return;
          }
          const cmd = prevT === null || t - prevT > gapMs ? 'M' : 'L';
          d += `${cmd}${x(t).toFixed(1)},${y(v).toFixed(1)}`;
          prevT = t;
        });
        if (d) s('path', { d, class: 'series-line', stroke: se.color, fill: 'none' }, svg);

        // Points with no neighbour on either side would be invisible as a line; draw them as dots.
        se.values.forEach((v, i) => {
          if (typeof v !== 'number' || times[i] < from) return;
          const prevOk = i > 0 && typeof se.values[i - 1] === 'number' && times[i] - times[i - 1] <= gapMs;
          const nextOk = i < se.values.length - 1 && typeof se.values[i + 1] === 'number' && times[i + 1] - times[i] <= gapMs;
          if (!prevOk && !nextOk) s('circle', { cx: x(times[i]), cy: y(v), r: 2.5, fill: se.color, class: 'point' }, svg);
        });
      }

      // hover layer
      const cross = s('line', { y1: pad.t, y2: pad.t + ph, class: 'crosshair', visibility: 'hidden' }, svg);
      const dots = series.map((se) => s('circle', { r: 4, class: 'dot', stroke: se.color, visibility: 'hidden' }, svg));
      const tip = h('div', 'chart-tip');
      tip.hidden = true;
      container.append(svg, tip);

      if (!times.length) {
        const empty = s('text', { x: pad.l + pw / 2, y: pad.t + ph / 2, 'text-anchor': 'middle', class: 'tick' }, svg);
        empty.textContent = 'No data yet';
        return;
      }

      let current = -1;
      const show = (i) => {
        if (i < 0 || i >= times.length) return;
        current = i;
        const t = times[i];
        const cx = x(t);
        cross.setAttribute('x1', cx);
        cross.setAttribute('x2', cx);
        cross.setAttribute('visibility', 'visible');
        tip.replaceChildren(h('div', 'tip-time', `${new Date(t).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit' })}`));
        series.forEach((se, k) => {
          const v = se.values[i];
          if (typeof v === 'number') {
            dots[k].setAttribute('cx', cx);
            dots[k].setAttribute('cy', y(v));
            dots[k].setAttribute('visibility', 'visible');
          } else dots[k].setAttribute('visibility', 'hidden');
          const row = h('div', 'tip-row');
          const key = h('span', 'tip-key');
          key.style.background = se.color;
          row.append(key, h('strong', null, typeof v === 'number' ? fmt(v) : '—'), h('span', 'tip-name', se.name));
          tip.append(row);
        });
        tip.hidden = false;
        const tw = tip.offsetWidth;
        tip.style.left = `${Math.min(Math.max(cx - tw / 2, 0), W - tw)}px`;
        tip.style.top = compact ? `${height + 4}px` : `${-4}px`;
      };
      const hide = () => {
        current = -1;
        cross.setAttribute('visibility', 'hidden');
        dots.forEach((d) => d.setAttribute('visibility', 'hidden'));
        tip.hidden = true;
      };
      const nearest = (t) => {
        let lo = 0;
        let hi = times.length - 1;
        while (lo < hi) {
          const mid = (lo + hi) >> 1;
          if (times[mid] < t) lo = mid + 1;
          else hi = mid;
        }
        return lo > 0 && Math.abs(times[lo - 1] - t) < Math.abs(times[lo] - t) ? lo - 1 : lo;
      };

      const hit = s('rect', { x: pad.l, y: 0, width: pw, height, fill: 'transparent' }, svg);
      hit.addEventListener('pointermove', (e) => {
        const r = svg.getBoundingClientRect();
        const t = from + ((e.clientX - r.left - pad.l) / pw) * (to - from);
        show(nearest(t));
      });
      hit.addEventListener('pointerleave', hide);
      svg.addEventListener('focus', () => show(times.length - 1));
      svg.addEventListener('blur', hide);
      svg.addEventListener('keydown', (e) => {
        if (e.key === 'ArrowLeft') show(Math.max(0, (current < 0 ? times.length : current) - (e.shiftKey ? 60 : 1)));
        else if (e.key === 'ArrowRight') show(Math.min(times.length - 1, current + (e.shiftKey ? 60 : 1)));
        else if (e.key === 'Escape') hide();
        else return;
        e.preventDefault();
      });
    };

    return { destroy: responsive(container, render) };
  }

  // ---------------- stacked bars ----------------
  // opts: { labels:[iso start of bucket], bucketMs, series:[{name, values, color}], height, format, ariaLabel }
  function stackedBars(container, opts) {
    container.classList.add('chart');
    const height = opts.height || 190;
    const fmt = opts.format || ((v) => v.toLocaleString());
    const labels = opts.labels.map((l) => Date.parse(l));
    const series = opts.series;
    const n = labels.length;
    const totals = labels.map((_, i) => series.reduce((a, se) => a + (se.values[i] || 0), 0));
    const yMax = niceMax(Math.max(...totals, 1) * 1.05);
    const GAP = 2;

    const render = (W) => {
      container.replaceChildren();
      const pad = { l: 40, r: 6, t: 10, b: 22 };
      const pw = Math.max(10, W - pad.l - pad.r);
      const ph = height - pad.t - pad.b;
      const band = pw / n;
      const bw = Math.max(2, Math.min(28, band - 3));
      const y = (v) => pad.t + ph - (v / yMax) * ph;

      const svg = s('svg', { width: W, height, viewBox: `0 0 ${W} ${height}`, role: 'img' });
      svg.setAttribute('aria-label', opts.ariaLabel || 'Stacked bar chart');

      for (const tv of [0, yMax / 2, yMax]) {
        s('line', { x1: pad.l, x2: pad.l + pw, y1: y(tv), y2: y(tv), class: tv === 0 ? 'axis' : 'grid' }, svg);
        const label = s('text', { x: pad.l - 6, y: y(tv) + 4, 'text-anchor': 'end', class: 'tick' }, svg);
        label.textContent = fmt(Math.round(tv));
      }
      labels.forEach((t, i) => {
        if (new Date(t).getHours() % 6 !== 0) return;
        const label = s('text', { x: pad.l + band * i + band / 2, y: height - 6, 'text-anchor': 'middle', class: 'tick' }, svg);
        label.textContent = fmtHour(t);
      });

      const tip = h('div', 'chart-tip');
      tip.hidden = true;

      labels.forEach((t, i) => {
        const g = s('g', { class: 'bar', tabindex: '0' }, svg);
        const bx = pad.l + band * i + (band - bw) / 2;
        s('rect', { x: pad.l + band * i, y: pad.t, width: band, height: ph, class: 'bar-hit' }, g);

        let cursor = y(0);
        const segs = series.map((se, k) => ({ v: se.values[i] || 0, color: se.color, k })).filter((x2) => x2.v > 0);
        segs.forEach((seg, j) => {
          const hPx = (seg.v / yMax) * ph;
          const gapBelow = j > 0 ? GAP : 0;
          const top = cursor - hPx;
          const segH = Math.max(1, hPx - gapBelow);
          const isTop = j === segs.length - 1;
          if (isTop && segH > 2) {
            const r = Math.min(4, segH / 2, bw / 2);
            const bottom = top + segH;
            s(
              'path',
              {
                d: `M${bx},${bottom}V${top + r}Q${bx},${top} ${bx + r},${top}H${bx + bw - r}Q${bx + bw},${top} ${bx + bw},${top + r}V${bottom}Z`,
                fill: seg.color,
              },
              g
            );
          } else {
            s('rect', { x: bx, y: top, width: bw, height: segH, fill: seg.color }, g);
          }
          cursor = top;
        });

        const showTip = () => {
          const end = t + (opts.bucketMs || 3600e3);
          tip.replaceChildren(h('div', 'tip-time', `${fmtClock(t)}–${fmtClock(end)}`));
          series.forEach((se) => {
            const row = h('div', 'tip-row');
            const key = h('span', 'tip-key');
            key.style.background = se.color;
            row.append(key, h('strong', null, fmt(se.values[i] || 0)), h('span', 'tip-name', se.name));
            tip.append(row);
          });
          tip.append(h('div', 'tip-total', `Total ${fmt(totals[i])}`));
          tip.hidden = false;
          const tw = tip.offsetWidth;
          const cx = pad.l + band * i + band / 2;
          tip.style.left = `${Math.min(Math.max(cx - tw / 2, 0), W - tw)}px`;
          tip.style.top = `-4px`;
          g.classList.add('active');
        };
        const hideTip = () => {
          tip.hidden = true;
          g.classList.remove('active');
        };
        g.addEventListener('pointerenter', showTip);
        g.addEventListener('pointerleave', hideTip);
        g.addEventListener('focus', showTip);
        g.addEventListener('blur', hideTip);
      });

      container.append(svg, tip);
    };

    return { destroy: responsive(container, render) };
  }

  return { line, stackedBars, niceMax };
})();
