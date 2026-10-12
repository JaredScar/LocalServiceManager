'use strict';

// Keeps one sample per minute for the last 24 hours: server CPU and memory,
// and CPU / memory per service. Persisted so a restart doesn't lose history.

const { readJson, writeJsonAtomic, writeJsonAtomicSync } = require('./util');

const WINDOW_MS = 24 * 3600e3;
const INTERVAL_MS = 60e3;

function createHistory({ file, getStatus, serviceNames, log }) {
  let points = []; // { t, cpu, mem, s: { name: [cpuPct|null, memMB|null] } }
  const prevCpu = new Map(); // service -> { t, cpuTime, key }
  let dirty = false;
  let timer = null;
  let saver = null;
  const startedAt = Date.now();

  function trim() {
    const cutoff = Date.now() - WINDOW_MS;
    while (points.length && points[0].t < cutoff) points.shift();
  }

  async function load() {
    try {
      const data = await readJson(file);
      if (Array.isArray(data.points)) points = data.points.filter((p) => p && typeof p.t === 'number');
      trim();
    } catch {
      points = [];
    }
  }

  function cpuForService(r, now) {
    if (r.cpuTime === null || r.cpuTime === undefined) {
      prevCpu.delete(r.name);
      return r.cpuPercent ?? null;
    }
    const key = (r.pids || []).join(',');
    const prev = prevCpu.get(r.name);
    prevCpu.set(r.name, { t: now, cpuTime: r.cpuTime, key });
    if (!prev || prev.key !== key || now <= prev.t) return null;
    const cpuMs = (r.cpuTime - prev.cpuTime) / 1e4;
    return Math.round(Math.max(0, Math.min(100, (cpuMs / ((now - prev.t) * Math.max(1, r.logicalCpus || 1))) * 100)) * 10) / 10;
  }

  async function sample() {
    try {
      const status = await getStatus(true);
      const now = Date.now();
      const sys = status.system || {};
      const s = {};
      for (const name of serviceNames) {
        const r = status.byName.get(name.toLowerCase());
        if (!r) continue;
        const running = r.state === 'Running';
        const cpu = running ? cpuForService({ ...r, logicalCpus: sys.logicalCpus }, now) : null;
        s[name] = [cpu, running ? r.memoryMB ?? null : null];
      }
      points.push({
        t: now,
        cpu: typeof sys.cpuPercent === 'number' ? Math.round(sys.cpuPercent) : null,
        mem: sys.memTotalMB ? Math.round(((sys.memTotalMB - sys.memFreeMB) / sys.memTotalMB) * 1000) / 10 : null,
        memTotalMB: sys.memTotalMB || null,
        s,
      });
      trim();
      dirty = true;
    } catch (e) {
      log(`History sample failed: ${e.message}`);
    }
  }

  async function save() {
    if (!dirty) return;
    dirty = false;
    try {
      await writeJsonAtomic(file, { points });
    } catch (e) {
      log(`Could not save history: ${e.message}`);
    }
  }

  function saveSync() {
    try {
      writeJsonAtomicSync(file, { points });
    } catch {
      /* best effort on shutdown */
    }
  }

  // Columnar output: one array per series, aligned with `times`.
  function snapshot() {
    trim();
    const times = points.map((p) => p.t);
    const services = {};
    for (const name of serviceNames) {
      services[name] = {
        cpu: points.map((p) => (p.s && p.s[name] ? p.s[name][0] : null)),
        mem: points.map((p) => (p.s && p.s[name] ? p.s[name][1] : null)),
      };
    }
    const last = points[points.length - 1];
    return {
      intervalMs: INTERVAL_MS,
      windowMs: WINDOW_MS,
      collectingSince: points.length ? points[0].t : startedAt,
      memTotalMB: last ? last.memTotalMB : null,
      times,
      system: { cpu: points.map((p) => p.cpu), mem: points.map((p) => p.mem) },
      services,
    };
  }

  // Test-only: fill 24h of synthetic samples so charts can be checked off Windows.
  function seed() {
    const now = Date.now();
    const demoDown = serviceNames.find((n) => !['caddy', 'mariadb', 'svcdash'].includes(n.toLowerCase()));
    points = [];
    for (let i = 24 * 60; i > 0; i -= 1) {
      const t = now - i * INTERVAL_MS;
      const h = i / 60;
      const s = {};
      serviceNames.forEach((name, k) => {
        const down = name === demoDown && h > 2 && h < 3.5;
        s[name] = down ? [null, null] : [Math.max(0, Math.round((1 + k * 1.3 + Math.sin(h / 2 + k) * (1 + k * 0.6) + (k === 0 && h > 6 && h < 6.3 ? 25 : 0)) * 10) / 10), Math.round(60 + k * 35 + Math.sin(h / 5 + k) * 10 + (24 - h) * k * 0.8)];
      });
      points.push({ t, cpu: Math.round(14 + Math.sin(h / 3) * 8 + (h > 6 && h < 6.3 ? 45 : 0) + Math.random() * 4), mem: Math.round((33 + Math.sin(h / 6) * 3 + (24 - h) * 0.15) * 10) / 10, memTotalMB: 262144, s });
    }
  }

  async function start() {
    await load();
    if (process.env.SVCDASH_SEED === '1' && points.length < 10) seed();
    await sample();
    timer = setInterval(sample, INTERVAL_MS);
    saver = setInterval(save, 5 * 60e3);
  }

  function stop() {
    clearInterval(timer);
    clearInterval(saver);
    saveSync();
  }

  return { start, stop, snapshot, sample };
}

module.exports = { createHistory };
