'use strict';

// Checks each configured site once a minute: HTTP status, response time,
// and the TLS certificate (expiry, issuer, whether it's trusted).

const http = require('http');
const net = require('net');
const https = require('https');
const { readJson, writeJsonAtomic, writeJsonAtomicSync } = require('./util');

const WINDOW_MS = 24 * 3600e3;
const INTERVAL_MS = 60e3;
const TIMEOUT_MS = 10e3;

function checkSite(site) {
  return new Promise((resolve) => {
    const url = new URL(site.url);
    const lib = url.protocol === 'https:' ? https : http;
    const started = process.hrtime.bigint();
    let tls = null;
    let settled = false;
    const done = (r) => {
      if (!settled) {
        settled = true;
        resolve({ t: Date.now(), ...r, tls });
      }
    };

    const req = lib.request(
      url,
      {
        method: 'GET',
        agent: false,
        timeout: TIMEOUT_MS,
        rejectUnauthorized: false, // we want to *report* bad certificates, not fail on them
        servername: net.isIP(url.hostname.replace(/^\[|\]$/g, '')) ? undefined : url.hostname,
        headers: { 'User-Agent': 'svcdash-sitecheck/1.0', Accept: '*/*' },
      },
      (res) => {
        const ms = Math.round(Number(process.hrtime.bigint() - started) / 1e6);
        const code = res.statusCode;
        const expect = site.expectStatus;
        const up = Array.isArray(expect) ? expect.includes(code) : typeof expect === 'number' ? code === expect : code < 500;
        res.destroy(); // we only need the headers
        done({ up, code, ms, error: up ? null : `HTTP ${code}` });
      }
    );

    req.on('socket', (sock) => {
      sock.on('secureConnect', () => {
        try {
          const c = sock.getPeerCertificate();
          tls = {
            authorized: sock.authorized,
            authError: sock.authorizationError ? String(sock.authorizationError) : null,
            validTo: c && c.valid_to ? new Date(c.valid_to).toISOString() : null,
            issuer: (c && c.issuer && (c.issuer.O || c.issuer.CN)) || null,
            subject: (c && c.subject && c.subject.CN) || null,
          };
        } catch {
          /* no certificate info */
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`No response within ${TIMEOUT_MS / 1000}s`)));
    req.on('error', (e) => done({ up: false, code: null, ms: null, error: e.code ? `${e.code}: ${e.message}` : e.message }));
    req.end();
  });
}

function createSites({ sites, file, log }) {
  const state = new Map(); // name -> { last, points: [[t, ms, up]] }
  sites.forEach((s) => state.set(s.name, { last: null, points: [] }));
  let timer = null;
  let saver = null;
  let running = null;

  function trim(points) {
    const cutoff = Date.now() - WINDOW_MS;
    while (points.length && points[0][0] < cutoff) points.shift();
  }

  async function load() {
    try {
      const data = await readJson(file);
      for (const s of sites) {
        const saved = data[s.name];
        if (saved && Array.isArray(saved.points)) {
          const st = state.get(s.name);
          st.points = saved.points;
          st.last = saved.last || null;
          trim(st.points);
        }
      }
    } catch {
      /* first run */
    }
  }

  async function runAll() {
    if (running) return running;
    running = Promise.all(
      sites.map(async (s) => {
        const r = await checkSite(s);
        const st = state.get(s.name);
        st.last = r;
        st.points.push([r.t, r.ms, r.up ? 1 : 0]);
        trim(st.points);
      })
    ).finally(() => {
      running = null;
    });
    return running;
  }

  function serialize() {
    const out = {};
    for (const [name, st] of state) out[name] = st;
    return out;
  }

  async function save() {
    try {
      await writeJsonAtomic(file, serialize());
    } catch (e) {
      log(`Could not save site history: ${e.message}`);
    }
  }

  function summary() {
    const now = Date.now();
    return sites.map((s) => {
      const st = state.get(s.name);
      trim(st.points);
      const pts = st.points;
      const ups = pts.filter((p) => p[2]).length;
      const times = pts.filter((p) => p[2] && typeof p[1] === 'number').map((p) => p[1]);
      const tls = st.last && st.last.tls;
      const daysLeft = tls && tls.validTo ? Math.floor((new Date(tls.validTo).getTime() - now) / 86400e3) : null;
      return {
        name: s.name,
        url: s.url,
        last: st.last,
        checks: pts.length,
        uptimePct: pts.length ? Math.round((ups / pts.length) * 1000) / 10 : null,
        avgMs: times.length ? Math.round(times.reduce((a, b) => a + b, 0) / times.length) : null,
        maxMs: times.length ? Math.max(...times) : null,
        cert: tls ? { ...tls, daysLeft } : null,
        points: pts,
      };
    });
  }

  async function start() {
    await load();
    runAll();
    timer = setInterval(runAll, INTERVAL_MS);
    saver = setInterval(save, 5 * 60e3);
  }

  function stop() {
    clearInterval(timer);
    clearInterval(saver);
    try {
      writeJsonAtomicSync(file, serialize());
    } catch {
      /* best effort */
    }
  }

  return { start, stop, summary, checkNow: runAll };
}

module.exports = { createSites, checkSite };
