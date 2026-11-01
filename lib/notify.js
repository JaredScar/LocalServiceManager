'use strict';

// Posts a webhook when something changes: a service stops or starts, a site
// goes down or comes back, a certificate crosses 14 or 7 days, an unexpected
// port appears or disappears, or the collector goes stale. The first look is
// saved and not sent, so a restart does not repeat the current state.

const http = require('http');
const https = require('https');
const { readJson, writeJsonAtomic } = require('./util');

const CERT_TEXT = {
  soon: 'expires within 14 days',
  urgent: 'expires within 7 days',
  untrusted: 'is not trusted',
  none: 'was not received',
  ok: 'is healthy again',
  plain: 'is healthy again',
};

function bodyFor(hostname, text) {
  const host = String(hostname || '').toLowerCase();
  if (host === 'discord.com' || host.endsWith('.discord.com') || host.endsWith('.discordapp.com')) {
    return { content: text.slice(0, 1900) };
  }
  if (host === 'hooks.slack.com' || host.endsWith('.slack.com')) return { text };
  return { message: text, title: 'Service Dashboard', text, content: text };
}

function postNotify(url, token, text) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(url);
    } catch (e) {
      reject(e);
      return;
    }
    if (target.protocol !== 'https:' && target.protocol !== 'http:') {
      reject(new Error('Notify URL must be http or https'));
      return;
    }
    const body = Buffer.from(JSON.stringify(bodyFor(target.hostname, text)), 'utf8');
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': body.length,
      'User-Agent': 'svcdash',
    };
    if (token) headers.Authorization = `Bearer ${token}`;
    const lib = target.protocol === 'https:' ? https : http;
    const req = lib.request(target, { method: 'POST', headers, timeout: 8000 }, (res) => {
      res.resume();
      if (res.statusCode >= 200 && res.statusCode < 300) resolve();
      else reject(new Error(`Notify URL returned HTTP ${res.statusCode}`));
    });
    req.on('timeout', () => req.destroy(new Error('Notify URL timed out')));
    req.on('error', reject);
    req.end(body);
  });
}

function certBand(site) {
  if (!site || !site.last) return null;
  if (!String(site.url || '').startsWith('https:')) return 'plain';
  const cert = site.cert;
  if (!cert) return 'none';
  if (cert.authorized === false) return 'untrusted';
  if (typeof cert.daysLeft !== 'number') return 'ok';
  if (cert.daysLeft <= 7) return 'urgent';
  if (cert.daysLeft <= 14) return 'soon';
  return 'ok';
}

function diffAlerts(prev, next) {
  const lines = [];
  const services = new Set([...Object.keys(prev.services || {}), ...Object.keys(next.services || {})]);
  for (const name of services) {
    const before = prev.services ? prev.services[name] : undefined;
    const after = next.services ? next.services[name] : undefined;
    if (!before || !after || before.state === after.state) continue;
    const label = after.label || before.label || name;
    if (after.state === 'Running') lines.push(`${label} is running again`);
    else if (before.state === 'Running') lines.push(`${label} is ${String(after.state).toLowerCase()}`);
    else lines.push(`${label} changed from ${before.state} to ${after.state}`);
  }

  const sites = new Set([...Object.keys(prev.sites || {}), ...Object.keys(next.sites || {})]);
  for (const name of sites) {
    const before = prev.sites ? prev.sites[name] : undefined;
    const after = next.sites ? next.sites[name] : undefined;
    if (!before || !after) continue;
    if (before.up !== null && after.up !== null && before.up !== after.up) {
      lines.push(after.up ? `${name} is back up` : `${name} is down${after.detail ? ` (${after.detail})` : ''}`);
    }
    if (before.band && after.band && before.band !== after.band && CERT_TEXT[after.band]) {
      lines.push(`${name} certificate ${CERT_TEXT[after.band]}`);
    }
  }

  const beforePorts = new Set(prev.ports || []);
  const afterPorts = new Set(next.ports || []);
  for (const port of afterPorts) if (!beforePorts.has(port)) lines.push(`Port ${port} is open to the internet and was not expected`);
  for (const port of beforePorts) if (!afterPorts.has(port)) lines.push(`Port ${port} is no longer unexpectedly open`);

  if (prev.collectorStale === false && next.collectorStale === true) {
    lines.push(next.collectorDetail || 'The collector has stopped writing. Check the svcdash-collector scheduled task.');
  } else if (prev.collectorStale === true && next.collectorStale === false) {
    lines.push('The collector is writing again.');
  }
  return lines;
}

function createNotify({ file, url, token, observe, log }) {
  let saved = null;
  let timer = null;
  let arm = null;
  let running = null;

  async function load() {
    try {
      const data = await readJson(file);
      if (data && data.services && data.sites) saved = data;
    } catch {
      saved = null;
    }
  }

  async function save(state) {
    saved = state;
    await writeJsonAtomic(file, state);
  }

  async function run() {
    if (running) return running;
    running = (async () => {
      const next = await observe();
      if (!next) return;
      if (!saved) {
        await save(next);
        log('Notifications armed. Current state was saved without sending.');
        return;
      }
      const lines = diffAlerts(saved, next);
      await save(next);
      if (!lines.length || !url) return;
      const text = ['Service Dashboard', ...lines.map((line) => `• ${line}`)].join('\n');
      try {
        await postNotify(url, token, text);
        log(`Sent ${lines.length} notification${lines.length === 1 ? '' : 's'}`);
      } catch (e) {
        log(`Notification failed: ${e.message}`);
      }
    })().finally(() => {
      running = null;
    });
    return running;
  }

  async function start() {
    if (!url) {
      log('Notifications are off. Set notify.url in config.json to enable them.');
      return;
    }
    await load();
    // Wait for the first site checks and collector write before the baseline.
    timer = setInterval(() => {
      run().catch((e) => log(`Notification check failed: ${e.message}`));
    }, 60e3);
    arm = setTimeout(() => {
      run().catch((e) => log(`Notification check failed: ${e.message}`));
    }, 15000);
    if (arm.unref) arm.unref();
  }

  function stop() {
    clearInterval(timer);
    clearTimeout(arm);
  }

  return { start, stop, run };
}

module.exports = { createNotify, diffAlerts, certBand, postNotify, bodyFor };
