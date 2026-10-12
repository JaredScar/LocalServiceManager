'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');

function decodeLog(buf) {
  // Detect UTF-16LE (some Windows tools write it) by counting zero bytes in odd positions.
  const n = Math.min(buf.length, 4096);
  let zeros = 0;
  for (let i = 1; i < n; i += 2) if (buf[i] === 0) zeros++;
  const text = n > 1 && zeros / (n / 2) > 0.3 ? buf.toString('utf16le') : buf.toString('utf8');
  return text
    .replace(/^\uFEFF/, '')
    .replace(/\x1b\[[0-9;?]*[A-Za-z]/g, ''); // strip ANSI colour codes (NestJS etc.)
}

// Reads the last `maxBytes` of a file and returns its lines (first partial line dropped).
async function readTailLines(filePath, maxBytes) {
  const fh = await fsp.open(filePath, 'r');
  try {
    const { size } = await fh.stat();
    let length = Math.min(size, maxBytes);
    if ((size - length) % 2 === 1) length -= 1; // keep UTF-16 alignment
    const buf = Buffer.alloc(length);
    if (length > 0) await fh.read(buf, 0, length, size - length);
    const lines = decodeLog(buf).split(/\r?\n/);
    if (length < size) lines.shift();
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    return { size, truncated: length < size, lines };
  } finally {
    await fh.close();
  }
}

async function readJson(filePath) {
  const text = await fsp.readFile(filePath, 'utf8');
  return JSON.parse(text.replace(/^\uFEFF/, ''));
}

async function writeJsonAtomic(filePath, data) {
  await fsp.mkdir(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  await fsp.writeFile(tmp, JSON.stringify(data));
  await fsp.rename(tmp, filePath);
}

function writeJsonAtomicSync(filePath, data) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data));
  fs.renameSync(tmp, filePath);
}

module.exports = { decodeLog, readTailLines, readJson, writeJsonAtomic, writeJsonAtomicSync };
