'use strict';

// Writes a small green-on-navy icon. No dependencies.

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const outDir = path.join(__dirname, 'assets');
fs.mkdirSync(outDir, { recursive: true });

function rgba(size) {
  const buf = Buffer.alloc(size * size * 4);
  const c = size / 2;
  const radius = size * 0.46;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;
      const dx = x + 0.5 - c;
      const dy = y + 0.5 - c;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist > radius) continue;
      const edge = Math.min(1, radius - dist);
      buf[i] = 23;
      buf[i + 1] = 48;
      buf[i + 2] = 66;
      buf[i + 3] = Math.round(255 * edge);
      // A short vertical mark, like a status pill.
      const inMark = Math.abs(dx) < size * 0.09 && dy > -size * 0.22 && dy < size * 0.22;
      if (inMark) {
        buf[i] = 61;
        buf[i + 1] = 196;
        buf[i + 2] = 140;
        buf[i + 3] = 255;
      }
    }
  }
  return buf;
}

function crc32(buf) {
  let c = ~0;
  for (let i = 0; i < buf.length; i++) {
    c ^= buf[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (~c) >>> 0;
}

function chunk(type, data) {
  const t = Buffer.from(type);
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])), 0);
  return Buffer.concat([len, t, data, crc]);
}

function png(size, pixels) {
  const raw = Buffer.alloc(size * (1 + size * 4));
  for (let y = 0; y < size; y++) {
    const row = y * (1 + size * 4);
    raw[row] = 0;
    pixels.copy(raw, row + 1, y * size * 4, (y + 1) * size * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([
    sig,
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

function ico(images) {
  const count = images.length;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(count, 4);
  const dir = Buffer.alloc(16 * count);
  let offset = 6 + 16 * count;
  const blobs = [];
  images.forEach((img, n) => {
    const dib = bmpDib(img.size, img.pixels);
    const at = n * 16;
    dir[at] = img.size >= 256 ? 0 : img.size;
    dir[at + 1] = img.size >= 256 ? 0 : img.size;
    dir.writeUInt16LE(1, at + 4);
    dir.writeUInt16LE(32, at + 6);
    dir.writeUInt32LE(dib.length, at + 8);
    dir.writeUInt32LE(offset, at + 12);
    offset += dib.length;
    blobs.push(dib);
  });
  return Buffer.concat([header, dir, ...blobs]);
}

function bmpDib(size, pixels) {
  // Bottom-up BGRA plus a 1-bit AND mask.
  const xorRow = size * 4;
  const andRow = Math.ceil(size / 32) * 4;
  const xorSize = xorRow * size;
  const andSize = andRow * size;
  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(size, 4);
  header.writeInt32LE(size * 2, 8);
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  header.writeUInt32LE(xorSize + andSize, 20);
  const xor = Buffer.alloc(xorSize);
  const and = Buffer.alloc(andSize, 0);
  for (let y = 0; y < size; y++) {
    const srcY = size - 1 - y;
    for (let x = 0; x < size; x++) {
      const s = (srcY * size + x) * 4;
      const d = y * xorRow + x * 4;
      xor[d] = pixels[s + 2];
      xor[d + 1] = pixels[s + 1];
      xor[d + 2] = pixels[s];
      xor[d + 3] = pixels[s + 3];
      if (pixels[s + 3] < 128) and[y * andRow + (x >> 3)] |= 0x80 >> (x & 7);
    }
  }
  return Buffer.concat([header, xor, and]);
}

const png256 = rgba(256);
fs.writeFileSync(path.join(outDir, 'svcdash.png'), png(256, png256));
fs.writeFileSync(
  path.join(outDir, 'svcdash.ico'),
  ico([16, 32, 48].map((size) => ({ size, pixels: rgba(size) })))
);
console.log('wrote installer/assets/svcdash.png and svcdash.ico');
