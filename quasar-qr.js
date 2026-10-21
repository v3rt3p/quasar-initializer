/* Dependency-free QR-LK payload and QR Code generator. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.QuasarQr = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const encoder = new TextEncoder();
  const QR_VERSION = 4;
  const QR_SIZE = 33;
  const DATA_CODEWORDS = 64;
  const TOTAL_CODEWORDS = 100;
  const ECC_CODEWORDS = 18;

  function bytesFor(value, name) {
    const bytes = encoder.encode(String(value || ''));
    if (bytes.length > 255) throw new Error(`${name} must be at most 255 UTF-8 bytes`);
    return bytes;
  }

  function crc16(bytes) {
    // QR-LK uses the MSB-first CRC-16 polynomial 0x2307, initial 0,
    // and no final XOR. The checksum is stored little-endian.
    let crc = 0;
    for (const byte of bytes) {
      crc ^= byte << 8;
      for (let bit = 0; bit < 8; bit++) {
        crc = (crc & 0x8000) ? ((crc << 1) ^ 0x2307) & 0xffff : (crc << 1) & 0xffff;
      }
    }
    return crc;
  }

  function makePayload(options) {
    const ssid = bytesFor(options.ssid, 'SSID');
    const password = bytesFor(options.password, 'password');
    const token = bytesFor(options.xTokenCode || options.token, 'xTokenCode');
    if (ssid.length > 255 || password.length > 255 || token.length > 255) throw new Error('QR-LK fields are too long');
    const body = Uint8Array.from([
      0x71, 0x72, 0x6c, 0x6b, // qrlk
      0,                       // protocol version
      2,                       // WPA
      ssid.length, ...ssid,
      password.length, ...password,
      token.length, ...token,
    ]);
    const checksum = crc16(body);
    const payload = new Uint8Array(body.length + 2);
    payload.set(body);
    payload[body.length] = checksum & 0xff;
    payload[body.length + 1] = checksum >>> 8;
    return payload;
  }

  const EXP = new Uint8Array(512);
  const LOG = new Uint8Array(256);
  (function initGf256() {
    let value = 1;
    for (let i = 0; i < 255; i++) {
      EXP[i] = value;
      LOG[value] = i;
      value <<= 1;
      if (value & 0x100) value ^= 0x11d;
    }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();

  function gfMultiply(a, b) {
    return a && b ? EXP[LOG[a] + LOG[b]] : 0;
  }

  function reedSolomon(data) {
    const generator = [1];
    for (let i = 0; i < ECC_CODEWORDS; i++) {
      const next = new Array(generator.length + 1).fill(0);
      for (let j = 0; j < generator.length; j++) {
        next[j] ^= generator[j];
        next[j + 1] ^= gfMultiply(generator[j], EXP[i]);
      }
      generator.splice(0, generator.length, ...next);
    }
    const remainder = new Uint8Array(ECC_CODEWORDS);
    for (const value of data) {
      const factor = value ^ remainder[0];
      remainder.copyWithin(0, 1);
      remainder[ECC_CODEWORDS - 1] = 0;
      for (let i = 0; i < ECC_CODEWORDS; i++) remainder[i] ^= gfMultiply(generator[i + 1], factor);
    }
    return remainder;
  }

  function makeCodewords(payload) {
    if (payload.length > 62) throw new Error('QR-LK payload is too large for QR version 4-M');
    const bits = [];
    const pushBits = (value, count) => { for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1); };
    pushBits(4, 4); // byte mode
    pushBits(payload.length, 8);
    for (const byte of payload) pushBits(byte, 8);
    for (let i = 0; i < 4 && bits.length < DATA_CODEWORDS * 8; i++) bits.push(0);
    while (bits.length % 8) bits.push(0);
    const data = [];
    for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((a, b) => (a << 1) | b, 0));
    let pad = 0xec;
    while (data.length < DATA_CODEWORDS) { data.push(pad); pad ^= 0xfd; }
    const first = Uint8Array.from(data.slice(0, 32));
    const second = Uint8Array.from(data.slice(32, 64));
    const ecc1 = reedSolomon(first);
    const ecc2 = reedSolomon(second);
    const result = [];
    for (let i = 0; i < 32; i++) result.push(first[i], second[i]);
    for (let i = 0; i < ECC_CODEWORDS; i++) result.push(ecc1[i], ecc2[i]);
    return Uint8Array.from(result);
  }

  function makeMatrix(codewords) {
    const modules = Array.from({ length: QR_SIZE }, () => Array(QR_SIZE).fill(null));
    const set = (row, col, value) => { if (row >= 0 && row < QR_SIZE && col >= 0 && col < QR_SIZE) modules[row][col] = Boolean(value); };
    const finder = (row, col) => {
      for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) {
        const on = r >= 0 && r <= 6 && c >= 0 && c <= 6 && (r === 0 || r === 6 || c === 0 || c === 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
        set(row + r, col + c, on);
      }
    };
    finder(0, 0); finder(0, QR_SIZE - 7); finder(QR_SIZE - 7, 0);
    for (const center of [6, 26]) {
      for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) set(center + r, center + c, Math.max(Math.abs(r), Math.abs(c)) !== 1);
    }
    for (let i = 8; i < QR_SIZE - 8; i++) { if (modules[6][i] === null) set(6, i, i % 2 === 0); if (modules[i][6] === null) set(i, 6, i % 2 === 0); }
    for (let i = 0; i < 9; i++) { if (i !== 6) { set(8, i, false); set(i, 8, false); } }
    for (let i = 0; i < 8; i++) { set(8, QR_SIZE - 1 - i, false); set(QR_SIZE - 1 - i, 8, false); }
    set(QR_SIZE - 8, 8, true);
    const format = 0x5412; // error correction M, mask 0
    for (let i = 0; i < 15; i++) {
      const bit = ((format >>> i) & 1) !== 0;
      if (i < 6) set(i, 8, bit); else if (i < 8) set(i + 1, 8, bit); else set(QR_SIZE - 15 + i, 8, bit);
      if (i < 8) set(8, QR_SIZE - i - 1, bit); else if (i < 9) set(8, 15 - i, bit); else set(8, 15 - i - 1, bit);
    }
    const dataBits = [];
    for (const byte of codewords) for (let i = 7; i >= 0; i--) dataBits.push((byte >>> i) & 1);
    let bitIndex = 0, row = QR_SIZE - 1, direction = -1, col = QR_SIZE - 1;
    while (col > 0) {
      if (col === 6) col--;
      while (true) {
        for (let c = col; c >= col - 1; c--) if (modules[row][c] === null) {
          let bit = dataBits[bitIndex++] || 0;
          if ((row + c) % 2 === 0) bit ^= 1; // mask 0
          modules[row][c] = Boolean(bit);
        }
        row += direction;
        if (row < 0 || row >= QR_SIZE) { row -= direction; direction = -direction; break; }
      }
      col -= 2;
    }
    for (const line of modules) for (let i = 0; i < line.length; i++) if (line[i] === null) line[i] = false;
    return modules;
  }

  function encode(options) {
    const payload = makePayload(options);
    return { payload, crc: payload[payload.length - 2] | (payload[payload.length - 1] << 8), version: QR_VERSION, matrix: makeMatrix(makeCodewords(payload)) };
  }

  function renderCanvas(canvas, matrix, scale) {
    scale = scale || 8;
    const border = 4;
    canvas.width = canvas.height = (matrix.length + border * 2) * scale;
    const context = canvas.getContext('2d');
    context.fillStyle = '#fff'; context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = '#000';
    matrix.forEach((row, y) => row.forEach((on, x) => { if (on) context.fillRect((x + border) * scale, (y + border) * scale, scale, scale); }));
  }

  function toSvg(matrix, scale) {
    scale = scale || 8; const border = 4; const size = (matrix.length + border * 2) * scale;
    const paths = [];
    matrix.forEach((row, y) => row.forEach((on, x) => { if (on) paths.push(`M${(x + border) * scale} ${(y + border) * scale}h${scale}v${scale}h-${scale}z`); }));
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" shape-rendering="crispEdges"><path fill="#fff" d="M0 0h${size}v${size}H0z"/><path d="${paths.join('')}"/></svg>`;
  }

  return { makePayload, crc16, encode, renderCanvas, toSvg, version: QR_VERSION };
});
