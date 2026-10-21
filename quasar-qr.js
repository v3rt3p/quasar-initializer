/* QR-LK payload contents. QR rendering is provided by a standard QR library. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.QuasarQr = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const encoder = new TextEncoder();

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

  // qrcode-generator's Byte mode accepts a one-byte-per-character string.
  function toBinaryString(bytes) {
    return String.fromCharCode(...bytes);
  }

  return { makePayload, crc16, toBinaryString };
});
