/*
 * Quasar pairing sound encoder.
 * Browser API:
 *   const result = QuasarSound.encode({
 *     ssid, password, hidden, wifiType, xTokenCode, volume,
 *   });
 *   result.wav is a WAV Blob.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.QuasarSound = factory();
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  const SAMPLE_RATE = 16000;
  // The APK writes exactly 40 ms for every tone. Longer tones sound slower but
  // are not compatible with the speaker's decoder, so keep this exact by default.
  const DEFAULT_TONE_DURATION = 0.04;
  const HANDSHAKE_START = [6192, 6192, 5120, 5120];
  // One zero byte is read as two zero nibbles by the APK's bit reader.
  const VERSION_TONES = [1024, 1024];
  const HANDSHAKE_END = [5632, 5632, 5632, 5632, 5632, 5632, 5632, 5632];
  const FIELD_LIMIT = 255;
  const GF = createGaloisField();

  function encode(config) {
    const options = normalizeConfig(config);
    const mode = getMode(options);
    const body = makePayload(mode, options.ssid, options.password, options.xTokenCode);
    const payload = appendCrc32(body);
    const encodedSymbols = reedSolomonEncode(payload);
    const tones = HANDSHAKE_START.concat(VERSION_TONES, encodedBytesToTones(encodedSymbols), HANDSHAKE_END);
    const samples = renderTones(tones, options.toneDuration, options.volume);
    const wav = makeWav(samples);

    return {
      wav,
      samples,
      tones,
      payload,
      encodedBytes: encodedSymbols,
      sampleRate: SAMPLE_RATE,
      toneDuration: options.toneDuration,
      duration: samples.length / SAMPLE_RATE,
      mode: mode.name,
    };
  }

  function generateWav(config) {
    return encode(config).wav;
  }

  function normalizeConfig(config) {
    config = config || {};
    const options = {
      ssid: String(config.ssid == null ? '' : config.ssid),
      password: String(config.password == null ? '' : config.password),
      xTokenCode: String(config.xTokenCode == null ? (config.token == null ? '' : config.token) : config.xTokenCode),
      hidden: Boolean(config.hidden),
      wifiType: String(config.wifiType == null ? 'wpa' : config.wifiType).toLowerCase(),
      volume: config.volume == null ? 1 : Number(config.volume),
      toneDuration: config.toneDuration == null ? DEFAULT_TONE_DURATION : Number(config.toneDuration),
    };
    if (!options.ssid && options.wifiType !== 'none') throw new Error('ssid is required');
    if (!options.xTokenCode) throw new Error('xTokenCode is required');
    if (options.wifiType !== 'none' && !options.password) throw new Error('password is required');
    if (!Number.isFinite(options.volume) || options.volume <= 0 || options.volume > 1) throw new Error('volume must be between 0 and 1');
    if (!Number.isFinite(options.toneDuration) || options.toneDuration <= 0) throw new Error('toneDuration must be positive');
    return options;
  }

  function getMode(options) {
    // The APK uses mode 4 for visible networks, regardless of security type.
    if (options.wifiType === 'none') return { value: 5, byte: 4, name: 'auth-only' };
    if (!options.hidden) return { value: 4, byte: 3, name: 'visible' };
    if (options.wifiType === 'wep') return { value: 2, byte: 1, name: 'hidden-wep' };
    if (options.wifiType === 'wpa') return { value: 3, byte: 2, name: 'hidden-wpa' };
    return { value: 1, byte: 0, name: 'hidden-open' };
  }

  function makePayload(mode, ssid, password, xTokenCode) {
    const result = [mode.byte];
    if (mode.value !== 5) {
      if (mode.value === 4) {
        // Visible mode is actually selected by the APK for hidden=false. Its
        // payload is: password hash, password, then xTokenCode.
        const hash = javaStringHash(ssid) % 32767;
        result.push(hash & 255, (hash >> 8) & 255);
        appendString(result, password);
      } else {
        // Hidden modes use: SSID, password, then xTokenCode.
        appendString(result, ssid);
        appendString(result, password);
      }
    }
    appendString(result, xTokenCode);
    return Uint8Array.from(result);
  }

  function appendString(target, value) {
    const bytes = new TextEncoder().encode(value);
    if (bytes.length > FIELD_LIMIT) throw new Error('a text field is longer than 255 UTF-8 bytes');
    target.push(bytes.length);
    for (const byte of bytes) target.push(byte);
  }

  function javaStringHash(value) {
    // String.hashCode() operates on UTF-16 code units, not UTF-8 bytes.
    let hash = 0;
    for (let i = 0; i < value.length; i++) hash = ((hash * 31) + value.charCodeAt(i)) | 0;
    return hash;
  }

  function appendCrc32(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
    crc = (crc ^ 0xffffffff) >>> 0;
    // The Java loop writes the low byte at length-1 and high byte at length-2.
    return Uint8Array.from([...bytes, crc & 255, (crc >>> 8) & 255]);
  }

  // The APK consumes its 4-bit stream in chunks of up to 11 symbols. The
  // final block is completed with four zero symbols before parity is made.
  function reedSolomonEncode(bytes) {
    const symbols = [];
    for (const byte of bytes) symbols.push(byte >>> 4, byte & 15);
    const result = [];
    const generator = getGenerator(4);
    for (let offset = 0; offset < symbols.length; offset += 11) {
      const block = symbols.slice(offset, offset + 11);
      result.push(...block, ...rsParity(block, 4));
    }
    return Uint8Array.from(result);
  }

  function encodedBytesToTones(symbols) {
    return Array.from(symbols, (symbol) => 1024 + symbol * 256);
  }

  function rsParity(data, degree) {
    const generator = getGenerator(degree);
    const parity = Array(degree).fill(0);
    for (const value of data) {
      const factor = value ^ parity[0];
      parity.shift();
      parity.push(0);
      for (let i = 0; i < degree; i++) parity[i] ^= GF.multiply(generator[i], factor);
    }
    return parity;
  }

  function getGenerator(degree) {
    let polynomial = [1];
    for (let i = 0; i < degree; i++) polynomial = multiplyPolynomials(polynomial, [1, GF.exp(i + 1)]);
    return polynomial.slice(1);
  }

  function multiplyPolynomials(left, right) {
    const result = Array(left.length + right.length - 1).fill(0);
    for (let i = 0; i < left.length; i++) {
      for (let j = 0; j < right.length; j++) result[i + j] ^= GF.multiply(left[i], right[j]);
    }
    return result;
  }

  function createGaloisField() {
    const exp = Array(30).fill(0);
    const log = Array(16).fill(0);
    let value = 1;
    for (let i = 0; i < 15; i++) {
      exp[i] = value;
      log[value] = i;
      value <<= 1;
      if (value >= 16) value = (value ^ 0x13) & 15;
    }
    for (let i = 15; i < exp.length; i++) exp[i] = exp[i - 15];
    return {
      exp: (power) => exp[power % 15],
      multiply: (left, right) => left === 0 || right === 0 ? 0 : exp[(log[left] + log[right]) % 15],
    };
  }

  function renderTones(tones, toneDuration, volume) {
    const samplesPerTone = Math.round(SAMPLE_RATE * toneDuration);
    const samples = new Float32Array(tones.length * samplesPerTone);
    const amplitude = Math.min(1, volume) * 0.95;
    let cursor = 0;
    for (const frequency of tones) {
      // The APK writes an unwindowed sine directly to AudioTrack. Keep tone
      // boundaries exact; an envelope changes the decoder's measurements.
      for (let i = 0; i < samplesPerTone; i++) {
        samples[cursor++] = Math.sin((2 * Math.PI * frequency * i) / SAMPLE_RATE) * amplitude;
      }
    }
    return samples;
  }

  function makeWav(samples) {
    const buffer = new ArrayBuffer(44 + samples.length * 2);
    const view = new DataView(buffer);
    const text = (offset, value) => { for (let i = 0; i < value.length; i++) view.setUint8(offset + i, value.charCodeAt(i)); };
    text(0, 'RIFF'); view.setUint32(4, 36 + samples.length * 2, true); text(8, 'WAVE'); text(12, 'fmt ');
    view.setUint32(16, 16, true); view.setUint16(20, 1, true); view.setUint16(22, 1, true); view.setUint32(24, SAMPLE_RATE, true);
    view.setUint32(28, SAMPLE_RATE * 2, true); view.setUint16(32, 2, true); view.setUint16(34, 16, true); text(36, 'data'); view.setUint32(40, samples.length * 2, true);
    for (let i = 0; i < samples.length; i++) view.setInt16(44 + i * 2, Math.max(-1, Math.min(1, samples[i])) * 32767, true);
    return new Blob([buffer], { type: 'audio/wav' });
  }

  return { encode, generateWav, sampleRate: SAMPLE_RATE, defaultToneDuration: DEFAULT_TONE_DURATION };
});
