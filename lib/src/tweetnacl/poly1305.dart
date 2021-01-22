import 'dart:typed_data';

/// Port of Andrew Moon's Poly1305-donna-16. Public domain.
/// https://github.com/floodyberry/poly1305-donna
class Poly1305 {
  Poly1305(Uint8List key) {
    final t0 = key[0] | key[1] << 8,
        t1 = key[2] | key[3] << 8,
        t2 = key[4] | key[5] << 8,
        t3 = key[6] | key[7] << 8,
        t4 = key[8] | key[9] << 8,
        t5 = key[10] | key[11] << 8,
        t6 = key[12] | key[13] << 8,
        t7 = key[14] | key[15] << 8;

    _r[0] = t0 & 0x1fff;
    _r[1] = ((t0 >> 13) | (t1 << 3)) & 0x1fff;
    _r[2] = ((t1 >> 10) | (t2 << 6)) & 0x1f03;
    _r[3] = ((t2 >> 7) | (t3 << 9)) & 0x1fff;
    _r[4] = ((t3 >> 4) | (t4 << 12)) & 0x00ff;
    _r[5] = (t4 >> 1) & 0x1ffe;
    _r[6] = ((t4 >> 14) | (t5 << 2)) & 0x1fff;
    _r[7] = ((t5 >> 11) | (t6 << 5)) & 0x1f81;
    _r[8] = ((t6 >> 8) | (t7 << 8)) & 0x1fff;
    _r[9] = (t7 >> 5) & 0x007f;

    _pad[0] = key[16] | key[17] << 8;
    _pad[1] = key[18] | key[19] << 8;
    _pad[2] = key[20] | key[21] << 8;
    _pad[3] = key[22] | key[23] << 8;
    _pad[4] = key[24] | key[25] << 8;
    _pad[5] = key[26] | key[27] << 8;
    _pad[6] = key[28] | key[29] << 8;
    _pad[7] = key[30] | key[31] << 8;
  }

  final _buffer = Uint8List(16);
  final _r = Int32List(10);
  final _h = Int32List(10);
  final _pad = Int32List(8);
  int _leftover = 0;
  int _fin = 0;

  Poly1305 _blocks(Uint8List m, int mpos, int bytes) {
    final hibit = _fin != 0 ? 0 : (1 << 11);
    int t0, t1, t2, t3, t4, t5, t6, t7, c;
    int d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;

    var h0 = _h[0],
        h1 = _h[1],
        h2 = _h[2],
        h3 = _h[3],
        h4 = _h[4],
        h5 = _h[5],
        h6 = _h[6],
        h7 = _h[7],
        h8 = _h[8],
        h9 = _h[9];

    final r0 = _r[0],
        r1 = _r[1],
        r2 = _r[2],
        r3 = _r[3],
        r4 = _r[4],
        r5 = _r[5],
        r6 = _r[6],
        r7 = _r[7],
        r8 = _r[8],
        r9 = _r[9];

    while (bytes >= 16) {
      t0 = m[mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8;
      h0 += t0 & 0x1fff;
      t1 = m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8;
      h1 += ((t0 >> 13) | (t1 << 3)) & 0x1fff;
      t2 = m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8;
      h2 += ((t1 >> 10) | (t2 << 6)) & 0x1fff;
      t3 = m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8;
      h3 += ((t2 >> 7) | (t3 << 9)) & 0x1fff;
      t4 = m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8;
      h4 += ((t3 >> 4) | (t4 << 12)) & 0x1fff;
      h5 += (t4 >> 1) & 0x1fff;
      t5 = m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8;
      h6 += ((t4 >> 14) | (t5 << 2)) & 0x1fff;
      t6 = m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8;
      h7 += ((t5 >> 11) | (t6 << 5)) & 0x1fff;
      t7 = m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8;
      h8 += ((t6 >> 8) | (t7 << 8)) & 0x1fff;
      h9 += (t7 >> 5) | hibit;

      c = 0;

      d0 = c;
      d0 += h0 * r0;
      d0 += h1 * 5 * r9;
      d0 += h2 * 5 * r8;
      d0 += h3 * 5 * r7;
      d0 += h4 * 5 * r6;
      c = d0 >> 13;
      d0 &= 0x1fff;
      d0 += h5 * 5 * r5;
      d0 += h6 * 5 * r4;
      d0 += h7 * 5 * r3;
      d0 += h8 * 5 * r2;
      d0 += h9 * 5 * r1;
      c += d0 >> 13;
      d0 &= 0x1fff;

      d1 = c;
      d1 += h0 * r1;
      d1 += h1 * r0;
      d1 += h2 * 5 * r9;
      d1 += h3 * 5 * r8;
      d1 += h4 * 5 * r7;
      c = d1 >> 13;
      d1 &= 0x1fff;
      d1 += h5 * 5 * r6;
      d1 += h6 * 5 * r5;
      d1 += h7 * 5 * r4;
      d1 += h8 * 5 * r3;
      d1 += h9 * 5 * r2;
      c += d1 >> 13;
      d1 &= 0x1fff;

      d2 = c;
      d2 += h0 * r2;
      d2 += h1 * r1;
      d2 += h2 * r0;
      d2 += h3 * 5 * r9;
      d2 += h4 * 5 * r8;
      c = d2 >> 13;
      d2 &= 0x1fff;
      d2 += h5 * 5 * r7;
      d2 += h6 * 5 * r6;
      d2 += h7 * 5 * r5;
      d2 += h8 * 5 * r4;
      d2 += h9 * 5 * r3;
      c += d2 >> 13;
      d2 &= 0x1fff;

      d3 = c;
      d3 += h0 * r3;
      d3 += h1 * r2;
      d3 += h2 * r1;
      d3 += h3 * r0;
      d3 += h4 * 5 * r9;
      c = d3 >> 13;
      d3 &= 0x1fff;
      d3 += h5 * 5 * r8;
      d3 += h6 * 5 * r7;
      d3 += h7 * 5 * r6;
      d3 += h8 * 5 * r5;
      d3 += h9 * 5 * r4;
      c += d3 >> 13;
      d3 &= 0x1fff;

      d4 = c;
      d4 += h0 * r4;
      d4 += h1 * r3;
      d4 += h2 * r2;
      d4 += h3 * r1;
      d4 += h4 * r0;
      c = d4 >> 13;
      d4 &= 0x1fff;
      d4 += h5 * 5 * r9;
      d4 += h6 * 5 * r8;
      d4 += h7 * 5 * r7;
      d4 += h8 * 5 * r6;
      d4 += h9 * 5 * r5;
      c += d4 >> 13;
      d4 &= 0x1fff;

      d5 = c;
      d5 += h0 * r5;
      d5 += h1 * r4;
      d5 += h2 * r3;
      d5 += h3 * r2;
      d5 += h4 * r1;
      c = d5 >> 13;
      d5 &= 0x1fff;
      d5 += h5 * r0;
      d5 += h6 * 5 * r9;
      d5 += h7 * 5 * r8;
      d5 += h8 * 5 * r7;
      d5 += h9 * 5 * r6;
      c += d5 >> 13;
      d5 &= 0x1fff;

      d6 = c;
      d6 += h0 * r6;
      d6 += h1 * r5;
      d6 += h2 * r4;
      d6 += h3 * r3;
      d6 += h4 * r2;
      c = d6 >> 13;
      d6 &= 0x1fff;
      d6 += h5 * r1;
      d6 += h6 * r0;
      d6 += h7 * 5 * r9;
      d6 += h8 * 5 * r8;
      d6 += h9 * 5 * r7;
      c += d6 >> 13;
      d6 &= 0x1fff;

      d7 = c;
      d7 += h0 * r7;
      d7 += h1 * r6;
      d7 += h2 * r5;
      d7 += h3 * r4;
      d7 += h4 * r3;
      c = d7 >> 13;
      d7 &= 0x1fff;
      d7 += h5 * r2;
      d7 += h6 * r1;
      d7 += h7 * r0;
      d7 += h8 * 5 * r9;
      d7 += h9 * 5 * r8;
      c += d7 >> 13;
      d7 &= 0x1fff;

      d8 = c;
      d8 += h0 * r8;
      d8 += h1 * r7;
      d8 += h2 * r6;
      d8 += h3 * r5;
      d8 += h4 * r4;
      c = d8 >> 13;
      d8 &= 0x1fff;
      d8 += h5 * r3;
      d8 += h6 * r2;
      d8 += h7 * r1;
      d8 += h8 * r0;
      d8 += h9 * 5 * r9;
      c += d8 >> 13;
      d8 &= 0x1fff;

      d9 = c;
      d9 += h0 * r9;
      d9 += h1 * r8;
      d9 += h2 * r7;
      d9 += h3 * r6;
      d9 += h4 * r5;
      c = d9 >> 13;
      d9 &= 0x1fff;
      d9 += h5 * r4;
      d9 += h6 * r3;
      d9 += h7 * r2;
      d9 += h8 * r1;
      d9 += h9 * r0;
      c += d9 >> 13;
      d9 &= 0x1fff;

      c = ((c << 2) + c) | 0;
      c = (c + d0) | 0;
      d0 = c & 0x1fff;
      c = c >> 13;
      d1 += c;

      h0 = d0;
      h1 = d1;
      h2 = d2;
      h3 = d3;
      h4 = d4;
      h5 = d5;
      h6 = d6;
      h7 = d7;
      h8 = d8;
      h9 = d9;

      mpos += 16;
      bytes -= 16;
    }
    _h[0] = h0;
    _h[1] = h1;
    _h[2] = h2;
    _h[3] = h3;
    _h[4] = h4;
    _h[5] = h5;
    _h[6] = h6;
    _h[7] = h7;
    _h[8] = h8;
    _h[9] = h9;

    return this;
  }

  Poly1305 finish(Uint8List mac, int macpos) {
    final g = Int32List(10);
    int i;
    int c, mask, f;

    if (_leftover != 0) {
      i = _leftover;
      _buffer[i++] = 1;
      for (; i < 16; i++) {
        _buffer[i] = 0;
      }
      _fin = 1;
      _blocks(_buffer, 0, 16);
    }

    c = _h[1] >> 13;
    _h[1] &= 0x1fff;
    for (i = 2; i < 10; i++) {
      _h[i] += c;
      c = _h[i] >> 13;
      _h[i] &= 0x1fff;
    }
    _h[0] += (c * 5);
    c = _h[0] >> 13;
    _h[0] &= 0x1fff;
    _h[1] += c;
    c = _h[1] >> 13;
    _h[1] &= 0x1fff;
    _h[2] += c;

    g[0] = _h[0] + 5;
    c = g[0] >> 13;
    g[0] &= 0x1fff;
    for (i = 1; i < 10; i++) {
      g[i] = _h[i] + c;
      c = g[i] >> 13;
      g[i] &= 0x1fff;
    }
    g[9] -= (1 << 13);
    g[9] &= 0xffff;

    /// BACKPORT from [tweetnacl-fast.js ](https://github.com/dchest/tweetnacl-js/releases/tag/v0.14.3)
    ///
    ///  "The issue was not properly detecting if st->h was >= 2^130 - 5,
    ///  coupled with [testing mistake] not catching the failure.
    ///  The chance of the bug affecting anything in the real world is essentially zero luckily,
    ///  but it's good to have it fixed."
    ///
    /// change mask = (g[9] >>> ((2 * 8) - 1)) - 1; to as
    mask = (c ^ 1) - 1;
    mask &= 0xffff;

    /// END OF BACKPORT

    for (i = 0; i < 10; i++) {
      g[i] &= mask;
    }
    mask = ~mask;
    for (i = 0; i < 10; i++) {
      _h[i] = (_h[i] & mask) | g[i];
    }

    _h[0] = _h[0] | (_h[1] << 13) & 0xffff;
    _h[1] = (_h[1] >> 3) | (_h[2] << 10) & 0xffff;
    _h[2] = (_h[2] >> 6) | (_h[3] << 7) & 0xffff;
    _h[3] = (_h[3] >> 9) | (_h[4] << 4) & 0xffff;
    _h[4] = (_h[4] >> 12) | (_h[5] << 1) | (_h[6] << 14) & 0xffff;
    _h[5] = (_h[6] >> 2) | (_h[7] << 11) & 0xffff;
    _h[6] = (_h[7] >> 5) | (_h[8] << 8) & 0xffff;
    _h[7] = (_h[8] >> 8) | (_h[9] << 5) & 0xffff;

    f = _h[0] + _pad[0];
    _h[0] = f & 0xffff;
    for (i = 1; i < 8; i++) {
      f = (((_h[i] + _pad[i]) | 0) + (f >> 16)) | 0;
      _h[i] = f & 0xffff;
    }

    mac[macpos + 0] = (_h[0] >> 0) & 0xff;
    mac[macpos + 1] = (_h[0] >> 8) & 0xff;
    mac[macpos + 2] = (_h[1] >> 0) & 0xff;
    mac[macpos + 3] = (_h[1] >> 8) & 0xff;
    mac[macpos + 4] = (_h[2] >> 0) & 0xff;
    mac[macpos + 5] = (_h[2] >> 8) & 0xff;
    mac[macpos + 6] = (_h[3] >> 0) & 0xff;
    mac[macpos + 7] = (_h[3] >> 8) & 0xff;
    mac[macpos + 8] = (_h[4] >> 0) & 0xff;
    mac[macpos + 9] = (_h[4] >> 8) & 0xff;
    mac[macpos + 10] = (_h[5] >> 0) & 0xff;
    mac[macpos + 11] = (_h[5] >> 8) & 0xff;
    mac[macpos + 12] = (_h[6] >> 0) & 0xff;
    mac[macpos + 13] = (_h[6] >> 8) & 0xff;
    mac[macpos + 14] = (_h[7] >> 0) & 0xff;
    mac[macpos + 15] = (_h[7] >> 8) & 0xff;

    return this;
  }

  Poly1305 update(Uint8List m, int mpos, int bytes) {
    int i, want;

    if (_leftover != 0) {
      want = (16 - _leftover);
      if (want > bytes) want = bytes;
      for (i = 0; i < want; i++) {
        _buffer[_leftover + i] = m[mpos + i];
      }
      bytes -= want;
      mpos += want;
      _leftover += want;
      if (_leftover < 16) return this;
      _blocks(_buffer, 0, 16);
      _leftover = 0;
    }

    if (bytes >= 16) {
      want = bytes - (bytes % 16);
      _blocks(m, mpos, want);
      mpos += want;
      bytes -= want;
    }

    if (bytes != 0) {
      for (i = 0; i < bytes; i++) {
        _buffer[_leftover + i] = m[mpos + i];
      }
      _leftover += bytes;
    }

    return this;
  }
}
