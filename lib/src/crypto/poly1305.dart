import 'dart:typed_data';
import 'package:fixnum/fixnum.dart';


/// Port of Andrew Moon's Poly1305-donna-16. Public domain.
/// https://github.com/floodyberry/poly1305-donna
class Poly1305 {
  Poly1305(Uint8List key) {
    this._buffer = Uint8List(16);
    this._r = List<Int32>.filled(10, Int32(0));
    this._h = List<Int32>.filled(10, Int32(0));
    this._pad = Int32List(8);
    this._leftover = 0;
    this._fin = 0;

    Int32 t0, t1, t2, t3, t4, t5, t6, t7;

    t0 = Int32(key[0] & 0xff | (key[1] & 0xff) << 8);
    this._r[0] = (t0) & 0x1fff;
    t1 = Int32(key[2] & 0xff | (key[3] & 0xff) << 8);
    this._r[1] = ((t0.shiftRightUnsigned(13)) | (t1 << 3)) & 0x1fff;
    t2 = Int32(key[4] & 0xff | (key[5] & 0xff) << 8);
    this._r[2] = ((t1.shiftRightUnsigned(10)) | (t2 << 6)) & 0x1f03;
    t3 = Int32(key[6] & 0xff | (key[7] & 0xff) << 8);
    this._r[3] = ((t2.shiftRightUnsigned(7)) | (t3 << 9)) & 0x1fff;
    t4 = Int32(key[8] & 0xff | (key[9] & 0xff) << 8);
    this._r[4] = ((t3.shiftRightUnsigned(4)) | (t4 << 12)) & 0x00ff;
    this._r[5] = ((t4.shiftRightUnsigned(1))) & 0x1ffe;
    t5 = Int32(key[10] & 0xff | (key[11] & 0xff) << 8);
    this._r[6] = ((t4.shiftRightUnsigned(14)) | (t5 << 2)) & 0x1fff;
    t6 = Int32(key[12] & 0xff | (key[13] & 0xff) << 8);
    this._r[7] = ((t5.shiftRightUnsigned(11)) | (t6 << 5)) & 0x1f81;
    t7 = Int32(key[14] & 0xff | (key[15] & 0xff) << 8);
    this._r[8] = ((t6.shiftRightUnsigned(8)) | (t7 << 8)) & 0x1fff;
    this._r[9] = ((t7.shiftRightUnsigned(5))) & 0x007f;

    this._pad[0] = key[16] & 0xff | (key[17] & 0xff) << 8;
    this._pad[1] = key[18] & 0xff | (key[19] & 0xff) << 8;
    this._pad[2] = key[20] & 0xff | (key[21] & 0xff) << 8;
    this._pad[3] = key[22] & 0xff | (key[23] & 0xff) << 8;
    this._pad[4] = key[24] & 0xff | (key[25] & 0xff) << 8;
    this._pad[5] = key[26] & 0xff | (key[27] & 0xff) << 8;
    this._pad[6] = key[28] & 0xff | (key[29] & 0xff) << 8;
    this._pad[7] = key[30] & 0xff | (key[31] & 0xff) << 8;
  }

  Uint8List _buffer;
  List<Int32> _r;
  List<Int32> _h;
  Int32List _pad;
  int _leftover;
  int _fin;

  Poly1305 blocks(Uint8List m, int mpos, int bytes) {
    int hibit = this._fin != 0 ? 0 : (1 << 11);
    Int32 t0, t1, t2, t3, t4, t5, t6, t7, c;
    Int32 d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;

    Int32 h0 = this._h[0],
        h1 = this._h[1],
        h2 = this._h[2],
        h3 = this._h[3],
        h4 = this._h[4],
        h5 = this._h[5],
        h6 = this._h[6],
        h7 = this._h[7],
        h8 = this._h[8],
        h9 = this._h[9];

    int r0 = this._r[0].toInt(),
        r1 = this._r[1].toInt(),
        r2 = this._r[2].toInt(),
        r3 = this._r[3].toInt(),
        r4 = this._r[4].toInt(),
        r5 = this._r[5].toInt(),
        r6 = this._r[6].toInt(),
        r7 = this._r[7].toInt(),
        r8 = this._r[8].toInt(),
        r9 = this._r[9].toInt();

    while (bytes >= 16) {
      t0 = Int32(m[mpos + 0] & 0xff | (m[mpos + 1] & 0xff) << 8);
      h0 += (t0).toInt() & 0x1fff;
      t1 = Int32(m[mpos + 2] & 0xff | (m[mpos + 3] & 0xff) << 8);
      h1 += ((t0.shiftRightUnsigned(13)) | (t1 << 3)).toInt() & 0x1fff;
      t2 = Int32(m[mpos + 4] & 0xff | (m[mpos + 5] & 0xff) << 8);
      h2 += ((t1.shiftRightUnsigned(10)) | (t2 << 6)).toInt() & 0x1fff;
      t3 = Int32(m[mpos + 6] & 0xff | (m[mpos + 7] & 0xff) << 8);
      h3 += ((t2.shiftRightUnsigned(7)) | (t3 << 9)).toInt() & 0x1fff;
      t4 = Int32(m[mpos + 8] & 0xff | (m[mpos + 9] & 0xff) << 8);
      h4 += ((t3.shiftRightUnsigned(4)) | (t4 << 12)).toInt() & 0x1fff;
      h5 += ((t4.shiftRightUnsigned(1))).toInt() & 0x1fff;
      t5 = Int32(m[mpos + 10] & 0xff | (m[mpos + 11] & 0xff) << 8);
      h6 += ((t4.shiftRightUnsigned(14)) | (t5 << 2)).toInt() & 0x1fff;
      t6 = Int32(m[mpos + 12] & 0xff | (m[mpos + 13] & 0xff) << 8);
      h7 += ((t5.shiftRightUnsigned(11)) | (t6 << 5)).toInt() & 0x1fff;
      t7 = Int32(m[mpos + 14] & 0xff | (m[mpos + 15] & 0xff) << 8);
      h8 += ((t6.shiftRightUnsigned(8)) | (t7 << 8)).toInt() & 0x1fff;
      h9 += ((t7.shiftRightUnsigned(5))).toInt() | hibit;

      c = Int32(0);

      d0 = c;
      d0 += h0 * r0;
      d0 += h1 * (5 * r9);
      d0 += h2 * (5 * r8);
      d0 += h3 * (5 * r7);
      d0 += h4 * (5 * r6);
      c = (d0.shiftRightUnsigned(13));
      d0 &= 0x1fff;
      d0 += h5 * (5 * r5);
      d0 += h6 * (5 * r4);
      d0 += h7 * (5 * r3);
      d0 += h8 * (5 * r2);
      d0 += h9 * (5 * r1);
      c += (d0.shiftRightUnsigned(13));
      d0 &= 0x1fff;

      d1 = c;
      d1 += h0 * r1;
      d1 += h1 * r0;
      d1 += h2 * (5 * r9);
      d1 += h3 * (5 * r8);
      d1 += h4 * (5 * r7);
      c = (d1.shiftRightUnsigned(13));
      d1 &= 0x1fff;
      d1 += h5 * (5 * r6);
      d1 += h6 * (5 * r5);
      d1 += h7 * (5 * r4);
      d1 += h8 * (5 * r3);
      d1 += h9 * (5 * r2);
      c += (d1.shiftRightUnsigned(13));
      d1 &= 0x1fff;

      d2 = c;
      d2 += h0 * r2;
      d2 += h1 * r1;
      d2 += h2 * r0;
      d2 += h3 * (5 * r9);
      d2 += h4 * (5 * r8);
      c = (d2.shiftRightUnsigned(13));
      d2 &= 0x1fff;
      d2 += h5 * (5 * r7);
      d2 += h6 * (5 * r6);
      d2 += h7 * (5 * r5);
      d2 += h8 * (5 * r4);
      d2 += h9 * (5 * r3);
      c += (d2.shiftRightUnsigned(13));
      d2 &= 0x1fff;

      d3 = c;
      d3 += h0 * r3;
      d3 += h1 * r2;
      d3 += h2 * r1;
      d3 += h3 * r0;
      d3 += h4 * (5 * r9);
      c = (d3.shiftRightUnsigned(13));
      d3 &= 0x1fff;
      d3 += h5 * (5 * r8);
      d3 += h6 * (5 * r7);
      d3 += h7 * (5 * r6);
      d3 += h8 * (5 * r5);
      d3 += h9 * (5 * r4);
      c += (d3.shiftRightUnsigned(13));
      d3 &= 0x1fff;

      d4 = c;
      d4 += h0 * r4;
      d4 += h1 * r3;
      d4 += h2 * r2;
      d4 += h3 * r1;
      d4 += h4 * r0;
      c = (d4.shiftRightUnsigned(13));
      d4 &= 0x1fff;
      d4 += h5 * (5 * r9);
      d4 += h6 * (5 * r8);
      d4 += h7 * (5 * r7);
      d4 += h8 * (5 * r6);
      d4 += h9 * (5 * r5);
      c += (d4.shiftRightUnsigned(13));
      d4 &= 0x1fff;

      d5 = c;
      d5 += h0 * r5;
      d5 += h1 * r4;
      d5 += h2 * r3;
      d5 += h3 * r2;
      d5 += h4 * r1;
      c = (d5.shiftRightUnsigned(13));
      d5 &= 0x1fff;
      d5 += h5 * r0;
      d5 += h6 * (5 * r9);
      d5 += h7 * (5 * r8);
      d5 += h8 * (5 * r7);
      d5 += h9 * (5 * r6);
      c += (d5.shiftRightUnsigned(13));
      d5 &= 0x1fff;

      d6 = c;
      d6 += h0 * r6;
      d6 += h1 * r5;
      d6 += h2 * r4;
      d6 += h3 * r3;
      d6 += h4 * r2;
      c = (d6.shiftRightUnsigned(13));
      d6 &= 0x1fff;
      d6 += h5 * r1;
      d6 += h6 * r0;
      d6 += h7 * (5 * r9);
      d6 += h8 * (5 * r8);
      d6 += h9 * (5 * r7);
      c += (d6.shiftRightUnsigned(13));
      d6 &= 0x1fff;

      d7 = c;
      d7 += h0 * r7;
      d7 += h1 * r6;
      d7 += h2 * r5;
      d7 += h3 * r4;
      d7 += h4 * r3;
      c = (d7.shiftRightUnsigned(13));
      d7 &= 0x1fff;
      d7 += h5 * r2;
      d7 += h6 * r1;
      d7 += h7 * r0;
      d7 += h8 * (5 * r9);
      d7 += h9 * (5 * r8);
      c += (d7.shiftRightUnsigned(13));
      d7 &= 0x1fff;

      d8 = c;
      d8 += h0 * r8;
      d8 += h1 * r7;
      d8 += h2 * r6;
      d8 += h3 * r5;
      d8 += h4 * r4;
      c = (d8.shiftRightUnsigned(13));
      d8 &= 0x1fff;
      d8 += h5 * r3;
      d8 += h6 * r2;
      d8 += h7 * r1;
      d8 += h8 * r0;
      d8 += h9 * (5 * r9);
      c += (d8.shiftRightUnsigned(13));
      d8 &= 0x1fff;

      d9 = c;
      d9 += h0 * r9;
      d9 += h1 * r8;
      d9 += h2 * r7;
      d9 += h3 * r6;
      d9 += h4 * r5;
      c = (d9.shiftRightUnsigned(13));
      d9 &= 0x1fff;
      d9 += h5 * r4;
      d9 += h6 * r3;
      d9 += h7 * r2;
      d9 += h8 * r1;
      d9 += h9 * r0;
      c += (d9.shiftRightUnsigned(13));
      d9 &= 0x1fff;

      c = (((c << 2) + c)) | 0;
      c = (c + d0) | 0;
      d0 = c & 0x1fff;
      c = (c.shiftRightUnsigned(13));
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
    this._h[0] = h0;
    this._h[1] = h1;
    this._h[2] = h2;
    this._h[3] = h3;
    this._h[4] = h4;
    this._h[5] = h5;
    this._h[6] = h6;
    this._h[7] = h7;
    this._h[8] = h8;
    this._h[9] = h9;

    return this;
  }

  Poly1305 finish(Uint8List mac, int macpos) {
    List<Int32> g = List<Int32>(10);
    int i;
    Int32 c, mask, f;

    if (this._leftover != 0) {
      i = this._leftover;
      this._buffer[i++] = 1;
      for (; i < 16; i++) {
        this._buffer[i] = 0;
      }
      this._fin = 1;
      this.blocks(this._buffer, 0, 16);
    }

    c = this._h[1].shiftRightUnsigned(13);
    this._h[1] &= 0x1fff;
    for (i = 2; i < 10; i++) {
      this._h[i] += c;
      c = this._h[i].shiftRightUnsigned(13);
      this._h[i] &= 0x1fff;
    }
    this._h[0] += (c * 5);
    c = this._h[0].shiftRightUnsigned(13);
    this._h[0] &= 0x1fff;
    this._h[1] += c;
    c = this._h[1].shiftRightUnsigned(13);
    this._h[1] &= 0x1fff;
    this._h[2] += c;

    g[0] = this._h[0] + 5;
    c = g[0].shiftRightUnsigned(13);
    g[0] &= 0x1fff;
    for (i = 1; i < 10; i++) {
      g[i] = this._h[i] + c;
      c = g[i].shiftRightUnsigned(13);
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
      this._h[i] = (this._h[i] & mask) | g[i];
    }

    this._h[0] = ((this._h[0]) | (this._h[1] << 13)) & 0xffff;
    this._h[1] =
        ((this._h[1].shiftRightUnsigned(3)) | (this._h[2] << 10)) & 0xffff;
    this._h[2] =
        ((this._h[2].shiftRightUnsigned(6)) | (this._h[3] << 7)) & 0xffff;
    this._h[3] =
        ((this._h[3].shiftRightUnsigned(9)) | (this._h[4] << 4)) & 0xffff;
    this._h[4] = ((this._h[4].shiftRightUnsigned(12)) |
            (this._h[5] << 1) |
            (this._h[6] << 14)) &
        0xffff;
    this._h[5] =
        ((this._h[6].shiftRightUnsigned(2)) | (this._h[7] << 11)) & 0xffff;
    this._h[6] =
        ((this._h[7].shiftRightUnsigned(5)) | (this._h[8] << 8)) & 0xffff;
    this._h[7] =
        ((this._h[8].shiftRightUnsigned(8)) | (this._h[9] << 5)) & 0xffff;

    f = this._h[0] + this._pad[0];
    this._h[0] = f & 0xffff;
    for (i = 1; i < 8; i++) {
      f = (((this._h[i] + this._pad[i]) | 0) + (f.shiftRightUnsigned(16))) | 0;
      this._h[i] = f & 0xffff;
    }

    mac[macpos + 0] = ((this._h[0].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 1] = ((this._h[0].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 2] = ((this._h[1].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 3] = ((this._h[1].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 4] = ((this._h[2].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 5] = ((this._h[2].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 6] = ((this._h[3].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 7] = ((this._h[3].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 8] = ((this._h[4].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 9] = ((this._h[4].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 10] = ((this._h[5].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 11] = ((this._h[5].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 12] = ((this._h[6].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 13] = ((this._h[6].shiftRightUnsigned(8)) & 0xff).toInt();
    mac[macpos + 14] = ((this._h[7].shiftRightUnsigned(0)) & 0xff).toInt();
    mac[macpos + 15] = ((this._h[7].shiftRightUnsigned(8)) & 0xff).toInt();

    return this;
  }

  Poly1305 update(Uint8List m, int mpos, int bytes) {
    int i, want;

    if (this._leftover != 0) {
      want = (16 - this._leftover);
      if (want > bytes) want = bytes;
      for (i = 0; i < want; i++) {
        this._buffer[this._leftover + i] = m[mpos + i];
      }
      bytes -= want;
      mpos += want;
      this._leftover += want;
      if (this._leftover < 16) return this;
      this.blocks(_buffer, 0, 16);
      this._leftover = 0;
    }

    if (bytes >= 16) {
      want = bytes - (bytes % 16);
      this.blocks(m, mpos, want);
      mpos += want;
      bytes -= want;
    }

    if (bytes != 0) {
      for (i = 0; i < bytes; i++) {
        this._buffer[this._leftover + i] = m[mpos + i];
      }
      this._leftover += bytes;
    }

    return this;
  }
}
