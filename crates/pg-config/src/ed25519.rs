//! Pure-Rust `#![no_std]`, `#![forbid(unsafe_code)]` SHA-512 (FIPS 180-4) and
//! Ed25519 signature verification and signing (RFC 8032).
//!
//! Usable directly inside `#![no_std]` seL4 protection domains (`policy_pd`) as
//! well as the Linux host proxy (`pg-proxy`) and signing tools.

// ---------------------------------------------------------------------------
// SHA-512 (FIPS 180-4)

const K512: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

#[derive(Clone)]
pub struct Sha512 {
    h: [u64; 8],
    buf: [u8; 128],
    buf_len: usize,
    total_len: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    pub const fn new() -> Self {
        Sha512 {
            h: [
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179,
            ],
            buf: [0u8; 128],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        let mut i = 0;
        while i < 16 {
            let off = i * 8;
            w[i] = u64::from_be_bytes([
                block[off],
                block[off + 1],
                block[off + 2],
                block[off + 3],
                block[off + 4],
                block[off + 5],
                block[off + 6],
                block[off + 7],
            ]);
            i += 1;
        }
        while i < 80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
            i += 1;
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        let mut r = 0;
        while r < 80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[r])
                .wrapping_add(w[r]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            r += 1;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u128);
        let mut i = 0;
        while i < data.len() {
            let take = (128 - self.buf_len).min(data.len() - i);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[i..i + take]);
            self.buf_len += take;
            i += take;
            if self.buf_len == 128 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;
        if self.buf_len > 112 {
            while self.buf_len < 128 {
                self.buf[self.buf_len] = 0;
                self.buf_len += 1;
            }
            let block = self.buf;
            self.compress(&block);
            self.buf_len = 0;
        }
        while self.buf_len < 112 {
            self.buf[self.buf_len] = 0;
            self.buf_len += 1;
        }
        let len_bytes = bit_len.to_be_bytes();
        self.buf[112..128].copy_from_slice(&len_bytes);
        let block = self.buf;
        self.compress(&block);

        let mut out = [0u8; 64];
        let mut i = 0;
        while i < 8 {
            let b = self.h[i].to_be_bytes();
            let off = i * 8;
            out[off..off + 8].copy_from_slice(&b);
            i += 1;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Field arithmetic modulo p = 2^255 - 19 using 5 limbs in radix 2^51

const MASK51: u64 = (1u64 << 51) - 1;

#[derive(Clone, Copy, Debug)]
struct Fe([u64; 5]);

const FE_ZERO: Fe = Fe([0, 0, 0, 0, 0]);
const FE_ONE: Fe = Fe([1, 0, 0, 0, 0]);

// d = -121665 / 121666 mod p
const FE_D: Fe = Fe([
    929955233495203,
    466365720129213,
    1662059464998953,
    2033849074728123,
    1442794654840575,
]);

// 2 * d mod p
const FE_2D: Fe = Fe([
    1859910466990425,
    932731440258426,
    1072319116312658,
    1815898335770999,
    633789495995903,
]);

// sqrt(-1) = 2^((p-1)/4) mod p
const FE_SQRT_M1: Fe = Fe([
    1718705420411056,
    234908883556509,
    2233514472574048,
    2117202627021982,
    765476049583133,
]);

impl Fe {
    fn add(self, rhs: Fe) -> Fe {
        let mut c = [0u64; 5];
        let mut carry = 0u64;
        let mut i = 0;
        while i < 5 {
            let s = self.0[i] + rhs.0[i] + carry;
            c[i] = s & MASK51;
            carry = s >> 51;
            i += 1;
        }
        c[0] += carry * 19;
        let carry0 = c[0] >> 51;
        c[0] &= MASK51;
        c[1] += carry0;
        Fe(c)
    }

    fn sub(self, rhs: Fe) -> Fe {
        // Add 2*p before subtracting to avoid underflow
        const TWO_P: [u64; 5] = [
            0xfffffffffffda,
            0xffffffffffffe,
            0xffffffffffffe,
            0xffffffffffffe,
            0xffffffffffffe,
        ];
        let mut c = [0u64; 5];
        let mut carry = 0u64;
        let mut i = 0;
        while i < 5 {
            let s = (self.0[i] + TWO_P[i]) - rhs.0[i] + carry;
            c[i] = s & MASK51;
            carry = s >> 51;
            i += 1;
        }
        c[0] += carry * 19;
        let carry0 = c[0] >> 51;
        c[0] &= MASK51;
        c[1] += carry0;
        Fe(c)
    }

    fn neg(self) -> Fe {
        FE_ZERO.sub(self)
    }

    fn mul(self, rhs: Fe) -> Fe {
        let a0 = self.0[0] as u128;
        let a1 = self.0[1] as u128;
        let a2 = self.0[2] as u128;
        let a3 = self.0[3] as u128;
        let a4 = self.0[4] as u128;

        let b0 = rhs.0[0] as u128;
        let b1 = rhs.0[1] as u128;
        let b2 = rhs.0[2] as u128;
        let b3 = rhs.0[3] as u128;
        let b4 = rhs.0[4] as u128;

        let b1_19 = b1 * 19;
        let b2_19 = b2 * 19;
        let b3_19 = b3 * 19;
        let b4_19 = b4 * 19;

        let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
        let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
        let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
        let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
        let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

        let c0 = t0 >> 51;
        t0 &= MASK51 as u128;
        t1 += c0;
        let c1 = t1 >> 51;
        t1 &= MASK51 as u128;
        t2 += c1;
        let c2 = t2 >> 51;
        t2 &= MASK51 as u128;
        t3 += c2;
        let c3 = t3 >> 51;
        t3 &= MASK51 as u128;
        t4 += c3;
        let c4 = t4 >> 51;
        t4 &= MASK51 as u128;
        t0 += c4 * 19;
        let c0b = t0 >> 51;
        t0 &= MASK51 as u128;
        t1 += c0b;

        Fe([t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64])
    }

    fn sq(self) -> Fe {
        self.mul(self)
    }

    /// Canonical reduction modulo p = 2^255 - 19 into 51-bit limbs.
    fn canonical(self) -> Fe {
        let mut l = self.0;
        let mut i = 0;
        while i < 4 {
            let c = l[i] >> 51;
            l[i] &= MASK51;
            l[i + 1] += c;
            i += 1;
        }
        let c4 = l[4] >> 51;
        l[4] &= MASK51;
        l[0] += c4 * 19;
        let c0 = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += c0;

        // Subtract p if l >= p; equivalently check if l + 19 >= 2^255
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;

        l[0] += 19 * q;
        let c0 = l[0] >> 51;
        l[0] &= MASK51;
        l[1] += c0;
        let c1 = l[1] >> 51;
        l[1] &= MASK51;
        l[2] += c1;
        let c2 = l[2] >> 51;
        l[2] &= MASK51;
        l[3] += c2;
        let c3 = l[3] >> 51;
        l[3] &= MASK51;
        l[4] = (l[4] + c3) & MASK51;

        Fe(l)
    }

    fn to_bytes(self) -> [u8; 32] {
        let c = self.canonical().0;
        let mut out = [0u8; 32];
        // Pack five 51-bit limbs into 256-bit little-endian byte array
        let mut acc: u128 = 0;
        let mut bits: u32 = 0;
        let mut out_idx = 0;
        let mut limb_idx = 0;
        while limb_idx < 5 {
            acc |= (c[limb_idx] as u128) << bits;
            bits += 51;
            while bits >= 8 && out_idx < 32 {
                out[out_idx] = (acc & 0xff) as u8;
                acc >>= 8;
                bits -= 8;
                out_idx += 1;
            }
            limb_idx += 1;
        }
        if out_idx < 32 {
            out[out_idx] = (acc & 0xff) as u8;
        }
        out
    }

    fn from_bytes_canonical(bytes: &[u8; 32]) -> Option<Fe> {
        let mut b = *bytes;
        b[31] &= 0x7f;
        let u0 = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let u1 = u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]);
        let u2 = u64::from_le_bytes([b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]]);
        let u3 = u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]]);

        let l0 = u0 & MASK51;
        let l1 = ((u0 >> 51) | (u1 << 13)) & MASK51;
        let l2 = ((u1 >> 38) | (u2 << 26)) & MASK51;
        let l3 = ((u2 >> 25) | (u3 << 39)) & MASK51;
        let l4 = (u3 >> 12) & MASK51;

        let fe = Fe([l0, l1, l2, l3, l4]);
        // Enforce canonical encoding (< p)
        if fe.to_bytes() != b {
            return None;
        }
        Some(fe)
    }

    fn eq_ct(self, other: Fe) -> bool {
        let a = self.to_bytes();
        let b = other.to_bytes();
        let mut diff = 0u8;
        let mut i = 0;
        while i < 32 {
            diff |= a[i] ^ b[i];
            i += 1;
        }
        diff == 0
    }

    /// Compute self^((p - 5) / 8) = self^(2^252 - 3).
    fn pow_p58(self) -> Fe {
        // 2^252 - 3 = (2^250 - 1) * 4 + 1
        let z2 = self.sq();
        let z9 = z2.sq().sq().mul(self);
        let z11 = z9.mul(z2);
        let t0 = z11.sq().mul(z9); // 2^5 - 1

        let mut t = t0;
        let mut i = 0;
        while i < 5 {
            t = t.sq();
            i += 1;
        }
        let t10 = t.mul(t0); // 2^10 - 1

        t = t10;
        i = 0;
        while i < 10 {
            t = t.sq();
            i += 1;
        }
        let t20 = t.mul(t10); // 2^20 - 1

        t = t20;
        i = 0;
        while i < 20 {
            t = t.sq();
            i += 1;
        }
        let t40 = t.mul(t20); // 2^40 - 1

        t = t40;
        i = 0;
        while i < 10 {
            t = t.sq();
            i += 1;
        }
        let t50 = t.mul(t10); // 2^50 - 1

        t = t50;
        i = 0;
        while i < 50 {
            t = t.sq();
            i += 1;
        }
        let t100 = t.mul(t50); // 2^100 - 1

        t = t100;
        i = 0;
        while i < 100 {
            t = t.sq();
            i += 1;
        }
        let t200 = t.mul(t100); // 2^200 - 1

        t = t200;
        i = 0;
        while i < 50 {
            t = t.sq();
            i += 1;
        }
        let t250 = t.mul(t50); // 2^250 - 1

        t250.sq().sq().mul(self)
    }

    /// Compute self^(p - 2) = self^(2^255 - 21).
    fn invert(self) -> Fe {
        // (2^250 - 1) * 32 + 11
        let z2 = self.sq();
        let z9 = z2.sq().sq().mul(self);
        let z11 = z9.mul(z2);
        let t0 = z11.sq().mul(z9); // 2^5 - 1

        let mut t = t0;
        let mut i = 0;
        while i < 5 {
            t = t.sq();
            i += 1;
        }
        let t10 = t.mul(t0);

        t = t10;
        i = 0;
        while i < 10 {
            t = t.sq();
            i += 1;
        }
        let t20 = t.mul(t10);

        t = t20;
        i = 0;
        while i < 20 {
            t = t.sq();
            i += 1;
        }
        let t40 = t.mul(t20);

        t = t40;
        i = 0;
        while i < 10 {
            t = t.sq();
            i += 1;
        }
        let t50 = t.mul(t10);

        t = t50;
        i = 0;
        while i < 50 {
            t = t.sq();
            i += 1;
        }
        let t100 = t.mul(t50);

        t = t100;
        i = 0;
        while i < 100 {
            t = t.sq();
            i += 1;
        }
        let t200 = t.mul(t100);

        t = t200;
        i = 0;
        while i < 50 {
            t = t.sq();
            i += 1;
        }
        let t250 = t.mul(t50);

        t = t250;
        i = 0;
        while i < 5 {
            t = t.sq();
            i += 1;
        }
        t.mul(z11)
    }
}

// ---------------------------------------------------------------------------
// Extended Twisted Edwards coordinates (X : Y : Z : T) with X*Y = Z*T

#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

const IDENTITY: Point = Point {
    x: FE_ZERO,
    y: FE_ONE,
    z: FE_ONE,
    t: FE_ZERO,
};

// Base point B (RFC 8032 §5.1)
const BASE_POINT: Point = Point {
    x: Fe([
        1738742601995546,
        1146398526822698,
        2070867633025821,
        562264141797630,
        587772402128613,
    ]),
    y: Fe([
        1801439850948184,
        1351079888211148,
        450359962737049,
        900719925474099,
        1801439850948198,
    ]),
    z: FE_ONE,
    t: Fe([
        1841354044333475,
        16398895984059,
        755974180946558,
        900171276175154,
        1821297809914039,
    ]),
};

impl Point {
    /// Complete unified addition formula (RFC 8032 §5.1.4).
    fn add(self, other: Point) -> Point {
        let a = self.y.sub(self.x).mul(other.y.sub(other.x));
        let b = self.y.add(self.x).mul(other.y.add(other.x));
        let c = self.t.mul(FE_2D).mul(other.t);
        let d = self.z.add(self.z).mul(other.z);
        let e = b.sub(a);
        let f = d.sub(c);
        let g = d.add(c);
        let h = b.add(a);
        Point {
            x: e.mul(f),
            y: g.mul(h),
            z: f.mul(g),
            t: e.mul(h),
        }
    }

    fn double(self) -> Point {
        self.add(self)
    }

    fn scalar_mul(self, scalar_le: &[u8; 32]) -> Point {
        let mut res = IDENTITY;
        let mut base = self;
        let mut i = 0;
        while i < 32 {
            let byte = scalar_le[i];
            let mut bit = 0;
            while bit < 8 {
                if ((byte >> bit) & 1) == 1 {
                    res = res.add(base);
                }
                base = base.double();
                bit += 1;
            }
            i += 1;
        }
        res
    }

    fn encode(self) -> [u8; 32] {
        let z_inv = self.z.invert();
        let x = self.x.mul(z_inv);
        let y = self.y.mul(z_inv);
        let x_bytes = x.to_bytes();
        let mut y_bytes = y.to_bytes();
        y_bytes[31] |= (x_bytes[0] & 1) << 7;
        y_bytes
    }

    fn decode(enc: &[u8; 32]) -> Option<Point> {
        let x_0 = (enc[31] >> 7) & 1;
        let y = Fe::from_bytes_canonical(enc)?;
        let y2 = y.sq();
        let u = y2.sub(FE_ONE);
        let v = y2.mul(FE_D).add(FE_ONE);
        let v3 = v.sq().mul(v);
        let v7 = v3.sq().mul(v);
        let uv7 = u.mul(v7);
        let mut x = u.mul(v3).mul(uv7.pow_p58());

        let vx2 = v.mul(x.sq());
        if vx2.eq_ct(u) {
            // x is valid
        } else if vx2.eq_ct(u.neg()) {
            x = x.mul(FE_SQRT_M1);
        } else {
            return None;
        }

        let x_bytes = x.to_bytes();
        if x.eq_ct(FE_ZERO) && x_0 == 1 {
            return None;
        }
        if (x_bytes[0] & 1) != x_0 {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: FE_ONE,
            t: x.mul(y),
        })
    }

    fn eq_projective(self, other: Point) -> bool {
        // X1 * Z2 == X2 * Z1 and Y1 * Z2 == Y2 * Z1
        self.x.mul(other.z).eq_ct(other.x.mul(self.z))
            && self.y.mul(other.z).eq_ct(other.y.mul(self.z))
    }
}

// ---------------------------------------------------------------------------
// Scalar arithmetic modulo L = 2^252 + 27742317777372353535851937790883648493

const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

const L_WORDS: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

fn scalar_is_canonical(s: &[u8; 32]) -> bool {
    let mut i = 31usize;
    loop {
        if s[i] < L_BYTES[i] {
            return true;
        }
        if s[i] > L_BYTES[i] {
            return false;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    false
}

fn ge_l(a: &[u64; 4]) -> bool {
    let mut i = 3usize;
    loop {
        if a[i] > L_WORDS[i] {
            return true;
        }
        if a[i] < L_WORDS[i] {
            return false;
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    true
}

fn sub_l(a: &mut [u64; 4]) {
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let (d1, b1) = a[i].overflowing_sub(L_WORDS[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        a[i] = d2;
        borrow = (b1 as u64) + (b2 as u64);
        i += 1;
    }
}

/// Reduce a 512-bit little-endian integer modulo L into a 32-byte little-endian scalar.
fn reduce_mod_l(x: &[u8; 64]) -> [u8; 32] {
    let mut acc = [0u64; 4];
    let mut byte_idx = 63usize;
    loop {
        let b = x[byte_idx];
        let mut bit = 7usize;
        loop {
            let incoming = ((b >> bit) & 1) as u64;
            let c0 = acc[0] >> 63;
            let c1 = acc[1] >> 63;
            let c2 = acc[2] >> 63;
            acc[0] = (acc[0] << 1) | incoming;
            acc[1] = (acc[1] << 1) | c0;
            acc[2] = (acc[2] << 1) | c1;
            acc[3] = (acc[3] << 1) | c2;
            if ge_l(&acc) {
                sub_l(&mut acc);
            }
            if bit == 0 {
                break;
            }
            bit -= 1;
        }
        if byte_idx == 0 {
            break;
        }
        byte_idx -= 1;
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 4 {
        let le = acc[i].to_le_bytes();
        out[i * 8..i * 8 + 8].copy_from_slice(&le);
        i += 1;
    }
    out
}

/// Add two canonical 32-byte scalars modulo L.
fn scalar_add_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut w = [0u64; 4];
    let mut carry = 0u64;
    let mut i = 0;
    while i < 4 {
        let off = i * 8;
        let aw = u64::from_le_bytes([
            a[off], a[off + 1], a[off + 2], a[off + 3], a[off + 4], a[off + 5], a[off + 6], a[off + 7],
        ]);
        let bw = u64::from_le_bytes([
            b[off], b[off + 1], b[off + 2], b[off + 3], b[off + 4], b[off + 5], b[off + 6], b[off + 7],
        ]);
        let (s1, c1) = aw.overflowing_add(bw);
        let (s2, c2) = s1.overflowing_add(carry);
        w[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
        i += 1;
    }
    if carry != 0 || ge_l(&w) {
        sub_l(&mut w);
    }
    let mut out = [0u8; 32];
    let mut j = 0;
    while j < 4 {
        out[j * 8..j * 8 + 8].copy_from_slice(&w[j].to_le_bytes());
        j += 1;
    }
    out
}

/// Multiply two 32-byte scalars modulo L.
fn scalar_mul_mod_l(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut prod = [0u8; 64];
    let mut i = 0;
    while i < 32 {
        let mut carry = 0u16;
        let mut j = 0;
        while j < 32 {
            let p = (prod[i + j] as u16) + (a[i] as u16) * (b[j] as u16) + carry;
            prod[i + j] = (p & 0xff) as u8;
            carry = p >> 8;
            j += 1;
        }
        prod[i + 32] = carry as u8;
        i += 1;
    }
    reduce_mod_l(&prod)
}

/// Derive the 32-byte Ed25519 public key from a 32-byte private key seed (RFC 8032 §5.1.5).
pub fn public_key_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(seed);
    let digest = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(&digest[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    BASE_POINT.scalar_mul(&s).encode()
}

/// Compute a deterministic Ed25519 signature over `msg` using a 32-byte private key `seed` (RFC 8032 §5.1.6).
pub fn sign_ed25519(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(seed);
    let digest = h.finalize();
    let mut s = [0u8; 32];
    s.copy_from_slice(&digest[..32]);
    s[0] &= 248;
    s[31] &= 127;
    s[31] |= 64;
    let prefix = &digest[32..64];
    let pubkey = BASE_POINT.scalar_mul(&s).encode();

    let mut hr = Sha512::new();
    hr.update(prefix);
    hr.update(msg);
    let r_scalar = reduce_mod_l(&hr.finalize());
    let r_point = BASE_POINT.scalar_mul(&r_scalar).encode();

    let mut hk = Sha512::new();
    hk.update(&r_point);
    hk.update(&pubkey);
    hk.update(msg);
    let k_scalar = reduce_mod_l(&hk.finalize());

    let s_reduced = reduce_mod_l(&{
        let mut s64 = [0u8; 64];
        s64[..32].copy_from_slice(&s);
        s64
    });
    let ks = scalar_mul_mod_l(&k_scalar, &s_reduced);
    let s_out = scalar_add_mod_l(&r_scalar, &ks);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_point);
    sig[32..].copy_from_slice(&s_out);
    sig
}

/// Verify an Ed25519 signature `sig` over `msg` against `pubkey` (RFC 8032 §5.1.7).
pub fn verify_ed25519(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig[..32]);
    s_bytes.copy_from_slice(&sig[32..64]);

    if !scalar_is_canonical(&s_bytes) {
        return false;
    }
    let a_point = match Point::decode(pubkey) {
        Some(p) => p,
        None => return false,
    };
    let r_point = match Point::decode(&r_bytes) {
        Some(p) => p,
        None => return false,
    };

    let mut hk = Sha512::new();
    hk.update(&r_bytes);
    hk.update(pubkey);
    hk.update(msg);
    let k = reduce_mod_l(&hk.finalize());

    let lhs = BASE_POINT.scalar_mul(&s_bytes);
    let rhs = r_point.add(a_point.scalar_mul(&k));
    lhs.eq_projective(rhs)
}
