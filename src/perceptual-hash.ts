// Perceptual hashes of a favicon: values that stay close when the icon is re-encoded, resized or
// slightly edited, compared by how many of their 64 bits differ (the Hamming distance) instead of by
// equality.
//
// pHash is the ImageHash library's (Johannes Buchner's, the implementation OkCupid evaluated):
// grayscale, Lanczos to 32x32, SciPy's 2-D DCT, and the top-left 8x8 coefficients against their median.
//
// dHash follows Krawetz's difference hash ("Kind of Like That"): one bit per pair of horizontally
// adjacent pixels of a 9x8 grayscale thumbnail. VirusTotal does not document its main_icon_dhash; this
// computes it as the icon dHash of SuperPeHasher and FileInsight-plugins does, which differs from
// Krawetz in three ways: the thumbnail is Pillow's Lanczos resize (Krawetz scales his own way), a bit is
// set when the LEFT pixel is brighter (Krawetz: the right one), and each byte fills from its lowest bit
// (Krawetz writes the bits big-endian). For Facebook's favicon that comes within 2 bits of the value a
// third-party VirusTotal query list gives (github.com/repulsivityy/vt_dorks), and Krawetz's packing
// within 11.
//
// Both start from Pillow's grayscale pixels (favicon-image.ts) and Pillow's LANCZOS resize, which is
// reproduced below to the bit: the same coefficients in the same 22-bit fixed point, the two passes in
// Pillow's order, each rounded back to 8 bits (Resample.c, Pillow 13). A resize that is off by one
// gray level moves hash bits.
import type { Gray } from './favicon-image';

const PRECISION_BITS = 32 - 8 - 2;

function lanczos(x: number): number {
    if (x < -3 || x >= 3) return 0;
    const sinc = (t: number) => (t === 0 ? 1 : Math.sin(t * Math.PI) / (t * Math.PI));
    return sinc(x) * sinc(x / 3);
}

/** Per output pixel: the first input pixel, how many it reads, and their fixed-point weights. */
function coefficients(inSize: number, outSize: number): { start: number[]; count: number[]; weights: number[][] } {
    const scale = inSize / outSize;
    const filterScale = Math.max(scale, 1);
    const support = 3 * filterScale;
    const start: number[] = [];
    const count: number[] = [];
    const weights: number[][] = [];
    for (let xx = 0; xx < outSize; xx++) {
        const center = (xx + 0.5) * scale;
        const ss = 1 / filterScale;
        const xmin = Math.max(0, Math.trunc(center - support + 0.5));
        const xmax = Math.min(inSize, Math.trunc(center + support + 0.5)) - xmin;
        const k: number[] = [];
        let ww = 0;
        for (let x = 0; x < xmax; x++) {
            const w = lanczos((x + xmin - center + 0.5) * ss);
            k.push(w);
            ww += w;
        }
        weights.push(
            k.map((w) => {
                const n = ww !== 0 ? w / ww : w;
                return Math.trunc(n < 0 ? -0.5 + n * (1 << PRECISION_BITS) : 0.5 + n * (1 << PRECISION_BITS));
            }),
        );
        start.push(xmin);
        count.push(xmax);
    }
    return { start, count, weights };
}

const clip8 = (v: number): number =>
    v >= 2 ** (PRECISION_BITS + 8) ? 255 : v <= 0 ? 0 : Math.floor(v / 2 ** PRECISION_BITS);

/** One pass along x (or y): each output sample from its input span, rounded to 8 bits. */
function pass(
    src: Uint8Array,
    srcW: number,
    outW: number,
    outH: number,
    c: { start: number[]; count: number[]; weights: number[][] },
    horizontal: boolean,
    rowOffset: number,
): Uint8Array {
    const out = new Uint8Array(outW * outH);
    for (let yy = 0; yy < outH; yy++)
        for (let xx = 0; xx < outW; xx++) {
            const i = horizontal ? xx : yy;
            const k = c.weights[i];
            let ss = 1 << (PRECISION_BITS - 1);
            for (let j = 0; j < c.count[i]; j++) {
                const at = horizontal ? (yy + rowOffset) * srcW + c.start[i] + j : (c.start[i] + j) * srcW + xx;
                ss += src[at] * k[j];
            }
            out[yy * outW + xx] = clip8(ss);
        }
    return out;
}

/** Pillow's Image.resize((outW, outH), Image.LANCZOS) on an 8-bit grayscale image. */
export function resizeLanczos(img: Gray, outW: number, outH: number): Gray {
    const { width: inW, height: inH } = img;
    if (inW === outW && inH === outH) return img;
    const h = coefficients(inW, outW);
    const v = coefficients(inH, outH);
    // Pillow runs the vertical pass first when the height shrinks more than twice as much as the width.
    const horizontalFirst = !(inH - outH > 0 && inH - outH > (inW - outW) * 2);
    if (horizontalFirst) {
        let src = img.pixels;
        let srcW = inW;
        if (outW !== inW) {
            // Only the rows the vertical pass will read.
            const first = v.start[0];
            const last = v.start[outH - 1] + v.count[outH - 1];
            src = pass(img.pixels, inW, outW, last - first, h, true, first);
            srcW = outW;
            v.start = v.start.map((s) => s - first);
        }
        if (outH === inH) return { width: outW, height: outH, pixels: src };
        return {
            width: outW,
            height: outH,
            pixels: pass(src, srcW, outW, outH, v, false, 0),
        };
    }
    const tall = pass(img.pixels, inW, inW, outH, v, false, 0);
    if (outW === inW) return { width: outW, height: outH, pixels: tall };
    return {
        width: outW,
        height: outH,
        pixels: pass(tall, inW, outW, outH, h, true, 0),
    };
}

/** 64 bits, most significant first, as 16 hex digits (ImageHash's _binary_array_to_hex). */
const bitsToHex = (bits: boolean[]): string => {
    let s = '';
    for (let i = 0; i < bits.length; i += 4)
        s += ((+bits[i] << 3) | (+bits[i + 1] << 2) | (+bits[i + 2] << 1) | +bits[i + 3]).toString(16);
    return s;
};

// ---- SciPy's DCT ----
//
// pHash compares DCT coefficients with their median, and on a mirrored or a smoothly shaded icon several
// coefficients are zero in exact arithmetic. What SciPy returns for those is rounding noise, of either
// sign, and that noise decides their bits. So the DCT is not computed from its formula but the way
// scipy.fftpack.dct computes it: pocketfft's DCT-II (T_dcst23) over its real backward FFT (rfftp, radix
// 2 and 4) and its twiddle tables (sincos_2pibyn), operation for operation in double precision. That
// matches SciPy up to 1.17 on x86-64 bit for bit. The noise is not the same everywhere: SciPy 1.18
// computes the DCT with ducc0 instead, and arm64 builds fuse multiplies and adds, so on such icons
// their bits can differ from these and from each other.

/** pocketfft's sincos_2pibyn(n)[idx]: cos and sin of 2*pi*idx/n, built from two short tables. */
function sincos2PiByN(n: number): (idx: number) => [number, number] {
    const ang = (0.25 * Math.PI) / n;
    const calc = (x: number): [number, number] => {
        x *= 8;
        if (x < 4 * n) {
            if (x < 2 * n) {
                if (x < n) return [Math.cos(x * ang), Math.sin(x * ang)];
                return [Math.sin((2 * n - x) * ang), Math.cos((2 * n - x) * ang)];
            }
            x -= 2 * n;
            if (x < n) return [-Math.sin(x * ang), Math.cos(x * ang)];
            return [-Math.cos((2 * n - x) * ang), Math.sin((2 * n - x) * ang)];
        }
        x = 8 * n - x;
        if (x < 2 * n) {
            if (x < n) return [Math.cos(x * ang), -Math.sin(x * ang)];
            return [Math.sin((2 * n - x) * ang), -Math.cos((2 * n - x) * ang)];
        }
        x -= 2 * n;
        if (x < n) return [-Math.sin(x * ang), -Math.cos(x * ang)];
        return [-Math.cos((2 * n - x) * ang), -Math.sin((2 * n - x) * ang)];
    };
    const nval = Math.floor((n + 2) / 2);
    let shift = 1;
    while ((1 << shift) * (1 << shift) < nval) shift++;
    const mask = (1 << shift) - 1;
    const v1: [number, number][] = [[1, 0]];
    for (let i = 1; i <= mask; i++) v1.push(calc(i));
    const v2: [number, number][] = [[1, 0]];
    for (let i = 1; i < Math.floor((nval + mask) / (mask + 1)); i++) v2.push(calc(i * (mask + 1)));
    return (idx) => {
        const flip = 2 * idx > n;
        if (flip) idx = n - idx;
        const [r1, i1] = v1[idx & mask];
        const [r2, i2] = v2[idx >> shift];
        const im = r1 * i2 + i1 * r2;
        return [r1 * r2 - i1 * i2, flip ? -im : im];
    };
}

/** pocketfft's rfftp for a length made of factors 4 and 2: its backward (halfcomplex to real) transform. */
function realBackwardFft(length: number): (c: Float64Array) => void {
    const fact: number[] = [];
    let len = length;
    while (len % 4 === 0) {
        fact.push(4);
        len /= 4;
    }
    if (len % 2 === 0) {
        len /= 2;
        fact.push(2);
        [fact[0], fact[fact.length - 1]] = [fact[fact.length - 1], fact[0]];
    }
    if (len !== 1) throw new Error(`rfftp length ${length} is not reproduced`);
    const twid = sincos2PiByN(length);
    const tw: Float64Array[] = [];
    for (let k = 0, l1 = 1; k < fact.length; k++) {
        const ip = fact[k];
        const ido = length / (l1 * ip);
        const t = new Float64Array((ip - 1) * (ido - 1));
        if (k < fact.length - 1)
            for (let j = 1; j < ip; j++)
                for (let i = 1; i <= (ido - 1) >> 1; i++) {
                    const [r, im] = twid(j * l1 * i);
                    t[(j - 1) * (ido - 1) + 2 * i - 2] = r;
                    t[(j - 1) * (ido - 1) + 2 * i - 1] = im;
                }
        tw.push(t);
        l1 *= ip;
    }

    const radb2 = (ido: number, l1: number, cc: Float64Array, ch: Float64Array, wa: Float64Array) => {
        const CC = (a: number, b: number, c: number) => cc[a + ido * (b + 2 * c)];
        const CH = (a: number, b: number, c: number) => a + ido * (b + l1 * c);
        const WA = (x: number, i: number) => wa[i + x * (ido - 1)];
        for (let k = 0; k < l1; k++) {
            ch[CH(0, k, 0)] = CC(0, 0, k) + CC(ido - 1, 1, k);
            ch[CH(0, k, 1)] = CC(0, 0, k) - CC(ido - 1, 1, k);
        }
        if ((ido & 1) === 0)
            for (let k = 0; k < l1; k++) {
                ch[CH(ido - 1, k, 0)] = 2 * CC(ido - 1, 0, k);
                ch[CH(ido - 1, k, 1)] = -2 * CC(0, 1, k);
            }
        if (ido <= 2) return;
        for (let k = 0; k < l1; k++)
            for (let i = 2; i < ido; i += 2) {
                const ic = ido - i;
                ch[CH(i - 1, k, 0)] = CC(i - 1, 0, k) + CC(ic - 1, 1, k);
                const tr2 = CC(i - 1, 0, k) - CC(ic - 1, 1, k);
                const ti2 = CC(i, 0, k) + CC(ic, 1, k);
                ch[CH(i, k, 0)] = CC(i, 0, k) - CC(ic, 1, k);
                ch[CH(i, k, 1)] = WA(0, i - 2) * ti2 + WA(0, i - 1) * tr2;
                ch[CH(i - 1, k, 1)] = WA(0, i - 2) * tr2 - WA(0, i - 1) * ti2;
            }
    };

    const radb4 = (ido: number, l1: number, cc: Float64Array, ch: Float64Array, wa: Float64Array) => {
        const CC = (a: number, b: number, c: number) => cc[a + ido * (b + 4 * c)];
        const CH = (a: number, b: number, c: number) => a + ido * (b + l1 * c);
        const WA = (x: number, i: number) => wa[i + x * (ido - 1)];
        for (let k = 0; k < l1; k++) {
            const tr2 = CC(0, 0, k) + CC(ido - 1, 3, k);
            const tr1 = CC(0, 0, k) - CC(ido - 1, 3, k);
            const tr3 = 2 * CC(ido - 1, 1, k);
            const tr4 = 2 * CC(0, 2, k);
            ch[CH(0, k, 0)] = tr2 + tr3;
            ch[CH(0, k, 2)] = tr2 - tr3;
            ch[CH(0, k, 3)] = tr1 + tr4;
            ch[CH(0, k, 1)] = tr1 - tr4;
        }
        if ((ido & 1) === 0)
            for (let k = 0; k < l1; k++) {
                const ti1 = CC(0, 3, k) + CC(0, 1, k);
                const ti2 = CC(0, 3, k) - CC(0, 1, k);
                const tr2 = CC(ido - 1, 0, k) + CC(ido - 1, 2, k);
                const tr1 = CC(ido - 1, 0, k) - CC(ido - 1, 2, k);
                ch[CH(ido - 1, k, 0)] = tr2 + tr2;
                ch[CH(ido - 1, k, 1)] = Math.SQRT2 * (tr1 - ti1);
                ch[CH(ido - 1, k, 2)] = ti2 + ti2;
                ch[CH(ido - 1, k, 3)] = -Math.SQRT2 * (tr1 + ti1);
            }
        if (ido <= 2) return;
        for (let k = 0; k < l1; k++)
            for (let i = 2; i < ido; i += 2) {
                const ic = ido - i;
                const tr2 = CC(i - 1, 0, k) + CC(ic - 1, 3, k);
                const tr1 = CC(i - 1, 0, k) - CC(ic - 1, 3, k);
                const ti1 = CC(i, 0, k) + CC(ic, 3, k);
                const ti2 = CC(i, 0, k) - CC(ic, 3, k);
                const tr4 = CC(i, 2, k) + CC(ic, 1, k);
                const ti3 = CC(i, 2, k) - CC(ic, 1, k);
                const tr3 = CC(i - 1, 2, k) + CC(ic - 1, 1, k);
                const ti4 = CC(i - 1, 2, k) - CC(ic - 1, 1, k);
                ch[CH(i - 1, k, 0)] = tr2 + tr3;
                const cr3 = tr2 - tr3;
                ch[CH(i, k, 0)] = ti2 + ti3;
                const ci3 = ti2 - ti3;
                const cr4 = tr1 + tr4;
                const cr2 = tr1 - tr4;
                const ci2 = ti1 + ti4;
                const ci4 = ti1 - ti4;
                for (const [j, ci, cr] of [
                    [1, ci2, cr2],
                    [2, ci3, cr3],
                    [3, ci4, cr4],
                ]) {
                    ch[CH(i, k, j)] = WA(j - 1, i - 2) * ci + WA(j - 1, i - 1) * cr;
                    ch[CH(i - 1, k, j)] = WA(j - 1, i - 2) * cr - WA(j - 1, i - 1) * ci;
                }
            }
    };

    return (c) => {
        let p1: Float64Array = c;
        let p2: Float64Array = new Float64Array(length);
        for (let k = 0, l1 = 1; k < fact.length; k++) {
            const ip = fact[k];
            const ido = length / (ip * l1);
            (ip === 4 ? radb4 : radb2)(ido, l1, p1, p2, tw[k]);
            [p1, p2] = [p2, p1];
            l1 *= ip;
        }
        if (p1 !== c) c.set(p1);
    };
}

/** scipy.fftpack.dct(x) of length n in place: type II, unnormalised, y[k] = 2 * sum x[j] cos(pi k (2j + 1) / 2n). */
function dctII(n: number): (c: Float64Array) => void {
    const fft = realBackwardFft(n);
    const tw = sincos2PiByN(4 * n);
    const twiddle = Array.from({ length: n }, (_, i) => tw(i + 1)[0]);
    const ns2 = (n + 1) >> 1;
    return (c) => {
        c[0] *= 2;
        if ((n & 1) === 0) c[n - 1] *= 2;
        for (let k = 1; k < n - 1; k += 2) {
            const t = c[k + 1];
            c[k + 1] -= c[k];
            c[k] = t + c[k];
        }
        fft(c);
        for (let k = 1, kc = n - 1; k < ns2; k++, kc--) {
            const t1 = twiddle[k - 1] * c[kc] + twiddle[kc - 1] * c[k];
            const t2 = twiddle[k - 1] * c[k] - twiddle[kc - 1] * c[kc];
            c[k] = 0.5 * (t1 + t2);
            c[kc] = 0.5 * (t1 - t2);
        }
        if ((n & 1) === 0) c[ns2] *= twiddle[ns2 - 1];
    };
}

const dct32 = dctII(32);

/** ImageHash phash(image): 32x32 Lanczos, scipy.fftpack.dct down the columns then along the rows, top-left 8x8 against their median. */
export function phashHex(img: Gray): string {
    const N = 32;
    const small = resizeLanczos(img, N, N).pixels;
    // Every column's transform, of which the first 8 rows are kept.
    const top = Array.from({ length: 8 }, () => new Float64Array(N));
    const col = new Float64Array(N);
    for (let x = 0; x < N; x++) {
        for (let y = 0; y < N; y++) col[y] = small[y * N + x];
        dct32(col);
        for (let u = 0; u < 8; u++) top[u][x] = col[u];
    }
    const low: number[] = [];
    for (const row of top) {
        dct32(row);
        for (let w = 0; w < 8; w++) low.push(row[w]);
    }
    // numpy.median of 64 values: the mean of the middle two.
    const sorted = [...low].sort((a, b) => a - b);
    const median = (sorted[31] + sorted[32]) / 2;
    return bitsToHex(low.map((d) => d > median));
}

/** Krawetz's dHash on a 9x8 Lanczos thumbnail, packed as VirusTotal's main_icon_dhash. */
export function dhashHex(img: Gray): string {
    const small = resizeLanczos(img, 9, 8).pixels;
    const bytes = new Uint8Array(8);
    for (let row = 0; row < 8; row++)
        for (let col = 0; col < 8; col++) {
            const i = row * 8 + col;
            if (small[row * 9 + col] > small[row * 9 + col + 1]) bytes[i >> 3] |= 1 << (i & 7);
        }
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
