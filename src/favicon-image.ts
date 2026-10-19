// The favicon's pixels in grayscale, exactly as Pillow gives them for Image.open(f).convert('L') —
// the first step of every perceptual hash (perceptual-hash.ts), and the reason this decodes by hand.
//
// The browser's decoders (createImageBitmap, a canvas) are close but not equal: they premultiply
// alpha, so a transparent pixel comes back black and a half-transparent one with rounded colour,
// while Pillow keeps the stored colour and convert('L') ignores alpha altogether. A favicon is mostly
// transparent edge, so that difference moves hash bits. The services that index these hashes are
// Python shops, and ImageHash (what OkCupid evaluated) runs on Pillow, so Pillow's reading is the one
// to reproduce: ICO (PNG or BMP frames), PNG and BMP. GIF, JPEG, SVG and WebP favicons get no
// perceptual hash rather than an approximate one.
//
// Rules taken from Pillow 13 (IcoImagePlugin, BmpImagePlugin, PngImagePlugin, Convert.c) and checked
// pixel for pixel against it.

export interface Gray {
    width: number;
    height: number;
    /** Row-major, one byte per pixel. */
    pixels: Uint8Array;
}

/** Pillow's RGB to L: ITU-R 601-2 luma in 16-bit fixed point, rounded (Convert.c L24). */
const luma = (r: number, g: number, b: number): number => (r * 19595 + g * 38470 + b * 7471 + 0x8000) >> 16;

/** A palette's entries in gray; an index past the file's palette reads as black, as in Pillow. */
function paletteLuma(rgb: number[][]): Uint8Array {
    const out = new Uint8Array(256);
    for (let i = 0; i < rgb.length && i < 256; i++) out[i] = luma(rgb[i][0], rgb[i][1], rgb[i][2]);
    return out;
}

/**
 * The longest side decoded, in pixels. A favicon is a few hundred pixels a side at most; the file can
 * claim any size, a few kilobytes of compressed data can inflate to gigabytes, and the resize's weights
 * grow with the side, while this runs on whatever a site under investigation chooses to serve. Pillow's
 * own limit is far higher; an icon past this one simply gets no perceptual hash.
 */
const MAX_SIDE = 2048;

const startsWith = (b: Uint8Array, at: number, sig: number[]): boolean =>
    b.length >= at + sig.length && sig.every((v, i) => b[at + i] === v);
const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];

/**
 * Grayscale pixels of an ICO, PNG or BMP favicon. Null for any other format, for a file Pillow refuses
 * (the checks it makes on structure, chunk CRCs and sizes are repeated here, though not every malformed
 * ancillary chunk it would reject), and for what is not reproduced: 16-bit grayscale PNG, 16-bit and
 * RLE BMP, and an image over MAX_SIDE.
 */
export async function decodeFavicon(bytes: Uint8Array): Promise<Gray | null> {
    try {
        if (startsWith(bytes, 0, PNG_MAGIC)) return await decodePng(bytes, 0);
        if (startsWith(bytes, 0, [0, 0, 1, 0])) return await decodeIco(bytes);
        if (startsWith(bytes, 0, [0x42, 0x4d])) return decodeBmpFile(bytes);
    } catch {
        // A truncated or malformed file: Pillow raises too.
    }
    return null;
}

// ---- ICO ----

/**
 * The frame Pillow loads: entries sorted by colour depth ascending, then (stable) by area descending,
 * and the first one taken — the largest frame, and among equal sizes the LOWEST colour depth.
 */
async function decodeIco(b: Uint8Array): Promise<Gray | null> {
    const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const count = v.getUint16(4, true);
    if (!count) return null;
    const entries = Array.from({ length: count }, (_, i) => {
        const at = 6 + 16 * i;
        const width = b[at] || 256;
        const height = b[at + 1] || 256;
        const nbColor = b[at + 2];
        const bpp = v.getUint16(at + 6, true);
        return {
            square: width * height,
            // Python: bpp or (nb_color != 0 and ceil(log(nb_color, 2))) or 256
            colorDepth: bpp || (nbColor !== 0 && Math.ceil(Math.log(nbColor) / Math.log(2))) || 256,
            bpp,
            size: v.getUint32(at + 8, true),
            offset: v.getUint32(at + 12, true),
        };
    });
    entries.sort((x, y) => x.colorDepth - y.colorDepth);
    entries.sort((x, y) => y.square - x.square);
    const { offset, size, bpp } = entries[0];
    if (startsWith(b, offset, PNG_MAGIC)) return decodePng(b, offset);
    // A BMP frame: a DIB whose height counts the colour rows and the AND mask together.
    const frame = decodeDib(b, offset, 0, true);
    if (!frame) return null;
    // The mask only sets alpha, which convert('L') drops, but Pillow reads it and refuses the icon when
    // it cannot: for a 32-bit entry the alpha bytes of the pixel data, otherwise a 1-bit mask that ends
    // where the directory says the frame ends.
    const { width: w, height: h } = frame;
    if (bpp === 32) {
        if (frame.dataAt + 4 * w * h > b.length) return null;
    } else {
        const maskStride = Math.ceil(w / 32) * 4;
        const maskAt = offset + size - maskStride * h;
        if (maskAt < 0 || maskAt + maskStride * (h - 1) + Math.ceil(w / 8) > b.length) return null;
    }
    return frame;
}

// ---- BMP / DIB ----

function decodeBmpFile(b: Uint8Array): Gray | null {
    const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
    return decodeDib(b, 14, v.getUint32(10, true), false);
}

/**
 * A DIB starting at `at`. `pixelOffset` is a BMP file's bfOffBits (Pillow skips the palette from
 * there only when it equals the end of the header); 0 means the pixels follow the header, the masks
 * and the palette, as in an ICO frame.
 */
function decodeDib(
    b: Uint8Array,
    at: number,
    pixelOffset: number,
    icoFrame: boolean,
): (Gray & { dataAt: number }) | null {
    const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
    const headerSize = v.getUint32(at, true);
    let width: number;
    let height: number;
    let bits: number;
    let compression = 0;
    let colors = 0;
    let topDown = false;
    let paletteSize: number;
    let p = at + headerSize;
    let rgbaMask: number[] | null = null;
    if (headerSize === 12) {
        width = v.getUint16(at + 4, true);
        height = v.getUint16(at + 6, true);
        bits = v.getUint16(at + 10, true);
        paletteSize = 3;
    } else if ([40, 52, 56, 64, 108, 124].includes(headerSize)) {
        topDown = b[at + 11] === 0xff;
        width = v.getInt32(at + 4, true);
        height = topDown ? 2 ** 32 - v.getUint32(at + 8, true) : v.getInt32(at + 8, true);
        bits = v.getUint16(at + 14, true);
        compression = v.getUint32(at + 16, true);
        colors = v.getUint32(at + 32, true);
        paletteSize = 4;
        if (compression === 3) {
            // BI_BITFIELDS: masks in the header when it has room (52+ bytes), else right after it.
            if (headerSize >= 52) {
                rgbaMask = [0, 1, 2].map((i) => v.getUint32(at + 40 + i * 4, true));
                rgbaMask.push(headerSize >= 56 ? v.getUint32(at + 52, true) : 0);
            } else {
                rgbaMask = [0, 1, 2].map((i) => v.getUint32(p + i * 4, true));
                rgbaMask.push(0);
                p += 12;
            }
        }
    } else {
        return null;
    }
    if (!colors) colors = 1 << bits;
    if (icoFrame) height = Math.trunc(height / 2);
    if (width <= 0 || height <= 0 || width > MAX_SIDE || height > MAX_SIDE) return null;
    if (compression !== 0 && compression !== 3) return null; // RLE: rare in favicons, not reproduced

    // Channel order of each supported layout, as byte offsets of R, G, B within the pixel.
    let rgbAt: [number, number, number] | null = null;
    let lut: Uint8Array | null = null;
    if (bits <= 8) {
        // Pillow takes bitfields only for 16, 24 and 32 bits.
        if (compression === 3 || ![1, 4, 8].includes(bits) || colors <= 0 || colors > 65536) return null;
        const pal = Array.from({ length: Math.min(colors, 256) }, (_, i) => {
            const e = p + i * paletteSize;
            return [b[e + 2], b[e + 1], b[e]];
        });
        // Pillow drops a palette that is exactly the identity ramp (black and white for two colours) and
        // reads the data as mode L, or "1" for two colours or fewer: the stored values themselves, with a
        // set bit as 255 in mode "1". That holds when the bit depth matches the mode (8 for L, 1 for "1");
        // any other depth it misreads, which is not reproduced.
        const indices = colors === 2 ? [0, 255] : Array.from({ length: colors }, (_, i) => i);
        const ramp = indices.every((val, i) => {
            const e = p + i * paletteSize;
            return b[e] === (val & 0xff) && b[e + 1] === (val & 0xff) && b[e + 2] === (val & 0xff);
        });
        if (ramp) {
            if (bits !== (colors <= 2 ? 1 : 8)) return null;
            lut =
                colors <= 2
                    ? Uint8Array.from({ length: 256 }, (_, i) => (i ? 255 : 0))
                    : Uint8Array.from({ length: 256 }, (_, i) => i);
        } else {
            // A palette image keeps at most 256 colours; Pillow refuses a longer one.
            if (colors > 256) return null;
            lut = paletteLuma(pal);
        }
        p += paletteSize * colors;
    } else if (bits === 24) {
        if (compression === 3 && JSON.stringify(rgbaMask!.slice(0, 3)) !== JSON.stringify([0xff0000, 0xff00, 0xff]))
            return null;
        rgbAt = [2, 1, 0];
    } else if (bits === 32) {
        if (compression === 0) rgbAt = [2, 1, 0];
        else {
            const m = JSON.stringify(rgbaMask);
            const layouts: Record<string, [number, number, number]> = {
                [JSON.stringify([0xff0000, 0xff00, 0xff, 0])]: [2, 1, 0], // BGRX
                [JSON.stringify([0xff000000, 0xff0000, 0xff00, 0])]: [3, 2, 1], // XBGR
                [JSON.stringify([0xff000000, 0xff00, 0xff, 0])]: [3, 1, 0], // BGXR
                [JSON.stringify([0xff000000, 0xff0000, 0xff00, 0xff])]: [3, 2, 1], // ABGR
                [JSON.stringify([0xff, 0xff00, 0xff0000, 0xff000000])]: [0, 1, 2], // RGBA
                [JSON.stringify([0xff0000, 0xff00, 0xff, 0xff000000])]: [2, 1, 0], // BGRA
                [JSON.stringify([0xff000000, 0xff00, 0xff, 0xff0000])]: [3, 1, 0], // BGAR
                [JSON.stringify([0, 0, 0, 0])]: [2, 1, 0], // BGRA
            };
            rgbAt = layouts[m] ?? null;
            if (!rgbAt) return null;
        }
    } else {
        return null; // 16-bit: rare in favicons, not reproduced
    }
    // A BMP file names where its pixels start; Pillow adds the palette to that only when the offset
    // stops at the end of the header.
    if (pixelOffset)
        p = pixelOffset === 14 + headerSize && bits <= 8 ? pixelOffset + paletteSize * colors : pixelOffset;

    // Rows are padded to 4 bytes, but Pillow does not need the last row's padding to be there.
    const stride = ((width * bits + 31) >> 3) & ~3;
    if (p + stride * (height - 1) + Math.ceil((width * bits) / 8) > b.length) return null;
    const out = new Uint8Array(width * height);
    for (let y = 0; y < height; y++) {
        const row = p + stride * (topDown ? y : height - 1 - y);
        for (let x = 0; x < width; x++) {
            let g: number;
            if (lut) {
                let idx: number;
                if (bits === 8) idx = b[row + x];
                else if (bits === 4) idx = (b[row + (x >> 1)] >> (x & 1 ? 0 : 4)) & 0xf;
                else idx = (b[row + (x >> 3)] >> (7 - (x & 7))) & 1;
                g = lut[idx];
            } else {
                const px = row + x * (bits >> 3);
                g = luma(b[px + rgbAt![0]], b[px + rgbAt![1]], b[px + rgbAt![2]]);
            }
            out[y * width + x] = g;
        }
    }
    return { width, height, pixels: out, dataAt: p };
}

// ---- PNG ----

/**
 * zlib-inflate `data` up to `limit` bytes, the size of the image's scanlines. Pillow stops reading once
 * the image is full, so whatever follows (more data, a missing checksum) is not read here either, and a
 * stream built to inflate to gigabytes is never held.
 */
async function inflate(data: Uint8Array<ArrayBuffer>, limit: number): Promise<Uint8Array> {
    const reader = new Blob([data]).stream().pipeThrough(new DecompressionStream('deflate')).getReader();
    const out = new Uint8Array(limit);
    let total = 0;
    while (total < limit) {
        const { done, value } = await reader.read();
        if (done) break;
        const take = Math.min(value.length, limit - total);
        out.set(value.subarray(0, take), total);
        total += take;
    }
    await reader.cancel().catch(() => {});
    return out.subarray(0, total);
}

/** Channels per pixel by PNG colour type. */
const CHANNELS: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

/** The bit depths each colour type allows; Pillow refuses any other pair. */
const DEPTHS: Record<number, number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };

const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, n) => {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    return c >>> 0;
});

/** The CRC-32 a PNG chunk carries, over its type and data. */
function crc32(data: Uint8Array): number {
    let c = 0xffffffff;
    for (const byte of data) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}

/** Adam7: x start, y start, x step, y step for each pass. */
const ADAM7 = [
    [0, 0, 8, 8],
    [4, 0, 8, 8],
    [0, 4, 4, 8],
    [2, 0, 4, 4],
    [0, 2, 2, 4],
    [1, 0, 2, 2],
    [0, 1, 1, 2],
];

async function decodePng(b: Uint8Array, at: number): Promise<Gray | null> {
    const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
    let p = at + 8;
    let width = 0;
    let height = 0;
    let depth = 0;
    let type = -1;
    let interlace = 0;
    let palette: number[][] = [];
    const idat: Uint8Array[] = [];
    // Pillow reads chunk by chunk up to the image data, refusing a chunk whose name is not four word
    // characters or whose CRC is wrong. The image data is the run of IDAT chunks from there; their CRCs
    // are not checked, and the first other chunk ends it.
    while (p + 8 <= b.length) {
        const len = v.getUint32(p);
        const name = String.fromCharCode(b[p + 4], b[p + 5], b[p + 6], b[p + 7]);
        if (idat.length && name !== 'IDAT') break;
        if (!/^\w{4}$/.test(name)) return null;
        const data = b.subarray(p + 8, p + 8 + len);
        p += 12 + len;
        if (name === 'IDAT') {
            idat.push(data);
            continue;
        }
        if (p > b.length || crc32(b.subarray(p - 8 - len, p - 4)) !== v.getUint32(p - 4)) return null;
        if (name === 'IHDR') {
            if (len < 13 || data[11] !== 0) return null;
            width = v.getUint32(p - 4 - len);
            height = v.getUint32(p - len);
            depth = data[8];
            type = data[9];
            interlace = data[12];
        } else if (name === 'PLTE' && type === 3 && DEPTHS[3].includes(depth)) {
            // Kept only once the header says the image is paletted; a palette over 256 colours is refused.
            if (len > 256 * 3) return null;
            palette = Array.from({ length: Math.floor(len / 3) }, (_, i) => [
                data[i * 3],
                data[i * 3 + 1],
                data[i * 3 + 2],
            ]);
        } else if (name === 'IEND') {
            break;
        }
    }
    const channels = CHANNELS[type];
    if (!channels || !DEPTHS[type].includes(depth) || !width || !height || !idat.length) return null;
    // 16-bit grayscale opens as mode I;16, whose conversion to L is not reproduced.
    if (type === 0 && depth === 16) return null;
    if (width > MAX_SIDE || height > MAX_SIDE) return null;
    // A paletted image without a palette (or with it after the image data) reads as black, as an index
    // past the end of a palette does.

    const joined = new Uint8Array(idat.reduce((n, c) => n + c.length, 0));
    let o = 0;
    for (const c of idat) {
        joined.set(c, o);
        o += c.length;
    }
    const bitsPerPixel = channels * depth;
    // Exactly what the scanlines take: a filter byte and the packed samples per line, per Adam7 pass.
    const passList = interlace ? ADAM7 : [[0, 0, 1, 1]];
    const expected = passList.reduce((n, [x0, y0, dx, dy]) => {
        const pw = Math.ceil((width - x0) / dx);
        const ph = Math.ceil((height - y0) / dy);
        return pw > 0 && ph > 0 ? n + ph * (1 + Math.ceil((pw * bitsPerPixel) / 8)) : n;
    }, 0);
    const raw = await inflate(joined, expected);

    const filterBpp = Math.max(1, bitsPerPixel >> 3);
    const lut = type === 3 ? paletteLuma(palette) : null;
    const out = new Uint8Array(width * height);

    /** Gray value of pixel x in an unfiltered scanline, as Pillow's mode and convert('L') give it. */
    const sample = (line: Uint8Array, x: number): number => {
        if (depth < 8) {
            const per = 8 / depth;
            const shift = 8 - depth * ((x % per) + 1);
            const val = (line[Math.floor(x / per)] >> shift) & ((1 << depth) - 1);
            if (type === 3) return lut![val];
            // Gray 1-bit is mode "1" (0 or 255); 2- and 4-bit scale up (L;2 x0x55, L;4 x0x11).
            return depth === 1 ? val * 255 : depth === 2 ? val * 0x55 : val * 0x11;
        }
        // 16-bit samples keep their high byte (Pillow's ;16B rawmodes).
        const step = depth >> 3;
        const px = x * channels * step;
        if (type === 0 || type === 4) return line[px];
        if (type === 3) return lut![line[px]];
        return luma(line[px], line[px + step], line[px + 2 * step]);
    };

    let q = 0;
    for (const [x0, y0, dx, dy] of passList) {
        const pw = Math.ceil((width - x0) / dx);
        const ph = Math.ceil((height - y0) / dy);
        if (pw <= 0 || ph <= 0) continue;
        const lineLen = Math.ceil((pw * bitsPerPixel) / 8);
        let prev = new Uint8Array(lineLen);
        for (let y = 0; y < ph; y++) {
            if (q + 1 + lineLen > raw.length) return null;
            const filter = raw[q];
            const line = raw.slice(q + 1, q + 1 + lineLen);
            q += 1 + lineLen;
            for (let i = 0; i < lineLen; i++) {
                const left = i >= filterBpp ? line[i - filterBpp] : 0;
                const up = prev[i];
                const ul = i >= filterBpp ? prev[i - filterBpp] : 0;
                let add = 0;
                if (filter === 1) add = left;
                else if (filter === 2) add = up;
                else if (filter === 3) add = (left + up) >> 1;
                else if (filter === 4) {
                    const pa = Math.abs(up - ul);
                    const pb = Math.abs(left - ul);
                    const pc = Math.abs(left + up - 2 * ul);
                    add = pa <= pb && pa <= pc ? left : pb <= pc ? up : ul;
                } else if (filter !== 0) return null;
                line[i] = (line[i] + add) & 0xff;
            }
            for (let x = 0; x < pw; x++) out[(y0 + y * dy) * width + x0 + x * dx] = sample(line, x);
            prev = line;
        }
    }
    return { width, height, pixels: out };
}
