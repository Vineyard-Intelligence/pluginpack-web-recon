"""Reference favicons for test-plugin.mjs, and what Pillow and ImageHash make of them.

The perceptual hashes in perceptual-hash.ts must equal what the Python ImageHash library computes on
Pillow (phash), and Krawetz's dHash in the bit order of VirusTotal's main_icon_dhash (dhash). This writes a
small set of icons that between them take every path the decoder and the resize have: PNG colour
types, bit depths, a short palette and Adam7; ICO with PNG frames and with 1-, 8- and 32-bit BMP
frames, including two frames of one size (Pillow takes the lower colour depth); a BMP file; a tall
icon (Pillow resizes vertically first); a flat and a mirrored icon (DCT coefficients that cancel); and
a GIF, which gets no perceptual hash. expected.json holds Pillow's answers. None of the icons has a pHash
bit that SciPy's rounding noise decides, so their values do not depend on the SciPy version or build.

Run:  python3 -m venv .venv && .venv/bin/pip install pillow imagehash
      .venv/bin/python test-fixtures/make-favicons.py
Checked with Pillow 13.0.0 and ImageHash 4.3.2.
"""
import io, json, os, random, struct, zlib

import imagehash
from PIL import Image

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'favicons')
rng = random.Random(20261019)


def content(w, h, channels):
    """Structured pixels: gradients, a few shapes and noise, so hashes have something to measure."""
    cx, cy, r = rng.random() * w, rng.random() * h, (0.2 + rng.random() * 0.5) * max(w, h)
    base = [rng.randrange(256) for _ in range(channels)]
    rows = []
    for y in range(h):
        row = []
        for x in range(w):
            inside = (x - cx) ** 2 + (y - cy) ** 2 < r * r
            px = []
            for c in range(channels):
                v = (base[c] + (x * 255 // max(1, w - 1)) * (c % 2) + (y * 255 // max(1, h - 1)) * ((c + 1) % 2)) % 256
                if inside:
                    v = 255 - v
                v = max(0, min(255, v + rng.randint(-20, 20)))
                px.append(v)
            row.append(px)
        rows.append(row)
    return rows


def chunk(name, data):
    return struct.pack('>I', len(data)) + name + data + struct.pack('>I', zlib.crc32(name + data) & 0xFFFFFFFF)


def png(w, h, ctype, depth, interlace=False, palette=None, samples=None):
    """A hand-written PNG: any colour type and depth, random filters, optional Adam7."""
    ch = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[ctype]
    maxv = (1 << depth) - 1
    if samples is None:
        samples = [[[rng.randint(0, maxv) for _ in range(ch)] for _ in range(w)] for _ in range(h)]
    bpp = max(1, ch * depth // 8)

    def scan(px_rows, pw):
        out = bytearray()
        prev = bytearray((pw * ch * depth + 7) // 8)
        for row in px_rows:
            bits = []
            raw = bytearray()
            if depth < 8:
                acc, n = 0, 0
                for p in row:
                    acc = (acc << depth) | p[0]
                    n += depth
                    if n == 8:
                        raw.append(acc); acc, n = 0, 0
                if n:
                    raw.append(acc << (8 - n))
            else:
                for p in row:
                    for v in p:
                        raw += v.to_bytes(depth // 8, 'big')
            f = rng.randrange(5)
            line = bytearray(len(raw))
            for i in range(len(raw)):
                a = raw[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                if f == 0: pred = 0
                elif f == 1: pred = a
                elif f == 2: pred = b
                elif f == 3: pred = (a + b) // 2
                else:
                    p_ = a + b - c
                    pa, pb, pc = abs(p_ - a), abs(p_ - b), abs(p_ - c)
                    pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                line[i] = (raw[i] - pred) & 0xFF
            out.append(f)
            out += line
            prev = raw
        return out

    data = bytearray()
    if interlace:
        for x0, y0, dx, dy in [(0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4), (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2)]:
            rows = [[samples[y][x] for x in range(x0, w, dx)] for y in range(y0, h, dy)]
            if rows and rows[0]:
                data += scan(rows, len(rows[0]))
    else:
        data = scan(samples, w)
    ihdr = struct.pack('>IIBBBBB', w, h, depth, ctype, 0, 0, 1 if interlace else 0)
    body = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', ihdr)
    if ctype == 3:
        body += chunk(b'PLTE', bytes(v for c in palette for v in c))
    body += chunk(b'IDAT', zlib.compress(bytes(data), 9)) + chunk(b'IEND', b'')
    return body


def dib(w, h, bpp, palette=None, rows=None, top_down=False):
    """A DIB (BITMAPINFOHEADER) for an ICO frame: colour rows plus an AND mask, height doubled."""
    stride = ((w * bpp + 31) >> 3) & ~3
    data = bytearray()
    order = range(h) if top_down else range(h - 1, -1, -1)
    for y in order:
        line = bytearray(stride)
        for x in range(w):
            px = rows[y][x]
            if bpp == 32:
                line[x * 4:x * 4 + 4] = bytes([px[2], px[1], px[0], px[3]])
            elif bpp == 24:
                line[x * 3:x * 3 + 3] = bytes([px[2], px[1], px[0]])
            elif bpp == 8:
                line[x] = px
            elif bpp == 4:
                line[x >> 1] |= px << (0 if x & 1 else 4)
            else:
                line[x >> 3] |= px << (7 - (x & 7))
        data += line
    mstride = ((w + 31) >> 5) << 2
    mask = bytes(rng.randrange(256) for _ in range(mstride * h))
    height = h * 2
    if top_down:
        height = (2 ** 32 - height) & 0xFFFFFFFF
    header = struct.pack('<IiIHHIIiiII', 40, w, 0, 1, bpp, 0, len(data), 0, 0, len(palette) if palette else 0, 0)
    header = header[:8] + struct.pack('<I', height) + header[12:]
    pal = b''.join(bytes([c[2], c[1], c[0], 0]) for c in palette) if palette else b''
    return header + pal + bytes(data) + mask


def ico(frames):
    """frames: list of (w, h, bpp_field, nb_color, payload)."""
    out = struct.pack('<HHH', 0, 1, len(frames))
    offset = 6 + 16 * len(frames)
    dirs, blobs = b'', b''
    for w, h, bppf, nbc, payload in frames:
        dirs += struct.pack('<BBBBHHII', w % 256, h % 256, nbc, 0, 1, bppf, len(payload), offset + len(blobs))
        blobs += payload
    return out + dirs + blobs



def save_pil(im, fmt, **kw):
    b = io.BytesIO()
    im.save(b, fmt, **kw)
    return b.getvalue()


def rgba(w, h):
    im = Image.new('RGBA', (w, h))
    im.putdata([tuple(p) for row in content(w, h, 4) for p in row])
    return im


fixtures = {}
fixtures['png-rgba-48.png'] = save_pil(rgba(48, 48), 'PNG')
short = [[rng.randrange(256) for _ in range(3)] for _ in range(5)]  # indices up to 15 read past it
fixtures['png-palette-short-31x17.png'] = png(31, 17, 3, 4, False, short)
fixtures['png-gray2-interlaced-16.png'] = png(16, 16, 0, 2, True)
fixtures['png-rgb16-interlaced-100x37.png'] = png(100, 37, 2, 16, True)
fixtures['png-tall-13x200.png'] = save_pil(rgba(13, 200).convert('1'), 'PNG')  # dithered: pass order shows
fixtures['png-flat-1x1.png'] = save_pil(Image.new('RGB', (1, 1), (200, 30, 90)), 'PNG')
mirror = rgba(16, 32)
whole = Image.new('RGBA', (32, 32))
whole.paste(mirror, (0, 0))
whole.paste(mirror.transpose(Image.Transpose.FLIP_LEFT_RIGHT), (16, 0))
fixtures['png-mirror-32.png'] = save_pil(whole, 'PNG')
fixtures['ico-png-frames.ico'] = save_pil(rgba(64, 64), 'ICO', sizes=[(16, 16), (32, 32), (48, 48), (64, 64)])
fixtures['ico-bmp32.ico'] = ico([(s, s, 32, 0, dib(s, s, 32, None, content(s, s, 4))) for s in (16, 32, 48)])
pal8 = [[rng.randrange(256) for _ in range(3)] for _ in range(256)]
fixtures['ico-bmp-tie.ico'] = ico([
    (32, 32, 32, 0, dib(32, 32, 32, None, content(32, 32, 4))),
    (32, 32, 8, 0, dib(32, 32, 8, pal8, [[rng.randrange(256) for _ in range(32)] for _ in range(32)])),
])
fixtures['ico-bmp1-bw.ico'] = ico([(32, 32, 1, 2, dib(32, 32, 1, [[0, 0, 0], [255, 255, 255]], [[rng.randrange(2) for _ in range(32)] for _ in range(32)]))])
fixtures['bmp-rgb-40x24.bmp'] = save_pil(rgba(40, 24).convert('RGB'), 'BMP')
fixtures['gif-16.gif'] = save_pil(rgba(16, 16).convert('RGB'), 'GIF')


def vt_dhash(img):
    g = img.convert('L').resize((9, 8), Image.Resampling.LANCZOS)
    out, v = [], 0
    for i in range(64):
        row, col = divmod(i, 8)
        if g.getpixel((col, row)) > g.getpixel((col + 1, row)):
            v += 2 ** (i % 8)
        if i % 8 == 7:
            out.append('%02x' % v); v = 0
    return ''.join(out)



os.makedirs(HERE, exist_ok=True)
expected = {}
for name, data in sorted(fixtures.items()):
    with open(os.path.join(HERE, name), 'wb') as f:
        f.write(data)
    im = Image.open(io.BytesIO(data))
    im.load()
    perceptual = im.format in ('PNG', 'ICO', 'BMP')
    expected[name] = {'phash': str(imagehash.phash(im)), 'dhash': vt_dhash(im)} if perceptual else {}
with open(os.path.join(HERE, 'expected.json'), 'w') as f:
    json.dump(expected, f, indent=2)
    f.write('\n')
print(f'{len(expected)} fixtures written to {HERE}')
