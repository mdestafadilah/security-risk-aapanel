#!/usr/bin/env python
# coding: utf-8
"""Draw the plugin icon (128x128 PNG, transparent) without any dependency.

    python tools/make_icon.py
"""

import io
import os
import math
import zlib
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(os.path.dirname(HERE), 'securityrisk', 'icon.png')

SIZE = 128
SS = 4  # supersampling factor


def quad(p0, p1, p2, steps=24):
    pts = []
    for i in range(steps + 1):
        t = i / float(steps)
        x = (1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0]
        y = (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1]
        pts.append((x, y))
    return pts


def shield_polygon():
    pts = [(0.18, 0.07), (0.82, 0.07)]
    pts += quad((0.82, 0.07), (0.905, 0.07), (0.905, 0.155))
    pts += [(0.905, 0.46)]
    pts += quad((0.905, 0.46), (0.905, 0.75), (0.5, 0.945))
    pts += quad((0.5, 0.945), (0.095, 0.75), (0.095, 0.46))
    pts += [(0.095, 0.155)]
    pts += quad((0.095, 0.155), (0.095, 0.07), (0.18, 0.07))
    return pts


def inside_polygon(x, y, poly):
    inside = False
    n = len(poly)
    j = n - 1
    for i in range(n):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if ((yi > y) != (yj > y)) and \
           (x < (xj - xi) * (y - yi) / (yj - yi + 1e-12) + xi):
            inside = not inside
        j = i
    return inside


def dist_to_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = ((px - ax) * dx + (py - ay) * dy) / float(dx * dx + dy * dy)
    t = max(0.0, min(1.0, t))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


CHECK = [(0.365, 0.500), (0.468, 0.600), (0.645, 0.400)]
STROKE = 0.060


def sample(u, v):
    """Return (r,g,b,a) for a unit-square point."""
    poly = shield_polygon()
    if not inside_polygon(u, v, poly):
        return (0, 0, 0, 0)
    d = min(dist_to_segment(u, v, CHECK[i][0], CHECK[i][1], CHECK[i + 1][0], CHECK[i + 1][1])
            for i in range(len(CHECK) - 1))
    if d <= STROKE:
        return (255, 255, 255, 255)
    # vertical gradient, light green at the top
    t = min(1.0, max(0.0, (v - 0.05) / 0.9))
    r = int(0x35 + (0x16 - 0x35) * t)
    g = int(0xc7 + (0x8c - 0xc7) * t)
    b = int(0x5a + (0x2f - 0x5a) * t)
    return (r, g, b, 255)


def render():
    rows = []
    for y in range(SIZE):
        row = bytearray()
        for x in range(SIZE):
            acc = [0, 0, 0, 0]
            for sy in range(SS):
                for sx in range(SS):
                    u = (x + (sx + 0.5) / SS) / SIZE
                    v = (y + (sy + 0.5) / SS) / SIZE
                    r, g, b, a = sample(u, v)
                    acc[0] += r * a
                    acc[1] += g * a
                    acc[2] += b * a
                    acc[3] += a
            n = SS * SS
            a = acc[3] / n
            if a <= 0:
                row += bytes((0, 0, 0, 0))
            else:
                row += bytes((int(acc[0] / acc[3]), int(acc[1] / acc[3]),
                              int(acc[2] / acc[3]), int(a)))
        rows.append(row)
    return rows


def write_png(path, rows):
    w = len(rows[0]) // 4
    h = len(rows)
    raw = b''.join(b'\x00' + bytes(r) for r in rows)

    def chunk(tag, data):
        return (struct.pack('>I', len(data)) + tag + data +
                struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff))

    png = (b'\x89PNG\r\n\x1a\n' +
           chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 6, 0, 0, 0)) +
           chunk(b'IDAT', zlib.compress(raw, 9)) +
           chunk(b'IEND', b''))
    with io.open(path, 'wb') as f:
        f.write(png)


if __name__ == '__main__':
    write_png(OUT, render())
    print('wrote %s' % OUT)
