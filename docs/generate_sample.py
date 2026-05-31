#!/usr/bin/env python3
"""Render a Network Scanner frame to docs/screenshot*.svg using privacy-safe
sample data (RFC 1918 IPs, generic hostnames, fabricated MACs — no real data).

Run from the repo root:  python docs/generate_sample.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import network_scanner as ns  # noqa: E402

CELL_W = 8.4            # px per character at the chosen font size
LINE_H = 19            # px per row
FONT_SIZE = 14
PAD = 16
BG = "#0c0c0c"
DEFAULT_FG = "#d0d0d0"

_SEQ = re.compile(r"\033\[([0-9;]*)m")
_BASE16 = [
    (12, 12, 12), (197, 15, 31), (19, 161, 14), (193, 156, 0),
    (0, 55, 218), (136, 23, 152), (58, 150, 221), (204, 204, 204),
    (118, 118, 118), (231, 72, 86), (22, 198, 12), (249, 241, 165),
    (59, 120, 255), (180, 0, 158), (97, 214, 214), (242, 242, 242),
]


def _xterm256(n):
    if n < 16:
        return _BASE16[n]
    if n < 232:
        n -= 16
        r, g, b = n // 36, (n % 36) // 6, n % 6
        conv = lambda x: 0 if x == 0 else 55 + 40 * x
        return conv(r), conv(g), conv(b)
    v = 8 + (n - 232) * 10
    return v, v, v


def _hex(rgb):
    return "#%02x%02x%02x" % rgb


def _spans(line):
    """Yield (text, color_hex, bold) runs for one ANSI-coded line."""
    fg, bold = DEFAULT_FG, False
    pos = 0
    for m in _SEQ.finditer(line):
        if m.start() > pos:
            yield line[pos:m.start()], fg, bold
        codes = [int(c) for c in m.group(1).split(";") if c != ""] or [0]
        i = 0
        while i < len(codes):
            c = codes[i]
            if c == 0:
                fg, bold = DEFAULT_FG, False
            elif c == 1:
                bold = True
            elif c == 38 and i + 2 < len(codes) and codes[i + 1] == 5:
                fg = _hex(_xterm256(codes[i + 2]))
                i += 2
            elif 30 <= c <= 37:
                fg = _hex(_BASE16[c - 30])
            elif 90 <= c <= 97:
                fg = _hex(_BASE16[c - 90 + 8])
            i += 1
        pos = m.end()
    if pos < len(line):
        yield line[pos:], fg, bold


def _esc(t):
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def to_svg(lines):
    width = int(max((ns.get_visible_len(l) for l in lines), default=80) * CELL_W) + 2 * PAD
    height = len(lines) * LINE_H + 2 * PAD
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}" font-family="Consolas,\'DejaVu Sans Mono\',monospace" '
        f'font-size="{FONT_SIZE}">',
        f'<rect width="{width}" height="{height}" fill="{BG}" rx="8"/>',
    ]
    for row, line in enumerate(lines):
        y = PAD + row * LINE_H + FONT_SIZE
        col = 0
        out.append(f'<text y="{y}" xml:space="preserve">')
        for text, color, bold in _spans(line):
            if text:
                x = PAD + col * CELL_W
                weight = ' font-weight="bold"' if bold else ""
                out.append(f'<tspan x="{x:.1f}" fill="{color}"{weight}>{_esc(text)}</tspan>')
                col += len(text)
        out.append('</text>')
    out.append('</svg>')
    return "\n".join(out)


def build_frame():
    lt = ns.LiveTable()
    frame = {}
    lt._write_frame = lambda output, clear_first=False: frame.update(lines=list(output))
    lt.set_network_info({'ip': '192.168.0.50', 'subnet_mask': '255.255.255.0',
                         'gateway': '192.168.0.1', 'dns_servers': ['192.168.0.1'],
                         'interface': 'Ethernet'})
    lt.scanned_subnets = ['192.168.0.0/24']
    lt.total_count = 254
    lt.local_ip = '192.168.0.50'
    lt.gateway_ip = '192.168.0.1'
    lt.set_phase("Analysis", 100)

    # Privacy-safe sample devices: generic roles, RFC 1918 IPs, fake MACs.
    sample = [
        ('192.168.0.1',   '2C:3A:FD:10:20:30', 'fritz.box',     2.1, 0.9, 6.0),
        ('192.168.0.10',  'B8:27:EB:11:22:33', 'raspberrypi',   1.4, 0.8, 3.2),
        ('192.168.0.20',  'AC:BC:32:44:55:66', 'macbook-air',   3.7, 1.1, 12.4),
        ('192.168.0.23',  'F0:18:98:77:88:99', 'iphone',        8.9, 2.0, 41.0),
        ('192.168.0.31',  'DC:A6:32:AA:BB:CC', 'nas-backup',    0.6, 0.4, 1.9),
        ('192.168.0.42',  '70:5A:0F:DD:EE:01', 'officejet',     5.2, 1.7, 18.0),
        ('192.168.0.50',  '8C:16:45:DE:AD:01', None,            0.3, 0.2, 0.8),
        ('192.168.0.88',  '54:60:09:12:34:56', 'living-room-tv', 14.0, 3.0, 60.0),
    ]
    for ip, mac, host, avg, mn, mx in sample:
        lt.devices[ip] = ns.Device(
            ip=ip, mac_address=mac, hostname=host, ping_status=True,
            current_pings=100, target_pings=100, last_ping=avg,
            ping_stats={'min': mn, 'max': mx, 'avg': avg, 'count': 100})
    # An offline device remembered from the database.
    lt.devices['192.168.0.30'] = ns.Device(
        ip='192.168.0.30', mac_address='28:6C:07:0A:0B:0C', hostname='work-laptop',
        ping_status=False, is_offline=True, from_db=True)

    lt.set_total_pings(25400)
    lt.ping_success = 15240
    lt.completed_count = 180
    lt.active_threads = 96
    lt.set_public_latency('8.8.8.8', {'min': 7.0, 'max': 22.0, 'avg': 11.5, 'count': 100})
    lt.set_public_latency('1.1.1.1', {'min': 6.2, 'max': 19.0, 'avg': 9.8, 'count': 100})
    lt.calculate_groups()
    lt._render_internal_locked()
    return frame['lines']


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    lines = build_frame()
    with open(os.path.join(here, "screenshot.svg"), "w", encoding="utf-8") as f:
        f.write(to_svg(lines))
    print("wrote docs/screenshot.svg")


if __name__ == "__main__":
    main()
