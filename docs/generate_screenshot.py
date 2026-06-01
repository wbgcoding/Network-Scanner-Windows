#!/usr/bin/env python3
"""
Generate docs/screenshot.svg by running the real LiveTable renderer with
sample data. No actual network scanning — all IPs/MACs/hostnames are fake.
"""
import sys, os, re, random
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# ── Patch terminal side-effects before import ─────────────────────────────────
import network_scanner as ns

ns._resize_terminal          = lambda *a, **kw: (0, 0)
ns._resize_terminal_windows  = lambda *a, **kw: (0, 0)
ns._center_console_window    = lambda: None
ns._enable_windows_ansi      = lambda: None
ns._maximize_console         = lambda *a, **kw: None

random.seed(12)   # stable spinner and title colour

# ── ANSI colour helpers ───────────────────────────────────────────────────────
_BASIC = {
    30:'#0c0c0c', 31:'#c50f1f', 32:'#13a10e', 33:'#c19c00',
    34:'#0037da', 35:'#881798', 36:'#3a96dd', 37:'#cccccc',
    90:'#767676', 91:'#e74856', 92:'#16c60c', 93:'#f9f1a5',
    94:'#3b78ff', 95:'#b4009e', 96:'#61d6d6', 97:'#f2f2f2',
}

def _256(n):
    if n < 16:
        return _BASIC.get(n + (90 if n >= 8 else 30), '#808080')
    if n < 232:
        n -= 16
        b = n % 6; n //= 6; g = n % 6; r = n // 6
        v = lambda x: 0 if x == 0 else 55 + x * 40
        return f'#{v(r):02x}{v(g):02x}{v(b):02x}'
    val = 8 + (n - 232) * 10
    return f'#{val:02x}{val:02x}{val:02x}'

def _dim(h):
    r, g, b = int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)
    return f'#{r//2:02x}{g//2:02x}{b//2:02x}'

# ── ANSI line parser ──────────────────────────────────────────────────────────
# Matches any escape sequence: captures params + terminator letter
_ALL_ESC = re.compile(r'\033\[([0-9;]*)([a-zA-Z])')

def _apply_sgr(codes_str, st):
    codes = [int(x) for x in codes_str.split(';') if x] if codes_str else [0]
    i = 0
    while i < len(codes):
        c = codes[i]
        if   c == 0:  st['fg'] = '#c8c8c8'; st['bold'] = False; st['dim'] = False
        elif c == 1:  st['bold'] = True
        elif c == 2:  st['dim']  = True
        elif c == 22: st['bold'] = False; st['dim'] = False
        elif c in _BASIC: st['fg'] = _BASIC[c]; st['dim'] = False
        elif c == 38 and i + 2 < len(codes) and codes[i+1] == 5:
            st['fg'] = _256(codes[i + 2]); st['dim'] = False; i += 2
        elif c == 39: st['fg'] = '#c8c8c8'
        i += 1

def parse_line(raw):
    """Return list of (text, hex_color, bold) for one ANSI-encoded line.
    Adjacent segments with identical color+bold are merged so runs of block
    characters become a single tspan (prevents inter-character gaps in SVG)."""
    st = {'fg': '#c8c8c8', 'bold': False, 'dim': False}
    result, pos = [], 0
    for m in _ALL_ESC.finditer(raw):
        txt = raw[pos:m.start()]
        if txt:
            c = _dim(st['fg']) if st['dim'] else st['fg']
            result.append((txt, c, st['bold']))
        if m.group(2) == 'm':
            _apply_sgr(m.group(1), st)
        pos = m.end()
    tail = raw[pos:]
    if tail:
        c = _dim(st['fg']) if st['dim'] else st['fg']
        result.append((tail, c, st['bold']))
    # Merge consecutive segments with same color and bold
    merged = []
    for txt, col, bold in result:
        if merged and merged[-1][1] == col and merged[-1][2] == bold:
            merged[-1] = (merged[-1][0] + txt, col, bold)
        else:
            merged.append((txt, col, bold))
    return merged

# ── Sample data ───────────────────────────────────────────────────────────────
SAMPLE_NET = {
    'ip':          '192.168.1.100',
    'subnet_mask': '255.255.255.0',
    'gateway':     '192.168.1.1',
    'dns_servers': ['192.168.1.1', '8.8.8.8'],
    'mac':         'C4:A3:66:E1:2F:08',
}

#            ip               hostname         mac                avg   mn    mx   last  done tot gid  off
SAMPLE_LAN = [
    ('192.168.1.1',  'router.local',  '12:34:56:78:90:01',  0.8,  0.7,  1.4,  0.9, 100,100, 1, False),
    ('192.168.1.2',  'desktop-main',  '12:34:56:78:90:02',  0.4,  0.3,  0.9,  0.4, 100,100, 2, False),
    ('192.168.1.5',  'laptop',        '12:34:56:78:90:03',  2.3,  1.8,  4.1,  2.1, 100,100, 3, False),
    ('192.168.1.8',  'nas-storage',   '12:34:56:78:90:04',  1.1,  0.9,  2.0,  1.0, 100,100, 4, False),
    ('192.168.1.12', 'android-phone', '12:34:56:78:90:05',  4.8,  3.1,  9.2,  4.2,  86,100, 5, False),
    ('192.168.1.20', 'smart-tv',      '12:34:56:78:90:06', 18.4, 11.9, 31.2, 16.7,  72,100, 6, False),
    ('192.168.1.31', 'raspi-01',      '12:34:56:78:90:07',  2.9,  2.4,  4.7,  3.1,  68,100, 7, False),
    ('192.168.1.35', '',              '12:34:56:78:90:08', None, None, None, None,    0,100, 8, True ),
]

SAMPLE_INET = [
    ('8.8.8.8', 'dns.google',      None, 12.4, 11.8, 15.3, 12.1, 100, 100),
    ('1.1.1.1', 'one.one.one.one', None,  9.8,  9.1, 12.6,  9.4, 100, 100),
]

# ── Build LiveTable with sample state ─────────────────────────────────────────
lt = ns.LiveTable()
lt.current_phase    = 'Analysis'
lt.phase_number     = 2
lt.pings_per_device = 100
lt.active_threads   = 8
lt.scanned_subnets  = ['192.168.1.0/24']
lt.known_network    = True
lt.is_infinite      = False

lt.set_network_info(SAMPLE_NET)
lt.local_ip   = SAMPLE_NET['ip']
lt.local_mac  = SAMPLE_NET['mac']
lt.gateway_ip = SAMPLE_NET['gateway']

total_done = 0
for ip, host, mac, avg, mn, mx, last, done, tot, gid, off in SAMPLE_LAN:
    d = ns.Device(ip=ip)
    d.hostname      = host or None
    d.mac_address   = mac
    d.ping_status   = not off
    d.seen          = not off
    d.current_pings = done
    d.target_pings  = tot
    d.is_offline    = off
    d.from_db       = off   # offline devices loaded from DB stay visible
    d.group_id      = gid
    if avg is not None:
        d.ping_stats = {'avg': avg, 'min': mn, 'max': mx}
        d.last_ping  = last
    lt.update_device(d)
    if off:
        with lt.lock:
            lt.devices[ip].from_db = True   # update_device doesn't copy from_db
    total_done += done

lt.total_count     = len(SAMPLE_LAN)
lt.completed_count = sum(1 for *_, off in SAMPLE_LAN if not off)

for ip, host, mac, avg, mn, mx, last, done, tot in SAMPLE_INET:
    lt.public_latencies[ip] = {'avg': avg, 'min': mn, 'max': mx, 'last': last, 'count': done}
    total_done += done

lt.total_pings_target    = 100 * (len(SAMPLE_LAN) + len(SAMPLE_INET))
lt.total_pings_completed = total_done
lt.ping_success  = int(total_done * 0.96)
lt.ping_failed   = int(total_done * 0.04)
lt.ping_skipped  = 0

# ── Intercept render output ───────────────────────────────────────────────────
captured = []

def _capture(output, clear_first=False):
    captured.extend(output)

lt._write_frame = _capture

with lt.lock:
    lt._render_internal_locked(clear_first=False)

print(f"Captured {len(captured)} lines from LiveTable renderer")

# ── ANSI lines → SVG ──────────────────────────────────────────────────────────
CW     = 8.4      # Consolas 14 px character width
LH     = 19       # line height
PAD_L  = 16.0     # left padding
CHR_H  = 32       # window chrome height

SVG_W  = int(PAD_L + ns.TABLE_WIDTH * CW) + 1   # canvas ends at table edge
SVG_H  = CHR_H + (len(captured) + 1) * LH + 8

svg = ET.Element('svg', {
    'xmlns':   'http://www.w3.org/2000/svg',
    'width':   str(SVG_W),
    'height':  str(SVG_H),
    'viewBox': f'0 0 {SVG_W} {SVG_H}',
})

# Background
ET.SubElement(svg, 'rect', {'width': str(SVG_W), 'height': str(SVG_H), 'fill': '#0c0c0c'})

# Chrome bar
ET.SubElement(svg, 'rect', {'width': str(SVG_W), 'height': str(CHR_H), 'fill': '#1e1e1e'})
for bx, col in [(16, '#ff5f57'), (36, '#febc2e'), (56, '#28c840')]:
    ET.SubElement(svg, 'circle', {'cx': str(bx), 'cy': '16', 'r': '6', 'fill': col})
ttl = ET.SubElement(svg, 'text', {
    'x': str(SVG_W // 2), 'y': '21', 'text-anchor': 'middle',
    'fill': '#555', 'font-size': '13', 'font-family': 'sans-serif',
})
ttl.text = 'NetworkScanner.exe'

# One <text> row per captured line
for ri, raw in enumerate(captured):
    y    = CHR_H + LH + ri * LH
    segs = parse_line(raw)
    if not segs:
        continue
    row = ET.SubElement(svg, 'text', {
        'y': str(y), 'xml:space': 'preserve',
        'font-family': "Consolas,'Courier New',monospace",
        'font-size': '14', 'dominant-baseline': 'auto',
    })
    char_pos = 0
    for text, color, bold in segs:
        if not text:
            continue
        ts = ET.SubElement(row, 'tspan', {
            'x': f'{PAD_L + char_pos * CW:.1f}', 'fill': color,
        })
        if bold:
            ts.set('font-weight', 'bold')
        ts.text = text
        char_pos += len(text)

# ── Write file ────────────────────────────────────────────────────────────────
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'screenshot.svg')
with open(out, 'w', encoding='utf-8') as f:
    f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
    f.write(ET.tostring(svg, encoding='unicode'))

print(f"Written:  {out}")
print(f"Size:     {os.path.getsize(out):,} bytes")
print(f"SVG size: {SVG_W} x {SVG_H} px")
