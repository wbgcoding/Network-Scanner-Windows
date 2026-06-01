"""
Generate docs/screenshot.svg — a stylised Windows conhost terminal screenshot
for the Network Scanner GitHub README.
"""

import os
import xml.etree.ElementTree as ET

# Layout constants
CW = 8.4
LH = 19
PAD_L = 16.0
CHROME_H = 32

# Canvas: symmetric left/right padding around 131 content chars
SVG_W  = int(PAD_L * 2 + 131 * CW)   # = 1132

# Colour palette
BG     = "#0c0c0c"
CHROME = "#1e1e1e"
BORDER = "#3b78ff"
DIM    = "#505050"
NORM   = "#c8c8c8"
BRIGHT = "#f2f2f2"
CYAN   = "#61d6d6"
GREEN  = "#16c60c"
RED    = "#e74856"
ORANGE = "#ff8700"
LIME   = "#afff00"
PURPLE = "#875fff"
GRAY   = "#606060"
AMBER  = "#e8a020"

# Column start positions (char units, 0 = first char after left padding)
# Layout (total 131 chars including ║ borders):
#  ║  IP(15)  Status(9)  Hostname(20)  Vendor(20)  Avg(12)  Min(12)  Max(12)  Progress(12)  MAC(17)  ║
#  0   1        16         25            45           65       77       89        101          113     130
COL_IP       = 1
COL_STATUS   = 16
COL_HOSTNAME = 25
COL_VENDOR   = 45
COL_AVG      = 65
COL_MIN      = 77
COL_MAX      = 89
COL_PROGRESS = 101
COL_MAC      = 113
COL_RIGHT    = 130   # right ║ border

def cx(col):
    return PAD_L + col * CW

def make_row(spans, row_index):
    """Return a <text> element for one content row."""
    y = CHROME_H + LH + row_index * LH
    text = ET.Element("text", {
        "y": str(y),
        "xml:space": "preserve",
        "font-family": "Consolas, 'Courier New', monospace",
        "font-size": "14",
        "dominant-baseline": "auto",
    })
    for span in spans:
        col     = span[0]
        content = span[1]
        fill    = span[2]
        bold    = len(span) > 3 and span[3]
        ts = ET.SubElement(text, "tspan", {"x": f"{cx(col):.1f}", "fill": fill})
        if bold:
            ts.set("font-weight", "bold")
        ts.text = content   # ElementTree auto-escapes &, <, >
    return text


def device_row(ip, status, hostname, vendor, avg, mn, mx, done, total, color, mac="",
               mark_high=False, mark_low=False):
    """One device row with all columns filled."""
    stat_color = GREEN if status == "ONLINE" else RED
    progress   = f"{done}/{total}".center(11)

    def fmt_ms(v):
        return f"{v:.1f}ms".ljust(10) if v is not None else "   ─    "

    spans = [
        (0,            "║",                   BORDER),
        (COL_IP,       ip[:14],               color),
        (COL_STATUS,   status,                stat_color, True),
        (COL_HOSTNAME, (hostname or "")[:19], color),
        (COL_VENDOR,   vendor[:19],           NORM),
    ]

    # Optional high/low ping markers (1 char left of Avg column)
    if mark_high and avg is not None:
        spans.append((COL_AVG - 2, "█", RED))
    if mark_low and avg is not None:
        spans.append((COL_AVG - 2, "█", GREEN))

    if avg is not None:
        spans += [
            (COL_AVG, fmt_ms(avg), NORM),
            (COL_MIN, fmt_ms(mn),  NORM),
            (COL_MAX, fmt_ms(mx),  NORM),
        ]
    else:
        spans += [
            (COL_AVG, "   ─    ", DIM),
            (COL_MIN, "   ─    ", DIM),
            (COL_MAX, "   ─    ", DIM),
        ]

    spans.append((COL_PROGRESS, progress, BRIGHT if done > 0 else DIM, True))

    if mac:
        spans.append((COL_MAC, mac, DIM))

    spans.append((COL_RIGHT, "║", BORDER))
    return spans


def build_svg():
    rows = []

    # Separator helpers
    def top_border():
        # Extend slightly past SVG_W so no dark gap shows at the right edge
        n = int((SVG_W - PAD_L) / CW) + 1
        rows.append([(0, "═" * n, BORDER)])

    def thick_sep():
        n = int((SVG_W - PAD_L) / CW) - 1
        rows.append([(0, "╠", BORDER), (1, "═" * (n - 1), BORDER), (n, "╣", BORDER)])

    def thin_sep():
        n = int((SVG_W - PAD_L) / CW) - 1
        rows.append([(0, "║", BORDER), (1, "─" * (n - 1), DIM), (n, "║", BORDER)])

    # ── Top border ────────────────────────────────────────────────────────────
    top_border()

    # ── Header: phase / title / subnet ────────────────────────────────────────
    rows.append([
        (0,   "║",             BORDER),
        (2,   "⚡",             LIME,   True),
        (4,   "2 – Analysis",  BRIGHT, True),
        (17,  "(100 pings)",   NORM),
        (46,  "Network Scanner", LIME, True),
        (96,  "Subnets:",      CYAN),
        (105, "192.168.1.0/24", BRIGHT, True),
        (COL_RIGHT, "║",       BORDER),
    ])

    # ── Threads ───────────────────────────────────────────────────────────────
    rows.append([
        (0,   "║",        BORDER),
        (44,  "Threads:", CYAN),
        (53,  "8",        BRIGHT, True),
        (COL_RIGHT, "║",  BORDER),
    ])

    # ── Pings progress bar ────────────────────────────────────────────────────
    rows.append([
        (0,   "║",               BORDER),
        (2,   "Pings",           CYAN),
        (8,   "█" * 26,          GREEN),
        (34,  "░" * 12,          DIM),
        (47,  "68/100",          BRIGHT, True),
        (57,  "IP:",             CYAN),
        (61,  "192.168.1.100",   BRIGHT),
        (79,  "MAC:",            CYAN),
        (84,  "C4-A3-66-E1-2F-08", NORM),
        (COL_RIGHT, "║",         BORDER),
    ])

    # ── Devices bar ───────────────────────────────────────────────────────────
    rows.append([
        (0,   "║",               BORDER),
        (2,   "Devcs",           CYAN),
        (8,   "█" * 38,          GREEN),
        (47,  "9 / 9",           BRIGHT, True),
        (57,  "GW:",             CYAN),
        (61,  "192.168.1.1",     BRIGHT),
        (79,  "DNS:",            CYAN),
        (84,  "192.168.1.1, 8.8.8.8", NORM),
        (COL_RIGHT, "║",         BORDER),
    ])

    thick_sep()

    # ── Column headers ────────────────────────────────────────────────────────
    rows.append([
        (0,            "║",          BORDER),
        (COL_IP,       "IP",         DIM),
        (COL_STATUS,   "Status",     DIM),
        (COL_HOSTNAME, "Hostname",   DIM),
        (COL_VENDOR,   "Vendor",     DIM),
        (COL_AVG,      "Avg",        DIM),
        (COL_MIN,      "Min",        DIM),
        (COL_MAX,      "Max",        DIM),
        (COL_PROGRESS, "Progress",   DIM),
        (COL_MAC,      "MAC Address",DIM),
        (COL_RIGHT,    "║",          BORDER),
    ])

    thick_sep()

    # ── LAN device rows ───────────────────────────────────────────────────────
    lan = [
        # ip,              status,    hostname,       vendor,          avg,  mn,   mx,  done,tot, color,  mac
        ("192.168.1.1",  "ONLINE",  "router.local",  "AVM GmbH",      0.8,  0.7,  1.4, 100, 100, CYAN,   "D4:21:22:A8:1F:01"),
        ("192.168.1.2",  "ONLINE",  "desktop-main",  "Intel Corp.",    0.4,  0.3,  0.9, 100, 100, GREEN,  "C4:A3:66:E1:2F:08"),
        ("192.168.1.5",  "ONLINE",  "laptop",        "Apple Inc.",     2.3,  1.8,  4.1, 100, 100, AMBER,  "A4:83:E7:2C:45:1F"),
        ("192.168.1.8",  "ONLINE",  "nas-storage",   "Synology Inc.",  1.1,  0.9,  2.0, 100, 100, BORDER, "00:11:32:AB:CD:EF"),
        ("192.168.1.12", "ONLINE",  "android-ph",    "Xiaomi Comm.",   4.8,  3.1,  9.2,  86, 100, PURPLE, "A8:B5:E1:3D:8C:21"),
        ("192.168.1.20", "ONLINE",  "smart-tv",      "Samsung Elec.", 18.4, 11.9, 31.2,  72, 100, ORANGE, "CC:DA:8E:12:34:56"),
        ("192.168.1.35", "OFFLINE", "",              "TP-Link Tech.", None, None, None,   0, 100, RED,    "70:4F:57:AA:BB:CC"),
    ]

    avgs = [d[4] for d in lan if d[4] is not None]
    hi, lo = max(avgs), min(avgs)

    for ip, status, hostname, vendor, avg, mn, mx, done, total, color, mac in lan:
        rows.append(device_row(ip, status, hostname, vendor, avg, mn, mx, done, total,
                               color, mac,
                               mark_high=(avg == hi),
                               mark_low=(avg == lo)))

    thin_sep()

    # ── Internet section ──────────────────────────────────────────────────────
    n = int((SVG_W - PAD_L) / CW) - 3
    rows.append([
        (0, "║", BORDER),
        (2, "─── Internet " + "─" * (n - 13), DIM),
        (COL_RIGHT, "║", BORDER),
    ])

    inet = [
        ("8.8.8.8", "ONLINE", "dns.google",      "Google LLC",  12.4, 11.8, 15.3, 100, 100, GREEN, ""),
        ("1.1.1.1", "ONLINE", "one.one.one.one",  "Cloudflare",   9.8,  9.1, 12.6, 100, 100, CYAN,  ""),
    ]
    for ip, status, hostname, vendor, avg, mn, mx, done, total, color, mac in inet:
        rows.append(device_row(ip, status, hostname, vendor, avg, mn, mx, done, total, color, mac))

    # ── Bottom border ─────────────────────────────────────────────────────────
    top_border()

    # ── Footer controls ───────────────────────────────────────────────────────
    rows.append([
        (2,  "[P]",       BORDER, True),
        (6,  "Pause",     NORM),
        (14, "[Q]",       BORDER, True),
        (18, "Stop & save", NORM),
        (32, "[+/-]",     BORDER, True),
        (38, "Timeout:",  NORM),
        (47, "100ms",     BRIGHT, True),
        (55, "[ESC]",     BORDER, True),
        (61, "Quit",      NORM),
    ])

    # ── Build SVG ─────────────────────────────────────────────────────────────
    num_rows = len(rows)
    svg_h    = int(CHROME_H + (num_rows + 1.5) * LH)

    svg = ET.Element("svg", {
        "xmlns":   "http://www.w3.org/2000/svg",
        "width":   str(SVG_W),
        "height":  str(svg_h),
        "viewBox": f"0 0 {SVG_W} {svg_h}",
    })

    ET.SubElement(svg, "rect", {"width": str(SVG_W), "height": str(svg_h), "fill": BG})
    ET.SubElement(svg, "rect", {"width": str(SVG_W), "height": str(CHROME_H), "fill": CHROME})

    for bx, col in [(16, "#ff5f57"), (36, "#febc2e"), (56, "#28c840")]:
        ET.SubElement(svg, "circle", {"cx": str(bx), "cy": "16", "r": "6", "fill": col})

    title_el = ET.SubElement(svg, "text", {
        "x": str(SVG_W // 2), "y": "21",
        "text-anchor": "middle",
        "fill": "#555555", "font-size": "13", "font-family": "sans-serif",
    })
    title_el.text = "NetworkScanner.exe"

    for i, spans in enumerate(rows):
        svg.append(make_row(spans, i))

    return ET.tostring(svg, encoding="unicode", xml_declaration=False)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path   = os.path.join(script_dir, "screenshot.svg")
    content    = '<?xml version="1.0" encoding="UTF-8"?>\n' + build_svg()

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Written: {out_path}")
    print(f"Size:    {os.path.getsize(out_path):,} bytes")


if __name__ == "__main__":
    main()
