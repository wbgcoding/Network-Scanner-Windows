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

SVG_W  = 1140

def cx(col):
    return PAD_L + col * CW

def escape(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def make_row(spans, row_index, num_rows):
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
        col   = span[0]
        content = span[1]
        fill  = span[2]
        bold  = len(span) > 3 and span[3]
        ts = ET.SubElement(text, "tspan", {"x": f"{cx(col):.1f}", "fill": fill})
        if bold:
            ts.set("font-weight", "bold")
        ts.text = content  # ElementTree auto-escapes &, <, >
    return text

def ping_bar(done, total, filled_color, empty_color, bar_len=10):
    filled = round(bar_len * done / total) if total else 0
    return "█" * filled + "░" * (bar_len - filled), filled_color, empty_color

def device_row(idx, ip, status, hostname, vendor, avg, mn, mx, done, total, color):
    """Build the list of spans for a device row."""
    stat_color = GREEN if status == "ONLINE" else RED
    progress   = f"{done}/{total}".center(11)

    def fmt_ms(v):
        return f"{v:.1f}ms".ljust(9) if v is not None else "   ─   "

    spans = [
        (0,   "║", BORDER),
        (2,   str(idx), color),
        (5,   ip,       color),
        (22,  status,   stat_color, True),
        (33,  hostname if hostname else "", color),
        (54,  vendor,   NORM),
    ]

    if avg is not None:
        spans.append((76, fmt_ms(avg), NORM))
        spans.append((88, fmt_ms(mn),  NORM))
        spans.append((100, fmt_ms(mx), NORM))
    else:
        spans.append((76, "   ─   ", DIM))
        spans.append((88, "   ─   ", DIM))
        spans.append((100, "   ─   ", DIM))

    spans.append((112, progress, BRIGHT if done > 0 else DIM, True))
    spans.append((130, "║", BORDER))
    return spans

def device_row_with_markers(idx, ip, status, hostname, vendor, avg, mn, mx, done, total, color,
                             mark_high=False, mark_low=False):
    """Like device_row but adds coloured marker squares before the Avg column."""
    spans = device_row(idx, ip, status, hostname, vendor, avg, mn, mx, done, total, color)

    if mark_high and avg is not None:
        spans.append((74, "█", RED))
    if mark_low and avg is not None:
        spans.append((74, "█", GREEN))

    return spans

def build_svg():
    # All content rows as lists-of-spans
    rows = []

    # ROW 0 — top border
    rows.append([(0, "═" * 131, BORDER)])

    # ROW 1 — header phase / title / subnet
    rows.append([
        (0,   "║",               BORDER),
        (2,   "⚡",               LIME,   True),
        (4,   "2 – Analysis",    BRIGHT, True),
        (17,  "(100 pings)",           NORM),
        (46,  "Network Scanner",       LIME,   True),
        (96,  "Subnets:",              CYAN),
        (105, "192.168.1.0/24",        BRIGHT, True),
        (130, "║",               BORDER),
    ])

    # ROW 2 — threads
    rows.append([
        (0,   "║",  BORDER),
        (44,  "Threads:", CYAN),
        (53,  "8",        BRIGHT, True),
        (130, "║",  BORDER),
    ])

    # ROW 3 — pings progress bar
    rows.append([
        (0,   "║",             BORDER),
        (2,   "Pings",              CYAN),
        (8,   "█" * 26,        GREEN),
        (34,  "░" * 12,        DIM),
        (47,  "68/100",             BRIGHT, True),
        (57,  "IP:",                CYAN),
        (61,  "192.168.1.100",      BRIGHT),
        (79,  "MAC:",               CYAN),
        (84,  "C4-A3-66-E1-2F-08", NORM),
        (130, "║",             BORDER),
    ])

    # ROW 4 — devices bar
    rows.append([
        (0,   "║",           BORDER),
        (2,   "Devcs",            CYAN),
        (8,   "█" * 38,      GREEN),
        (47,  "9 / 9",            BRIGHT, True),
        (57,  "GW:",              CYAN),
        (61,  "192.168.1.1",      BRIGHT),
        (79,  "DNS:",             CYAN),
        (84,  "192.168.1.1, 8.8.8.8", NORM),
        (130, "║",           BORDER),
    ])

    # ROW 5 — thick separator
    thick_sep = [(0, "╠", BORDER), (1, "═" * 129, BORDER), (130, "╣", BORDER)]
    rows.append(thick_sep)

    # ROW 6 — column header
    rows.append([
        (0,   "║",        BORDER),
        (2,   "#",             DIM),
        (5,   "IP",            DIM),
        (22,  "Status",        DIM),
        (33,  "Hostname",      DIM),
        (54,  "Vendor / MAC",  DIM),
        (76,  "Avg",           DIM),
        (88,  "Min",           DIM),
        (100, "Max",           DIM),
        (112, "Progress",      DIM),
        (130, "║",        BORDER),
    ])

    # ROW 7 — thick separator
    rows.append(thick_sep)

    # Devices
    lan_devices = [
        (1,  "192.168.1.1",  "ONLINE",  "router.local", "AVM GmbH",      0.8, 0.7,  1.4,  100, 100, CYAN),
        (2,  "192.168.1.2",  "ONLINE",  "desktop-main", "Intel Corp.",    0.4, 0.3,  0.9,  100, 100, GREEN),
        (3,  "192.168.1.5",  "ONLINE",  "laptop",       "Apple Inc.",     2.3, 1.8,  4.1,  100, 100, AMBER),
        (4,  "192.168.1.8",  "ONLINE",  "nas-storage",  "Synology Inc.",  1.1, 0.9,  2.0,  100, 100, BORDER),
        (5,  "192.168.1.12", "ONLINE",  "android-ph",   "Xiaomi Comm.",   4.8, 3.1,  9.2,   86, 100, PURPLE),
        (6,  "192.168.1.20", "ONLINE",  "smart-tv",     "Samsung Elec.", 18.4, 11.9, 31.2,  72, 100, ORANGE),
        (7,  "192.168.1.35", "OFFLINE", "",             "TP-Link Tech.", None, None, None,   0, 100, RED),
    ]
    avgs = [d[6] for d in lan_devices if d[6] is not None]
    max_avg = max(avgs)
    min_avg = min(avgs)

    for dev in lan_devices:
        idx, ip, status, hostname, vendor, avg, mn, mx, done, total, color = dev
        mark_high = avg == max_avg
        mark_low  = avg == min_avg
        rows.append(device_row_with_markers(
            idx, ip, status, hostname, vendor, avg, mn, mx, done, total, color,
            mark_high=mark_high, mark_low=mark_low
        ))

    # ROW 15 — thin separator
    rows.append([
        (0,   "║",        BORDER),
        (1,   "─" * 129,  DIM),
        (130, "║",        BORDER),
    ])

    # ROW 16 — internet section header
    rows.append([
        (0,   "║",                                                                          BORDER),
        (2,   "─── Internet " + "─" * 119, DIM),
        (130, "║",                                                                          BORDER),
    ])

    # ROW 17-18 — internet devices
    inet_devices = [
        (8, "8.8.8.8", "ONLINE", "dns.google",      "Google LLC",  12.4, 11.8, 15.3, 100, 100, GREEN),
        (9, "1.1.1.1", "ONLINE", "one.one.one.one",  "Cloudflare",   9.8,  9.1, 12.6, 100, 100, CYAN),
    ]
    for dev in inet_devices:
        idx, ip, status, hostname, vendor, avg, mn, mx, done, total, color = dev
        rows.append(device_row(idx, ip, status, hostname, vendor, avg, mn, mx, done, total, color))

    # ROW 19 — bottom border
    rows.append([(0, "═" * 131, BORDER)])

    # ROW 20 — footer
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

    num_rows = len(rows)
    svg_h = int(CHROME_H + (num_rows + 1.5) * LH)

    # Build SVG
    svg = ET.Element("svg", {
        "xmlns":   "http://www.w3.org/2000/svg",
        "width":   str(SVG_W),
        "height":  str(svg_h),
        "viewBox": f"0 0 {SVG_W} {svg_h}",
    })

    # Background
    ET.SubElement(svg, "rect", {"width": str(SVG_W), "height": str(svg_h), "fill": BG})

    # Chrome bar
    ET.SubElement(svg, "rect", {"width": str(SVG_W), "height": str(CHROME_H), "fill": CHROME})

    # Traffic-light buttons
    for bx, col in [(16, "#ff5f57"), (36, "#febc2e"), (56, "#28c840")]:
        ET.SubElement(svg, "circle", {"cx": str(bx), "cy": "16", "r": "6", "fill": col})

    # Window title
    title_el = ET.SubElement(svg, "text", {
        "x": str(SVG_W // 2),
        "y": "21",
        "text-anchor": "middle",
        "fill": "#555555",
        "font-size": "13",
        "font-family": "sans-serif",
    })
    title_el.text = "NetworkScanner.exe"

    # Content rows
    for i, spans in enumerate(rows):
        text_el = make_row(spans, i, num_rows)
        svg.append(text_el)

    return ET.tostring(svg, encoding="unicode", xml_declaration=False)

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "screenshot.svg")

    svg_content = '<?xml version="1.0" encoding="UTF-8"?>\n' + build_svg()

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(svg_content)

    size = os.path.getsize(out_path)
    print(f"Written: {out_path}")
    print(f"Size:    {size:,} bytes")

if __name__ == "__main__":
    main()
