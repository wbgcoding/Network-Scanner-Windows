#!/usr/bin/env python3
"""Network Scanner - Pings entire subnet and lists devices with IP, MAC, hostname, and ping status."""

import socket
import subprocess
import ctypes
import platform
import re
import threading
import sys
import time
import select
import os
import csv
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

# ── Terminal Module Imports ──────────────────────────────────────────────────
if platform.system() == "Windows":
    termios = None
    tty = None
    try:
        import msvcrt as _msvcrt
    except ImportError:
        _msvcrt = None
elif sys.stdin.isatty():
    try:
        import termios
        import tty
    except ImportError:
        termios = None
        tty = None
    _msvcrt = None
else:
    termios = None
    tty = None
    _msvcrt = None


# Console font height (pixels). The scanner picks the LARGEST height up to this
# ceiling at which the full table still fits the screen, so the window adapts to
# the table width while staying readable. Overridable via the [display]
# console_font_size config option; 0 disables all font handling.
CONSOLE_FONT_HEIGHT: int = 18
# Never shrink the font below this (keeps text readable on small screens; we
# accept a capped window rather than an unreadable font).
CONSOLE_FONT_MIN_HEIGHT: int = 12


def _run(args, timeout: int = None) -> subprocess.CompletedProcess:
    """subprocess.run wrapper that uses UTF-8 with replacement so Windows OEM
    output (ipconfig, arp, ping) never raises a UnicodeDecodeError."""
    return subprocess.run(
        args, capture_output=True, text=True,
        encoding='utf-8', errors='replace',
        timeout=timeout
    )


def _open_conout() -> int:
    """Open CONOUT$ and return its handle (or 0 on failure).
    CONOUT$ always points to the real console window even when sys.stdout is
    redirected to a pipe or file (which happens when Python runs as a child of
    PowerShell).  Caller must CloseHandle() the returned value when done."""
    try:
        import ctypes
        GENERIC_READ_WRITE = 0xC0000000
        FILE_SHARE_RW      = 0x00000003
        OPEN_EXISTING      = 3
        INVALID_HANDLE     = ctypes.c_size_t(-1).value
        h = ctypes.windll.kernel32.CreateFileW(
            "CONOUT$", GENERIC_READ_WRITE, FILE_SHARE_RW, None, OPEN_EXISTING, 0, None
        )
        return h if (h and h != INVALID_HANDLE) else 0
    except Exception:
        return 0


def _in_windows_terminal() -> bool:
    """True when running inside Windows Terminal (it sets WT_SESSION). Its ConPTY
    ignores app-driven window resizing/font changes; only conhost.exe honours them."""
    return bool(os.environ.get("WT_SESSION"))


def _conhost_relaunch_command() -> List[str]:
    """Command line that re-runs this program under conhost.exe, for both the
    frozen .exe (sys.frozen) and `python script.py`."""
    if getattr(sys, "frozen", False):
        inner = [sys.executable] + sys.argv[1:]
    else:
        inner = [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:]
    return ["conhost.exe"] + inner


def _ensure_classic_console() -> None:
    """Re-host under conhost.exe when launched in Windows Terminal, which ignores
    the window-resize/font calls the scanner needs. Relaunches once and exits;
    the NS_CONHOST guard prevents a loop (WT_SESSION is inherited by the child)."""
    if platform.system() != "Windows":
        return
    if os.environ.get("NS_CONHOST") == "1":
        return
    if not _in_windows_terminal():
        return
    try:
        env = dict(os.environ)
        env["NS_CONHOST"] = "1"
        CREATE_NEW_CONSOLE = 0x00000010
        subprocess.Popen(_conhost_relaunch_command(), env=env,
                         creationflags=CREATE_NEW_CONSOLE)
    except Exception:
        return   # keep running in place (degraded but usable)
    else:
        sys.exit(0)


def _enable_windows_ansi() -> None:
    """Enable VT100/ANSI escape processing in the Windows console.
    Uses CONOUT$ so it works even when sys.stdout is redirected."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = _open_conout()
        if not handle:
            return
        try:
            mode = ctypes.c_ulong(0)
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                # ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        pass


def _init_console_encoding() -> None:
    """Force UTF-8 I/O so the block-bar (█/░) and braille-spinner glyphs never
    raise UnicodeEncodeError. The default stdout encoding is cp1252 in a frozen
    PyInstaller exe (and some consoles), which cannot encode those characters."""
    if platform.system() == "Windows":
        try:
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)  # CP_UTF8 — console interprets bytes as UTF-8
            kernel32.SetConsoleCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _normalize_console_font(height: int = CONSOLE_FONT_HEIGHT) -> bool:
    """Set the console font to the given pixel height, preserving the existing
    face/weight (falling back to Consolas). Pass height<=0 to skip. No-op on
    non-Windows or when no console is attached."""
    if platform.system() != "Windows" or height <= 0:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        class _COORD(ctypes.Structure):
            _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]

        class _CONSOLE_FONT_INFOEX(ctypes.Structure):
            _fields_ = [
                ("cbSize",     wintypes.ULONG),
                ("nFont",      wintypes.DWORD),
                ("dwFontSize", _COORD),
                ("FontFamily", wintypes.UINT),
                ("FontWeight", wintypes.UINT),
                ("FaceName",   wintypes.WCHAR * 32),
            ]

        kernel32 = ctypes.windll.kernel32
        handle = _open_conout()
        if not handle:
            return False
        try:
            font = _CONSOLE_FONT_INFOEX()
            font.cbSize = ctypes.sizeof(_CONSOLE_FONT_INFOEX)
            kernel32.GetCurrentConsoleFontEx(handle, False, ctypes.byref(font))
            # Keep a sane TrueType face; otherwise use Consolas (a fixed-width font
            # that renders the block-bar/ANSI glyphs cleanly).
            if not font.FaceName or font.FaceName.startswith("\x00"):
                font.FaceName = "Consolas"
                font.FontFamily = 54   # FF_DONTCARE | TMPF_TRUETYPE
                font.FontWeight = 400
            font.dwFontSize = _COORD(0, height)   # width auto
            return bool(kernel32.SetCurrentConsoleFontEx(handle, False, ctypes.byref(font)))
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return False


def _console_max_cols() -> int:
    """Largest window width (columns) that fits the screen at the current font
    (dwMaximumWindowSize.X), or 0 when unavailable."""
    if platform.system() != "Windows":
        return 0
    try:
        from ctypes import wintypes

        class _COORD(ctypes.Structure):
            _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]

        class _SMALL_RECT(ctypes.Structure):
            _fields_ = [
                ("Left",  wintypes.SHORT), ("Top",    wintypes.SHORT),
                ("Right", wintypes.SHORT), ("Bottom", wintypes.SHORT),
            ]

        class _CSBI(ctypes.Structure):
            _fields_ = [
                ("dwSize",              _COORD),
                ("dwCursorPosition",    _COORD),
                ("wAttributes",         wintypes.WORD),
                ("srWindow",            _SMALL_RECT),
                ("dwMaximumWindowSize", _COORD),
            ]

        kernel32 = ctypes.windll.kernel32
        handle = _open_conout()
        if not handle:
            return 0
        try:
            csbi = _CSBI()
            if kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(csbi)):
                return int(csbi.dwMaximumWindowSize.X)
            return 0
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return 0


def _fit_console_font(needed_cols: int,
                      max_height: int = CONSOLE_FONT_HEIGHT,
                      min_height: int = CONSOLE_FONT_MIN_HEIGHT) -> int:
    """Apply the largest font height in [min_height, max_height] at which
    `needed_cols` columns still fit on screen, so the window can grow to the full
    table width while staying as readable as possible (only shrinks when needed).
    Returns the height applied, or 0 when font handling is disabled/unavailable."""
    if platform.system() != "Windows" or max_height <= 0:
        return 0
    lo = max(1, min(min_height, max_height))
    applied = 0
    for h in range(max_height, lo - 1, -1):
        if not _normalize_console_font(h):
            continue
        applied = h
        if _console_max_cols() >= needed_cols:
            break
    return applied


def _resize_terminal_windows(cols: int, rows: int = 0) -> Tuple[int, int]:
    """Resize the Windows console to cols × rows via CONOUT$.
    rows=0 → maximum height that fits the screen.
    Returns (actual_cols, actual_rows) after resize, or (0, 0) on failure."""
    try:
        import ctypes
        from ctypes import wintypes

        class _COORD(ctypes.Structure):
            _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]

        class _SMALL_RECT(ctypes.Structure):
            _fields_ = [
                ("Left",   wintypes.SHORT), ("Top",    wintypes.SHORT),
                ("Right",  wintypes.SHORT), ("Bottom", wintypes.SHORT),
            ]

        class _CSBI(ctypes.Structure):
            _fields_ = [
                ("dwSize",              _COORD),
                ("dwCursorPosition",    _COORD),
                ("wAttributes",         wintypes.WORD),
                ("srWindow",            _SMALL_RECT),
                ("dwMaximumWindowSize", _COORD),
            ]

        kernel32 = ctypes.windll.kernel32
        handle = _open_conout()
        if not handle:
            return (0, 0)

        try:
            csbi = _CSBI()
            if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(csbi)):
                return (0, 0)
            if csbi.dwMaximumWindowSize.X == 0 or csbi.dwMaximumWindowSize.Y == 0:
                return (0, 0)

            # The window can only grow as far as the screen allows at the current
            # font (_fit_console_font already chose a fitting one).
            target_cols = min(cols, csbi.dwMaximumWindowSize.X)
            target_rows = (csbi.dwMaximumWindowSize.Y if rows <= 0
                           else min(rows, csbi.dwMaximumWindowSize.Y))

            # Buffer must be at least the window size. Grow it first (shrinking a
            # large scroll buffer often fails and would undo the resize).
            if target_cols > csbi.dwSize.X or target_rows > csbi.dwSize.Y:
                kernel32.SetConsoleScreenBufferSize(
                    handle,
                    _COORD(max(csbi.dwSize.X, target_cols),
                           max(csbi.dwSize.Y, target_rows))
                )

            kernel32.SetConsoleWindowInfo(
                handle, True,
                ctypes.byref(_SMALL_RECT(0, 0, target_cols - 1, target_rows - 1))
            )

            # Re-read to report the size actually applied.
            after = _CSBI()
            kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(after))
            actual_cols = after.srWindow.Right - after.srWindow.Left + 1
            actual_rows = after.srWindow.Bottom - after.srWindow.Top + 1
            return (actual_cols, actual_rows)
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return (0, 0)


def _console_window_metrics() -> Tuple[int, int]:
    """Return (current_window_cols, max_window_cols) for the Windows console, or
    (0, 0) when unavailable (non-Windows / redirected). Used to check the window
    width on every render so it can be kept matched to the table width."""
    if platform.system() != "Windows":
        return (0, 0)
    try:
        import ctypes
        from ctypes import wintypes

        class _COORD(ctypes.Structure):
            _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]

        class _SMALL_RECT(ctypes.Structure):
            _fields_ = [("Left", wintypes.SHORT), ("Top", wintypes.SHORT),
                        ("Right", wintypes.SHORT), ("Bottom", wintypes.SHORT)]

        class _CSBI(ctypes.Structure):
            _fields_ = [("dwSize", _COORD), ("dwCursorPosition", _COORD),
                        ("wAttributes", wintypes.WORD), ("srWindow", _SMALL_RECT),
                        ("dwMaximumWindowSize", _COORD)]

        handle = _open_conout()
        if not handle:
            return (0, 0)
        try:
            csbi = _CSBI()
            if not ctypes.windll.kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(csbi)):
                return (0, 0)
            cur = csbi.srWindow.Right - csbi.srWindow.Left + 1
            return (cur, csbi.dwMaximumWindowSize.X)
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    except Exception:
        return (0, 0)


def _should_resize_window(cur_cols: int, max_cols: int, target_cols: int) -> bool:
    """Decide whether the console window needs resizing to match the target width.
    Returns False when the width can't be read (cur_cols == 0). The target is
    capped at the screen's maximum, so once the window sits at that cap it is left
    alone (no per-frame resize loop); otherwise any mismatch triggers a resize."""
    if not cur_cols:
        return False
    effective = min(target_cols, max_cols) if max_cols else target_cols
    return cur_cols != effective


def _resize_terminal(cols: int, rows: int = 0) -> Tuple[int, int]:
    """Resize terminal to cols × rows.  rows=0 → max screen height.
    Returns (actual_cols, actual_rows), or (0, 0) when resize is not applicable."""
    if platform.system() == "Windows":
        return _resize_terminal_windows(cols, rows)
    elif sys.stdin.isatty():
        r = rows if rows > 0 else 9999
        sys.stdout.write(f"\033[8;{r};{cols}t")
        sys.stdout.flush()
    return (0, 0)


def _center_console_window() -> None:
    """Move the console window to the centre of its current monitor (Windows).
    Uses the work area (excludes the taskbar) and MonitorFromWindow so it works
    correctly on multi-monitor setups. SetWindowPos is used instead of MoveWindow
    so the window size is never accidentally changed by the centering call.
    No-op on non-Windows or when no console window is attached."""
    if platform.system() != "Windows":
        return
    try:
        import ctypes
        from ctypes import wintypes

        user32   = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        # GetConsoleWindow can return 0 briefly at startup (window not yet ready).
        # Try a second time after a tiny pause before giving up.
        hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            time.sleep(0.05)
            hwnd = kernel32.GetConsoleWindow()
        if not hwnd:
            return

        # Current window rect (pixel coordinates on the virtual desktop).
        rect = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return
        win_w = rect.right - rect.left

        # Get the monitor that currently contains (most of) the window, then
        # query its work area (screen minus taskbar/docks).
        MONITOR_DEFAULTTONEAREST = 2

        class _MONITORINFO(ctypes.Structure):
            _fields_ = [
                ("cbSize",    wintypes.DWORD),
                ("rcMonitor", wintypes.RECT),
                ("rcWork",    wintypes.RECT),
                ("dwFlags",   wintypes.DWORD),
            ]

        mi = _MONITORINFO()
        mi.cbSize = ctypes.sizeof(_MONITORINFO)
        hmon = user32.MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST)
        if not user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
            # Fallback: primary-monitor work area
            work = wintypes.RECT()
            user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work), 0)
            mi.rcWork = work

        wa = mi.rcWork
        area_w = wa.right  - wa.left
        area_h = wa.bottom - wa.top   # full height excluding taskbar

        # Horizontally centred, fills the full work-area height.
        x = wa.left + max(0, (area_w - win_w) // 2)
        y = wa.top

        # SetWindowPos: move AND set height to fill the screen.
        # SWP_NOZORDER keeps the window's z-order unchanged.
        SWP_NOZORDER = 0x0004
        HWND_TOP     = 0
        user32.SetWindowPos(hwnd, HWND_TOP,
                            int(x), int(y), int(win_w), int(area_h),
                            SWP_NOZORDER)
    except Exception:
        pass


# Set once the font has been fitted, so a restart from the controls menu does
# NOT re-fit it. Re-fitting can land on a different size (the console's
# buffer/screen metrics differ after a scan), which would visibly change the
# font and the window. The resize/centre below are idempotent at a fixed font,
# so they may run every time without altering an already-stable window.
_console_font_fitted: bool = False


def _maximize_console(content_cols: int, font_max_height: int) -> None:
    """Bring the console to its full usable size and centre it.

    Order matters so a restart never leaves a shrunken window (the menu between
    runs can scroll the buffer and desync the viewport): (1) once, pick the
    largest readable font that still fits the content; (2) grow the window to the
    maximum rows the screen allows at that font (rows=0); (3) recentre at full
    work-area height. The font is fitted only on the first run so restarts keep a
    stable font/size. A no-op on non-Windows; font handling is skipped when
    font_max_height <= 0 (the 'console_font_size = 0' config opt-out)."""
    global _console_font_fitted
    if not _console_font_fitted:
        _fit_console_font(content_cols + CONSOLE_FONT_FIT_MARGIN, max_height=font_max_height)
        _console_font_fitted = True
    _resize_terminal(content_cols + CONSOLE_BORDER_MARGIN, rows=0)
    _center_console_window()


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Default Ping Values ──────────────────────────────────────────────────────
DEFAULT_PING_COUNT: int = 10
# Presets offered in the restart menu. The 1,000,000 preset was dropped in favour
# of the unlimited (∞) mode below.
PING_COUNT_OPTIONS: Tuple[int, ...] = (10, 100, 1_000, 10_000, 100_000)
# Sentinel target meaning "ping forever" (∞ mode): each device keeps pinging at
# PING_INTERVAL_MS until the user stops the run. -1 is never a valid real count.
PING_COUNT_INFINITE: int = -1

# ── Discovery Phase ──────────────────────────────────────────────────────────
DISCOVERY_PING_COUNT: int = 1
ANALYSIS_MAX_CONSECUTIVE_FAILURES: int = 5  # Stop pinging a device after this many consecutive failures
# Offline re-probe: a device that didn't answer is retried once every this many
# seconds for the rest of the run. The first reply promotes it back online and
# starts its normal ping cycle. Each IP is promoted at most once (bounded work).
OFFLINE_RETRY_INTERVAL_SECONDS: int = 5
OFFLINE_RETRY_WORKERS: int = 32   # parallel re-probe pings per retry cycle

# ── Subnet Scanning ──────────────────────────────────────────────────────────
SUBNET_FIRST_IP: int = 1
SUBNET_LAST_IP: int = 254   # .255 is the broadcast address — a /24 has 254 usable hosts
SUBNET_OCTET_COUNT: int = 3
IP_OCTET_COUNT: int = 4
# Fallback interface label when auto-detection fails (cosmetic only).
DEFAULT_INTERFACE_NAME: str = "eth0"
# Fast local-IP probe: a UDP "connect" to this host:port makes the OS pick the
# routing source address WITHOUT sending any packet, so we learn our own subnet
# instantly and the discovery scan can start before the slow PowerShell network
# query (gateway/DNS/MAC) returns. Any routable address works; nothing is sent.
LOCAL_IP_PROBE_HOST: str = "8.8.8.8"
LOCAL_IP_PROBE_PORT: int = 80
LINK_LOCAL_PREFIX: str = "169.254."

# ── Threading ────────────────────────────────────────────────────────────────
MAX_WORKERS_INIT: int = 254
MAX_WORKERS_ANALYSIS: int = 100
HIGH_PRESSURE_SUBTHREADS_PER_DEVICE: int = 10

# ── Timing ───────────────────────────────────────────────────────────────────
PING_TIMEOUT_SECONDS: int = 2
WINDOWS_PING_TIMEOUT_MS: int = 1000
UNIX_PING_TIMEOUT_S: int = 1
# Pause between two consecutive pings to the SAME host (milliseconds). Without it
# a high ping_count races to 100% on fast LAN hosts; this paces each host so a
# run takes a sensible amount of time. Overridable via [scanning] ping_interval_ms.
PING_INTERVAL_MS: int = 100
# Granularity for pause/stop-aware waits. The inter-ping interval is sliced into
# chunks this small so pressing P (pause) or Q/ESC (stop) takes effect within
# this many seconds instead of waiting out the full ping_interval_ms.
PAUSE_POLL_INTERVAL_S: float = 0.05
RENDER_THROTTLE_SECONDS: float = 1.0
# Minimum gap between live redraws. Each ping wakes the render thread, but bursts
# from many worker threads are coalesced to at most one redraw per this interval
# (≈33 fps) so the screen updates live and smoothly without flicker.
LIVE_RENDER_MIN_INTERVAL: float = 0.03
GROUP_CALC_INTERVAL_SECONDS: int = 5
INPUT_POLL_TIMEOUT: float = 0.1
INPUT_READ_SIZE: int = 3
KEY_SLEEP_INTERVAL: float = 0.01
ARP_TIMEOUT_SECONDS: int = 2
NETBIOS_TIMEOUT_SECONDS: int = 6

# ── Initial Internet Ping ────────────────────────────────────────────────────
INITIAL_INTERNET_PING_COUNT: int = 3
INTERNET_PING_HOSTS: List[str] = ['1.1.1.1', '8.8.8.8', '8.8.4.4', '9.9.9.9']
INTERNET_HOST_NAMES: Dict[str, str] = {
    '1.1.1.1': 'Cloudflare',
    '8.8.8.8': 'Google',
    '8.8.4.4': 'Google DNS',
    '9.9.9.9': 'Quad9'
}

# ── Table Layout ─────────────────────────────────────────────────────────────
TABLE_WIDTH: int = 131   # 119 base + 12 for the "Last Ping" column
TERMINAL_ROWS: int = 50
TERMINAL_COLS: int = 148
PROGRESS_BAR_MAX_LEN: int = 46
PROGRESS_BAR_MARGIN: int = 4
DEVICE_PROGRESS_BAR_MARGIN: int = 4
HEADER_INFO_GAP: int = 2   # gap bars→stats and stats→net (kept tight, packed left)
# Console-window sizing margins (added to TABLE_WIDTH; no magic numbers inline).
CONSOLE_BORDER_MARGIN: int = 2   # extra cols so the table border never wraps
CONSOLE_FONT_FIT_MARGIN: int = 4 # cols of slack when choosing the largest font
# Min gap (cols) the title row keeps between its blocks.
TITLE_BLOCK_GAP: int = 2
# Prefix used to label the bar/threads column when measuring the title row.
PINGS_LABEL: str = "Pings:  "
# Left indent (cols) of the phase text in the plain-text report header. Matches
# the visible width of the live view's "   <spinner>   " prefix.
FILE_HEADER_PHASE_INDENT: int = 8

# ── Column Widths ────────────────────────────────────────────────────────────
COL_IP_WIDTH: int = 15       # "192.168.100.100" = 15 chars
COL_STATUS_WIDTH: int = 9    # "OFFLINE" = 7, 1 pad each side
COL_GROUP_WIDTH: int = 5     # "███" = 3, 1 pad each side
COL_HOSTNAME_WIDTH: int = 22 # truncated hostname
COL_PING_WIDTH: int = 12     # "1.000,00ms" = 10, 1 pad each side
COL_PROGRESS_WIDTH: int = 13 # "10.000/10.000" = 13, fits exactly
COL_MAC_WIDTH: int = 18      # "AA:BB:CC:DD:EE:FF" = 17, 1 pad

# ── Statistic Panel ────────────────────────────────────────────────────────
STAT_LEFT_WIDTH: int = 65
STAT_DIVIDER_LEN: int = 30

# ── Group Colors ─────────────────────────────────────────────────────────────
GROUP_UNKNOWN_COLOR: int = 244          # Gray (unknown devices, unless already grouped)
GROUP_GATEWAY_COLOR_DEFAULT: int = 46   # Green
GROUP_GATEWAY_COLOR_UNIFI: int = 21     # Blue
GROUP_GATEWAY_COLOR_FRITZBOX: int = 196 # Red
GROUP_DYNAMIC_COLORS: List[int] = [
    196, 202, 208, 214, 220, 226, 190, 154, 118, 82,   # reds/oranges/yellows/greens
    46, 51, 21, 27, 33, 39, 45, 50, 63, 69,            # greens/teals/purples
    75, 81, 87, 93, 99, 105, 111, 117, 129, 135,       # blues/cyans
    141, 147, 201, 207, 213, 219, 225, 231, 165, 171   # magentas/cyans
]


def _xterm_to_rgb(n: int) -> Tuple[int, int, int]:
    """Approximate RGB values for an xterm-256 colour index."""
    _BASIC_16 = [
        (0,0,0),(128,0,0),(0,128,0),(128,128,0),
        (0,0,128),(128,0,128),(0,128,128),(192,192,192),
        (128,128,128),(255,0,0),(0,255,0),(255,255,0),
        (0,0,255),(255,0,255),(0,255,255),(255,255,255),
    ]
    if n < 16:
        return _BASIC_16[n]
    if n < 232:
        n -= 16
        conv = lambda x: 0 if x == 0 else 55 + 40 * x
        return conv(n // 36), conv((n % 36) // 6), conv(n % 6)
    v = 8 + (n - 232) * 10
    return v, v, v


def _color_dist_sq(a: int, b: int) -> int:
    """Squared Euclidean distance between two xterm-256 colours in RGB space."""
    ra, ga, ba = _xterm_to_rgb(a)
    rb, gb, bb = _xterm_to_rgb(b)
    return (ra - rb) ** 2 + (ga - gb) ** 2 + (ba - bb) ** 2


def _max_diversity_sequence(colors: List[int]) -> List[int]:
    """Return `colors` reordered so each colour is as far as possible (in RGB
    space) from all previously placed ones. Guarantees that any k active groups
    get k maximally-distinct colours regardless of k — no two similar colours
    will ever appear adjacent in the assignment order."""
    if len(colors) <= 1:
        return list(colors)
    remaining = list(colors)
    # Anchor: start with the most saturated red-channel colour (reproducible).
    first = max(remaining, key=lambda c: _xterm_to_rgb(c)[0])
    ordered = [first]
    remaining.remove(first)
    while remaining:
        # Greedy pick: maximise the minimum distance to any already-placed colour.
        best = max(remaining,
                   key=lambda c: min(_color_dist_sq(c, p) for p in ordered))
        ordered.append(best)
        remaining.remove(best)
    return ordered


# Minimum acceptable squared RGB distance between any two group colours.
# sqrt(16900) ≈ 130 — solid block chars (███) closer than this look visually
# similar on a dark terminal background. Empirically derived threshold that
# gives ~9 clearly-distinct colours from the xterm-256 palette.
MIN_GROUP_COLOR_DIST_SQ: int = 16900


def _filter_diverse_colors(colors: List[int], min_dist_sq: int) -> List[int]:
    """Return a maximal subset of `colors` where every pair has squared distance
    >= min_dist_sq. Iteratively removes the colour with the most too-close
    neighbours until the constraint is satisfied throughout."""
    pool = list(colors)
    changed = True
    while changed:
        changed = False
        # Score each colour by how many others in the pool are too close.
        close = {c: sum(1 for o in pool if o != c and _color_dist_sq(c, o) < min_dist_sq)
                 for c in pool}
        worst_score = max(close.values())
        if worst_score > 0:
            # Break ties by removing the colour that is lexically last so the
            # result is deterministic across Python runs.
            worst = max((c for c in pool if close[c] == worst_score), key=lambda c: -c)
            pool.remove(worst)
            changed = True
    return pool


# Pre-computed assignment sequence. The pool is first filtered so that every
# colour in it is at least ~150 RGB units from every other, then ordered by the
# max-diversity greedy algorithm. Any k active groups therefore get k colours
# that all look clearly distinct — no two similar colours ever.
GROUP_COLOR_SEQUENCE: List[int] = _max_diversity_sequence(
    _filter_diverse_colors(GROUP_DYNAMIC_COLORS, MIN_GROUP_COLOR_DIST_SQ)
)

# ── Group IDs ────────────────────────────────────────────────────────────────
GROUP_ID_NONE: int = 0
GROUP_ID_UNKNOWN: int = 1
GROUP_ID_GATEWAY: int = 2
GROUP_ID_DYNAMIC_START: int = 3

# ── Group Logic ──────────────────────────────────────────────────────────────
HOSTNAME_PATTERN_MIN_LEN: int = 2
MAC_PREFIX_LENGTH: int = 8
GROUP_MIN_DEVICE_COUNT: int = 2

# ── Ping Latency Thresholds (ms) ─────────────────────────────────────────────
PING_EXCELLENT_MAX: int = 50
PING_GOOD_MAX: int = 100
PING_OKAY_MAX: int = 200
PING_BAD_MAX: int = 400

# ── ANSI Color Codes ─────────────────────────────────────────────────────────
COLOR_RESET: str = '\033[0m'
COLOR_BOLD: str = '\033[1m'
COLOR_BRIGHT_WHITE: str = '\033[1;97m'
COLOR_WHITE: str = '\033[97m'
COLOR_GREEN: str = '\033[1;92m'
COLOR_YELLOW: str = '\033[1;93m'
COLOR_RED: str = '\033[1;91m'
COLOR_CYAN: str = '\033[96m'
COLOR_MAGENTA: str = '\033[95m'
COLOR_BLUE: str = '\033[94m'
COLOR_DARK_GRAY: str = '\033[90m'
COLOR_ORANGE: str = '\033[1;38;5;208m'
COLOR_LIGHT_BLUE: str = '\033[1;38;5;117m'
COLOR_LIGHT_GREEN: str = '\033[1;38;5;154m'
COLOR_PURPLE: str = '\033[1;38;5;93m'   # ∞ (unlimited) mode accent

# ── Title Colors (randomized each render) ─────────────────────────────────────
TITLE_COLORS: List[int] = [
    46, 82, 118, 154, 190, 226, 208, 202, 197, 163,
    129, 93, 57, 63, 87, 51, 45, 39, 33, 27,
    21, 27, 33, 39, 45, 51, 87, 123, 159, 195,
    214, 220, 226, 190, 154, 118, 82, 46, 77, 72
]

# Animated spinner shown left of the phase status: each redraw picks a random
# char in a random colour. Special characters only (no digits/letters), ASCII so
# it renders in every console. Thin/low glyphs (. , ' ` : ; - ^ ~) are excluded —
# they look like specks; only visually substantial characters are kept.
SPINNER_CHARS: str = "@#$%&*+=?!<>()[]{}"

# ── Live Controls Footer (shown at the bottom while scanning) ────────────────
CONTROLS_HINT_RUNNING: str = "[P] Pause    [Q] Abbrechen (Ergebnis speichern)    [ESC] Sofort beenden"
CONTROLS_HINT_PAUSED:  str = "PAUSE  —  [P] weiter    [Q] abbrechen    [ESC] beenden"
# Shown the instant ESC is pressed so the screen reads as an intentional shutdown
# (not a freeze) during the brief moment the process tears down. EN + DE.
CLOSING_MESSAGE: str = "Beende Network Scanner …  /  Closing Network Scanner …"

# ── Phase Numbers ────────────────────────────────────────────────────────────
PHASE_DISCOVERY: int = 1
PHASE_ANALYSIS: int = 2
PHASE_SAVE_TXT: int = 3
PHASE_READY: int = 4

# ── Misc Strings ─────────────────────────────────────────────────────────────
UNKNOWN_VALUE: str = "Unknown"
STATUS_ONLINE: str = "ONLINE"
STATUS_OFFLINE: str = "OFFLINE"
STATUS_UNKNOWN: str = "UNKNOWN"
INFINITE_SYMBOL: str = "∞"
# The ∞ symbol drawn in the unlimited-mode purple (for the live view only — the
# saved report stays plain text and uses INFINITE_SYMBOL directly).
INFINITE_DISPLAY: str = f"{COLOR_PURPLE}{INFINITE_SYMBOL}{COLOR_RESET}"
# Markers placed just left of a value (1-space gap) in each ping column: a red
# block on the highest (slowest) value, a green block on the lowest (fastest).
PING_MARK_HIGH: str = "\033[91m█\033[0m "   # red block + gap
PING_MARK_LOW:  str = "\033[92m█\033[0m "   # green block + gap

# ── Output ───────────────────────────────────────────────────────────────────
DEFAULT_OUTPUT_DIR: str = "./Scans"

# ── Known-Devices Database & CSV Export ──────────────────────────────────────
KNOWN_DEVICES_DB_FILE: str = "scanner.db"
CSV_FILENAME_PREFIX: str = "network_scan_"
TXT_FILENAME_PREFIX: str = "network_scan_"
# Marker placed before the gateway's hostname when the network was recognised
# from the known-devices DB (so a returning network is visible at a glance).
KNOWN_GATEWAY_HOST_PREFIX: str = "# "


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

# Valid ranges used for clamping and warn-on-bad-value in ConfigManager
_CONF_RANGES: Dict[str, Tuple] = {
    'init_ping_threads': (0, 1000),
    'ping_threads':      (1, 1000),
    'init_ping_count':   (1, 100),
    'ping_count':        (1, 10_000_000),
    'ping_interval_ms':  (0, 10_000),   # pause between pings to the same host
    'refresh_rate':      (0.1, 60.0),
    'console_font_size': (0, 72),   # 0 = leave the console font untouched
}


def _is_ipv4(text: str) -> bool:
    """True for a well-formed dotted IPv4 address (four 0-255 octets)."""
    parts = text.split('.')
    if len(parts) != IP_OCTET_COUNT:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class ConfigManager:
    """Loads config from network_scanner.conf (flat key=value) or config.ini (INI sections).
    All call-sites use cfg.get(key, fallback, section=...). Flat keys are stored in a
    '_conf' pseudo-section; the get() search falls through to it automatically."""

    def __init__(self, path: str = "network_scanner.conf"):
        self.path = path
        self._section: Dict[str, Dict[str, str]] = {}
        self._warnings: List[str] = []
        self._load()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load(self):
        if not os.path.isfile(self.path):
            return

        # Try INI format first (config.ini with [sections])
        try:
            import configparser
            cp = configparser.ConfigParser()
            cp.read(self.path, encoding='utf-8')
            if cp.sections():
                for section in cp.sections():
                    self._section[section] = dict(cp.items(section))
                return
        except Exception:
            pass

        # Flat key=value format (network_scanner.conf)
        flat: Dict[str, str] = {}
        try:
            with open(self.path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith(';'):
                        continue
                    if '=' not in line:
                        continue
                    key, _, value = line.partition('=')
                    key   = key.strip().lower()
                    value = value.split('#')[0].split(';')[0].strip()
                    if key:
                        flat[key] = value
        except Exception:
            pass

        if flat:
            self._section['_conf'] = flat

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get(self, key: str, fallback=None, section: str = None):
        # 1. Named section first
        if section and section in self._section and key in self._section[section]:
            return self._section[section][key]
        # 2. Any section (covers flat '_conf' and any INI section)
        for sec_values in self._section.values():
            if key in sec_values:
                return sec_values[key]
        return fallback

    def get_int(self, key: str, fallback: int = 0, section: str = None) -> int:
        raw = self.get(key, None, section)
        if raw is None:
            return fallback
        try:
            val = int(str(raw).strip())
        except (ValueError, TypeError):
            self._warnings.append(f"  {key}: '{raw}' is not a whole number -> using default {fallback}")
            return fallback
        if key in _CONF_RANGES:
            lo, hi = _CONF_RANGES[key]
            if not (lo <= val <= hi):
                clamped = max(lo, min(hi, val))
                self._warnings.append(
                    f"  {key}: {val} out of range [{lo}, {hi}] -> corrected to {clamped}"
                )
                return clamped
        return val

    def get_float(self, key: str, fallback: float = 0.0, section: str = None) -> float:
        raw = self.get(key, None, section)
        if raw is None:
            return fallback
        try:
            val = float(str(raw).strip().replace(',', '.'))
        except (ValueError, AttributeError):
            self._warnings.append(f"  {key}: '{raw}' is not a number -> using default {fallback}")
            return fallback
        if key in _CONF_RANGES:
            lo, hi = _CONF_RANGES[key]
            if not (lo <= val <= hi):
                clamped = max(lo, min(hi, val))
                self._warnings.append(
                    f"  {key}: {val} außerhalb [{lo}, {hi}] → korrigiert zu {clamped}"
                )
                return clamped
        return val

    def get_bool(self, key: str, fallback: bool = False, section: str = None) -> bool:
        raw = self.get(key, None, section)
        if raw is None:
            return fallback
        return str(raw).strip().lower() in ('true', 'yes', '1', 'on', 'enabled')

    def get_str(self, key: str, fallback: str = '', section: str = None) -> str:
        val = self.get(key, None, section)
        return str(val).strip() if val is not None else fallback

    def get_subnets(self) -> List[str]:
        """Collect every configured subnet: 'subnet' plus 'subnet_2', 'subnet_3',
        … across all sections. Returns values in ascending key order, de-duped."""
        found: Dict[str, str] = {}
        for sec_values in self._section.values():
            for key, val in sec_values.items():
                if re.fullmatch(r'subnet(_\d+)?', key) and str(val).strip():
                    found[key] = str(val).strip()

        def _order(k: str) -> int:
            return 0 if k == 'subnet' else int(k.split('_', 1)[1])

        result, seen = [], set()
        for key in sorted(found, key=_order):
            v = found[key]
            if v not in seen:
                seen.add(v)
                result.append(v)
        return result

    def get_ip_list(self, key: str, section: str = None) -> List[str]:
        """Parse a comma/semicolon-separated list of IPv4 addresses (order kept,
        duplicates and invalid entries dropped). Empty when unset."""
        raw = self.get(key, None, section)
        if not raw:
            return []
        out, seen = [], set()
        for part in str(raw).replace(';', ',').split(','):
            ip = part.strip()
            if ip and ip not in seen and _is_ipv4(ip):
                seen.add(ip)
                out.append(ip)
        return out

    def print_warnings(self) -> None:
        if self._warnings:
            print(f"\n{COLOR_YELLOW}Configuration warnings:{COLOR_RESET}")
            for w in self._warnings:
                print(w)


def load_config_manager() -> ConfigManager:
    """Singleton ConfigManager.
    Priority: network_scanner.conf → config.ini → network_scanner.conf.template
    (template is always present because _ensure_conf_template writes it at startup).
    This means a fresh install with no .conf still picks up all the documented
    defaults (output_directory, ping_threads, …) from the template."""
    if not hasattr(load_config_manager, '_instance') or load_config_manager._instance is None:
        if os.path.isfile("network_scanner.conf"):
            path = "network_scanner.conf"
        elif os.path.isfile("config.ini"):
            path = "config.ini"
        elif os.path.isfile("network_scanner.conf.template"):
            path = "network_scanner.conf.template"
        else:
            path = "network_scanner.conf"   # all values will be Python defaults
        load_config_manager._instance = ConfigManager(path)
    return load_config_manager._instance


# ── Template constant ─────────────────────────────────────────────────────────
# Single source of truth for network_scanner.conf.template. Everything is
# commented out, so a fresh config runs entirely on the built-in defaults.
_CONF_TEMPLATE_CONTENT = """\
# ===============================================================================
#  Network Scanner - configuration
# -------------------------------------------------------------------------------
#  Every setting below is OPTIONAL and shown with its default. The scanner runs
#  fine with no config at all - it just uses these defaults.
#
#  To change something: copy this file to "network_scanner.conf", then uncomment
#  a line (remove the leading #) and set your value.
#  Lines starting with # or ; are ignored. Out-of-range values are auto-corrected.
# ===============================================================================


# -- NETWORK -------------------------------------------------------------------

# subnet  Network to scan, in CIDR notation. Leave unset to auto-detect the
#   subnet of this PC. Example: 192.168.1.0/24
#subnet = 192.168.1.0/24

# subnet_2, subnet_3, ...  Extra subnets to scan in the same run, in order.
#subnet_2 = 10.0.0.0/24
#subnet_3 = 172.16.0.0/24

# pinned_ips  Always ping these IPs every scan and pin them to the TOP of the
#   list - even when they are offline. Comma-separated. Handy for your router,
#   NAS, server, printer... Default: none.
#pinned_ips = 192.168.2.1, 192.168.2.10


# -- PING BEHAVIOUR ------------------------------------------------------------

# ping_count  How many times each device is pinged (you can also pick this from
#   the start menu). Internet hosts are pinged the same number of times.
#   Range: 1-10000000 | Default: 10
#ping_count = 10

# ping_interval_ms  Pause between two pings to the SAME host, in milliseconds.
#   Stops fast LAN hosts from finishing instantly. Range: 0-10000 | Default: 100
#ping_interval_ms = 100

# init_ping_count  Pings per device during the quick discovery sweep.
#   Range: 1-100 | Default: 1
#init_ping_count = 1

# high_pressure_mode  Ping every device at once with several threads each.
#   true  = maximum speed (high CPU / network load)
#   false = smooth pipelined scan (discovery, then analysis). Default: false
#high_pressure_mode = false


# -- INTERNET LATENCY ----------------------------------------------------------

# enable_internet_ping  Also ping a few public hosts to compare LAN vs internet
#   latency. Default: true
#enable_internet_ping = true

# internet_hosts  Public IPs to measure against. Comma-separated.
#   Default: 8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9
#internet_hosts = 8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9


# -- KNOWN-DEVICES DATABASE ----------------------------------------------------

# known_devices_db  Remember devices per network in scanner.db. On a later scan
#   the same network's devices are listed again (offline until they answer), so
#   you instantly see what is missing. Default: true
#known_devices_db = true


# -- OUTPUT --------------------------------------------------------------------

# output_directory  Where scan reports are saved (created automatically).
#   Default: ./Scans
#output_directory = ./Scans

# file_output  Write a plain-text report after each scan. Default: true
#file_output = true

# export_csv  Also write a CSV file next to the report. Default: false
#export_csv = false


# -- PERFORMANCE ---------------------------------------------------------------

# ping_threads  Worker threads during the analysis phase.
#   Range: 1-1000 | Default: 100
#ping_threads = 100

# init_ping_threads  Worker threads during discovery. 0 = one per IP.
#   Range: 0-1000 | Default: 254
#init_ping_threads = 254


# -- DISPLAY -------------------------------------------------------------------

# refresh_rate  Minimum seconds between screen redraws. Range: 0.1-60.0 | Default: 1.0
#refresh_rate = 1.0

# console_font_size  Console font height in pixels (0 = leave the font untouched).
#   Range: 0-72 | Default: 18
#console_font_size = 18
"""


def _ensure_conf_template() -> None:
    """Always write the canonical template so it never goes stale after an update."""
    path = "network_scanner.conf.template"
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(_CONF_TEMPLATE_CONTENT)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class Device:
    ip: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    ping_status: bool = False
    latency_ms: Optional[float] = None
    ping_stats: Dict[str, float] = field(default_factory=dict)
    current_pings: int = 0
    target_pings: int = DEFAULT_PING_COUNT
    group_id: int = GROUP_ID_NONE
    is_offline: bool = False
    last_ping: Optional[float] = None   # most recently measured latency (ms)
    from_db: bool = False   # known device loaded from the DB (may be offline)


class ScannerControl:
    """Manages scan state and user interruptions."""
    def __init__(self):
        self.stop_requested = False
        self.hard_exit = False   # ESC: abort immediately, no end screen
        self.paused = False
        self.shutdown = False
        self.lock = threading.Lock()
        self.pause_event = threading.Event()
        self.pause_event.set()  # Not paused by default

    def reset(self):
        with self.lock:
            self.stop_requested = False
            self.hard_exit = False
            self.paused = False
        self.pause_event.set()

    def request_hard_exit(self):
        """ESC pressed: stop everything at once and skip the end screen."""
        with self.lock:
            self.hard_exit = True
            self.stop_requested = True
            self.shutdown = True
        self.pause_event.set()  # Unblock any paused worker so it can exit

    def request_stop(self):
        with self.lock:
            self.stop_requested = True
        self.pause_event.set()  # Unblock if paused

    def toggle_pause(self):
        with self.lock:
            self.paused = not self.paused
            if self.paused:
                self.pause_event.clear()
            else:
                self.pause_event.set()

    def wait_if_paused(self):
        """Block while paused. Returns immediately if not paused."""
        self.pause_event.wait()

    def should_exit_task(self) -> bool:
        with self.lock:
            return self.stop_requested or self.shutdown


def _interruptible_sleep(seconds: float, ctrl: "Optional[ScannerControl]" = None) -> None:
    """Sleep up to `seconds`, but wake the instant a pause or stop is requested so
    controls take effect immediately instead of waiting out the ping interval.
    Falls back to a plain sleep when no control is attached."""
    if seconds <= 0:
        return
    if ctrl is None:
        time.sleep(seconds)
        return
    end = time.monotonic() + seconds
    while True:
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        # Pause: stop sleeping now; the caller's loop blocks on wait_if_paused().
        # Stop: stop sleeping now; the caller's loop sees should_exit_task().
        if ctrl.paused or ctrl.should_exit_task():
            return
        time.sleep(min(PAUSE_POLL_INTERVAL_S, remaining))


# ═══════════════════════════════════════════════════════════════════════════════
# NETWORK HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_network_info(interface: str) -> Dict[str, Optional[str]]:
    """Get comprehensive network information including gateway, subnet mask, and DNS."""
    system = platform.system()
    info = {
        'ip': None, 'mac': None, 'gateway': None,
        'subnet_mask': None, 'dns_servers': [], 'interface': interface
    }

    if system == "Linux":
        try:
            result = _run(["ip", "link", "show", interface])
            match = re.search(r'link/ether\s+(([a-f0-9]{2}[:]){5}[a-f0-9]{2})', result.stdout, re.IGNORECASE)
            if match:
                info['mac'] = match.group(1).upper()

            result = _run(["ip", "-4", "addr", "show", interface])
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)', result.stdout)
            if match:
                info['ip'] = match.group(1)
                # Convert CIDR prefix to subnet mask
                prefix = int(match.group(2))
                mask_parts = []
                for i in range(4):
                    if prefix >= 8:
                        mask_parts.append('255')
                        prefix -= 8
                    elif prefix > 0:
                        mask_parts.append(str(256 - (2 ** (8 - prefix))))
                        prefix = 0
                    else:
                        mask_parts.append('0')
                info['subnet_mask'] = '.'.join(mask_parts)
        except Exception:
            pass

        try:
            result = _run(["ip", "route"])
            for line in result.stdout.split('\n'):
                if 'default' in line and 'via' in line:
                    match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        info['gateway'] = match.group(1)
                        break
        except Exception:
            pass

        try:
            result = _run(["cat", "/etc/resolv.conf"])
            for line in result.stdout.split('\n'):
                if line.startswith('nameserver'):
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        info['dns_servers'].append(match.group(1))
        except Exception:
            pass

    elif system == "Windows":
        # Use PowerShell Get-NetIPConfiguration — locale-independent property names.
        try:
            ps_iface = interface.replace("'", "''")  # escape PS single quotes
            ps = (
                f"$c = Get-NetIPConfiguration -InterfaceAlias '{ps_iface}'; "
                "$ip4 = $c.IPv4Address | Select-Object -First 1; "
                "$gw  = $c.IPv4DefaultGateway | Select-Object -First 1; "
                "$dnsObj = $c.DNSServer | Where-Object { $_.AddressFamily -eq 2 }; "
                "$dns = if ($dnsObj) { ($dnsObj.ServerAddresses -join ',') } else { '' }; "
                "$mac = (Get-NetAdapter -InterfaceAlias $c.InterfaceAlias).MacAddress; "
                "Write-Output ($ip4.IPAddress + '|' + $ip4.PrefixLength + '|' + $gw.NextHop + '|' + $dns + '|' + $mac)"
            )
            res = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
            row = res.stdout.strip()
            if row and '|' in row:
                parts = row.split('|')
                if len(parts) >= 5:
                    ip_str, pfx_str, gw_str, dns_str, mac_str = (parts + [''] * 5)[:5]
                    if ip_str:
                        info['ip'] = ip_str
                    if pfx_str.isdigit():
                        prefix = int(pfx_str)
                        mask_bits = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
                        info['subnet_mask'] = '.'.join(
                            str((mask_bits >> (8 * (3 - i))) & 0xFF) for i in range(4)
                        )
                    if gw_str:
                        info['gateway'] = gw_str
                    if dns_str:
                        info['dns_servers'] = [d.strip() for d in dns_str.split(',') if d.strip()]
                    if mac_str:
                        info['mac'] = mac_str.replace('-', ':').upper()
        except Exception:
            pass

    elif system == "Darwin":
        try:
            result = _run(["ifconfig", interface])
            match_mac = re.search(r'ether\s+(([a-f0-9]{2}[:]){5}[a-f0-9]{2})', result.stdout, re.IGNORECASE)
            if match_mac:
                info['mac'] = match_mac.group(1).upper()
            match_ip = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match_ip:
                info['ip'] = match_ip.group(1)
        except Exception:
            pass

        try:
            result = _run(["netstat", "-rn"])
            for line in result.stdout.split('\n'):
                if 'default' in line and ('UGS' in line or 'UG' in line):
                    parts = line.split()
                    for part in parts:
                        if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                            info['gateway'] = part
                            break
                    if info['gateway']:
                        break
        except Exception:
            pass

    return info


def get_ethernet_interface() -> Optional[str]:
    """Get the primary ethernet interface name."""
    system = platform.system()
    if system == "Linux":
        try:
            result = _run(["ip", "route"])
            for line in result.stdout.split('\n'):
                if 'dev' in line:
                    match = re.search(r'dev\s+(\w+)', line)
                    if match and match.group(1).startswith(('eth', 'en')):
                        return match.group(1)
        except Exception:
            pass

    elif system == "Windows":
        # Use PowerShell: property names are English regardless of OS locale.
        # Prefer adapters with an IPv4 default gateway; fall back to any with a
        # non-link-local IPv4 address.
        try:
            ps = (
                "$c = Get-NetIPConfiguration | "
                "  Where-Object { $_.IPv4DefaultGateway } | Select-Object -First 1; "
                "if (-not $c) { $c = Get-NetIPConfiguration | "
                "  Where-Object { $_.IPv4Address -and "
                "    ($_.IPv4Address.IPAddress -notlike '169.254.*') } | "
                "  Select-Object -First 1 }; "
                "if ($c) { Write-Output $c.InterfaceAlias }"
            )
            res = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
            name = res.stdout.strip()
            if name:
                return name
        except Exception:
            pass

    elif system == "Darwin":
        try:
            result = _run(["netstat", "-r"])
            for line in result.stdout.split('\n'):
                if 'link' in line.lower() and 'ethernet' in line.lower():
                    match = re.search(r'^(\w+)', line)
                    if match:
                        return match.group(1)
        except Exception:
            pass

    return None


def get_local_ip_fast() -> Optional[str]:
    """Return this machine's primary LAN IPv4 instantly, or None.

    Opens a UDP socket and "connects" it to a routable address: the OS resolves
    which local interface/source-IP would be used, but because UDP is
    connectionless no packet is actually transmitted. This is microseconds-fast
    and avoids the multi-second PowerShell query on the startup critical path, so
    the discovery scan can begin almost immediately (the full gateway/DNS/MAC
    details are gathered in the background afterwards)."""
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((LOCAL_IP_PROBE_HOST, LOCAL_IP_PROBE_PORT))
        ip = s.getsockname()[0]
        if ip and ip != "0.0.0.0" and not ip.startswith(LINK_LOCAL_PREFIX):
            return ip
    except Exception:
        return None
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
    return None


class _MIB_IPFORWARDROW(ctypes.Structure):
    # Win32 routing-table row (iphlpapi). Only dwForwardNextHop is read here.
    _fields_ = [("dwForwardDest", ctypes.c_uint32),
                ("dwForwardMask", ctypes.c_uint32),
                ("dwForwardPolicy", ctypes.c_uint32),
                ("dwForwardNextHop", ctypes.c_uint32),
                ("dwForwardIfIndex", ctypes.c_uint32),
                ("dwForwardType", ctypes.c_uint32),
                ("dwForwardProto", ctypes.c_uint32),
                ("dwForwardAge", ctypes.c_uint32),
                ("dwForwardNextHopAS", ctypes.c_uint32),
                ("dwForwardMetric1", ctypes.c_uint32),
                ("dwForwardMetric2", ctypes.c_uint32),
                ("dwForwardMetric3", ctypes.c_uint32),
                ("dwForwardMetric4", ctypes.c_uint32),
                ("dwForwardMetric5", ctypes.c_uint32)]


def get_default_gateway_fast() -> Optional[str]:
    """Return the default-gateway IPv4 instantly via the IP Helper API, or None.

    Uses iphlpapi!GetBestRoute to the probe host — the routing layer returns the
    next hop (the gateway) without any network round-trip. This lets the
    known-devices DB be looked up and pre-loaded at startup (DB devices need the
    gateway IP) WITHOUT waiting on the slow PowerShell query, so recognised
    devices appear and start pinging at the same time as freshly-discovered ones.
    Windows only; returns None elsewhere or on any failure."""
    if platform.system() != "Windows":
        return None
    try:
        octets = [int(x) for x in LOCAL_IP_PROBE_HOST.split('.')]
        if len(octets) != IP_OCTET_COUNT:
            return None
        # Network-byte-order address packed as a little-endian DWORD (Windows LE).
        dest = octets[0] | (octets[1] << 8) | (octets[2] << 16) | (octets[3] << 24)
        row = _MIB_IPFORWARDROW()
        if ctypes.windll.iphlpapi.GetBestRoute(dest, 0, ctypes.byref(row)) != 0:
            return None
        nh = row.dwForwardNextHop
        gw = f"{nh & 0xFF}.{(nh >> 8) & 0xFF}.{(nh >> 16) & 0xFF}.{(nh >> 24) & 0xFF}"
        return gw if gw != "0.0.0.0" else None
    except Exception:
        return None


def get_subnet(ip: str) -> Optional[str]:
    """Extract the subnet from an IP address."""
    if not ip:
        return None
    parts = ip.split('.')
    if len(parts) == IP_OCTET_COUNT:
        return '.'.join(parts[:SUBNET_OCTET_COUNT])
    return None


# ── Windows high-resolution ICMP (sub-millisecond latency, no admin) ─────────
# The Windows `ping.exe` only reports whole milliseconds and prints "<1ms" for
# anything faster. To get sub-millisecond values like Linux's ping, we send the
# echo request through the IP Helper API (iphlpapi!IcmpSendEcho — no admin
# required) and time the round-trip with a high-resolution clock.
_ICMP_API = None          # cached iphlpapi handle (or False once known-bad)
_ICMP_INET_ADDR = None    # cached ws2_32.inet_addr


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte),
                ("Tos", ctypes.c_ubyte),
                ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte),
                ("OptionsData", ctypes.POINTER(ctypes.c_ubyte))]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32),
                ("Status", ctypes.c_uint32),
                ("RoundTripTime", ctypes.c_uint32),
                ("DataSize", ctypes.c_uint16),
                ("Reserved", ctypes.c_uint16),
                ("Data", ctypes.c_void_p),
                ("Options", _IP_OPTION_INFORMATION)]


def _ensure_icmp_api():
    """Lazily wire up the IP Helper API. Returns the iphlpapi handle or None."""
    global _ICMP_API, _ICMP_INET_ADDR
    if _ICMP_API is not None:
        return _ICMP_API or None
    try:
        from ctypes import wintypes
        api = ctypes.windll.iphlpapi
        ws2 = ctypes.windll.ws2_32
        api.IcmpCreateFile.restype = wintypes.HANDLE
        api.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        api.IcmpSendEcho.restype = wintypes.DWORD
        api.IcmpSendEcho.argtypes = [
            wintypes.HANDLE, ctypes.c_uint32, ctypes.c_void_p, wintypes.WORD,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        ]
        ws2.inet_addr.restype = ctypes.c_uint32
        ws2.inet_addr.argtypes = [ctypes.c_char_p]
        _ICMP_API = api
        _ICMP_INET_ADDR = ws2.inet_addr
    except Exception:
        _ICMP_API = False
    return _ICMP_API or None


def windows_icmp_ping(ip: str, timeout_ms: int) -> Optional[Tuple[bool, Optional[float], Optional[int]]]:
    """Send one ICMP echo via the IP Helper API and time it with a
    high-resolution clock. Returns (success, latency_ms, ttl), with sub-ms
    precision, or None if the API is unavailable (caller falls back to ping.exe)."""
    api = _ensure_icmp_api()
    if api is None:
        return None
    try:
        from ctypes import wintypes
        dest = _ICMP_INET_ADDR(ip.encode('ascii'))
        if dest == 0xFFFFFFFF:  # INADDR_NONE — let the caller fall back
            return None
        handle = api.IcmpCreateFile()
        if not handle or handle == wintypes.HANDLE(-1).value:
            return None
        try:
            data = b'abcdefghijklmnopqrstuvwabcdefghi'  # 32 bytes, like ping.exe
            reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(data) + 8
            reply_buf = ctypes.create_string_buffer(reply_size)
            t0 = time.perf_counter()
            n = api.IcmpSendEcho(handle, dest, data, len(data), None,
                                 reply_buf, reply_size, int(timeout_ms))
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            if n == 0:
                return (False, None, None)
            reply = ctypes.cast(reply_buf, ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
            if reply.Status != 0:  # 0 == IP_SUCCESS
                return (False, None, None)
            return (True, elapsed_ms, reply.Options.Ttl)
        finally:
            api.IcmpCloseHandle(handle)
    except Exception:
        return None


def _netbios_lookup(ip: str) -> Tuple[Optional[str], Optional[str]]:
    """Query a host directly via `nbtstat -A` (UDP/137) and return
    (hostname, mac). This works across subnets where reverse DNS has no PTR
    record and ARP cannot reach (a routed host). Locale-independent: keys off
    the <20>/<00> name-table codes, not the localized UNIQUE/GROUP words."""
    try:
        res = _run(["nbtstat", "-A", ip], timeout=NETBIOS_TIMEOUT_SECONDS)
    except Exception:
        return (None, None)
    if not res or not res.stdout:
        return (None, None)
    text = res.stdout
    name = None
    # Prefer <20> (File Server Service — always the unique machine name)
    for code in ("<20>", "<00>"):
        for line in text.splitlines():
            m = re.match(r'\s*([^\s<].*?)\s+' + re.escape(code) + r'\s', line)
            if m:
                cand = m.group(1).strip()
                if cand and cand != UNKNOWN_VALUE:
                    name = cand
                    break
        if name:
            break
    mac = None
    mm = re.search(r'(([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2})', text)
    if mm and mm.group(1).upper() != "00-00-00-00-00-00":
        mac = mm.group(1).upper()
    return (name, mac)


def measure_ping(ip: str, system: str) -> Tuple[bool, Optional[float]]:
    """One ping → (success, latency_ms). On Windows this uses the IP Helper API
    for sub-millisecond precision; everything else (and any Windows fallback)
    parses `ping`/`ping.exe` output."""
    if system == "Windows":
        r = windows_icmp_ping(ip, WINDOWS_PING_TIMEOUT_MS)
        if r is not None:
            return r[0], r[1]
        # else: fall through to the ping.exe fallback below

    timeout_arg = WINDOWS_PING_TIMEOUT_MS if system == "Windows" else UNIX_PING_TIMEOUT_S
    cmd = ["ping", "-n" if system == "Windows" else "-c", "1",
           "-w" if system == "Windows" else "-W", str(timeout_arg), ip]
    try:
        res = _run(cmd, timeout=PING_TIMEOUT_SECONDS)
    except Exception:
        return (False, None)
    if not ping_succeeded(res.returncode, res.stdout):
        return (False, None)
    m = (re.search(r'(?:time|zeit)\s*[=<]\s*([\d.]+)\s*ms', res.stdout, re.IGNORECASE)
         or re.search(r'Minimum\s*=\s*([\d.]+)\s*ms', res.stdout, re.IGNORECASE))
    return (True, float(m.group(1)) if m else None)


def get_mac_address(ip: str, system: str, local_ip: str = None, local_mac: str = None) -> Optional[str]:
    """Get MAC address for an IP using ARP or local info."""
    if local_ip and ip == local_ip:
        return local_mac
    try:
        if system in ("Linux", "Darwin"):
            res = _run(["arp", "-n", ip], timeout=ARP_TIMEOUT_SECONDS)
            match = re.search(r'(([a-f0-9]{2}[:]){5}[a-f0-9]{2})', res.stdout, re.IGNORECASE)
            if match:
                return match.group(1).upper()
        elif system == "Windows":
            res = _run(["arp", "-a", ip], timeout=ARP_TIMEOUT_SECONDS)
            match = re.search(r'(([0-9A-Fa-f]{2}[-]){5}[0-9A-Fa-f]{2})', res.stdout)
            if match:
                return match.group(1).upper()
    except Exception:
        pass
    return None


def get_hostname(ip: str) -> Optional[str]:
    """Get hostname for an IP using reverse DNS."""
    try:
        h = socket.gethostbyaddr(ip)[0]
        if h.endswith('.localdomain'):
            return h[:-12]
        return h
    except Exception:
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# KNOWN-DEVICES DATABASE (SQLite)
# ═══════════════════════════════════════════════════════════════════════════════
# A small SQLite store remembers every device ever seen on a network, keyed by the
# network's gateway MAC. When the same router is recognised on a later scan, its
# known devices are listed again — even the ones that are currently offline — and
# the store is topped up with whatever the new scan found.

def _db_connect(db_path: str):
    """Open the known-devices DB, creating the schema on first use.
    Returns None when sqlite3 is unavailable or the DB can't be opened
    (the feature is then silently disabled — the app still runs fully)."""
    try:
        import sqlite3  # lazy: keeps the exe from crashing when _sqlite3.pyd is missing
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS known_devices ("
            " network_mac TEXT NOT NULL,"
            " mac         TEXT NOT NULL,"
            " ip          TEXT,"
            " hostname    TEXT,"
            " last_seen   TEXT,"
            " PRIMARY KEY (network_mac, mac))"
        )
        return conn
    except Exception:
        return None


def save_known_devices(db_path: str, network_mac: str, devices: List[Device],
                       timestamp: str) -> None:
    """Upsert every device that has a real MAC into the DB for this network."""
    if not network_mac:
        return
    conn = _db_connect(db_path)
    if conn is None:
        return
    try:
        with conn:
            for d in devices:
                if not d.mac_address or d.mac_address == UNKNOWN_VALUE:
                    continue
                # Skip entries without a plausible IPv4 address (e.g. "Unknown")
                parts = (d.ip or "").split('.')
                if len(parts) != IP_OCTET_COUNT or not all(p.isdigit() for p in parts):
                    continue
                mac = d.mac_address.upper()
                hostname = d.hostname if (d.hostname and d.hostname != UNKNOWN_VALUE) else None
                conn.execute(
                    "INSERT INTO known_devices (network_mac, mac, ip, hostname, last_seen)"
                    " VALUES (?, ?, ?, ?, ?)"
                    " ON CONFLICT(network_mac, mac) DO UPDATE SET"
                    "   ip=excluded.ip,"
                    "   hostname=COALESCE(excluded.hostname, known_devices.hostname),"
                    "   last_seen=excluded.last_seen",
                    (network_mac.upper(), mac, d.ip, hostname, timestamp)
                )
    except Exception:
        pass
    finally:
        conn.close()


def load_known_devices(db_path: str, network_mac: str) -> List[Device]:
    """Return all devices remembered for the given network (by gateway MAC),
    marked as offline/from_db so callers can show them even when unreachable."""
    if not network_mac or not os.path.isfile(db_path):
        return []
    conn = _db_connect(db_path)
    if conn is None:
        return []
    try:
        rows = conn.execute(
            "SELECT ip, mac, hostname FROM known_devices WHERE network_mac = ?",
            (network_mac.upper(),)
        ).fetchall()
    except Exception:
        rows = []
    finally:
        conn.close()
    result = []
    for ip, mac, hostname in rows:
        result.append(Device(
            ip=ip or UNKNOWN_VALUE,
            mac_address=mac.upper() if mac else UNKNOWN_VALUE,
            hostname=hostname if hostname else UNKNOWN_VALUE,
            ping_status=False, is_offline=True, from_db=True
        ))
    return result


def _get_network_mac_from_db(db_path: str, gateway_ip: str) -> Optional[str]:
    """Return the network_mac (= gateway MAC) that the DB has recorded for
    `gateway_ip`, or None when this network has never been seen before.
    The gateway is the one device whose MAC equals the network_mac key."""
    if not gateway_ip or not os.path.isfile(db_path):
        return None
    conn = _db_connect(db_path)
    if conn is None:
        return None
    try:
        row = conn.execute(
            "SELECT network_mac FROM known_devices"
            " WHERE ip = ? AND mac = network_mac LIMIT 1",
            (gateway_ip,)
        ).fetchone()
        return row[0] if row else None
    except Exception:
        return None
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════════
# FORMATTING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_visible_len(s: str) -> int:
    """Calculate the visible length of a string, ignoring ANSI escape codes."""
    return len(re.sub(r'\033\[[0-9;]*m', '', s))


def format_num(n: int) -> str:
    """Format integer with dot as thousands separator."""
    return f"{n:,}".replace(',', '.')


def format_num_short(n: int) -> str:
    """Abbreviate a large MAX/target value for the progress bars with NO decimals:
    1000 -> '1k', 12345 -> '12k', 1000000 -> '1M', 1300000 -> '1M'. Values below
    1000 are returned unchanged so they stay exact. Only used for the bar's
    denominator (the ceiling); the running count keeps format_num() so every single
    ping is still shown in full while the scan runs."""
    n = int(n)
    for divisor, suffix in ((1_000_000_000, 'B'), (1_000_000, 'M'), (1_000, 'k')):
        if abs(n) >= divisor:
            return f"{n // divisor}{suffix}"   # integer only, no decimal places
    return str(n)


def _value_extremes(pairs):
    """Given an iterable of (key, value) pairs, return (key_of_highest,
    key_of_lowest). Returns (None, None) when there are fewer than two values or
    all values are equal — in those cases there is no meaningful highest/lowest to
    mark. Used to put a red block on the slowest and a green block on the fastest
    value in each ping column; recomputed every render so the marks move live."""
    vals = [(k, v) for k, v in pairs if v is not None]
    if len(vals) < 2:
        return (None, None)
    hi = max(vals, key=lambda p: p[1])
    lo = min(vals, key=lambda p: p[1])
    if hi[1] == lo[1]:
        return (None, None)
    return (hi[0], lo[0])


def _done_str(done: int, target: int, infinite: bool = False) -> str:
    """The 'done' side of a progress count (done/target). Shown in FULL during the
    scan so every single ping is visible, but ABBREVIATED once finished (done has
    reached the target) so a completed bar reads cleanly, e.g. '1k/1k'."""
    if not infinite and target and done >= target:
        return format_num_short(done)
    return format_num(done)


def format_float(n: float) -> str:
    """Format a ping value: dot thousands separator, comma decimals, 'ms' suffix.
    A whole number drops the ',00' decimals entirely (e.g. 5ms, not 5,00ms)."""
    if n is None:
        return UNKNOWN_VALUE
    int_part, dec_part = f"{n:,.2f}".split('.')
    int_part = int_part.replace(',', '.')
    # Drop trailing zero(s): '00' → '' (5ms), '50' → '5' (1,5ms), '05' stays.
    dec_part = dec_part.rstrip('0')
    if not dec_part:
        return f"{int_part}ms"
    return f"{int_part},{dec_part}ms"


def format_cell(text: str, width: int) -> str:
    """Format a cell left-aligned with the given width, taking ANSI codes into account."""
    vlen = get_visible_len(text)
    return text + (" " * max(0, width - vlen))


def format_cell_center(text: str, width: int) -> str:
    """Format a cell centered with the given width, taking ANSI codes into account."""
    vlen = get_visible_len(text)
    pad = max(0, width - vlen)
    left = pad // 2
    right = pad - left
    return (" " * left) + text + (" " * right)


def _pad_vis(text: str, width: int) -> str:
    """Right-pad text with spaces to a visible width (ANSI-aware)."""
    return text + " " * max(0, width - get_visible_len(text))


def _lpad_vis(text: str, width: int) -> str:
    """Left-pad text with spaces to a visible width (ANSI-aware) — right-aligns it."""
    return " " * max(0, width - get_visible_len(text)) + text


def kv_block_rows(lab0: str, val0: str, lab1: str, val1: str) -> Tuple[str, str]:
    """Format a two-line label/value block: labels left-aligned, values
    right-aligned, with exactly one space between the longest label and the
    value column. ANSI-aware, so colour codes don't break the alignment.
    Labels are expected to already include their trailing ':'."""
    label_w = max(get_visible_len(lab0), get_visible_len(lab1))
    val_w   = max(get_visible_len(val0), get_visible_len(val1))
    row0 = _pad_vis(lab0, label_w) + " " + _lpad_vis(val0, val_w)
    row1 = _pad_vis(lab1, label_w) + " " + _lpad_vis(val1, val_w)
    return row0, row1


def truncate_host(host: str, width: int) -> str:
    """Truncate a hostname to fit `width` characters, ending with '..' when cut.
    Guarantees the result is never longer than `width`, so it can never push the
    following table columns out of alignment."""
    if len(host) <= width:
        return host
    return host[:max(0, width - 2)] + ".."


def _assemble_row(segments: List[Tuple[int, str]]) -> str:
    """Place (start_col, text) segments on one line, filling gaps with spaces.
    start_col is a visible column; text may contain ANSI codes. Segments that
    would overlap are simply concatenated (caller is responsible for spacing)."""
    line = ""
    cur = 0
    for start, text in sorted(segments, key=lambda s: s[0]):
        if start > cur:
            line += " " * (start - cur)
            cur = start
        line += text
        cur += get_visible_len(text)
    return line


def colorize_ping(avg_ms: float) -> Tuple[str, str]:
    """Return ANSI color code based on ping latency."""
    if avg_ms is None or avg_ms < 0:
        return (COLOR_WHITE, COLOR_RESET)
    if avg_ms < PING_EXCELLENT_MAX:
        i = max(0, 100 - (avg_ms / PING_EXCELLENT_MAX) * 25)
        return (f'\033[38;5;{int(46 + i * 0.4)}m', COLOR_RESET)
    elif avg_ms < PING_GOOD_MAX:
        i = max(0, 100 - (avg_ms - PING_EXCELLENT_MAX) / (PING_GOOD_MAX - PING_EXCELLENT_MAX) * 25)
        return (f'\033[38;5;{int(114 + i * 0.2)}m', COLOR_RESET)
    elif avg_ms < PING_OKAY_MAX:
        i = max(0, 100 - (avg_ms - PING_GOOD_MAX) / (PING_OKAY_MAX - PING_GOOD_MAX) * 50)
        return (f'\033[38;5;{int(226 - i * 0.4)}m', COLOR_RESET)
    elif avg_ms < PING_BAD_MAX:
        i = max(0, 100 - (avg_ms - PING_OKAY_MAX) / (PING_BAD_MAX - PING_OKAY_MAX) * 50)
        return (f'\033[38;5;{int(208 - i * 0.4)}m', COLOR_RESET)
    return ('\033[91m', COLOR_RESET)


def colorize_status(status: str) -> str:
    """Return colored status text."""
    if status == STATUS_ONLINE:
        return f"{COLOR_GREEN}{status}{COLOR_RESET}"
    elif status == STATUS_OFFLINE:
        return f"{COLOR_RED}{status}{COLOR_RESET}"
    elif status == STATUS_UNKNOWN:
        return f"{COLOR_YELLOW}{status}{COLOR_RESET}"
    return f"{COLOR_RED}{status}{COLOR_RESET}"


def colorize_ip(ip: str) -> str:
    return f"{COLOR_CYAN}{ip}{COLOR_RESET}"


def colorize_local_ip(ip: str) -> str:
    """The local/scanner IP uses the same magenta as the hostnames."""
    return f"{COLOR_MAGENTA}{ip}{COLOR_RESET}"


def colorize_local_hostname(name: str) -> str:
    """The local/scanner hostname uses the same magenta as the other hostnames."""
    return f"{COLOR_MAGENTA}{name}{COLOR_RESET}"


def colorize_mac(mac: str) -> str:
    if mac != UNKNOWN_VALUE:
        return f"{COLOR_YELLOW}{mac}{COLOR_RESET}"
    return f"{COLOR_DARK_GRAY}{mac}{COLOR_RESET}"


def colorize_hostname(name: str) -> str:
    if name != UNKNOWN_VALUE:
        return f"{COLOR_MAGENTA}{name}{COLOR_RESET}"
    return f"{COLOR_DARK_GRAY}{name}{COLOR_RESET}"


def colorize_header(text: str) -> str:
    return f"{COLOR_ORANGE}{text}{COLOR_RESET}"


# ── MAC → Vendor (OUI) lookup ────────────────────────────────────────────────
# Curated subset of IEEE OUI assignments covering common consumer/office gear.
# Key = first three octets (uppercase, colon-separated). Value = short vendor.
MAC_VENDOR_PREFIXES: Dict[str, str] = {
    # Apple
    "00:03:93": "Apple", "00:0A:27": "Apple", "00:1B:63": "Apple",
    "00:1E:C2": "Apple", "00:25:00": "Apple", "00:26:BB": "Apple",
    "3C:07:54": "Apple", "A4:C3:61": "Apple", "AC:BC:32": "Apple",
    "DC:A9:04": "Apple", "F0:18:98": "Apple", "F4:0F:24": "Apple",
    "F8:1E:DF": "Apple", "88:66:A5": "Apple", "B8:E8:56": "Apple",
    # Samsung
    "00:12:FB": "Samsung", "00:15:99": "Samsung", "00:1D:25": "Samsung",
    "08:08:C2": "Samsung", "10:30:47": "Samsung", "34:23:87": "Samsung",
    "5C:0A:5B": "Samsung", "78:1F:DB": "Samsung", "B8:5E:7B": "Samsung",
    # Intel
    "00:1B:21": "Intel", "00:1E:67": "Intel", "3C:97:0E": "Intel",
    "7C:5C:F8": "Intel", "8C:16:45": "Intel", "A0:88:69": "Intel",
    "DC:53:60": "Intel", "94:65:9C": "Intel",
    # Cisco / Cisco-Meraki
    "00:00:0C": "Cisco", "00:1A:A1": "Cisco", "00:25:9C": "Cisco",
    "E0:55:3D": "Cisco", "00:18:0A": "Cisco Meraki", "88:15:44": "Cisco Meraki",
    # TP-Link
    "00:27:19": "TP-Link", "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link",
    "A4:2B:B0": "TP-Link", "C0:06:C3": "TP-Link", "EC:08:6B": "TP-Link",
    # Ubiquiti
    "00:15:6D": "Ubiquiti", "04:18:D6": "Ubiquiti", "24:5A:4C": "Ubiquiti",
    "78:8A:20": "Ubiquiti", "B4:FB:E4": "Ubiquiti", "FC:EC:DA": "Ubiquiti",
    # AVM (FritzBox)
    "00:04:0E": "AVM FritzBox", "00:1C:4A": "AVM FritzBox", "08:96:D7": "AVM FritzBox",
    "2C:3A:FD": "AVM FritzBox", "38:10:D5": "AVM FritzBox", "C0:25:06": "AVM FritzBox",
    # Google / Nest
    "00:1A:11": "Google", "3C:5A:B4": "Google", "54:60:09": "Google",
    "F4:F5:D8": "Google", "F4:F5:E8": "Google", "DA:A1:19": "Google",
    # Amazon
    "00:FC:8B": "Amazon", "0C:47:C9": "Amazon", "44:65:0D": "Amazon",
    "68:37:E9": "Amazon", "74:75:48": "Amazon", "FC:65:DE": "Amazon",
    # Raspberry Pi
    "28:CD:C1": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    # Espressif (ESP32/ESP8266 IoT)
    "24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "5C:CF:7F": "Espressif",
    "84:CC:A8": "Espressif", "A0:20:A6": "Espressif", "EC:FA:BC": "Espressif",
    # Huawei
    "00:E0:FC": "Huawei", "48:46:FB": "Huawei", "70:72:3C": "Huawei",
    "AC:E2:15": "Huawei", "F4:8C:50": "Huawei",
    # Xiaomi
    "28:6C:07": "Xiaomi", "50:8F:4C": "Xiaomi", "64:09:80": "Xiaomi",
    "78:11:DC": "Xiaomi", "F8:A4:5F": "Xiaomi",
    # Dell / HP / Lenovo / Microsoft
    "00:14:22": "Dell", "18:03:73": "Dell", "B8:CA:3A": "Dell",
    "00:1B:78": "HP", "3C:D9:2B": "HP", "70:5A:0F": "HP",
    "00:21:CC": "Lenovo", "54:EE:75": "Lenovo",
    "00:15:5D": "Microsoft", "28:18:78": "Microsoft", "7C:1E:52": "Microsoft",
    # Sonos / Philips Hue / AVM smart home
    "00:0E:58": "Sonos", "5C:AA:FD": "Sonos", "94:9F:3E": "Sonos",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips Hue",
    # Netgear / D-Link / ASUS
    "00:09:5B": "Netgear", "20:E5:2A": "Netgear", "A0:40:A0": "Netgear",
    "00:1B:11": "D-Link", "1C:BD:B9": "D-Link",
    "00:1B:FC": "ASUS", "2C:56:DC": "ASUS", "AC:9E:17": "ASUS",
}


def lookup_mac_vendor(mac: Optional[str]) -> Optional[str]:
    """Return the manufacturer for a MAC address via its OUI prefix, or None."""
    if not mac or mac == UNKNOWN_VALUE:
        return None
    parts = mac.replace('-', ':').upper().split(':')
    if len(parts) < 3:
        return None
    return MAC_VENDOR_PREFIXES.get(":".join(parts[:3]))


def resolve_hostname_display(hostname: Optional[str], mac: Optional[str]) -> Tuple[str, str]:
    """Decide what to show in the Hostname column and how to colour it.
    Returns (text, kind) where kind ∈ {'known', 'vendor', 'unknown'}.
      known  → real hostname  (magenta / red-if-local)
      vendor → MAC manufacturer (yellow)
      unknown→ literal 'Unknown' (gray)"""
    if hostname and hostname != UNKNOWN_VALUE:
        return hostname, 'known'
    vendor = lookup_mac_vendor(mac)
    if vendor:
        return vendor, 'vendor'
    return UNKNOWN_VALUE, 'unknown'


# ═══════════════════════════════════════════════════════════════════════════════
# LIVE TABLE
# ═══════════════════════════════════════════════════════════════════════════════

class LiveTable:
    """Manages dynamic terminal table updates."""

    def __init__(self):
        self.devices = {}
        self.lock = threading.RLock()  # RLock allows re-entry from same thread
        self.completed_count, self.total_count = 0, 0
        self.last_render_time, self.render_throttle = 0, RENDER_THROTTLE_SECONDS
        self.current_phase, self.pings_per_device = "Initializing", 0
        self.phase_number = 0
        self.total_pings_completed, self.total_pings_target = 0, 0
        # Per-ping outcome counters — used for the coloured progress bar
        self.ping_success = 0
        self.ping_failed  = 0
        self.ping_skipped = 0
        self.table_width = TABLE_WIDTH
        self.public_latencies = {}
        self.network_info = {}  # Set via set_network_info()
        self.scanned_subnets: List[str] = []  # CIDRs shown next to the title
        self.pinned_ips: List[str] = []        # always pinged + pinned to list top
        self.active_threads = 0  # Live count of in-flight ping workers
        self.local_ip = None
        self.local_mac = None
        self.gateway_ip = None
        self.gateway_color = GROUP_GATEWAY_COLOR_DEFAULT
        self.paused = False        # set by the input listener; drives the footer hint
        self.is_infinite = False   # ∞ mode: pings run until the user stops the scan
        self.known_network = False # True when the DB recognised this network's gateway
        self._refresh_timer = None
        self._refresh_stop = threading.Event()
        self._render_event = threading.Event()  # set by each ping to trigger a redraw
        self._exiting = False      # set on ESC so no worker thread repaints the table

        if platform.system() == "Windows":
            _enable_windows_ansi()
        # The device table has a FIXED width (TABLE_WIDTH); the framing borders
        # must match it, so the screen is widened to fit rather than the table
        # being shrunk below the content (which would let rows poke past the
        # borders). table_width therefore stays >= TABLE_WIDTH.  rows=0 → the
        # window grows to the FULL screen height that fits at the current font.
        _resize_terminal(TABLE_WIDTH + CONSOLE_BORDER_MARGIN)
        self.table_width = TABLE_WIDTH
        # Centre the (now full-height) console window on the primary monitor.
        _center_console_window()

    def set_paused(self, value: bool) -> None:
        """Flag the paused state so the footer shows the pause/controls hint."""
        with self.lock:
            self.paused = value
        self.request_render()

    def set_infinite(self, value: bool) -> None:
        with self.lock:
            self.is_infinite = value

    def _required_width_locked(self) -> int:
        """Width the header layout needs: bars + centred stats + right-aligned
        network info (IP/MASK | GW/DNS). Uses worst-case counts so the width is
        stable for the whole scan (no mid-scan reflow)."""
        ni = self.network_info
        ip_str   = ni.get('ip',          UNKNOWN_VALUE) or UNKNOWN_VALUE
        mask_str = ni.get('subnet_mask', UNKNOWN_VALUE) or UNKNOWN_VALUE
        gw_str   = ni.get('gateway',     UNKNOWN_VALUE) or UNKNOWN_VALUE
        dns_str  = ni.get('dns_servers', [UNKNOWN_VALUE])[0] if ni.get('dns_servers') else UNKNOWN_VALUE
        big = format_num(self.total_count or 0)
        onoff_w = max(len(f"Online: {big}"), len(f"Offline: {big}"))
        uf_w    = max(len(f"Used: {big}"),   len(f"Free: {big}"))
        stats_w = onoff_w + 2 + uf_w
        ipmask_w = max(len(f"IP: {ip_str}"),  len(f"MASK: {mask_str}"))
        gwdns_w  = max(len(f"GW: {gw_str}"),  len(f"DNS: {dns_str}"))
        net_w = ipmask_w + 2 + gwdns_w
        pings = format_num(self.total_pings_target or self.total_count or 0)
        count_w = max(len(f"{big}/{big}"), len(f"{pings}/{pings}"))
        bar_region = len("Devices:") + PROGRESS_BAR_MAX_LEN + 1 + count_w
        return bar_region + HEADER_INFO_GAP + stats_w + HEADER_INFO_GAP + net_w

    def fit_width(self) -> None:
        """Grow the console window + table_width so the header layout never wraps
        (request: widen the window dynamically when the view is too wide). Only
        ever grows — never shrinks below the base TABLE_WIDTH."""
        with self.lock:
            needed = max(TABLE_WIDTH, self._required_width_locked())
            current = self.table_width
        if needed <= current:
            return
        # Widen the console to fit; keep the border (table_width) at the content
        # width even if the console can't grow that far, so rows never poke past
        # the borders (they wrap together instead).
        _resize_terminal(needed + CONSOLE_BORDER_MARGIN)
        with self.lock:
            self.table_width = needed
        # Re-centre: the window just changed width, so its old centred position is
        # now off to the left. Keep it centred on the primary monitor.
        _center_console_window()

    def request_render(self):
        """Signal the refresh thread to redraw promptly (called on every ping)."""
        self._render_event.set()

    def start_refresh_timer(self):
        """Start the single render thread. It redraws as soon as a ping requests
        it (live), but never more often than LIVE_RENDER_MIN_INTERVAL, and at
        least every render_throttle seconds as a heartbeat (keeps the spinner
        animating while idle). A single renderer avoids garbled output from many
        worker threads writing at once."""
        if self._refresh_timer is not None:
            return
        def _timer_loop():
            while not self._refresh_stop.is_set():
                # Wake on a ping request, or fall back to the heartbeat interval.
                self._render_event.wait(timeout=self.render_throttle)
                if self._refresh_stop.is_set():
                    break
                self._render_event.clear()
                self._render(force=True)
                # Coalesce bursts: cap the redraw rate so many threads pinging at
                # once don't cause flicker.
                self._refresh_stop.wait(timeout=LIVE_RENDER_MIN_INTERVAL)
        self._refresh_stop.clear()
        self._render_event.clear()
        self._refresh_timer = threading.Thread(target=_timer_loop, daemon=True)
        self._refresh_timer.start()

    def stop_refresh_timer(self):
        """Stop the render thread (wake it immediately so it exits without delay)."""
        self._refresh_stop.set()
        self._render_event.set()
        self._refresh_timer = None

    def set_gateway(self, ip: str):
        self.gateway_ip = ip
        self.gateway_color = GROUP_GATEWAY_COLOR_DEFAULT

    def set_pinned_ips(self, ips: List[str]) -> None:
        """Register always-ping IPs that are pinned to the top of the list and
        shown even when offline. Adds an offline placeholder row for each so they
        appear immediately, before the first ping."""
        with self.lock:
            self.pinned_ips = list(ips)
            for ip in self.pinned_ips:
                if ip not in self.devices:
                    self.devices[ip] = Device(ip=ip, ping_status=False, is_offline=True)
        self.request_render()

    def set_local_mac(self, mac: Optional[str]) -> None:
        """Record this machine's own MAC once it's known (resolved in the
        background after the fast-start scan has already begun) and back-fill it
        onto the local device row if that row already exists. The own IP can't be
        resolved via ARP, so without this the local row would keep showing an
        unknown MAC. update_device() only ever overwrites a MAC with a genuine
        value, so a later re-ping won't undo this."""
        if not mac:
            return
        with self.lock:
            self.local_mac = mac
            dev = self.devices.get(self.local_ip) if self.local_ip else None
            if dev and (not dev.mac_address or dev.mac_address == UNKNOWN_VALUE):
                dev.mac_address = mac
        self.request_render()

    def set_network_info(self, info: Dict):
        """Store network info for display in header."""
        self.network_info = info
        if info.get('ip'):
            self.local_ip = info['ip']

    def _resolve_gateway_color(self):
        if not self.gateway_ip or self.gateway_ip not in self.devices:
            self.gateway_color = GROUP_GATEWAY_COLOR_DEFAULT
            return
        gw = self.devices[self.gateway_ip]
        hostname = (gw.hostname or "").lower()
        if 'unifi' in hostname:
            self.gateway_color = GROUP_GATEWAY_COLOR_UNIFI
        elif 'fritzbox' in hostname or 'fritz' in hostname:
            self.gateway_color = GROUP_GATEWAY_COLOR_FRITZBOX
        else:
            self.gateway_color = GROUP_GATEWAY_COLOR_DEFAULT

    def _is_unknown_device(self, device: Device) -> bool:
        return (
            (not device.mac_address or device.mac_address == UNKNOWN_VALUE) and
            (not device.hostname or device.hostname == UNKNOWN_VALUE)
        )

    def calculate_groups(self):
        """Analyze MAC and hostname patterns to group devices.
        Hostname patterns take priority. Devices sharing a MAC prefix with
        an already-grouped device join that group even if hostnames differ."""
        with self.lock:
            self._resolve_gateway_color()
            gateway_color = self.gateway_color
            reserved = {GROUP_UNKNOWN_COLOR, gateway_color}

            for d in self.devices.values():
                d.group_id = GROUP_ID_NONE

            pattern_counts: Dict[str, int] = {}
            patterns: Dict[str, int] = {}
            current_id = GROUP_ID_DYNAMIC_START
            device_patterns: Dict[str, List[str]] = {}

            # Pass 1: Collect patterns and counts (hostname first, then MAC)
            for d in self.devices.values():
                if self._is_unknown_device(d) or (self.gateway_ip and d.ip == self.gateway_ip):
                    continue

                keys = []
                if d.hostname and d.hostname != UNKNOWN_VALUE:
                    base = re.sub(r'[-_].*$', '', d.hostname.lower())
                    if len(base) > HOSTNAME_PATTERN_MIN_LEN:
                        keys.append(base)

                if d.mac_address and d.mac_address != UNKNOWN_VALUE:
                    keys.append(d.mac_address[:MAC_PREFIX_LENGTH].upper())

                device_patterns[d.ip] = keys
                for k in keys:
                    pattern_counts[k] = pattern_counts.get(k, 0) + 1

            # Pass 2: Assign groups — hostname pattern first, then MAC.
            for d in self.devices.values():
                if self._is_unknown_device(d):
                    d.group_id = GROUP_ID_UNKNOWN
                    continue

                if self.local_ip and d.ip == self.local_ip:
                    d.group_id = GROUP_ID_UNKNOWN
                    continue

                if self.gateway_ip and d.ip == self.gateway_ip:
                    d.group_id = GROUP_ID_GATEWAY
                    continue

                # Try hostname pattern first
                if d.hostname and d.hostname != UNKNOWN_VALUE:
                    host_base = re.sub(r'[-_].*$', '', d.hostname.lower())
                    if len(host_base) > HOSTNAME_PATTERN_MIN_LEN:
                        if pattern_counts.get(host_base, 0) >= GROUP_MIN_DEVICE_COUNT:
                            if host_base in patterns:
                                d.group_id = patterns[host_base]
                            else:
                                while current_id - GROUP_ID_DYNAMIC_START < len(GROUP_COLOR_SEQUENCE) and GROUP_COLOR_SEQUENCE[(current_id - GROUP_ID_DYNAMIC_START) % len(GROUP_COLOR_SEQUENCE)] in reserved:
                                    current_id += 1
                                patterns[host_base] = current_id
                                d.group_id = current_id
                                current_id += 1
                            continue

                # Fall back to MAC pattern
                if d.mac_address and d.mac_address != UNKNOWN_VALUE:
                    mac_key = d.mac_address[:MAC_PREFIX_LENGTH].upper()
                    if pattern_counts.get(mac_key, 0) >= GROUP_MIN_DEVICE_COUNT:
                        if mac_key in patterns:
                            d.group_id = patterns[mac_key]
                        else:
                            while current_id - GROUP_ID_DYNAMIC_START < len(GROUP_COLOR_SEQUENCE) and GROUP_COLOR_SEQUENCE[(current_id - GROUP_ID_DYNAMIC_START) % len(GROUP_COLOR_SEQUENCE)] in reserved:
                                current_id += 1
                            patterns[mac_key] = current_id
                            d.group_id = current_id
                            current_id += 1
                        continue

                # Pass 2b: If no pattern matched, check if this device's MAC prefix
                # matches a device already in a group — join that group.
                if d.group_id == GROUP_ID_NONE and d.mac_address and d.mac_address != UNKNOWN_VALUE:
                    mac_key = d.mac_address[:MAC_PREFIX_LENGTH].upper()
                    for other in self.devices.values():
                        if other.ip == d.ip or other.group_id <= GROUP_ID_NONE:
                            continue
                        if other.mac_address and other.mac_address != UNKNOWN_VALUE:
                            if other.mac_address[:MAC_PREFIX_LENGTH].upper() == mac_key:
                                d.group_id = other.group_id
                                break

                if d.group_id == GROUP_ID_NONE:
                    d.group_id = GROUP_ID_NONE

    def set_public_latency(self, p: str, s: Dict[str, float]):
        with self.lock:
            self.public_latencies[p] = s

    def update_device(self, device: Device):
        with self.lock:
            if device.ip not in self.devices:
                self.devices[device.ip] = Device(
                    ip=device.ip,
                    mac_address=device.mac_address,
                    hostname=device.hostname,
                    ping_status=device.ping_status,
                    latency_ms=device.latency_ms,
                    ping_stats=dict(device.ping_stats),
                    current_pings=device.current_pings,
                    target_pings=device.target_pings,
                    group_id=device.group_id,
                    is_offline=device.is_offline,
                    last_ping=device.last_ping
                )
            else:
                o = self.devices[device.ip]
                if device.ping_status:
                    o.ping_status = True
                    o.is_offline = False  # Once online, no longer offline
                if device.latency_ms is not None:
                    o.latency_ms = device.latency_ms
                if device.last_ping is not None:
                    o.last_ping = device.last_ping
                if device.ping_stats:
                    o.ping_stats.update(device.ping_stats)
                # Only overwrite with a *genuine* new value. get_mac_address /
                # get_hostname return None on failure (common for devices in an
                # additional/routed subnet), and None != UNKNOWN_VALUE — so the
                # old condition wiped good discovery data on a flaky re-ping.
                if device.mac_address and device.mac_address != UNKNOWN_VALUE:
                    o.mac_address = device.mac_address
                if device.hostname and device.hostname != UNKNOWN_VALUE:
                    o.hostname = device.hostname
                o.current_pings = device.current_pings
                o.target_pings = device.target_pings
        self.request_render()   # live redraw when a device's ping data changes

    def bump_completed(self, n: int = 1) -> None:
        """Atomically mark n more devices as fully processed (pipeline mode)."""
        with self.lock:
            self.completed_count = min(self.total_count, self.completed_count + n)
        self.request_render()

    def set_total_pings(self, target: int):
        """Set the total ping target. Completion is tracked via record_ping/record_skipped."""
        with self.lock:
            self.total_pings_target = target

    def record_ping(self, success: bool) -> None:
        """Record one ping outcome; updates completion counters atomically."""
        with self.lock:
            if success:
                self.ping_success += 1
            else:
                self.ping_failed += 1
            self.total_pings_completed = self.ping_success + self.ping_failed + self.ping_skipped
        self.request_render()   # live redraw after each ping

    def record_skipped(self, n: int) -> None:
        """Record n pings that were skipped (offline device or 5-fail rule)."""
        if n <= 0:
            return
        with self.lock:
            self.ping_skipped += n
            self.total_pings_completed = self.ping_success + self.ping_failed + self.ping_skipped
        self.request_render()   # live redraw when pings are skipped

    def reclaim_skipped(self, n: int) -> None:
        """Give back n previously-skipped pings. Used when an offline device comes
        back online mid-run: its planned pings were counted as skipped, so we undo
        that before its normal ping cycle records them for real (keeps the pings
        bar consistent — total target is unchanged)."""
        if n <= 0:
            return
        with self.lock:
            self.ping_skipped = max(0, self.ping_skipped - n)
            self.total_pings_completed = self.ping_success + self.ping_failed + self.ping_skipped
        self.request_render()

    @staticmethod
    def _overlay_center(chars: List[str], center_text: str, pb_len: int,
                        color: str = COLOR_BOLD + COLOR_WHITE) -> str:
        """Overlay center_text onto the middle of a bar's cell list and join it into
        a single string. `color` defaults to bold white; the ∞ label is drawn in the
        unlimited-mode purple. Used by every progress bar so a bar at 0% still shows
        its '0%'/∞ label on the empty outline."""
        start = (pb_len - len(center_text)) // 2
        for i, ch in enumerate(center_text):
            pos = start + i
            if 0 <= pos < pb_len:
                chars[pos] = f"{color}{ch}{COLOR_RESET}"
        return "".join(chars)

    def _build_ping_bar(self, pb_len: int, center_text: str,
                        center_color: str = COLOR_BOLD + COLOR_WHITE) -> str:
        """Coloured ping progress bar:
          green  █ = successful pings
          red    █ = every ping that got no answer (failed + skipped/offline)
          dark   ░ = not yet attempted
        """
        total = self.total_pings_target
        if total <= 0:
            # No target yet (startup) or ∞ mode → empty outline, label still shown.
            chars = [f"{COLOR_DARK_GRAY}░{COLOR_RESET}"] * pb_len
            return self._overlay_center(chars, center_text, pb_len, center_color)

        def _blocks(count: int) -> int:
            return max(0, round(pb_len * count / total))

        s = _blocks(self.ping_success)
        # Every ping without a reply is red — failed AND skipped (offline / 5-fail).
        f = _blocks(self.ping_failed + self.ping_skipped)
        # Clamp so rounding never pushes us past pb_len
        s = min(s, pb_len)
        f = min(f, pb_len - s)
        r = pb_len - s - f

        chars = (
            [f"\033[92m█{COLOR_RESET}"] * s +        # bright green  — success
            [f"\033[91m█{COLOR_RESET}"] * f +        # bright red    — no answer
            [f"{COLOR_DARK_GRAY}░{COLOR_RESET}"] * r # outline       — remaining
        )
        return self._overlay_center(chars, center_text, pb_len, center_color)

    def set_phase(self, ph: str, pi: int):
        with self.lock:
            self.current_phase, self.pings_per_device = ph, pi
            phase_map = {
                "Discovery": PHASE_DISCOVERY,
                "Analysis": PHASE_ANALYSIS,
                "Save TXT": PHASE_SAVE_TXT,
                "Ready": PHASE_READY
            }
            self.phase_number = phase_map.get(ph, 0)

    def _build_bar(self, pb_len: int, filled: int, center_text: str) -> str:
        """Build a simple two-tone progress bar with centered text (file output)."""
        chars = [f"{COLOR_GREEN}█{COLOR_RESET}" if i < filled else f"{COLOR_DARK_GRAY}░{COLOR_RESET}"
                 for i in range(pb_len)]
        return self._overlay_center(chars, center_text, pb_len)

    def _build_devices_bar(self, pb_len: int, center_text: str) -> str:
        """Devices progress bar coloured by device status:
          green  █ = online   (responded this scan)
          gray   █ = unknown   (processed, neither online nor identified-offline)
          gray   █ = offline   (identified device that did not respond)
          dark   ░ = not yet processed
        Fully filled once every device has been processed."""
        total = self.total_count
        if total == 0:
            chars = [f"{COLOR_DARK_GRAY}░{COLOR_RESET}"] * pb_len
            return self._overlay_center(chars, center_text, pb_len)

        online  = sum(1 for d in self.devices.values() if d.ping_status)
        offline = sum(1 for d in self.devices.values() if not d.ping_status and (
            (d.mac_address and d.mac_address != UNKNOWN_VALUE) or
            (d.hostname   and d.hostname   != UNKNOWN_VALUE)
        ))
        completed = min(max(self.completed_count, online + offline), total)
        unknown   = max(0, completed - online - offline)

        def _blocks(count: int) -> int:
            return max(0, round(pb_len * count / total))

        g = _blocks(online)
        y = _blocks(unknown)
        k = _blocks(offline)
        # Clamp so rounding never exceeds pb_len
        g = min(g, pb_len)
        y = min(y, pb_len - g)
        k = min(k, pb_len - g - y)
        r = pb_len - g - y - k

        chars = (
            [f"\033[92m█{COLOR_RESET}"] * g +         # bright green  — online
            [f"\033[90m█{COLOR_RESET}"] * y +         # dark gray blk — unknown
            [f"\033[90m█{COLOR_RESET}"] * k +         # dark gray blk — offline
            [f"{COLOR_DARK_GRAY}░{COLOR_RESET}"] * r  # outline       — pending
        )
        return self._overlay_center(chars, center_text, pb_len)

    def finalize_progress(self) -> None:
        """Force both progress bars to 100% at the end of a scan.
        Tops up skipped pings to the target and marks all devices processed,
        so neither bar shows a partial fill due to rounding/early-exit."""
        with self.lock:
            if self.total_pings_target > 0:
                done = self.ping_success + self.ping_failed + self.ping_skipped
                remaining = self.total_pings_target - done
                if remaining > 0:
                    self.ping_skipped += remaining
                self.total_pings_completed = self.total_pings_target
            self.completed_count = self.total_count

    def _internet_avg(self) -> Optional[float]:
        """Overall average latency across all tested internet hosts (mean of each
        host's average), or None when no internet host has a result yet."""
        avgs = [s.get('avg') for s in self.public_latencies.values()
                if s.get('avg') is not None]
        return sum(avgs) / len(avgs) if avgs else None

    def _get_statistics_lines(self, devices: List[Device], colors: bool = True) -> List[str]:
        """Return the Internet hosts section arranged horizontally, 2 lines per host."""
        lines = []

        def format_value(v, is_ping=True):
            if v is None:
                return f"{COLOR_DARK_GRAY}N/A{COLOR_RESET}"
            if not is_ping:
                return f"{COLOR_BLUE}{format_num(v)}{COLOR_RESET}"
            f = format_float(v)
            if not colors:
                return f
            c, r = colorize_ping(v)
            return f"{c}{f}{r}"

        # Preferred order: Google 8.8.8.8, Google 8.8.4.4, Cloudflare 1.1.1.1, Quad9 9.9.9.9
        preferred_order = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9']
        host_items = list(self.public_latencies.items())
        # Sort by preferred order
        sorted_items = sorted(host_items, key=lambda x: preferred_order.index(x[0]) if x[0] in preferred_order else 99)

        # Build two rows: Row 1 = host names + avg, Row 2 = Min/Max aligned under 2nd character
        row1_parts = []
        row2_parts = []
        col_widths = []
        indent = 1  # Min/Max starts 1 char in from the start of the host entry
        for host_ip, stats in sorted_items:
            name = INTERNET_HOST_NAMES.get(host_ip, host_ip)
            # Row 1: "Name (IP) Avg"
            entry = f"{COLOR_BRIGHT_WHITE}{name} ({host_ip}){COLOR_RESET} {format_value(stats.get('avg'))}"
            row1_parts.append(entry)
            # Row 2: "Min/Max: min/max" indented by 2 chars from start of entry
            minmax = f"{' ' * indent}{COLOR_BRIGHT_WHITE}Min/Max:{COLOR_RESET} {format_value(stats.get('min'))}/{format_value(stats.get('max'))}"
            row2_parts.append(minmax)
            col_widths.append(max(get_visible_len(entry), get_visible_len(minmax)))

        if row1_parts:
            gap = "  "  # spacing between host columns
            row1_cols, row2_cols = [], []
            for i, (entry, minmax) in enumerate(zip(row1_parts, row2_parts)):
                w = col_widths[i]
                row1_cols.append(entry + " " * (w - get_visible_len(entry)))
                row2_cols.append(minmax + " " * (w - get_visible_len(minmax)))
            row1 = gap.join(row1_cols)
            row2 = gap.join(row2_cols)
            # Center both rows on the SAME origin so columns stay aligned,
            # then strip trailing spaces so the line never reaches the console
            # width (a full-width line auto-wraps and looks like a blank line).
            max_vis = max(get_visible_len(row1), get_visible_len(row2))
            pad = max(0, (self.table_width - max_vis) // 2)
            lines.append((" " * pad + row1).rstrip())
            lines.append((" " * pad + row2).rstrip())
        else:
            lines.append(f"  {COLOR_DARK_GRAY}No internet hosts tested{COLOR_RESET}")

        return lines

    def _render_internal(self, clear_first: bool = False):
        with self.lock:
            return self._render_internal_locked(clear_first=clear_first)

    def _render_internal_locked(self, clear_first: bool = False, _rebuilding: bool = False):
        output = []
        output.append(f"{COLOR_BLUE}{'=' * self.table_width}{COLOR_RESET}")

        # Phase + spinner on the left
        phi = f"{COLOR_CYAN}{self.phase_number}{COLOR_RESET} - {COLOR_BRIGHT_WHITE}{self.current_phase}"
        if self.pings_per_device == PING_COUNT_INFINITE:
            phi += f" ({INFINITE_SYMBOL} pings)"
        elif self.pings_per_device > 0:
            phi += f" ({format_num(self.pings_per_device)} pings)"
        phi += COLOR_RESET
        title_color = random.choice(TITLE_COLORS)
        title = f"\033[1;38;5;{title_color}mNetwork Scanner{COLOR_RESET}"
        title_visible = "Network Scanner"
        spin_char = random.choice(SPINNER_CHARS)
        spin_color = random.choice(TITLE_COLORS)
        spinner = f"\033[1;38;5;{spin_color}m{spin_char}{COLOR_RESET}"
        # Phase + spinner on the far left.
        phase_prefix = f"   {spinner}   {phi}"
        phase_vis = get_visible_len(phase_prefix)

        # "Threads: N" right-aligned so its right edge meets the progress bar's
        # end column — it sits just left of the centred title, above the bar.
        thr_text = (f"{COLOR_CYAN}Threads: {COLOR_RESET}"
                    f"{COLOR_BRIGHT_WHITE}{format_num(self.active_threads)}{COLOR_RESET}")
        thr_len = len(f"Threads: {format_num(self.active_threads)}")
        bar_end_col = len(PINGS_LABEL) + PROGRESS_BAR_MAX_LEN
        thr_start = max(phase_vis + 1, bar_end_col - thr_len)
        left_vis = thr_start + thr_len

        # Right block: Subnets: ...
        subnets_block = ""
        subnets_vis = 0
        if self.scanned_subnets:
            nets = f"{COLOR_CYAN}Subnets:{COLOR_RESET} {COLOR_BRIGHT_WHITE}{', '.join(self.scanned_subnets)}{COLOR_RESET}"
            subnets_block += nets
            subnets_vis += get_visible_len(nets)

        # Centre "Network Scanner" between the Threads block and the subnets block.
        right_limit = self.table_width - subnets_vis - (TITLE_BLOCK_GAP if subnets_vis else 0)
        title_start = max(left_vis + TITLE_BLOCK_GAP, (self.table_width - len(title_visible)) // 2)
        if title_start + len(title_visible) > right_limit:
            title_start = max(left_vis + TITLE_BLOCK_GAP, right_limit - len(title_visible))
        line = phase_prefix + " " * max(0, thr_start - phase_vis) + thr_text
        line += " " * max(0, title_start - left_vis) + title
        if subnets_block:
            cur = title_start + len(title_visible)
            gap = max(TITLE_BLOCK_GAP, self.table_width - subnets_vis - cur)
            line += " " * gap + subnets_block
        output.append(line)

        # ── Progress bars (always drawn; at 0 they show an empty outline) ─────
        pb_len = PROGRESS_BAR_MAX_LEN
        done = self.ping_success + self.ping_failed + self.ping_skipped
        ping_center_color = COLOR_BOLD + COLOR_WHITE
        if self.is_infinite:
            ping_center = INFINITE_SYMBOL
            ping_center_color = COLOR_PURPLE                 # ∞ in the unlimited purple
            ping_count_text = f"{format_num(done)}/{INFINITE_DISPLAY}"
        elif self.total_pings_target > 0:
            ping_center = f"{done / self.total_pings_target * 100:.0f}%"
            ping_count_text = f"{_done_str(done, self.total_pings_target)}/{format_num_short(self.total_pings_target)}"
        else:
            ping_center, ping_count_text = "0%", "0/0"
        ping_bar_str = (
            f"{COLOR_CYAN}{PINGS_LABEL}{COLOR_RESET}"
            f"{self._build_ping_bar(pb_len, ping_center, ping_center_color)}"
            f" {COLOR_BLUE}{ping_count_text}{COLOR_RESET}"
        )

        if self.total_count > 0:
            dev_center = f"{self.completed_count / self.total_count * 100:.0f}%"
            dev_count_text = f"{format_num(self.completed_count)}/{format_num(self.total_count)}"
        else:
            dev_center, dev_count_text = "0%", "0/0"
        dev_bar_str = (
            f"{COLOR_CYAN}Devices:{COLOR_RESET}"
            f"{self._build_devices_bar(pb_len, dev_center)}{COLOR_RESET}"
            f" {COLOR_BLUE}{dev_count_text}{COLOR_RESET}"
        )

        ni = self.network_info
        ip_str   = ni.get('ip',          UNKNOWN_VALUE) or UNKNOWN_VALUE
        mask_str = ni.get('subnet_mask', UNKNOWN_VALUE) or UNKNOWN_VALUE
        gw_str   = ni.get('gateway',     UNKNOWN_VALUE) or UNKNOWN_VALUE
        dns_str  = ni.get('dns_servers', [UNKNOWN_VALUE])[0] if ni.get('dns_servers') else UNKNOWN_VALUE

        on  = [d for d in self.devices.values() if d.ping_status]
        off = [d for d in self.devices.values() if not d.ping_status and (
            (d.mac_address and d.mac_address != UNKNOWN_VALUE) or
            (d.hostname   and d.hostname   != UNKNOWN_VALUE)
        )]
        fr = max(0, self.total_count - len(on) - len(off))
        used = len(on) + len(off)

        # Two-row info blocks beside the bars. Each block uses kv_block_rows so
        # labels are left-aligned and values right-aligned with a single space
        # between the longest label and the value column.
        def _lab(text, color=COLOR_LIGHT_GREEN):
            return f"{color}{text}:{COLOR_RESET}"
        def _val(value, color):
            return f"{color}{format_num(value)}{COLOR_RESET}"
        def _nval(value):
            return f"{COLOR_BRIGHT_WHITE}{value}{COLOR_RESET}"
        onoff_r0, onoff_r1 = kv_block_rows(_lab('Online'),  _val(len(on), COLOR_GREEN),
                                           _lab('Offline'), _val(len(off), COLOR_RED))
        uf_r0, uf_r1       = kv_block_rows(_lab('Used'), _val(used, COLOR_YELLOW),
                                           _lab('Free'), _val(fr, COLOR_BLUE))
        ipmask_r0, ipmask_r1 = kv_block_rows(_lab('IP', COLOR_CYAN),   _nval(ip_str),
                                             _lab('MASK', COLOR_CYAN), _nval(mask_str))
        gwdns_r0, gwdns_r1   = kv_block_rows(_lab('GW', COLOR_CYAN),  _nval(gw_str),
                                             _lab('DNS', COLOR_CYAN), _nval(dns_str))
        stat_r0 = onoff_r0 + "  " + uf_r0
        stat_r1 = onoff_r1 + "  " + uf_r1
        net_r0  = ipmask_r0 + "  " + gwdns_r0
        net_r1  = ipmask_r1 + "  " + gwdns_r1
        stats_w = get_visible_len(stat_r0)

        max_bar_len = max(get_visible_len(ping_bar_str), get_visible_len(dev_bar_str))
        # Pack the stats + network info immediately to the right of the bars so
        # they sit close to the bars and the table stays as narrow as possible.
        stats_start = max_bar_len + HEADER_INFO_GAP
        net_start = stats_start + stats_w + HEADER_INFO_GAP

        output.append(_assemble_row([(0, ping_bar_str), (stats_start, stat_r0), (net_start, net_r0)]).rstrip())
        output.append(_assemble_row([(0, dev_bar_str), (stats_start, stat_r1), (net_start, net_r1)]).rstrip())

        output.append(f"{COLOR_BLUE}{'=' * self.table_width}{COLOR_RESET}")

        headers = [
            format_cell(colorize_header("IP Address"), COL_IP_WIDTH),
            format_cell_center(colorize_header("Status"), COL_STATUS_WIDTH),
            format_cell_center(colorize_header("Group"), COL_GROUP_WIDTH),
            " ",
            format_cell(colorize_header("Hostname"), COL_HOSTNAME_WIDTH),
            format_cell_center(colorize_header("Ping Avg"), COL_PING_WIDTH),
            format_cell_center(colorize_header("Ping Min"), COL_PING_WIDTH),
            format_cell_center(colorize_header("Ping Max"), COL_PING_WIDTH),
            format_cell_center(colorize_header("Last Ping"), COL_PING_WIDTH),
            format_cell_center(colorize_header("Progress"), COL_PROGRESS_WIDTH),
            format_cell_center(colorize_header("MAC Address"), COL_MAC_WIDTH)
        ]
        output.append("".join(headers))
        output.append(f"{COLOR_BLUE}{'-' * self.table_width}{COLOR_RESET}")

        pinned_order = {ip: i for i, ip in enumerate(self.pinned_ips)}

        def _ip_sort_key(x: str):
            parts = x.split('.')
            ip_key = tuple(int(p) for p in parts) if len(parts) == IP_OCTET_COUNT and all(p.isdigit() for p in parts) else (999, 0, 0, 0)
            # Pinned IPs always sort to the very top, in their configured order.
            if x in pinned_order:
                return (0, pinned_order[x], (0, 0, 0, 0))
            return (1, 0, ip_key)
        # Per-column extremes among online devices: a red block marks the highest
        # (slowest) value and a green block the lowest (fastest) in each column.
        # Recomputed every render, so the marks follow the values dynamically.
        online_devs = [(dip, dv) for dip, dv in self.devices.items() if dv.ping_status]
        avg_hi, avg_lo = _value_extremes((dip, dv.ping_stats.get('avg')) for dip, dv in online_devs)
        min_hi, min_lo = _value_extremes((dip, dv.ping_stats.get('min')) for dip, dv in online_devs)
        max_hi, max_lo = _value_extremes((dip, dv.ping_stats.get('max')) for dip, dv in online_devs)
        last_hi, last_lo = _value_extremes((dip, dv.last_ping) for dip, dv in online_devs)

        def _mark(dip, hi, lo):
            if dip == hi:
                return PING_MARK_HIGH
            if dip == lo:
                return PING_MARK_LOW
            return ""

        sorted_ips = sorted(self.devices.keys(), key=_ip_sort_key)
        for ip in sorted_ips:
            d = self.devices[ip]
            # Show devices that responded this scan, plus known devices loaded from
            # the DB and pinned IPs (these are listed even while offline).
            if not d.ping_status and not d.from_db and ip not in pinned_order:
                continue
            online = d.ping_status
            status = STATUS_ONLINE if online else STATUS_OFFLINE
            na = f"{COLOR_DARK_GRAY}N/A{COLOR_RESET}"
            if online:
                ac, ar = colorize_ping(d.ping_stats.get('avg'))
                mc, mr = colorize_ping(d.ping_stats.get('max')) if d.ping_stats.get('max') else (COLOR_WHITE, COLOR_RESET)
                nc, nr = colorize_ping(d.ping_stats.get('min')) if d.ping_stats.get('min') else (COLOR_WHITE, COLOR_RESET)
                avg_text = f"{_mark(ip, avg_hi, avg_lo)}{ac}{format_float(d.ping_stats.get('avg'))}{ar}" if d.ping_stats.get('avg') else na
                max_text = f"{_mark(ip, max_hi, max_lo)}{mc}{format_float(d.ping_stats.get('max'))}{mr}" if d.ping_stats.get('max') else na
                min_text = f"{_mark(ip, min_hi, min_lo)}{nc}{format_float(d.ping_stats.get('min'))}{nr}" if d.ping_stats.get('min') else na
                lc, lr = colorize_ping(d.last_ping) if d.last_ping is not None else (COLOR_WHITE, COLOR_RESET)
                last_text = f"{_mark(ip, last_hi, last_lo)}{lc}{format_float(d.last_ping)}{lr}" if d.last_ping is not None else na
            else:
                avg_text = min_text = max_text = last_text = na

            mac = d.mac_address or UNKNOWN_VALUE
            # Hostname column: real name → magenta; if unknown, fall back to the
            # MAC manufacturer in yellow; otherwise 'Unknown' in gray.
            host, host_kind = resolve_hostname_display(d.hostname, mac)
            # Mark the gateway's hostname when this network was recognised from
            # the known-devices DB (request: a "#" before the GW hostname).
            if self.known_network and self.gateway_ip and d.ip == self.gateway_ip:
                host = f"{KNOWN_GATEWAY_HOST_PREFIX}{host}"
            host = truncate_host(host, COL_HOSTNAME_WIDTH)

            is_local = self.local_ip and d.ip == self.local_ip
            if is_local:
                host_color = colorize_local_hostname(host)
            elif host_kind == 'vendor':
                host_color = f"{COLOR_YELLOW}{host}{COLOR_RESET}"
            else:
                host_color = colorize_hostname(host)

            # Group visualization — 3 colored blocks if grouped, 3 spaces if not.
            # The own host's group uses the same magenta as its IP/hostname.
            group_text = "   "
            if is_local:
                group_text = f"{COLOR_MAGENTA}███{COLOR_RESET}"
            elif d.group_id > GROUP_ID_NONE:
                if d.group_id == GROUP_ID_UNKNOWN:
                    color = GROUP_UNKNOWN_COLOR
                elif d.group_id == GROUP_ID_GATEWAY:
                    color = self.gateway_color
                else:
                    c_idx = (d.group_id - GROUP_ID_DYNAMIC_START) % len(GROUP_COLOR_SEQUENCE)
                    color = GROUP_COLOR_SEQUENCE[c_idx]
                group_text = f"\033[38;5;{color}m███{COLOR_RESET}"

            if online:
                inf = d.target_pings == PING_COUNT_INFINITE
                target_disp = INFINITE_DISPLAY if inf else f"{COLOR_GREEN}{format_num_short(d.target_pings)}{COLOR_RESET}"
                cur_disp = _done_str(d.current_pings, d.target_pings, infinite=inf)
                progress_text = f"{COLOR_GREEN}{cur_disp}{COLOR_RESET}/{target_disp}"
            else:
                progress_text = na

            # Color IP: magenta for local, cyan for online, gray for offline.
            if self.local_ip and d.ip == self.local_ip:
                ip_color = colorize_local_ip(d.ip)
            elif online:
                ip_color = colorize_ip(d.ip)
            else:
                ip_color = f"{COLOR_DARK_GRAY}{d.ip}{COLOR_RESET}"
            # 'Unknown' MAC is centered; a real MAC stays left-aligned.
            mac_cell = (format_cell_center(colorize_mac(mac), COL_MAC_WIDTH)
                        if mac == UNKNOWN_VALUE else
                        format_cell(colorize_mac(mac), COL_MAC_WIDTH))
            line = (
                format_cell(ip_color, COL_IP_WIDTH) +
                format_cell_center(colorize_status(status), COL_STATUS_WIDTH) +
                format_cell_center(group_text, COL_GROUP_WIDTH) +
                " " +
                format_cell(host_color, COL_HOSTNAME_WIDTH) +
                format_cell_center(avg_text, COL_PING_WIDTH) +
                format_cell_center(min_text, COL_PING_WIDTH) +
                format_cell_center(max_text, COL_PING_WIDTH) +
                format_cell_center(last_text, COL_PING_WIDTH) +
                format_cell_center(progress_text, COL_PROGRESS_WIDTH) +
                mac_cell
            )
            output.append(line)

        # Whole Network summary row
        all_avgs = [d.ping_stats.get('avg') for d in self.devices.values() if d.ping_stats.get('avg') is not None]
        all_mins = [d.ping_stats.get('min') for d in self.devices.values() if d.ping_stats.get('min') is not None]
        all_maxs = [d.ping_stats.get('max') for d in self.devices.values() if d.ping_stats.get('max') is not None]
        if all_avgs:
            net_avg = sum(all_avgs) / len(all_avgs)
            net_min = min(all_mins) if all_mins else None
            net_max = max(all_maxs) if all_maxs else None
            ac, ar = colorize_ping(net_avg)
            avg_text = f"{ac}{format_float(net_avg)}{ar}"
            min_text = f"{colorize_ping(net_min)[0]}{format_float(net_min)}{colorize_ping(net_min)[1]}" if net_min else f"{COLOR_DARK_GRAY}N/A{COLOR_RESET}"
            max_text = f"{colorize_ping(net_max)[0]}{format_float(net_max)}{colorize_ping(net_max)[1]}" if net_max else f"{COLOR_DARK_GRAY}N/A{COLOR_RESET}"
            wn_label = f"{COLOR_BOLD}{COLOR_LIGHT_GREEN}Whole Network{COLOR_RESET}"
            # Overall internet ping average, shown to the right of "Whole Network".
            inet_avg = self._internet_avg()
            if inet_avg is not None:
                iac, iar = colorize_ping(inet_avg)
                inet_label = f"{COLOR_BRIGHT_WHITE}Internet Avg:{COLOR_RESET} {iac}{format_float(inet_avg)}{iar}"
            else:
                inet_label = ""
            mid_width = COL_STATUS_WIDTH + COL_GROUP_WIDTH + 1 + COL_HOSTNAME_WIDTH
            output.append(f"{COLOR_BLUE}{'-' * self.table_width}{COLOR_RESET}")
            output.append(
                format_cell(wn_label, COL_IP_WIDTH) +
                format_cell(inet_label, mid_width) +
                format_cell_center(avg_text, COL_PING_WIDTH) +
                format_cell_center(min_text, COL_PING_WIDTH) +
                format_cell_center(max_text, COL_PING_WIDTH) +
                format_cell_center("", COL_PING_WIDTH) +
                format_cell_center("", COL_PROGRESS_WIDTH) +
                format_cell("", COL_MAC_WIDTH)
            )

        # Separator between the Whole Network row and the internet pings.
        output.append(f"{COLOR_BLUE}{'-' * self.table_width}{COLOR_RESET}")
        output.extend(self._get_statistics_lines(list(self.devices.values()), colors=True))
        output.append(f"{COLOR_BLUE}{'=' * self.table_width}{COLOR_RESET}")

        # Controls hint footer — only while actively scanning. Turns yellow and
        # shows the resume wording while paused.
        if self.phase_number in (PHASE_DISCOVERY, PHASE_ANALYSIS):
            if self.paused:
                hint = f"{COLOR_YELLOW}{CONTROLS_HINT_PAUSED}{COLOR_RESET}"
            else:
                hint = f"{COLOR_DARK_GRAY}{CONTROLS_HINT_RUNNING}{COLOR_RESET}"
            pad = max(0, (self.table_width - get_visible_len(hint)) // 2)
            output.append(" " * pad + hint)

        # On every update: (1) grow the table width to the widest output line so no
        # line ever wraps, and (2) re-check the actual console window width and
        # adjust it to match the table width (the window can drift — be too small
        # or too large — so this keeps it fitted on every frame, not just on
        # growth). Table width only ever grows, never below TABLE_WIDTH.
        content_w = max((get_visible_len(line) for line in output), default=0)
        needed = max(TABLE_WIDTH, content_w)
        grew = needed > self.table_width
        if grew:
            self.table_width = needed
        target_cols = self.table_width + CONSOLE_BORDER_MARGIN
        cur_cols, max_cols = _console_window_metrics()
        if grew or _should_resize_window(cur_cols, max_cols, target_cols):
            _resize_terminal(target_cols)
            _center_console_window()
            # If the table grew, the output was built at the OLD width — rebuild
            # once so this very frame is already correct (no wrap, no flicker).
            if grew and not _rebuilding:
                return self._render_internal_locked(clear_first=clear_first, _rebuilding=True)

        self._write_frame(output, clear_first)

    def _write_frame(self, output: List[str], clear_first: bool = False) -> None:
        """Redraw the whole frame in place, smoothly and without leaving scrollback.

        - \\033[H homes the cursor; each line ends with \\033[K (erase to EOL) and
          the frame ends with \\033[J (erase to end of screen). This overwrites
          the previous frame in place instead of a full \\033[2J clear (which
          flashes and pushes old content into the scrollback on Windows). With no
          trailing newline the cursor never advances past the last line, so a
          fitting frame creates no scrollback — the user can't scroll up.
        - The first frame additionally does \\033[3J\\033[2J to wipe whatever was
          on screen (and its scrollback) before the scan started.

        (No synchronized-output \\033[?2026 markers: some Windows consoles hold the
        frame until a resize forces a repaint, which left the window blank.)
        """
        body = "\033[K\n".join(output) + "\033[K"
        prefix = "\033[3J\033[2J\033[H" if clear_first else "\033[H"
        sys.stdout.write(prefix + body + "\033[J")
        sys.stdout.flush()

    def _render(self, force: bool = False, clear_first: bool = False):
        if self._exiting:   # ESC pressed: keep the closing screen, don't repaint
            return
        if not force:
            now = time.time()
            if now - self.last_render_time < self.render_throttle:
                return
        self.last_render_time = time.time()
        self._render_internal(clear_first=clear_first)

    def get_final_results_text(self) -> str:
        """Generate plain text output matching the terminal format."""
        with self.lock:
            devs = list(self.devices.values())
            lines = []

            def fmt(s):
                """Strip ANSI codes."""
                return re.sub(r'\033\[[0-9;]*m', '', s)

            # Header separator
            lines.append("=" * self.table_width)

            # Title line: phase on the left, title centred,
            # "Threads: N  Subnets: ..." on the right — mirrors the live view.
            phase = f"{self.phase_number} - {self.current_phase}"
            if self.pings_per_device == PING_COUNT_INFINITE:
                phase += f" ({INFINITE_SYMBOL} pings)"
            elif self.pings_per_device > 0:
                phase += f" ({format_num(self.pings_per_device)} pings)"
            title = "Network Scanner"
            phase_prefix = " " * FILE_HEADER_PHASE_INDENT + phase
            phase_vis = len(phase_prefix)
            # "Threads: N" right-aligned to the progress-bar end column, just
            # left of the centred title — mirrors the live view.
            thr_plain = f"Threads: {format_num(self.active_threads)}"
            bar_end_col = len(PINGS_LABEL) + PROGRESS_BAR_MAX_LEN
            thr_start = max(phase_vis + 1, bar_end_col - len(thr_plain))
            left_vis = thr_start + len(thr_plain)
            subnets_text = f"Subnets: {', '.join(self.scanned_subnets)}" if self.scanned_subnets else ""
            right_vis = len(subnets_text)

            right_limit = self.table_width - right_vis - (TITLE_BLOCK_GAP if subnets_text else 0)
            title_start = max(left_vis + TITLE_BLOCK_GAP, (self.table_width - len(title)) // 2)
            if title_start + len(title) > right_limit:
                title_start = max(left_vis + TITLE_BLOCK_GAP, right_limit - len(title))
            header_line = phase_prefix + " " * max(0, thr_start - phase_vis) + thr_plain
            header_line += " " * max(0, title_start - left_vis) + title
            if subnets_text:
                cur = title_start + len(title)
                gap = max(TITLE_BLOCK_GAP, self.table_width - right_vis - cur)
                header_line += " " * gap + subnets_text
            lines.append(header_line)

            # Progress bars (always at 100%)
            ping_bar_str = ""
            if self.total_pings_target > 0:
                pb_len = PROGRESS_BAR_MAX_LEN
                pct = 100.0
                filled = pb_len
                pct_text = f"{pct:.0f}%"
                ping_bar_str = f"{PINGS_LABEL}{self._build_bar(pb_len, filled, pct_text)} {_done_str(self.total_pings_completed, self.total_pings_target)}/{format_num_short(self.total_pings_target)}"

            dev_bar_str = ""
            if self.total_count > 0:
                dev_pb_len = PROGRESS_BAR_MAX_LEN
                dev_pct = 100.0
                dev_filled = dev_pb_len
                dev_pct_text = f"{dev_pct:.0f}%"
                dev_bar_str = f"Devices:{self._build_bar(dev_pb_len, dev_filled, dev_pct_text)} {format_num(self.completed_count)}/{format_num(self.total_count)}"

            # Two-row info block (mirrors the live view): stats centred, network
            # info right-aligned. Plain text — no colours.
            ni = self.network_info
            ip_str   = ni.get('ip',          UNKNOWN_VALUE) or UNKNOWN_VALUE
            mask_str = ni.get('subnet_mask', UNKNOWN_VALUE) or UNKNOWN_VALUE
            gw_str   = ni.get('gateway',     UNKNOWN_VALUE) or UNKNOWN_VALUE
            dns_str  = ni.get('dns_servers', [UNKNOWN_VALUE])[0] if ni.get('dns_servers') else UNKNOWN_VALUE
            on  = [d for d in devs if d.ping_status]
            off = [d for d in devs if not d.ping_status and (
                (d.mac_address and d.mac_address != UNKNOWN_VALUE) or
                (d.hostname    and d.hostname    != UNKNOWN_VALUE)
            )]
            fr = max(0, self.total_count - len(on) - len(off))
            used = len(on) + len(off)
            # Same label-left / value-right blocks as the live view (plain text).
            onoff_r0, onoff_r1 = kv_block_rows("Online:", format_num(len(on)),
                                               "Offline:", format_num(len(off)))
            uf_r0, uf_r1       = kv_block_rows("Used:", format_num(used),
                                               "Free:", format_num(fr))
            ipmask_r0, ipmask_r1 = kv_block_rows("IP:", ip_str, "MASK:", mask_str)
            gwdns_r0, gwdns_r1   = kv_block_rows("GW:", gw_str, "DNS:", dns_str)
            stat_r0 = onoff_r0 + "  " + uf_r0
            stat_r1 = onoff_r1 + "  " + uf_r1
            net_r0  = ipmask_r0 + "  " + gwdns_r0
            net_r1  = ipmask_r1 + "  " + gwdns_r1
            stats_w = get_visible_len(stat_r0)

            max_bar_len = max(get_visible_len(ping_bar_str), get_visible_len(dev_bar_str)) if (ping_bar_str or dev_bar_str) else 0
            stats_start = max_bar_len + HEADER_INFO_GAP
            net_start = stats_start + stats_w + HEADER_INFO_GAP
            lines.append(_assemble_row([(0, ping_bar_str), (stats_start, stat_r0), (net_start, net_r0)]).rstrip())
            lines.append(_assemble_row([(0, dev_bar_str), (stats_start, stat_r1), (net_start, net_r1)]).rstrip())

            lines.append("=" * self.table_width)

            # Table header — the Group column is omitted in the plain-text file
            # output (the block glyphs misaligned in text viewers); the remaining
            # columns are shifted up to fill the gap.
            lines.append(
                f"{'IP Address':<{COL_IP_WIDTH-1}} {'Status':<{COL_STATUS_WIDTH-1}} "
                f"{'Hostname':<{COL_HOSTNAME_WIDTH-1}} "
                f"{'Ping Avg':<{COL_PING_WIDTH-1}} {'Ping Min':<{COL_PING_WIDTH-1}} {'Ping Max':<{COL_PING_WIDTH-1}} {'Last Ping':<{COL_PING_WIDTH-1}} "
                f"{'Progress':<{COL_PROGRESS_WIDTH-1}} {'MAC Address':<{COL_MAC_WIDTH}}"
            )
            lines.append("-" * self.table_width)

            # Device rows — online devices plus known (DB) and pinned devices,
            # even offline. Pinned IPs are listed first, in configured order.
            pinned_order = {pip: i for i, pip in enumerate(self.pinned_ips)}

            def _ip_sort_key(x: str):
                parts = x.split('.')
                ip_key = (tuple(int(p) for p in parts)
                          if len(parts) == IP_OCTET_COUNT and all(p.isdigit() for p in parts)
                          else (999, 0, 0, 0))
                if x in pinned_order:
                    return (0, pinned_order[x], (0, 0, 0, 0))
                return (1, 0, ip_key)
            sorted_ips = sorted(self.devices.keys(), key=_ip_sort_key)
            for ip in sorted_ips:
                d = self.devices[ip]
                if not d.ping_status and not d.from_db and ip not in pinned_order:
                    continue
                online = d.ping_status
                status = STATUS_ONLINE if online else STATUS_OFFLINE
                mac = d.mac_address or UNKNOWN_VALUE
                host, _ = resolve_hostname_display(d.hostname, mac)
                # Mark the gateway's hostname when the network was recognised
                # from the known-devices DB — mirrors the live view.
                if self.known_network and self.gateway_ip and d.ip == self.gateway_ip:
                    host = f"{KNOWN_GATEWAY_HOST_PREFIX}{host}"
                # File field is COL_HOSTNAME_WIDTH-1 wide; truncate to fit exactly
                # so a long name can never shift the following columns.
                host = truncate_host(host, COL_HOSTNAME_WIDTH - 1)

                if online:
                    inf = d.target_pings == PING_COUNT_INFINITE
                    target_disp = INFINITE_SYMBOL if inf else format_num_short(d.target_pings)
                    progress = f"{_done_str(d.current_pings, d.target_pings, infinite=inf)}/{target_disp}"
                    avg = format_float(d.ping_stats.get('avg')) if d.ping_stats.get('avg') else "N/A"
                    mn  = format_float(d.ping_stats.get('min')) if d.ping_stats.get('min') else "N/A"
                    mx  = format_float(d.ping_stats.get('max')) if d.ping_stats.get('max') else "N/A"
                    lp  = format_float(d.last_ping) if d.last_ping is not None else "N/A"
                else:
                    progress, avg, mn, mx, lp = "-", "N/A", "N/A", "N/A", "N/A"

                # 'Unknown' MAC is centered; a real MAC stays left-aligned.
                mac_cell = mac.center(COL_MAC_WIDTH) if mac == UNKNOWN_VALUE else f"{mac:<{COL_MAC_WIDTH}}"
                lines.append(
                    f"{d.ip:<{COL_IP_WIDTH-1}} {status:<{COL_STATUS_WIDTH-1}} "
                    f"{host:<{COL_HOSTNAME_WIDTH-1}} "
                    f"{avg:<{COL_PING_WIDTH-1}} {mn:<{COL_PING_WIDTH-1}} {mx:<{COL_PING_WIDTH-1}} {lp:<{COL_PING_WIDTH-1}} "
                    f"{progress:<{COL_PROGRESS_WIDTH-1}} {mac_cell}"
                )

            # Whole Network summary row
            all_avgs = [d.ping_stats.get('avg') for d in devs if d.ping_stats.get('avg') is not None]
            all_mins = [d.ping_stats.get('min') for d in devs if d.ping_stats.get('min') is not None]
            all_maxs = [d.ping_stats.get('max') for d in devs if d.ping_stats.get('max') is not None]
            if all_avgs:
                net_avg = sum(all_avgs) / len(all_avgs)
                net_min = min(all_mins) if all_mins else None
                net_max = max(all_maxs) if all_maxs else None
                inet_avg = self._internet_avg()
                inet_text = (f"Internet Avg: {format_float(inet_avg)}"
                             if inet_avg is not None else "")
                mid_width = (COL_STATUS_WIDTH - 1) + 1 + (COL_HOSTNAME_WIDTH - 1)
                lines.append("-" * self.table_width)
                lines.append(
                    f"{'Whole Network':<{COL_IP_WIDTH-1}} "
                    f"{inet_text:<{mid_width}} "
                    f"{format_float(net_avg):<{COL_PING_WIDTH-1}} "
                    f"{format_float(net_min) if net_min else 'N/A':<{COL_PING_WIDTH-1}} "
                    f"{format_float(net_max) if net_max else 'N/A':<{COL_PING_WIDTH-1}} "
                    f"{'':<{COL_PING_WIDTH-1}} "
                    f"{'':<{COL_PROGRESS_WIDTH-1}} {'':<{COL_MAC_WIDTH}}"
                )

            # Separator between the Whole Network row and the internet pings.
            lines.append("-" * self.table_width)
            # Internet stats (2 lines, centered)
            stat_lines = self._get_statistics_lines(devs, colors=False)
            ansi_re = re.compile(r'\033\[[0-9;]*m')
            lines.extend(ansi_re.sub('', line) for line in stat_lines)

            lines.append("=" * self.table_width)
            # The saved report must be pure plain text — strip every escape code
            # (the progress-bar rows still carry colour codes at this point).
            return ansi_re.sub('', '\n'.join(lines))


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT LISTENER
# ═══════════════════════════════════════════════════════════════════════════════

def _hard_exit_now(lt: "Optional[LiveTable]" = None) -> None:
    """ESC handler: stop repainting, wipe the table and show a short closing
    message so the screen reads as an intentional shutdown (not a crash) while the
    process tears down, then kill it at once (daemon worker threads die with it)."""
    try:
        if lt is not None:
            lt._exiting = True          # stop any worker thread from repainting
            lt.stop_refresh_timer()
    except Exception:
        pass
    try:
        # Clear the screen + scrollback so the frozen table is gone immediately,
        # reset colours, show the cursor, and print a centred closing message.
        width = lt.table_width if lt is not None else TABLE_WIDTH
        pad = max(0, (width - len(CLOSING_MESSAGE)) // 2)
        sys.stdout.write("\033[3J\033[2J\033[H" + COLOR_RESET + "\033[?25h"
                         + "\n" + " " * pad + CLOSING_MESSAGE + "\n")
        sys.stdout.flush()
    except Exception:
        pass
    os._exit(0)


def _handle_scan_key(ch: str, control: ScannerControl, lt: "Optional[LiveTable]") -> bool:
    """Apply one keypress during a scan. Returns True when the listener should
    stop. ESC aborts immediately; P pauses/resumes; Q stops and keeps results."""
    if ch in ('\x1b', '\x03'):          # ESC / Ctrl-C → abort now, no end screen
        control.request_hard_exit()
        _hard_exit_now(lt)              # does not return
        return True
    if ch == 'p':                       # pause / resume
        control.toggle_pause()
        if lt is not None:
            lt.set_paused(control.paused)
        return False
    if ch == 'q':                       # graceful stop → show end screen
        control.request_stop()
        return True
    return False


def input_listener(control: ScannerControl, lt: "Optional[LiveTable]" = None):
    if platform.system() == "Windows":
        _input_listener_windows(control, lt)
        return
    if not sys.stdin.isatty() or termios is None or tty is None:
        return

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while not control.shutdown:
            rl, _, _ = select.select([fd], [], [], INPUT_POLL_TIMEOUT)
            if rl:
                inp = os.read(fd, INPUT_READ_SIZE).decode('utf-8', errors='ignore').lower()
                ch = '\x1b' if '\x1b' in inp else (inp[:1] if inp else '')
                if ch and _handle_scan_key(ch, control, lt):
                    break
            if control.should_exit_task():
                break
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _input_listener_windows(control: ScannerControl, lt: "Optional[LiveTable]" = None):
    """Non-blocking keyboard listener for Windows using msvcrt."""
    if _msvcrt is None:
        return
    while not control.shutdown:
        if _msvcrt.kbhit():
            raw = _msvcrt.getch()
            if raw in (b'\x00', b'\xe0'):
                _msvcrt.getch()  # consume extended key (arrows, F-keys, …)
                continue
            ch = raw.decode('utf-8', errors='ignore').lower()
            if _handle_scan_key(ch, control, lt):
                break
        if control.should_exit_task():
            break
        time.sleep(KEY_SLEEP_INTERVAL)


# ═══════════════════════════════════════════════════════════════════════════════
# PING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def ping_succeeded(returncode: int, stdout: str) -> bool:
    """True only for a genuine echo reply from the target host.

    Windows `ping` returns exit code 0 even when a router answers with
    'Destination host unreachable' (DE: 'Zielhost nicht erreichbar') — that is
    NOT the host being online. A real reply always reports a TTL, while
    unreachable/timeout replies do not. We therefore require a TTL and reject
    the known unreachable/timeout phrases (English + German)."""
    if returncode != 0:
        return False
    low = stdout.lower()
    if 'ttl=' not in low:
        return False
    bad = ('unreachable', 'nicht erreichbar', 'timed out',
           'zeitüberschreitung', 'expired in transit', 'abgelaufen',
           'general failure', 'allgemeiner fehler')
    return not any(b in low for b in bad)


def _seed_device_identity(lt: "Optional[LiveTable]", ip: str,
                          local_ip: Optional[str], local_mac: Optional[str]):
    """Return (mac, hostname) for a host WITHOUT any slow lookup. Uses the local
    node name for our own IP and any values already known from the DB pre-load;
    everything else stays None and is resolved later — and only AFTER the host has
    actually replied. This keeps the ~9.45s reverse-DNS stall off the ping path so
    known/DB devices start pinging immediately."""
    if local_ip and ip == local_ip:
        # Docker Desktop injects "host.docker.internal" → use the real machine name.
        return local_mac, platform.node()
    if lt:
        with lt.lock:
            existing = lt.devices.get(ip)
        if existing:
            mac = (existing.mac_address
                   if existing.mac_address and existing.mac_address != UNKNOWN_VALUE else None)
            host = (existing.hostname
                    if existing.hostname and existing.hostname != UNKNOWN_VALUE else None)
            return mac, host
    return None, None


def _resolve_device_identity(ip: str, dev: Device, lt: "Optional[LiveTable]", system: str,
                             local_ip: Optional[str], local_mac: Optional[str]) -> None:
    """Resolve MAC / hostname for a host that just came online. Runs in a daemon
    thread so the slow reverse-DNS / NetBIOS lookups never stall the ping loop —
    the device already shows as online; its name just fills in a moment later."""
    if dev.mac_address is None or dev.mac_address == UNKNOWN_VALUE:
        refreshed = get_mac_address(ip, system, local_ip, local_mac)
        if refreshed:
            dev.mac_address = refreshed
    if dev.hostname is None or dev.hostname == UNKNOWN_VALUE:
        h = get_hostname(ip)
        if h:
            dev.hostname = h
    # Cross-subnet fallback: a direct NetBIOS query reaches hosts that reverse
    # DNS / ARP cannot (different subnet, no PTR).
    need_host = dev.hostname is None or dev.hostname == UNKNOWN_VALUE
    need_mac = dev.mac_address is None or dev.mac_address == UNKNOWN_VALUE
    if system == "Windows" and (need_host or need_mac):
        nb_name, nb_mac = _netbios_lookup(ip)
        if need_host and nb_name:
            dev.hostname = nb_name
        if need_mac and nb_mac:
            dev.mac_address = nb_mac
    if lt:
        # Patch ONLY the identity fields on the live entry. This thread can finish
        # seconds late (slow reverse DNS); calling the full update_device() would
        # write back this dev's stale current_pings/target_pings (= the single
        # discovery ping) and clobber the running analysis — making a device look
        # like it was "pinged only once". So never touch the ping counters here.
        with lt.lock:
            entry = lt.devices.get(ip)
            if entry is not None:
                if dev.mac_address and dev.mac_address != UNKNOWN_VALUE:
                    entry.mac_address = dev.mac_address
                if dev.hostname and dev.hostname != UNKNOWN_VALUE:
                    entry.hostname = dev.hostname
        lt.request_render()


def ping_host_multiple(
    ip: str,
    count: int = DEFAULT_PING_COUNT,
    lt: Optional[LiveTable] = None,
    ctrl: Optional[ScannerControl] = None,
    local_ip: str = None,
    local_mac: str = None,
    interval_ms: int = PING_INTERVAL_MS
) -> Device:
    """Ping a host multiple times and return a Device with collected stats.
    count == PING_COUNT_INFINITE pings forever until the scan is stopped."""
    system = platform.system()
    # Identity is seeded WITHOUT a network lookup (no upfront reverse DNS / arp);
    # the ping fires immediately and the name is resolved after the first reply.
    mac, host = _seed_device_identity(lt, ip, local_ip, local_mac)

    lats: List[float] = []
    dev = Device(ip=ip, mac_address=mac, hostname=host, target_pings=count, current_pings=0)

    if lt:
        lt.update_device(dev)
        with lt.lock:
            lt.active_threads += 1

    try:
        _ping_loop(ip, count, lt, ctrl, local_ip, local_mac, dev, lats, system, interval_ms)
    finally:
        if lt:
            with lt.lock:
                lt.active_threads = max(0, lt.active_threads - 1)
    return dev


def _ping_loop(ip, count, lt, ctrl, local_ip, local_mac, dev, lats, system,
               interval_ms=PING_INTERVAL_MS):
    """Inner ping loop for ping_host_multiple (kept separate so the active-thread
    counter can be decremented reliably in a finally block). Paces consecutive
    pings to the same host by interval_ms, and supports an unlimited (∞) count."""
    succ = 0
    consecutive_failures = 0
    infinite = count == PING_COUNT_INFINITE
    interval_s = max(0, interval_ms) / 1000.0
    i = 0
    while infinite or i < count:
        if ctrl and ctrl.should_exit_task():
            # Record remaining as skipped (scan was aborted)
            if lt and not infinite and count - i > 0:
                lt.record_skipped(count - i)
            break
        if ctrl:
            ctrl.wait_if_paused()
            if ctrl.should_exit_task():
                if lt and not infinite and count - i > 0:
                    lt.record_skipped(count - i)
                break

        try:
            success, latency = measure_ping(ip, system)
            dev.current_pings = i + 1

            if success:
                consecutive_failures = 0
                succ += 1
                dev.ping_status = True
                if lt:
                    lt.record_ping(True)
                if succ == 1:
                    # First reply: resolve any still-unknown MAC/hostname in a
                    # daemon thread so the slow reverse-DNS / NetBIOS lookups never
                    # stall this ping loop. Known/DB devices are already seeded, so
                    # this is skipped for them entirely.
                    if (dev.mac_address is None or dev.mac_address == UNKNOWN_VALUE
                            or dev.hostname is None or dev.hostname == UNKNOWN_VALUE):
                        threading.Thread(
                            target=_resolve_device_identity,
                            args=(ip, dev, lt, system, local_ip, local_mac),
                            daemon=True
                        ).start()
                if latency is not None:
                    lats.append(latency)
                    dev.last_ping = latency   # most recently measured value
                    dev.latency_ms = sum(lats) / len(lats)
                    dev.ping_stats = {
                        'min': min(lats),
                        'max': max(lats),
                        'avg': sum(lats) / len(lats),
                        'count': succ
                    }
            else:
                consecutive_failures += 1
                if lt:
                    lt.record_ping(False)
                # 5 consecutive failures during a finite analysis → device is
                # offline, skip the rest. (∞ mode keeps probing — it's a monitor.)
                if (not infinite and count > DISCOVERY_PING_COUNT
                        and consecutive_failures >= ANALYSIS_MAX_CONSECUTIVE_FAILURES):
                    remaining = count - (i + 1)
                    if remaining > 0:
                        dev.current_pings = count   # show as fully processed
                        if lt:
                            lt.record_skipped(remaining)
                            lt.update_device(dev)
                    break

            if lt:
                lt.update_device(dev)
        except Exception:
            dev.current_pings = i + 1
            if lt:
                lt.update_device(dev)
            i += 1
            continue

        i += 1
        # Pace consecutive pings to the same host (no wait after the last ping).
        # Interruptible so pressing pause/stop takes effect at once instead of
        # waiting out the full interval before the loop re-checks the controls.
        if interval_s and (infinite or i < count):
            _interruptible_sleep(interval_s, ctrl)

    return dev


def ping_internet_hosts(live_table: LiveTable, hosts: List[str],
                        count: int = DEFAULT_PING_COUNT,
                        interval_ms: int = PING_INTERVAL_MS,
                        ctrl: "Optional[ScannerControl]" = None):
    """Ping internet hosts in parallel and update latency. Each host gets its own
    thread and is pinged the SAME number of times as the local devices (the count
    chosen in the controls, including ∞ = run until stopped). Latency updates live
    after every reply. Honours pause/stop so these threads halt with the rest."""
    infinite = count == PING_COUNT_INFINITE
    interval_s = max(0, interval_ms) / 1000.0

    def _ping_one(host: str):
        system = platform.system()
        lats: List[float] = []
        succ = 0
        i = 0
        while infinite or i < count:
            if ctrl and ctrl.should_exit_task():
                break
            if ctrl:
                ctrl.wait_if_paused()
                if ctrl.should_exit_task():
                    break
            try:
                success, latency = measure_ping(host, system)
                if success and latency is not None:
                    lats.append(latency)
                    succ += 1
                    live_table.set_public_latency(host, {
                        'min': min(lats),
                        'max': max(lats),
                        'avg': sum(lats) / len(lats),
                        'count': succ
                    })
            except Exception:
                pass
            i += 1
            if interval_s and (infinite or i < count):
                _interruptible_sleep(interval_s, ctrl)

    threads = [threading.Thread(target=_ping_one, args=(h,), daemon=True) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def prefill_internet_latency(live_table: LiveTable, hosts: List[str],
                             ctrl: "Optional[ScannerControl]" = None) -> None:
    """Quick parallel pre-fill of internet latencies so the header shows values
    early. Runs in the background so it never blocks the layout or the scan."""
    ping_internet_hosts(live_table, hosts, INITIAL_INTERNET_PING_COUNT, ctrl=ctrl)


# ═══════════════════════════════════════════════════════════════════════════════
# SUBNET SCAN
# ═══════════════════════════════════════════════════════════════════════════════

def _merge_known_devices(live_table: "LiveTable", db_path: str, gateway_mac: str) -> None:
    """Persist this scan's devices to the DB and merge the network's known
    devices back in: enrich online entries with stored MAC/hostname and add
    offline known devices so they appear in the table too."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with live_table.lock:
        current = list(live_table.devices.values())
    save_known_devices(db_path, gateway_mac, current, timestamp)

    known = load_known_devices(db_path, gateway_mac)
    with live_table.lock:
        present_macs = {(d.mac_address or "").upper()
                        for d in live_table.devices.values()
                        if d.mac_address and d.mac_address != UNKNOWN_VALUE}
        for kd in known:
            if kd.ip in live_table.devices:
                curr = live_table.devices[kd.ip]
                if (not curr.mac_address or curr.mac_address == UNKNOWN_VALUE) and kd.mac_address != UNKNOWN_VALUE:
                    curr.mac_address = kd.mac_address
                if (not curr.hostname or curr.hostname == UNKNOWN_VALUE) and kd.hostname != UNKNOWN_VALUE:
                    curr.hostname = kd.hostname
                # A known device that was probed but didn't answer this scan is
                # still listed (as a known offline device).
                if not curr.ping_status:
                    curr.from_db = True
                continue
            # A known device that wasn't probed at all (e.g. its IP is outside the
            # scanned range) and isn't already listed under another IP → add it.
            if (kd.mac_address or "").upper() in present_macs:
                continue
            live_table.devices[kd.ip] = kd


def _offline_retry_candidates(ip_range: List[str], online_ips: "set",
                              local_ip: "Optional[str]", promoted: "set") -> List[str]:
    """IPs eligible for a periodic offline re-probe this cycle: in the scanned
    range, not currently online, not the local host, and not already promoted
    (each IP is promoted back online at most once). Order is preserved."""
    return [ip for ip in ip_range
            if ip not in online_ips and ip != local_ip and ip not in promoted]


def _prioritize_known_ips(ip_range: List[str], known_ips: "set") -> List[str]:
    """Move IPs that are already known (pre-loaded from the DB) to the front of the
    discovery queue so their pings start in the very first sweep instead of waiting
    behind dozens of offline IPs — each of which can burn a full ping timeout — when
    the worker pool is smaller than the address range. Order within each group is
    preserved, so the numeric sweep is otherwise unchanged."""
    if not known_ips:
        return ip_range
    prioritized = [ip for ip in ip_range if ip in known_ips]
    rest = [ip for ip in ip_range if ip not in known_ips]
    return prioritized + rest


def scan_subnet(
    subnet: str,
    ping_count: int = DEFAULT_PING_COUNT,
    max_workers: int = MAX_WORKERS_ANALYSIS,
    init_workers: int = MAX_WORKERS_INIT,
    control: Optional[ScannerControl] = None,
    live_table_obj: Optional[LiveTable] = None,
    local_ip: str = None,
    local_mac: str = None,
    high_pressure: bool = False,
    internet_hosts: Optional[List[str]] = None,
    output_dir: str = ".",
    file_output: bool = True,
    interval_ms: int = PING_INTERVAL_MS,
    use_db: bool = True,
    db_path: str = KNOWN_DEVICES_DB_FILE
) -> LiveTable:
    """Scan one or more subnets and ping all devices.
    `subnet` may be a single '/24' prefix string (e.g. '192.168.1') or a list
    of such prefixes; every host 1..255 in each subnet is scanned.
    ping_count == PING_COUNT_INFINITE keeps pinging until the scan is stopped."""
    live_table = live_table_obj if live_table_obj else LiveTable()
    subnets = [subnet] if isinstance(subnet, str) else list(subnet)
    ip_range = [f"{sn}.{i}" for sn in subnets
                for i in range(SUBNET_FIRST_IP, SUBNET_LAST_IP + 1)]
    # Pinned IPs are pinged every run even when they fall outside the scanned
    # subnets — add any that aren't already covered.
    seen_ips = set(ip_range)
    for pip in live_table.pinned_ips:
        if pip not in seen_ips:
            ip_range.append(pip)
            seen_ips.add(pip)
    # Known/DB-recognised + pinned devices are already in the table at this point —
    # ping them first so they don't wait their numeric turn behind many offline IPs.
    with live_table.lock:
        known_ips = set(live_table.devices.keys())
    ip_range = _prioritize_known_ips(ip_range, known_ips)
    live_table.total_count = len(ip_range)

    infinite = ping_count == PING_COUNT_INFINITE
    live_table.set_infinite(infinite)

    live_table.start_refresh_timer()
    last_group_calc = time.time()

    def _maybe_recalc_groups():
        nonlocal last_group_calc
        if time.time() - last_group_calc > GROUP_CALC_INTERVAL_SECONDS:
            live_table.calculate_groups()
            last_group_calc = time.time()

    # Progress-bar totals. ∞ mode has no finite ping target, so the pings bar is
    # left indeterminate (it renders the ∞ symbol instead of a percentage).
    # High-pressure mode pings ping_count times per device with no separate
    # discovery pass, so it has no discovery pings to count.
    _internet_hosts = internet_hosts if internet_hosts else []
    analysis_per_ip = 0 if (ping_count <= 0 or infinite) else ping_count
    # Internet hosts are pinged as often as the local devices (same control value,
    # including ∞). The startup prefill already gave a quick initial reading.
    internet_count = ping_count
    discovery_pings = 0 if high_pressure else len(ip_range) * DISCOVERY_PING_COUNT
    analysis_pings = len(ip_range) * analysis_per_ip
    internet_pings = len(_internet_hosts) * max(0, internet_count)
    if infinite:
        live_table.set_total_pings(0)
    else:
        live_table.set_total_pings(discovery_pings + analysis_pings + internet_pings)
    # The ping totals can be wider than the device count — refit the width now.
    live_table.fit_width()

    live_table.set_phase("Discovery", DISCOVERY_PING_COUNT)
    live_table._render(force=True)

    # Start internet pings in a separate thread immediately.
    if _internet_hosts and ping_count != 0:
        threading.Thread(
            target=ping_internet_hosts,
            args=(live_table, _internet_hosts, internet_count, interval_ms, control),
            daemon=True
        ).start()

    if high_pressure:
        # High pressure: all devices at once, several subthreads per device.
        hp_workers = min(MAX_WORKERS_INIT, len(ip_range) * HIGH_PRESSURE_SUBTHREADS_PER_DEVICE)
        with ThreadPoolExecutor(max_workers=hp_workers) as executor:
            futures = {
                executor.submit(ping_host_multiple, ip, ping_count, live_table,
                                control, local_ip, local_mac, interval_ms): ip
                for ip in ip_range
            }
            for _ in as_completed(futures):
                if control and control.should_exit_task():
                    break
                if control:
                    control.wait_if_paused()
                live_table.bump_completed()
                _maybe_recalc_groups()
    else:
        # Pipeline: discover (1 ping each) and, the moment a host answers, hand it
        # straight to the analysis pool — analysis of the first hosts starts while
        # the rest of the subnet is still being discovered.
        analyse = ping_count != 0
        analysis_executor = ThreadPoolExecutor(max_workers=max_workers) if analyse else None
        analysis_futures = []          # initial online-device cycles (counted via callback)
        analysis_lock = threading.Lock()
        promoted = set()               # offline IPs already brought back online (once each)
        promoted_futures = []          # ping cycles for promoted devices (already counted)
        scan_active = threading.Event()
        scan_active.set()
        system = platform.system()

        def _on_analysis_done(_fut):
            live_table.bump_completed()

        def _promote_offline(ip):
            """A previously-offline device answered a re-probe: reclaim its skipped
            pings and start its normal ping cycle. Completion is NOT re-counted —
            the IP was already counted as processed during discovery."""
            with analysis_lock:
                if ip in promoted or not scan_active.is_set():
                    return
                promoted.add(ip)
            if analyse and not infinite:
                live_table.reclaim_skipped(analysis_per_ip)
            try:
                af = analysis_executor.submit(ping_host_multiple, ip, ping_count,
                                              live_table, control, local_ip, local_mac, interval_ms)
            except RuntimeError:
                return   # executor already shutting down
            with analysis_lock:
                promoted_futures.append(af)

        def _probe_offline(ip):
            """Single detection ping for an offline IP (not counted on the bar)."""
            if control and (control.should_exit_task() or not scan_active.is_set()):
                return
            if control:
                control.wait_if_paused()
                if control.should_exit_task():
                    return
            success, _lat = measure_ping(ip, system)
            if success:
                _promote_offline(ip)

        def _offline_monitor():
            """Re-probe offline IPs every OFFLINE_RETRY_INTERVAL_SECONDS while the
            scan runs; promote any that come online. The detection pings are kept
            off the progress bar — only a promoted device's real cycle counts."""
            probe_pool = ThreadPoolExecutor(max_workers=OFFLINE_RETRY_WORKERS)
            try:
                while scan_active.is_set() and not control.should_exit_task():
                    _interruptible_sleep(OFFLINE_RETRY_INTERVAL_SECONDS, control)
                    if not scan_active.is_set() or control.should_exit_task():
                        break
                    control.wait_if_paused()
                    with live_table.lock:
                        online_ips = {d.ip for d in live_table.devices.values() if d.ping_status}
                    with analysis_lock:
                        done = set(promoted)
                    for ip in _offline_retry_candidates(ip_range, online_ips, local_ip, done):
                        if not scan_active.is_set() or control.should_exit_task():
                            break
                        probe_pool.submit(_probe_offline, ip)
            finally:
                probe_pool.shutdown(wait=False)

        disc_executor = ThreadPoolExecutor(max_workers=init_workers)
        disc_futures = {
            disc_executor.submit(ping_host_multiple, ip, DISCOVERY_PING_COUNT,
                                 live_table, control, local_ip, local_mac, interval_ms): ip
            for ip in ip_range
        }
        for fut in as_completed(disc_futures):
            if control and control.should_exit_task():
                break
            if control:
                control.wait_if_paused()
            ip = disc_futures[fut]
            online = ip in live_table.devices and live_table.devices[ip].ping_status
            if analyse and online:
                af = analysis_executor.submit(ping_host_multiple, ip, ping_count,
                                              live_table, control, local_ip, local_mac, interval_ms)
                af.add_done_callback(_on_analysis_done)
                analysis_futures.append(af)
            else:
                # Offline host (or analysis disabled): processed now; its planned
                # analysis pings count as skipped on the pings bar (reclaimed later
                # if the offline monitor brings this device back online).
                if analyse and not infinite:
                    live_table.record_skipped(analysis_per_ip)
                live_table.bump_completed()
            _maybe_recalc_groups()
        disc_executor.shutdown(wait=False)

        # Re-probe offline devices for the rest of the run (off the critical path):
        # any that come online are promoted and start their normal ping cycle.
        if analyse and control is not None:
            threading.Thread(target=_offline_monitor, daemon=True).start()

        # Drain the analysis pool. bump_completed already fired via callbacks; here
        # we just wait, keep groups fresh, and honour stop/pause.
        if analysis_executor is not None:
            live_table.set_phase("Analysis", ping_count)
            for _ in as_completed(analysis_futures):
                if control and control.should_exit_task():
                    break
                if control:
                    control.wait_if_paused()
                _maybe_recalc_groups()
            # Initial online-device work is done (or the scan was stopped): stop the
            # offline monitor, then drain any promoted cycles it started. Each IP is
            # promoted at most once, so this is bounded and always terminates.
            scan_active.clear()
            while not (control and control.should_exit_task()):
                with analysis_lock:
                    pending = [f for f in promoted_futures if not f.done()]
                if not pending:
                    break
                for _ in as_completed(pending):
                    if control and control.should_exit_task():
                        break
                    if control:
                        control.wait_if_paused()
                    _maybe_recalc_groups()
            analysis_executor.shutdown(wait=False)

    live_table.calculate_groups()

    # Known-devices DB: remember everything seen on this network, then list the
    # network's known devices (incl. offline) so they always show up.
    gateway_mac = None
    if live_table.gateway_ip and live_table.gateway_ip in live_table.devices:
        gateway_mac = live_table.devices[live_table.gateway_ip].mac_address
    if use_db and gateway_mac and gateway_mac != UNKNOWN_VALUE:
        _merge_known_devices(live_table, db_path, gateway_mac)

    live_table.calculate_groups()
    # Ensure BOTH progress bars are completely filled at the end (skip in ∞ mode —
    # there is no finite target to fill).
    if not infinite:
        live_table.finalize_progress()
    live_table.stop_refresh_timer()
    live_table._render(force=True)
    return live_table


# ═══════════════════════════════════════════════════════════════════════════════
# SAVE RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

def _gw_slug(live_table: "LiveTable") -> str:
    """Return a filename-safe version of the gateway hostname (max 40 chars).
    Falls back to the gateway IP, then to an empty string."""
    host = None
    if live_table.gateway_ip and live_table.gateway_ip in live_table.devices:
        h = live_table.devices[live_table.gateway_ip].hostname
        if h and h != UNKNOWN_VALUE:
            host = h
    if not host:
        host = live_table.gateway_ip or ""
    # Strip every character that is invalid in Windows/POSIX filenames
    safe = re.sub(r'[\\/:*?"<>|\s]', '', host)
    return safe[:40]


def save_results(live_table: LiveTable, network_info: Dict, output_dir: str = ".") -> str:
    """Save scan results to a text file."""
    if output_dir and output_dir not in (".", "./"):
        os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    gw = _gw_slug(live_table)
    suffix = f"-{gw}" if gw else ""
    filename = os.path.join(output_dir, f"{TXT_FILENAME_PREFIX}{timestamp}{suffix}.txt")

    lines = [
        "=" * live_table.table_width,
        "NETWORK SCAN REPORT",
        f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * live_table.table_width,
        "",
        "Network Information:",
        "-" * STAT_DIVIDER_LEN
    ]

    lines.append(f"Interface:      {network_info.get('interface', UNKNOWN_VALUE)}")
    local_host = platform.node() or UNKNOWN_VALUE
    ip_val = network_info.get('ip', UNKNOWN_VALUE)
    lines.append(f"IP Address:     {ip_val:<18}Hostname:  {local_host}")

    gateway = network_info.get('gateway')
    if gateway:
        lines.append(f"Gateway:        {gateway}")

    subnet_mask = network_info.get('subnet_mask')
    if subnet_mask:
        lines.append(f"Subnet Mask:    {subnet_mask}")

    dns_servers = network_info.get('dns_servers', [])
    if dns_servers:
        lines.append(f"DNS Servers:    {', '.join(dns_servers)}")
    else:
        lines.append(f"DNS Servers:    {UNKNOWN_VALUE}")

    lines.append("")
    lines.append(live_table.get_final_results_text())

    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    return filename


# Column headers for the CSV export, in order.
CSV_COLUMNS: Tuple[str, ...] = (
    "ip", "status", "hostname", "vendor", "mac",
    "ping_avg_ms", "ping_min_ms", "ping_max_ms", "last_ping_ms",
    "pings_done", "pings_target", "from_db"
)


def save_results_csv(live_table: LiveTable, output_dir: str = ".") -> str:
    """Write the scan results as a machine-readable CSV (online + known devices).
    Numbers use a dot decimal so the file parses cleanly in any locale/tool."""
    if output_dir and output_dir not in (".", "./"):
        os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    gw = _gw_slug(live_table)
    suffix = f"-{gw}" if gw else ""
    filename = os.path.join(output_dir, f"{CSV_FILENAME_PREFIX}{timestamp}{suffix}.csv")

    def _num(v):
        return "" if v is None else f"{v:.2f}"

    with live_table.lock:
        devices = sorted(live_table.devices.values(),
                         key=lambda d: tuple(map(int, d.ip.split('.')))
                         if re.match(r'^\d+\.\d+\.\d+\.\d+$', d.ip) else (0, 0, 0, 0))
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(CSV_COLUMNS)
            for d in devices:
                if not d.ping_status and not d.from_db:
                    continue
                mac = d.mac_address if (d.mac_address and d.mac_address != UNKNOWN_VALUE) else ""
                hostname = d.hostname if (d.hostname and d.hostname != UNKNOWN_VALUE) else ""
                target = (INFINITE_SYMBOL if d.target_pings == PING_COUNT_INFINITE
                          else d.target_pings)
                writer.writerow([
                    d.ip,
                    STATUS_ONLINE if d.ping_status else STATUS_OFFLINE,
                    hostname,
                    lookup_mac_vendor(mac) or "",
                    mac,
                    _num(d.ping_stats.get('avg')),
                    _num(d.ping_stats.get('min')),
                    _num(d.ping_stats.get('max')),
                    _num(d.last_ping),
                    d.current_pings,
                    target,
                    "1" if d.from_db else "0",
                ])
    return filename


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

# Absolute path of the most recent saved report — printed under the controls.
_last_results_path: Optional[str] = None


def _hard_clear() -> None:
    """Fully clear the console (screen + scrollback) so only the next frame is
    visible. ANSI 3J is unreliable on legacy consoles, so fall back to cls."""
    try:
        if platform.system() == "Windows":
            # Fixed literal command, no user input → no injection risk. `cls` is a
            # shell builtin (not an .exe), so subprocess.run([...]) can't run it.
            os.system('cls')  # noqa: S605
        else:
            sys.stdout.write("\033[3J\033[2J\033[H")
            sys.stdout.flush()
    except Exception:
        pass


def main(ping_count: int = DEFAULT_PING_COUNT, high_pressure: bool = False) -> str:
    """Run a network scan."""
    _ensure_classic_console()  # re-host under conhost (Win Terminal can't resize)
    _init_console_encoding()   # UTF-8 stdout BEFORE any glyphs are written
    _ensure_conf_template()
    cfg = load_config_manager()
    cfg.print_warnings()       # Show range/type corrections if any

    # Maximize the console (font fit + full-height window + centre) BEFORE the
    # live table draws. Re-running this on every scan keeps a restart from the
    # controls menu from leaving a shrunken window. console_font_size = 0 opts
    # out of font handling.
    font_max_height = cfg.get_int('console_font_size', CONSOLE_FONT_HEIGHT, 'display')
    _maximize_console(TABLE_WIDTH, font_max_height)

    cfg_ping_count = cfg.get_int('ping_count', DEFAULT_PING_COUNT, 'scanning')
    if ping_count == DEFAULT_PING_COUNT and cfg_ping_count != DEFAULT_PING_COUNT:
        ping_count = cfg_ping_count
    cfg_high_pressure = cfg.get_bool('high_pressure_mode', False, 'scanning')
    if not high_pressure and cfg_high_pressure:
        high_pressure = True

    # Build the live table FIRST, then draw an initial frame immediately.
    # LiveTable() resizes/centres the console window, so the UI appears instantly —
    # the user never waits on a blank screen while the PowerShell-based network
    # detection runs (slow on a cold first start). The keyboard listener is started
    # right after, with the table, so P/Q/ESC work from the very first frame.
    control = ScannerControl()
    live_table = LiveTable()
    live_table.render_throttle = cfg.get_float('refresh_rate', RENDER_THROTTLE_SECONDS, 'scanning')
    live_table.set_phase("Discovery", DISCOVERY_PING_COUNT)
    live_table._render(force=True, clear_first=True)
    live_table.start_refresh_timer()

    listener = threading.Thread(target=input_listener, args=(control, live_table), daemon=True)
    listener.start()

    def _to_prefix(value: str) -> str:
        # "192.168.1.0/24" / "192.168.1.0" / "192.168.1" → "192.168.1"
        base = value.split('/')[0]
        return '.'.join(base.split('.')[:SUBNET_OCTET_COUNT])

    cfg_subnets = [_to_prefix(s) for s in cfg.get_subnets() if _to_prefix(s)]
    cfg_use_db = cfg.get_bool('known_devices_db', True, 'database')
    db_path = KNOWN_DEVICES_DB_FILE

    # Pinned IPs: always pinged every run and pinned to the top of the list (shown
    # even when offline). Registering them now adds their placeholder rows.
    live_table.set_pinned_ips(cfg.get_ip_list('pinned_ips'))

    def _preload_known_devices(gw: Optional[str]) -> None:
        """Pre-load DB devices (listed OFFLINE until a ping succeeds) when the
        gateway's network is recognised. Thread-safe; runs from either the
        synchronous fallback or the background resolver."""
        if not (cfg_use_db and gw):
            return
        known_gw_mac = _get_network_mac_from_db(db_path, gw)
        if not known_gw_mac:
            return
        for kd in load_known_devices(db_path, known_gw_mac):
            with live_table.lock:
                if kd.ip not in live_table.devices:
                    live_table.devices[kd.ip] = kd
        live_table.known_network = True
        live_table.calculate_groups()   # resolves gateway_color from stored hostname

    # ── Fast start ───────────────────────────────────────────────────────────
    # Determine our subnet INSTANTLY via a UDP-socket probe so discovery begins
    # without waiting on the slow PowerShell query (the main cause of the >5 s
    # cold-start delay). The full network info (gateway/DNS/MAC) and the DB
    # pre-load then run in the background and fill the header in as they arrive.
    fast_ip = get_local_ip_fast()
    fast_start = bool(fast_ip)
    if fast_start:
        live_table.set_network_info({'ip': fast_ip})
        # Resolve the gateway instantly too (IP Helper API) so recognised DB
        # devices are pre-loaded NOW and get pinged in the first discovery
        # sweep — not several seconds later when the slow query returns.
        fast_gw = get_default_gateway_fast()
        if fast_gw:
            live_table.set_network_info({'ip': fast_ip, 'gateway': fast_gw})
            live_table.set_gateway(fast_gw)
            _preload_known_devices(fast_gw)
    else:
        # Fallback: the socket probe failed (no route?) — use the slow query.
        interface = get_ethernet_interface() or DEFAULT_INTERFACE_NAME
        network_info = get_network_info(interface)
        fast_ip = network_info.get('ip')
        live_table.set_network_info(network_info)
        if network_info.get('gateway'):
            live_table.set_gateway(network_info['gateway'])
        live_table.set_local_mac(network_info.get('mac'))

    # The auto-detected own subnet is ALWAYS scanned first. Config subnets follow.
    # Duplicates are removed while preserving order, so the own subnet stays on top.
    own_prefix = get_subnet(fast_ip)
    subnet_prefixes, _seen = [], set()
    for p in ([own_prefix] if own_prefix else []) + cfg_subnets:
        if p and p not in _seen:
            _seen.add(p)
            subnet_prefixes.append(p)

    if not subnet_prefixes:
        live_table.stop_refresh_timer()
        print("Error: Could not determine subnet")
        return 'exit'

    # Subnets being scanned, as CIDR — shown next to the title.
    live_table.scanned_subnets = [f"{p}.0/24" for p in subnet_prefixes]

    # Populate the device count so the full layout (incl. Devices bar) is visible.
    hosts_per_subnet = SUBNET_LAST_IP - SUBNET_FIRST_IP + 1
    live_table.total_count = len(subnet_prefixes) * hosts_per_subnet

    if fast_start:
        # Off the critical path: resolve gateway/DNS/MAC + DB pre-load while the
        # scan is already running. The header and the local row's MAC fill in
        # as soon as this returns.
        def _resolve_network_background():
            interface = get_ethernet_interface() or DEFAULT_INTERFACE_NAME
            ni = get_network_info(interface)
            if not ni.get('ip'):
                ni['ip'] = fast_ip
            # Keep the fast-detected gateway if the slow query didn't find one,
            # so the header gateway and the DB lookup stay consistent.
            if not ni.get('gateway') and live_table.gateway_ip:
                ni['gateway'] = live_table.gateway_ip
            live_table.set_network_info(ni)
            if ni.get('gateway'):
                live_table.set_gateway(ni['gateway'])
            live_table.set_local_mac(ni.get('mac'))
            # Pre-load now if the fast gateway lookup didn't already (idempotent);
            # always recalc groups so the gateway colour reflects the real host.
            _preload_known_devices(ni.get('gateway'))
            live_table.calculate_groups()
            live_table.fit_width()
            live_table.request_render()
        threading.Thread(target=_resolve_network_background, daemon=True).start()
    else:
        _preload_known_devices(live_table.gateway_ip)
        live_table.fit_width()
        _center_console_window()
    live_table._render(force=True, clear_first=True)

    # Internet latency: quick pre-fill in the background — never blocks the scan.
    cfg_enable_inet = cfg.get_bool('enable_internet_ping', True, 'internet')
    if cfg_enable_inet:
        raw_hosts = cfg.get_str('internet_hosts', '', 'internet')
        internet_hosts = [h.strip() for h in raw_hosts.split(',') if h.strip()] if raw_hosts else INTERNET_PING_HOSTS
        threading.Thread(
            target=prefill_internet_latency, args=(live_table, internet_hosts, control), daemon=True
        ).start()
    else:
        internet_hosts = []

    output_dir = cfg.get_str('output_directory', DEFAULT_OUTPUT_DIR, 'output')
    live_table = scan_subnet(
        subnet_prefixes,
        ping_count=ping_count,
        max_workers=cfg.get_int('ping_threads', MAX_WORKERS_ANALYSIS, 'scanning'),
        init_workers=cfg.get_int('init_ping_threads', MAX_WORKERS_INIT, 'scanning') or MAX_WORKERS_INIT,
        control=control,
        live_table_obj=live_table,
        local_ip=fast_ip,
        local_mac=live_table.local_mac,
        high_pressure=high_pressure,
        internet_hosts=internet_hosts if cfg_enable_inet else [],
        output_dir=output_dir,
        file_output=cfg.get_bool('file_output', True, 'output'),
        interval_ms=cfg.get_int('ping_interval_ms', PING_INTERVAL_MS, 'scanning'),
        use_db=cfg_use_db,
        db_path=db_path
    )

    control.shutdown = True

    # Internet reachability warning — any configured host without a latency result
    if cfg_enable_inet and internet_hosts:
        reachable = set(live_table.public_latencies.keys())
        if any(h not in reachable for h in internet_hosts):
            print(f"\n{COLOR_YELLOW}Warning: Some internet hosts were unreachable. Check your network connection.{COLOR_RESET}")

    # Phase 3: Save TXT (and optionally CSV) — always, even after an early Q stop.
    # The path is shown UNDER the controls (not here), so it isn't wiped by the
    # final clear; we just record it.
    global _last_results_path
    _last_results_path = None
    if cfg.get_bool('file_output', True, 'output'):
        live_table.set_phase("Save TXT", 0)
        filename = save_results(live_table, live_table.network_info, output_dir)
        _last_results_path = os.path.abspath(filename)
        if cfg.get_bool('export_csv', False, 'output'):
            save_results_csv(live_table, output_dir)

    # Phase 4: Ready — hard-clear so ONLY the final report frame remains (no
    # leftover second frame from the scan), then render once.
    live_table.set_phase("Ready", 0)
    _hard_clear()
    live_table._render(force=True, clear_first=True)

    # Both a finished scan and a Q ("Abbrechen, Ergebnis speichern") land here:
    # results are saved and the restart controls menu is shown (which displays
    # the saved-results path beneath it). Only ESC quits immediately — it never
    # reaches this point because _hard_exit_now() exits the process directly.
    return 'completed'


# ═══════════════════════════════════════════════════════════════════════════════
# RESTART OPTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def show_restart_options() -> str:
    """Show restart options menu (4 columns, centered) and wait for user input."""
    k = COLOR_YELLOW
    r = COLOR_RESET
    b = COLOR_BOLD
    rd = COLOR_RED
    cols = 4
    gap = 3  # spaces between columns

    pu = COLOR_PURPLE
    # Row 1: [1] 10 pings, [2] 100 pings, [3] 1.000 pings, [4] 10.000 pings
    row1 = [
        f"[{k}1{r}] {b}{format_num(PING_COUNT_OPTIONS[0])}{r} pings",
        f"[{k}2{r}] {b}{format_num(PING_COUNT_OPTIONS[1])}{r} pings",
        f"[{k}3{r}] {b}{format_num(PING_COUNT_OPTIONS[2])}{r} pings",
        f"[{k}4{r}] {b}{format_num(PING_COUNT_OPTIONS[3])}{r} pings",
    ]
    # Row 2: [5] 100.000 pings, [8] ∞ unlimited, [h] HIGH PRESSURE, [q/ESC] Quit
    row2 = [
        f"[{k}5{r}] {b}{format_num(PING_COUNT_OPTIONS[4])}{r} pings",
        f"[{k}8{r}] {pu}{INFINITE_SYMBOL} Unlimited{r}",
        f"[{k}h{r}] {rd}HIGH PRESSURE{r}",
        f"[{k}q{r}/ESC] Quit",
    ]

    # One column width for ALL cells → columns line up vertically; the whole
    # block shares a single centred indent so it sits centred as one unit.
    col_w = max(get_visible_len(item) for item in row1 + row2)
    block_w = col_w * cols + gap * (cols - 1)
    indent = " " * max(0, (TABLE_WIDTH - block_w) // 2)

    print()
    for row in (row1, row2):
        cells = [item + " " * max(0, col_w - get_visible_len(item)) for item in row]
        print(indent + (" " * gap).join(cells).rstrip())
    print()

    # Under the controls: where the report was saved (full path).
    if _last_results_path:
        print(f"Results saved to: {COLOR_GREEN}{_last_results_path}{COLOR_RESET}\n")

    if platform.system() == "Windows":
        if _msvcrt is None:
            return 'q'
        while True:
            if _msvcrt.kbhit():
                raw = _msvcrt.getch()
                if raw in (b'\x00', b'\xe0'):
                    _msvcrt.getch()
                    continue
                ch = raw.decode('utf-8', errors='ignore').lower()
                if ch in ('\x1b', '\x03'):
                    return 'q'
                if ch in ('1', '2', '3', '4', '5', '8', 'h', 'q'):
                    return ch
            time.sleep(KEY_SLEEP_INTERVAL)

    if not sys.stdin.isatty() or termios is None or tty is None:
        return 'q'

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        termios.tcflush(fd, termios.TCIFLUSH)
        tty.setcbreak(fd)
        while True:
            rl, _, _ = select.select([fd], [], [], INPUT_POLL_TIMEOUT)
            if rl:
                inp = os.read(fd, INPUT_READ_SIZE).decode('utf-8', errors='ignore').lower()
                if not inp:
                    continue
                for key in ['1', '2', '3', '4', '5', '8', 'h', 'q']:
                    if key in inp:
                        return key
                if '\x1b' in inp:
                    return 'q'
            time.sleep(KEY_SLEEP_INTERVAL)
    except Exception:
        return 'q'
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


# ═══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Maps a menu key to (ping_count, high_pressure) for the next run.
    MENU_ACTIONS = {
        '1': (PING_COUNT_OPTIONS[0], False),
        '2': (PING_COUNT_OPTIONS[1], False),
        '3': (PING_COUNT_OPTIONS[2], False),
        '4': (PING_COUNT_OPTIONS[3], False),
        '5': (PING_COUNT_OPTIONS[4], False),
        '8': (PING_COUNT_INFINITE,  False),   # ∞ — ping until stopped
        'h': (PING_COUNT_OPTIONS[0], True),   # HIGH PRESSURE
    }
    cp = DEFAULT_PING_COUNT
    high_pressure = False
    while True:
        status = main(ping_count=cp, high_pressure=high_pressure)
        if status == 'exit':
            break
        if not sys.stdin.isatty():
            break
        choice = show_restart_options()
        if choice == 'q':
            print("\nExiting... Goodbye!")
            break
        cp, high_pressure = MENU_ACTIONS.get(choice, (DEFAULT_PING_COUNT, False))
