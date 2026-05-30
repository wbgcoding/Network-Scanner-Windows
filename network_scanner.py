#!/usr/bin/env python3
"""Network Scanner - Pings entire subnet and lists devices with IP, MAC, hostname, and ping status."""

import socket
import subprocess
import platform
import re
import threading
import sys
import time
import select
import os
import glob
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


def _run(args, timeout: int = None) -> subprocess.CompletedProcess:
    """subprocess.run wrapper that uses UTF-8 with replacement so Windows OEM
    output (ipconfig, arp, ping) never raises a UnicodeDecodeError."""
    return subprocess.run(
        args, capture_output=True, text=True,
        encoding='utf-8', errors='replace',
        timeout=timeout
    )


def _enable_windows_ansi() -> None:
    """Enable VT100/ANSI escape processing in the Windows console."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong(0)
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def _resize_terminal_windows(cols: int, rows: int = 0) -> None:
    """Resize the Windows console to cols × rows.
    rows=0 means the maximum height that fits the current screen (GetConsoleScreenBufferInfo
    dwMaximumWindowSize.Y already accounts for font size, DPI and taskbar height).
    """
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
                ("dwSize",            _COORD),
                ("dwCursorPosition",  _COORD),
                ("wAttributes",       wintypes.WORD),
                ("srWindow",          _SMALL_RECT),
                ("dwMaximumWindowSize", _COORD),
            ]

        kernel32 = ctypes.windll.kernel32
        handle   = kernel32.GetStdHandle(-11)
        csbi     = _CSBI()
        if not kernel32.GetConsoleScreenBufferInfo(handle, ctypes.byref(csbi)):
            return
        # dwMaximumWindowSize is 0 when stdout is a pipe/redirect — nothing to resize
        if csbi.dwMaximumWindowSize.X == 0 or csbi.dwMaximumWindowSize.Y == 0:
            return

        # Target size — capped to what the screen can physically show
        target_cols = min(cols, csbi.dwMaximumWindowSize.X)
        target_rows = (csbi.dwMaximumWindowSize.Y if rows <= 0
                       else min(rows, csbi.dwMaximumWindowSize.Y))

        # Growing the window past the current buffer → enlarge buffer first
        if target_cols > csbi.dwSize.X or target_rows > csbi.dwSize.Y:
            kernel32.SetConsoleScreenBufferSize(
                handle,
                _COORD(max(csbi.dwSize.X, target_cols),
                       max(csbi.dwSize.Y, target_rows))
            )

        # Resize the visible window
        kernel32.SetConsoleWindowInfo(
            handle, True,
            ctypes.byref(_SMALL_RECT(0, 0, target_cols - 1, target_rows - 1))
        )

        # Keep scroll buffer at 2× window so previous scan output is scrollable
        kernel32.SetConsoleScreenBufferSize(
            handle, _COORD(target_cols, target_rows * 2)
        )
    except Exception:
        pass


def _resize_terminal(cols: int, rows: int = 0) -> None:
    """Resize the terminal to cols wide × rows tall.
    rows=0 → maximum screen height (platform-specific logic).
    """
    if platform.system() == "Windows":
        _resize_terminal_windows(cols, rows)
    elif sys.stdin.isatty():
        # xterm escape: rows=9999 lets the terminal expand to its own screen limit
        r = rows if rows > 0 else 9999
        sys.stdout.write(f"\033[8;{r};{cols}t")
        sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

# ── Default Ping Values ──────────────────────────────────────────────────────
DEFAULT_PING_COUNT: int = 10
PING_COUNT_OPTIONS: Tuple[int, ...] = (10, 100, 1_000, 10_000, 100_000, 1_000_000)

# ── Discovery Phase ──────────────────────────────────────────────────────────
DISCOVERY_PING_COUNT: int = 1

# ── Subnet Scanning ──────────────────────────────────────────────────────────
SUBNET_FIRST_IP: int = 1
SUBNET_LAST_IP: int = 255
SUBNET_OCTET_COUNT: int = 3
IP_OCTET_COUNT: int = 4

# ── Threading ────────────────────────────────────────────────────────────────
MAX_WORKERS_INIT: int = 254
MAX_WORKERS_ANALYSIS: int = 100
HIGH_PRESSURE_SUBTHREADS_PER_DEVICE: int = 10

# ── Timing ───────────────────────────────────────────────────────────────────
PING_TIMEOUT_SECONDS: int = 2
WINDOWS_PING_TIMEOUT_MS: int = 1000
UNIX_PING_TIMEOUT_S: int = 1
RENDER_THROTTLE_SECONDS: float = 1.0
GROUP_CALC_INTERVAL_SECONDS: int = 5
INPUT_POLL_TIMEOUT: float = 0.1
INPUT_READ_SIZE: int = 3
KEY_SLEEP_INTERVAL: float = 0.01
ARP_TIMEOUT_SECONDS: int = 2

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
TABLE_WIDTH: int = 149
TERMINAL_ROWS: int = 50
TERMINAL_COLS: int = 148
PROGRESS_BAR_MAX_LEN: int = 55
PROGRESS_BAR_MARGIN: int = 4
DEVICE_PROGRESS_BAR_MARGIN: int = 4

# ── Column Widths ────────────────────────────────────────────────────────────
COL_IP_WIDTH: int = 19
COL_STATUS_WIDTH: int = 13
COL_GROUP_WIDTH: int = 5
COL_HOSTNAME_WIDTH: int = 30
COL_PING_WIDTH: int = 13
COL_PROGRESS_WIDTH: int = 13
COL_MAC_WIDTH: int = 21
HOSTNAME_TRUNCATE_LEN: int = 27
HOSTNAME_MAX_DISPLAY: int = 30

# ── Statistic Panel ────────────────────────────────────────────────────────
STAT_LEFT_WIDTH: int = 65
STAT_DIVIDER_LEN: int = 30

# ── Group Colors ─────────────────────────────────────────────────────────────
GROUP_UNKNOWN_COLOR: int = 196          # Red
GROUP_GATEWAY_COLOR_DEFAULT: int = 46   # Green
GROUP_GATEWAY_COLOR_UNIFI: int = 21     # Blue
GROUP_GATEWAY_COLOR_FRITZBOX: int = 196 # Red
GROUP_DYNAMIC_COLORS: List[int] = [
    196, 202, 208, 214, 220, 226, 190, 154, 118, 82,   # reds/oranges/yellows/greens
    46, 51, 21, 27, 33, 39, 45, 50, 63, 69,            # greens/teals/purples
    75, 81, 87, 93, 99, 105, 111, 117, 129, 135,       # blues/cyans
    141, 147, 201, 207, 213, 219, 225, 231, 165, 171  # magentas/cyans
]

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

# ── Title Colors (randomized each render) ─────────────────────────────────────
TITLE_COLORS: List[int] = [
    46, 82, 118, 154, 190, 226, 208, 202, 197, 163,
    129, 93, 57, 63, 87, 51, 45, 39, 33, 27,
    21, 27, 33, 39, 45, 51, 87, 123, 159, 195,
    214, 220, 226, 190, 154, 118, 82, 46, 77, 72
]

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


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION MANAGER
# ═══════════════════════════════════════════════════════════════════════════════

# Valid ranges used for clamping and warn-on-bad-value in ConfigManager
_CONF_RANGES: Dict[str, Tuple] = {
    'init_ping_threads': (0, 1000),
    'ping_threads':      (1, 1000),
    'init_ping_count':   (1, 100),
    'ping_count':        (1, 10_000_000),
    'refresh_rate':      (0.1, 60.0),
}


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
            self._warnings.append(f"  {key}: '{raw}' ist keine ganze Zahl → Standardwert {fallback}")
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

    def get_float(self, key: str, fallback: float = 0.0, section: str = None) -> float:
        raw = self.get(key, None, section)
        if raw is None:
            return fallback
        try:
            val = float(str(raw).strip().replace(',', '.'))
        except (ValueError, AttributeError):
            self._warnings.append(f"  {key}: '{raw}' ist keine Zahl → Standardwert {fallback}")
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

    def print_warnings(self) -> None:
        if self._warnings:
            print(f"\n{COLOR_YELLOW}Konfigurations-Warnungen:{COLOR_RESET}")
            for w in self._warnings:
                print(w)


def load_config_manager() -> ConfigManager:
    """Singleton ConfigManager — prefers network_scanner.conf, falls back to config.ini."""
    if not hasattr(load_config_manager, '_instance') or load_config_manager._instance is None:
        if os.path.isfile("network_scanner.conf"):
            path = "network_scanner.conf"
        elif os.path.isfile("config.ini"):
            path = "config.ini"
        else:
            path = "network_scanner.conf"   # will silently use all defaults
        load_config_manager._instance = ConfigManager(path)
    return load_config_manager._instance


# ── Template constant ─────────────────────────────────────────────────────────
_CONF_TEMPLATE_CONTENT = """\
# ═══════════════════════════════════════════════════════════════════════════════
# Network Scanner — Konfigurationsdatei
# Kopiere diese Datei nach network_scanner.conf und passe die Werte an.
# Zeilen mit # oder ; werden ignoriert. Ungültige Werte werden auf Standardwerte
# zurückgesetzt.
# ═══════════════════════════════════════════════════════════════════════════════

# ── THREADS ─────────────────────────────────────────────────────────────────
# init_ping_threads  Threads in der Discovery-Phase.  0 = ein Thread pro IP.
#   Bereich: 0–1000 | Standard: 254
#init_ping_threads = 254

# ping_threads  Threads in der Analyse-Phase.
#   Bereich: 1–1000 | Standard: 100
ping_threads = 100

# ── PING ────────────────────────────────────────────────────────────────────
# init_ping_count  Pings pro Gerät in der Discovery-Phase.
#   Bereich: 1–100 | Standard: 1
#init_ping_count = 1

# ping_count  Pings pro Gerät in der Analyse-Phase.
#   Bereich: 1–10.000.000 | Standard: 10
#ping_count = 10

# refresh_rate  Mindestabstand zwischen Bildschirmaktualisierungen (Sekunden).
#   Bereich: 0.1–60.0 | Standard: 1.0
#refresh_rate = 1.0

# ── NETZWERK ────────────────────────────────────────────────────────────────
# subnet  Zielnetz in CIDR-Notation.  Leer = automatische Erkennung.
#   Beispiel: 192.168.1.0/24
# subnet = 192.168.1.0/24

# Zusätzliche Netze für denselben Scan-Durchlauf (werden nacheinander gescannt).
# subnet_2 = 10.0.0.0/24
# subnet_3 = 172.16.0.0/24
# subnet_4 = 192.168.2.0/24

# ── HIGH PRESSURE MODE ──────────────────────────────────────────────────────
# Alle Geräte gleichzeitig mit mehreren Subthreads pingen.
#   true  = maximaler Durchsatz (hohe CPU/Netzlast)
#   false = zweiphasiger Scan (Discovery + Analyse)  | Standard: false
#high_pressure_mode = false

# ── AUSGABE ─────────────────────────────────────────────────────────────────
# output_directory  Verzeichnis für Scan-Ergebnisse. Wird automatisch angelegt.
#   Standard: . (aktuelles Verzeichnis)
output_directory = .

# file_output  Ergebnisse nach dem Scan in eine Textdatei schreiben.
#   Standard: true
#file_output = true

# ── INTERNET-PING ───────────────────────────────────────────────────────────
# enable_internet_ping  Externe Hosts für Latenzmessung pingen.
#   Standard: true
#enable_internet_ping = true

# internet_hosts  Kommagetrennte Liste von IPv4-Adressen.
#   Standard: 8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9
#internet_hosts = 8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9
"""


def _ensure_conf_template() -> None:
    """Write network_scanner.conf.template if it does not already exist."""
    path = "network_scanner.conf.template"
    if os.path.isfile(path):
        return
    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(_CONF_TEMPLATE_CONTENT)
    except Exception:
        pass


def print_config_info(cfg: ConfigManager):
    """Print a formatted summary of the active configuration."""
    print(f"\n{COLOR_BRIGHT_WHITE}Configuration:{COLOR_RESET}")
    print(f"  ping_count:          {COLOR_CYAN}{cfg.get_int('ping_count', DEFAULT_PING_COUNT, 'scanning')}{COLOR_RESET}")
    print(f"  ping_threads:        {COLOR_CYAN}{cfg.get_int('ping_threads', MAX_WORKERS_ANALYSIS, 'scanning')}{COLOR_RESET}")
    print(f"  init_ping_threads:   {COLOR_CYAN}{cfg.get_int('init_ping_threads', MAX_WORKERS_INIT, 'scanning')}{COLOR_RESET}")
    print(f"  init_ping_count:     {COLOR_CYAN}{cfg.get_int('init_ping_count', DISCOVERY_PING_COUNT, 'scanning')}{COLOR_RESET}")
    print(f"  refresh_rate:        {COLOR_CYAN}{cfg.get_float('refresh_rate', RENDER_THROTTLE_SECONDS, 'scanning')}s{COLOR_RESET}")
    subnet = cfg.get_str('subnet', '', 'network')
    print(f"  subnet:              {COLOR_CYAN}{subnet or 'Auto-detect'}{COLOR_RESET}")
    hp = cfg.get_bool('high_pressure_mode', False, 'scanning')
    print(f"  high_pressure_mode:  {COLOR_CYAN}{hp}{COLOR_RESET}")
    inet = cfg.get_bool('enable_internet_ping', True, 'internet')
    print(f"  internet_ping:       {COLOR_CYAN}{inet}{COLOR_RESET}")
    if inet:
        ih = cfg.get_str('internet_hosts', '8.8.8.8, 8.8.4.4, 1.1.1.1, 9.9.9.9', 'internet')
        print(f"  internet_hosts:      {COLOR_CYAN}{ih}{COLOR_RESET}")
    print()


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


class ScannerControl:
    """Manages scan state and user interruptions."""
    def __init__(self):
        self.stop_requested = False
        self.restart_requested = False
        self.paused = False
        self.shutdown = False
        self.lock = threading.Lock()
        self.pause_event = threading.Event()
        self.pause_event.set()  # Not paused by default

    def reset(self):
        with self.lock:
            self.stop_requested = False
            self.restart_requested = False
            self.paused = False
        self.pause_event.set()

    def request_stop(self):
        with self.lock:
            self.stop_requested = True
        self.pause_event.set()  # Unblock if paused

    def request_restart(self):
        with self.lock:
            self.restart_requested = True
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
            return self.stop_requested or self.restart_requested or self.shutdown


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


def get_subnet(ip: str) -> Optional[str]:
    """Extract the subnet from an IP address."""
    if not ip:
        return None
    parts = ip.split('.')
    if len(parts) == IP_OCTET_COUNT:
        return '.'.join(parts[:SUBNET_OCTET_COUNT])
    return None


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


def load_previous_devices(output_dir: str = ".", gateway_mac: str = None) -> List[Device]:
    """Load devices from previous scan files. Only includes devices whose router MAC
    matches the current gateway MAC, so we only show offline devices from the same network."""
    devices = []
    scan_files = sorted(glob.glob(os.path.join(output_dir, "network_scan_*.txt")), reverse=True)
    # Only use the most recent scan file
    if not scan_files:
        return devices

    try:
        with open(scan_files[0], 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception:
        return devices

    # Find the gateway IP from the scan file header
    file_gateway_ip = None
    for line in content.split('\n'):
        if 'Gateway:' in line:
            gw_part = line.split('Gateway:')[1].strip().split()[0] if 'Gateway:' in line else None
            if gw_part and re.match(r'\d+\.\d+\.\d+\.\d+', gw_part):
                file_gateway_ip = gw_part
            break

    # Parse device lines from the scan file
    # Format: "192.168.2.1        ONLINE       G2         unifi                          0,33ms         ..."
    ip_pattern = re.compile(r'^(\d+\.\d+\.\d+\.\d+)\s+')
    parsed_devices = []
    gateway_mac_in_file = None

    for line in content.split('\n'):
        line = line.strip()
        m = ip_pattern.match(line)
        if not m:
            continue
        parts = line.split()
        if len(parts) < 9:
            continue

        ip = parts[0]
        status = parts[1]
        # Group is parts[2]
        # Find MAC (last field)
        mac = parts[-1] if parts[-1] != 'Unknown' and re.match(r'([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}', parts[-1]) else None
        hostname = parts[3] if len(parts) > 3 else UNKNOWN_VALUE

        dev = Device(
            ip=ip,
            mac_address=mac.upper() if mac else UNKNOWN_VALUE,
            hostname=hostname if hostname != 'Unknown' else UNKNOWN_VALUE,
            ping_status=(status == STATUS_ONLINE),
            target_pings=DEFAULT_PING_COUNT,
            current_pings=DEFAULT_PING_COUNT,
            is_offline=(status != STATUS_ONLINE)
        )
        parsed_devices.append(dev)

        # Track gateway MAC from file
        if file_gateway_ip and ip == file_gateway_ip and mac:
            gateway_mac_in_file = mac.upper()

    # Only include devices if the gateway MAC matches (same network)
    if gateway_mac and gateway_mac_in_file and gateway_mac != gateway_mac_in_file:
        return []  # Different network — don't merge

    return parsed_devices


# ═══════════════════════════════════════════════════════════════════════════════
# FORMATTING HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def get_visible_len(s: str) -> int:
    """Calculate the visible length of a string, ignoring ANSI escape codes."""
    return len(re.sub(r'\033\[[0-9;]*m', '', s))


def format_num(n: int) -> str:
    """Format integer with dot as thousands separator."""
    return f"{n:,}".replace(',', '.')


def format_float(n: float) -> str:
    """Format float with dot as thousands separator and comma as decimal."""
    if n is None:
        return UNKNOWN_VALUE
    formatted = f"{n:,.2f}"
    parts = formatted.split('.')
    return f"{parts[0].replace(',', '.')},{parts[1]}ms"


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
    """Highlight the local/scanner IP in red."""
    return f"{COLOR_RED}{ip}{COLOR_RESET}"


def colorize_local_hostname(name: str) -> str:
    """Highlight the local/scanner hostname in red."""
    return f"{COLOR_RED}{name}{COLOR_RESET}"


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
        self.table_width = TABLE_WIDTH
        self.public_latencies = {}
        self.network_info = {}  # Set via set_network_info()
        self.local_ip = None
        self.gateway_ip = None
        self.gateway_color = GROUP_GATEWAY_COLOR_DEFAULT
        self._needs_render = False
        self._refresh_timer = None
        self._refresh_stop = threading.Event()

        if platform.system() == "Windows":
            _enable_windows_ansi()
        # Resize: width = table + small margin, height = max screen height
        _resize_terminal(TABLE_WIDTH + 2)

    def start_refresh_timer(self):
        """Start a background thread that triggers periodic renders."""
        if self._refresh_timer is not None:
            return
        def _timer_loop():
            while not self._refresh_stop.is_set():
                self._refresh_stop.wait(timeout=self.render_throttle)
                if not self._refresh_stop.is_set():
                    self._render(force=True)
        self._refresh_stop.clear()
        self._refresh_timer = threading.Thread(target=_timer_loop, daemon=True)
        self._refresh_timer.start()

    def stop_refresh_timer(self):
        """Stop the periodic refresh timer."""
        self._refresh_stop.set()
        self._refresh_timer = None

    def _try_render(self):
        """Render only if enough time has passed since last render (throttled)."""
        now = time.time()
        if now - self.last_render_time >= self.render_throttle:
            self._render(force=True)

    def set_gateway(self, ip: str):
        self.gateway_ip = ip
        self.gateway_color = GROUP_GATEWAY_COLOR_DEFAULT

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
            random.shuffle(GROUP_DYNAMIC_COLORS)
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
                                while current_id - GROUP_ID_DYNAMIC_START < len(GROUP_DYNAMIC_COLORS) and GROUP_DYNAMIC_COLORS[(current_id - GROUP_ID_DYNAMIC_START) % len(GROUP_DYNAMIC_COLORS)] in reserved:
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
                            while current_id - GROUP_ID_DYNAMIC_START < len(GROUP_DYNAMIC_COLORS) and GROUP_DYNAMIC_COLORS[(current_id - GROUP_ID_DYNAMIC_START) % len(GROUP_DYNAMIC_COLORS)] in reserved:
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

    def update_device(self, device: Device, force_render: bool = False):
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
                    is_offline=device.is_offline
                )
            else:
                o = self.devices[device.ip]
                if device.ping_status:
                    o.ping_status = True
                    o.is_offline = False  # Once online, no longer offline
                if device.latency_ms is not None:
                    o.latency_ms = device.latency_ms
                if device.ping_stats:
                    o.ping_stats.update(device.ping_stats)
                if device.mac_address != UNKNOWN_VALUE:
                    o.mac_address = device.mac_address
                if device.hostname != UNKNOWN_VALUE:
                    o.hostname = device.hostname
                o.current_pings = device.current_pings
                o.target_pings = device.target_pings

    def set_completed(self, count, force_render: bool = False):
        with self.lock:
            self.completed_count = count

    def set_total_pings(self, completed: int, target: int):
        with self.lock:
            self.total_pings_completed = completed
            self.total_pings_target = target

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
        """Build a progress bar with centered text."""
        pct_start = (pb_len - len(center_text)) // 2
        chars = [f"{COLOR_GREEN}█{COLOR_RESET}" if i < filled else f"{COLOR_DARK_GRAY}░{COLOR_RESET}" for i in range(pb_len)]
        for i, ch in enumerate(center_text):
            pos = pct_start + i
            if pos < pb_len:
                chars[pos] = f"{COLOR_BOLD}{COLOR_WHITE}{ch}{COLOR_RESET}"
        return "".join(chars)

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
            row1 = ""
            row2 = ""
            for i, (entry, minmax) in enumerate(zip(row1_parts, row2_parts)):
                gap = 2  # spacing between columns
                w = col_widths[i]
                entry_pad = w - get_visible_len(entry)
                minmax_pad = w - get_visible_len(minmax)
                row1 += "  " + entry + " " * entry_pad + " " * gap
                row2 += "  " + minmax + " " * minmax_pad + " " * gap
            # Center both rows within the table width
            row1_vis = get_visible_len(row1)
            row2_vis = get_visible_len(row2)
            max_vis = max(row1_vis, row2_vis)
            r1_pad = max(0, (self.table_width - max_vis) // 2)
            r2_pad = max(0, (self.table_width - row2_vis) // 2)
            lines.append(" " * r1_pad + row1)
            lines.append(" " * r2_pad + row2)
        else:
            lines.append(f"  {COLOR_DARK_GRAY}No internet hosts tested{COLOR_RESET}")

        return lines

    def _render_internal(self, move_home: bool = True):
        with self.lock:
            return self._render_internal_locked(move_home=move_home)

    def _render_internal_locked(self, move_home: bool = True):
        output = []
        if move_home:
            output.append("\033[2J\033[H")  # Clear screen and move cursor home
        output.append(f"{COLOR_BLUE}{'=' * self.table_width}{COLOR_RESET}")
        # Title always centered in table width, phase on the left (indented 8 chars)
        phi = f"{COLOR_CYAN}{self.phase_number}{COLOR_RESET} - {COLOR_BRIGHT_WHITE}{self.current_phase}"
        if self.pings_per_device > 0:
            phi += f" ({format_num(self.pings_per_device)} pings)"
        phi += COLOR_RESET
        title_color = random.choice(TITLE_COLORS)
        title = f"\033[1;38;5;{title_color}mNetwork Scanner{COLOR_RESET}"
        title_visible = "Network Scanner"
        # Phase left-aligned with 8 spaces indent, title centered in full table width
        phase_indent = 8
        title_pad = (self.table_width - len(title_visible)) // 2
        phase_prefix = f"{' ' * phase_indent}{phi}"
        phase_vis_len = phase_indent + get_visible_len(phi)
        min_title_start = phase_vis_len + 2
        title_start = max(title_pad, min_title_start)
        left_spaces = max(0, title_start - phase_vis_len)
        output.append(f"{phase_prefix}{' ' * left_spaces}{title}")

        # Progress bars
        # Pings bar
        ping_bar_str = ""
        if self.total_pings_target > 0:
            pb_len = PROGRESS_BAR_MAX_LEN
            pct = (self.total_pings_completed / self.total_pings_target) * 100
            filled = int(pb_len * pct / 100)
            pct_text = f"{pct:.0f}%"
            ping_bar_str = f"{COLOR_CYAN}Pings:  {COLOR_RESET}{self._build_bar(pb_len, filled, pct_text)}{COLOR_RESET} {COLOR_BLUE}{format_num(self.total_pings_completed)}/{format_num(self.total_pings_target)}{COLOR_RESET}"

        # Devices bar
        dev_bar_str = ""
        if self.total_count > 0:
            dev_pb_len = PROGRESS_BAR_MAX_LEN
            dev_pct = (self.completed_count / self.total_count) * 100
            dev_filled = int(dev_pb_len * dev_pct / 100)
            dev_pct_text = f"{dev_pct:.0f}%"
            dev_bar_str = f"{COLOR_CYAN}Devices:{COLOR_RESET}{self._build_bar(dev_pb_len, dev_filled, dev_pct_text)}{COLOR_RESET} {COLOR_BLUE}{format_num(self.completed_count)}/{format_num(self.total_count)}{COLOR_RESET}"

        # Network info — aligned in 2 columns, IP/GW top, Subnet/DNS bottom
        ni = self.network_info
        gw_str = ni.get('gateway', UNKNOWN_VALUE) or UNKNOWN_VALUE
        ip_str = ni.get('ip', UNKNOWN_VALUE) or UNKNOWN_VALUE
        mask_str = ni.get('subnet_mask', UNKNOWN_VALUE) or UNKNOWN_VALUE
        dns_str = ni.get('dns_servers', [UNKNOWN_VALUE])[0] if ni.get('dns_servers') else UNKNOWN_VALUE

        # Column layout: left col = IP/Subnet, right col = GW/DNS
        # Compact layout: label + 1 space + value, right col aligned
        net_r1 = (
            f"{COLOR_CYAN}IP:{COLOR_RESET} {COLOR_BRIGHT_WHITE}{ip_str:<15}{COLOR_RESET}"
            f"  "
            f"{COLOR_CYAN}GW:{COLOR_RESET} {COLOR_BRIGHT_WHITE}{gw_str:<15}{COLOR_RESET}"
        )
        net_r2 = (
            f"{COLOR_CYAN}Subnet:{COLOR_RESET} {COLOR_BRIGHT_WHITE}{mask_str:<12}{COLOR_RESET}"
            f"  "
            f"{COLOR_CYAN}DNS:{COLOR_RESET} {COLOR_BRIGHT_WHITE}{dns_str:<12}{COLOR_RESET}"
        )

        # Device stats — aligned in 2 columns, Online/Used top, Offline/Free bottom
        on = [d for d in self.devices.values() if d.ping_status]
        off = [d for d in self.devices.values() if not d.ping_status and (
            (d.mac_address and d.mac_address != UNKNOWN_VALUE) or
            (d.hostname and d.hostname != UNKNOWN_VALUE)
        )]
        fr = max(0, self.total_count - len(on) - len(off))
        used = len(on) + len(off)

        # Stats: compact layout, label + space + value
        stats_r1 = (
            f"{COLOR_LIGHT_GREEN}Online:{COLOR_RESET} {COLOR_GREEN}{format_num(len(on)):<5}{COLOR_RESET}"
            f"  "
            f"{COLOR_LIGHT_GREEN}Offline:{COLOR_RESET} {COLOR_RED}{format_num(len(off)):<5}{COLOR_RESET}"
        )
        stats_r2 = (
            f"{COLOR_LIGHT_GREEN}Used:{COLOR_RESET} {COLOR_BRIGHT_WHITE}{format_num(used):<5}{COLOR_RESET}"
            f"  "
            f"{COLOR_LIGHT_GREEN}Free:{COLOR_RESET} {COLOR_BLUE}{format_num(fr):<5}{COLOR_RESET}"
        )

        # Calculate max bar width for alignment
        max_bar_len = max(get_visible_len(ping_bar_str), get_visible_len(dev_bar_str)) if (ping_bar_str or dev_bar_str) else 0

        # Output: Pings bar + net_r1 + stats_r1, then Devices bar + net_r2 + stats_r2
        if ping_bar_str:
            padding = max(PROGRESS_BAR_MARGIN, max_bar_len + PROGRESS_BAR_MARGIN - get_visible_len(ping_bar_str))
            output.append(f"{ping_bar_str}{' ' * padding}{net_r1}  {stats_r1}")
        if dev_bar_str:
            padding = max(PROGRESS_BAR_MARGIN, max_bar_len + PROGRESS_BAR_MARGIN - get_visible_len(dev_bar_str))
            output.append(f"{dev_bar_str}{' ' * padding}{net_r2}  {stats_r2}")

        output.append(f"{COLOR_BLUE}{'=' * self.table_width}{COLOR_RESET}")

        if not self.devices:
            if move_home:
                output.append("\033[J")
            sys.stdout.write("".join(output))
            sys.stdout.flush()
            return

        headers = [
            format_cell(colorize_header("IP Address"), COL_IP_WIDTH),
            format_cell_center(colorize_header("Status"), COL_STATUS_WIDTH),
            format_cell_center(colorize_header("Group"), COL_GROUP_WIDTH),
            " ",
            format_cell(colorize_header("Hostname"), COL_HOSTNAME_WIDTH),
            format_cell_center(colorize_header("Ping Avg"), COL_PING_WIDTH),
            format_cell_center(colorize_header("Ping Min"), COL_PING_WIDTH),
            format_cell_center(colorize_header("Ping Max"), COL_PING_WIDTH),
            format_cell_center(colorize_header("Progress"), COL_PROGRESS_WIDTH),
            format_cell_center(colorize_header("MAC Address"), COL_MAC_WIDTH)
        ]
        output.append("".join(headers))
        output.append(f"{COLOR_BLUE}{'-' * self.table_width}{COLOR_RESET}")

        sorted_ips = sorted(self.devices.keys(), key=lambda x: tuple(map(int, x.split('.'))))
        for ip in sorted_ips:
            d = self.devices[ip]
            if not d.ping_status:
                continue  # Only show devices that actively responded in this scan
            status = STATUS_ONLINE
            ac, ar = colorize_ping(d.ping_stats.get('avg'))
            mc, mr = colorize_ping(d.ping_stats.get('max')) if d.ping_stats.get('max') else (COLOR_WHITE, COLOR_RESET)
            nc, nr = colorize_ping(d.ping_stats.get('min')) if d.ping_stats.get('min') else (COLOR_WHITE, COLOR_RESET)

            avg_text = f"{ac}{format_float(d.ping_stats.get('avg'))}{ar}" if d.ping_stats.get('avg') else f"{COLOR_DARK_GRAY}N/A{COLOR_RESET}"
            max_text = f"{mc}{format_float(d.ping_stats.get('max'))}{mr}" if d.ping_stats.get('max') else f"{COLOR_DARK_GRAY}N/A{COLOR_RESET}"
            min_text = f"{nc}{format_float(d.ping_stats.get('min'))}{nr}" if d.ping_stats.get('min') else f"{COLOR_DARK_GRAY}N/A{COLOR_RESET}"

            host = d.hostname or UNKNOWN_VALUE
            mac = d.mac_address or UNKNOWN_VALUE
            if len(host) > HOSTNAME_MAX_DISPLAY:
                host = host[:HOSTNAME_TRUNCATE_LEN] + "..."

            # Color hostname: red for local IP, magenta for others
            is_local = self.local_ip and d.ip == self.local_ip
            host_color = colorize_local_hostname(host) if is_local else colorize_hostname(host)

            # Group visualization — 3 colored blocks if grouped, 3 spaces if not
            group_text = "   "
            if d.group_id > GROUP_ID_NONE:
                if d.group_id == GROUP_ID_UNKNOWN:
                    color = GROUP_UNKNOWN_COLOR
                elif d.group_id == GROUP_ID_GATEWAY:
                    color = self.gateway_color
                else:
                    c_idx = (d.group_id - GROUP_ID_DYNAMIC_START) % len(GROUP_DYNAMIC_COLORS)
                    color = GROUP_DYNAMIC_COLORS[c_idx]
                group_text = f"\033[38;5;{color}m███{COLOR_RESET}"

            progress_text = f"{COLOR_BLUE}{format_num(d.current_pings)}{COLOR_RESET}/{COLOR_BLUE}{format_num(d.target_pings)}{COLOR_RESET}"

            # Color IP: red for local, cyan for others
            ip_color = colorize_local_ip(d.ip) if self.local_ip and d.ip == self.local_ip else colorize_ip(d.ip)
            line = (
                format_cell(ip_color, COL_IP_WIDTH) +
                format_cell_center(colorize_status(status), COL_STATUS_WIDTH) +
                format_cell_center(group_text, COL_GROUP_WIDTH) +
                " " +
                format_cell(host_color, COL_HOSTNAME_WIDTH) +
                format_cell_center(avg_text, COL_PING_WIDTH) +
                format_cell_center(min_text, COL_PING_WIDTH) +
                format_cell_center(max_text, COL_PING_WIDTH) +
                format_cell_center(progress_text, COL_PROGRESS_WIDTH) +
                format_cell(colorize_mac(mac), COL_MAC_WIDTH)
            )
            output.append(line)

        # Whole Network summary row
        online_devs = [d for d in self.devices.values() if d.ping_status]
        all_avgs = [d.ping_stats.get('avg') for d in self.devices.values() if d.ping_stats.get('avg')]
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
            output.append(f"{COLOR_BLUE}{'-' * self.table_width}{COLOR_RESET}")
            output.append(
                format_cell(wn_label, COL_IP_WIDTH) +
                format_cell_center("", COL_STATUS_WIDTH) +
                format_cell_center("", COL_GROUP_WIDTH) +
                " " +
                format_cell("", COL_HOSTNAME_WIDTH) +
                format_cell_center(avg_text, COL_PING_WIDTH) +
                format_cell_center(min_text, COL_PING_WIDTH) +
                format_cell_center(max_text, COL_PING_WIDTH) +
                format_cell_center("", COL_PROGRESS_WIDTH) +
                format_cell("", COL_MAC_WIDTH)
            )

        output.extend(self._get_statistics_lines(list(self.devices.values()), colors=True))
        output.append(f"{COLOR_BLUE}{'=' * self.table_width}{COLOR_RESET}")

        if move_home:
            output.append("\033[J")
            sys.stdout.write("\n".join(output))
        else:
            sys.stdout.write("\n" + "\n".join(output) + "\n")
        sys.stdout.flush()

    def _render(self, force: bool = False, move_home: bool = True):
        if not force:
            now = time.time()
            if now - self.last_render_time < self.render_throttle:
                return
        self.last_render_time = time.time()
        self._render_internal(move_home=move_home)

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

            # Title with phase
            phase = f"{self.phase_number} - {self.current_phase}"
            if self.pings_per_device > 0:
                phase += f" ({format_num(self.pings_per_device)} pings)"
            title = "Network Scanner"
            phase_indent = 8
            title_pad = (self.table_width - len(title)) // 2
            phase_prefix = " " * phase_indent + phase
            phase_vis_len = len(phase_prefix)
            min_title_start = phase_vis_len + 2
            title_start = max(title_pad, min_title_start)
            left_spaces = max(0, title_start - phase_vis_len)
            header_line = phase_prefix + " " * left_spaces + title
            lines.append(fmt(header_line))

            # Progress bars (always at 100%)
            ping_bar_str = ""
            if self.total_pings_target > 0:
                pb_len = PROGRESS_BAR_MAX_LEN
                pct = 100.0
                filled = pb_len
                pct_text = f"{pct:.0f}%"
                ping_bar_str = f"Pings:  {self._build_bar(pb_len, filled, pct_text)} {format_num(self.total_pings_completed)}/{format_num(self.total_pings_target)}"

            dev_bar_str = ""
            if self.total_count > 0:
                dev_pb_len = PROGRESS_BAR_MAX_LEN
                dev_pct = 100.0
                dev_filled = dev_pb_len
                dev_pct_text = f"{dev_pct:.0f}%"
                dev_bar_str = f"Devices:{self._build_bar(dev_pb_len, dev_filled, dev_pct_text)} {format_num(self.completed_count)}/{format_num(self.total_count)}"

            # Network info in 2 columns
            ni = self.network_info
            gw_str = ni.get('gateway', UNKNOWN_VALUE) or UNKNOWN_VALUE
            ip_str = ni.get('ip', UNKNOWN_VALUE) or UNKNOWN_VALUE
            mask_str = ni.get('subnet_mask', UNKNOWN_VALUE) or UNKNOWN_VALUE
            dns_str = ni.get('dns_servers', [UNKNOWN_VALUE])[0] if ni.get('dns_servers') else UNKNOWN_VALUE
            net_label_w = 4
            net_val_w = 15
            net_r1 = f"IP:{' ' * (net_label_w - 3 + 3)}{ip_str:<{net_val_w}}GW:{' ' * (net_label_w - 3 + 3)}{gw_str:<{net_val_w}}"
            net_r2 = f"Subnet:{' ' * (net_label_w - 6 + 3)}{mask_str:<{net_val_w}}DNS:{' ' * (net_label_w - 4 + 3)}{dns_str:<{net_val_w}}"

            # Device stats in 2 columns
            on = [d for d in devs if d.ping_status]
            off = [d for d in devs if not d.ping_status and (
                (d.mac_address and d.mac_address != UNKNOWN_VALUE) or
                (d.hostname and d.hostname != UNKNOWN_VALUE)
            )]
            fr = max(0, self.total_count - len(on) - len(off))
            used = len(on) + len(off)
            stat_label_w = 4
            stat_val_w = 4
            stats_r1 = f"Online:{' ' * (stat_label_w - 7 + 3)}{format_num(len(on)):<{stat_val_w}}Offline:{' ' * (stat_label_w - 8 + 3)}{format_num(len(off)):<{stat_val_w}}"
            stats_r2 = f"Used:{' ' * (stat_label_w - 5 + 3)}{format_num(used):<{stat_val_w}}Free:{' ' * (stat_label_w - 5 + 3)}{format_num(fr):<{stat_val_w}}"

            max_bar_len = max(get_visible_len(ping_bar_str), get_visible_len(dev_bar_str)) if (ping_bar_str or dev_bar_str) else 0

            if ping_bar_str:
                padding = max(PROGRESS_BAR_MARGIN, max_bar_len + PROGRESS_BAR_MARGIN - get_visible_len(ping_bar_str))
                lines.append(ping_bar_str + " " * padding + net_r1 + "  " + stats_r1)
            if dev_bar_str:
                padding = max(PROGRESS_BAR_MARGIN, max_bar_len + PROGRESS_BAR_MARGIN - get_visible_len(dev_bar_str))
                lines.append(dev_bar_str + " " * padding + net_r2 + "  " + stats_r2)

            lines.append("=" * self.table_width)

            # Table header (Group centered in COL_GROUP_WIDTH + 1 space gap)
            grp_header = "Group"
            g_pad = max(0, COL_GROUP_WIDTH - len(grp_header))
            g_left = g_pad // 2
            g_right = g_pad - g_left
            lines.append(
                f"{'IP Address':<18} {'Status':<12} {' ' * g_left}{grp_header}{' ' * g_right}  {'Hostname':<30} "
                f"{'Ping Avg':<13} {'Ping Min':<13} {'Ping Max':<13} "
                f"{'Progress':<12} {'MAC Address':<20}"
            )
            lines.append("-" * self.table_width)

            # Device rows — only confirmed online devices
            sorted_ips = sorted(self.devices.keys(), key=lambda x: tuple(map(int, x.split('.'))))
            for ip in sorted_ips:
                d = self.devices[ip]
                if not d.ping_status:
                    continue
                status = STATUS_ONLINE
                host = d.hostname or UNKNOWN_VALUE
                mac = d.mac_address or UNKNOWN_VALUE
                if len(host) > HOSTNAME_MAX_DISPLAY:
                    host = host[:HOSTNAME_TRUNCATE_LEN] + "..."

                # Group: 3 colored blocks or 3 dashes
                if d.group_id > GROUP_ID_NONE:
                    group = "███"
                else:
                    group = "   "

                progress = f"{format_num(d.current_pings)}/{format_num(d.target_pings)}"
                avg = format_float(d.ping_stats.get('avg')) if d.ping_stats.get('avg') else "N/A"
                mn = format_float(d.ping_stats.get('min')) if d.ping_stats.get('min') else "N/A"
                mx = format_float(d.ping_stats.get('max')) if d.ping_stats.get('max') else "N/A"

                # Center group in COL_GROUP_WIDTH
                g_pad = max(0, COL_GROUP_WIDTH - len(group))
                g_left = g_pad // 2
                g_right = g_pad - g_left
                lines.append(
                    f"{d.ip:<18} {status:<12} {' ' * g_left}{group}{' ' * g_right}  {host:<30} "
                    f"{avg:<13} {mn:<13} {mx:<13} {progress:<12} {mac:<20}"
                )

            # Whole Network summary row
            all_avgs = [d.ping_stats.get('avg') for d in devs if d.ping_stats.get('avg')]
            all_mins = [d.ping_stats.get('min') for d in devs if d.ping_stats.get('min') is not None]
            all_maxs = [d.ping_stats.get('max') for d in devs if d.ping_stats.get('max') is not None]
            if all_avgs:
                net_avg = sum(all_avgs) / len(all_avgs)
                net_min = min(all_mins) if all_mins else None
                net_max = max(all_maxs) if all_maxs else None
                lines.append("-" * self.table_width)
                lines.append(
                    f"{'Whole Network':<18} {'':12} {'':3}  {'':30} "
                    f"{format_float(net_avg):<13} "
                    f"{format_float(net_min) if net_min else 'N/A':<13} "
                    f"{format_float(net_max) if net_max else 'N/A':<13} {'':12} {'':20}"
                )

            # Internet stats (2 lines, centered)
            stat_lines = self._get_statistics_lines(devs, colors=False)
            ansi_re = re.compile(r'\033\[[0-9;]*m')
            lines.extend(ansi_re.sub('', line) for line in stat_lines)

            lines.append("=" * self.table_width)
            return '\n'.join(lines)


# ═══════════════════════════════════════════════════════════════════════════════
# INPUT LISTENER
# ═══════════════════════════════════════════════════════════════════════════════

def input_listener(control: ScannerControl):
    if platform.system() == "Windows":
        _input_listener_windows(control)
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
                if '\x1b' in inp:
                    control.request_stop()
                    break
                elif 'p' in inp:
                    control.toggle_pause()
                elif 'r' in inp:
                    control.request_restart()
                    break
                elif 'q' in inp:
                    control.request_stop()
                    break
            if control.stop_requested or control.restart_requested:
                break
    except Exception:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def _input_listener_windows(control: ScannerControl):
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
            if ch in ('\x1b', '\x03'):
                control.request_stop()
                break
            elif ch == 'p':
                control.toggle_pause()
            elif ch == 'r':
                control.request_restart()
                break
            elif ch == 'q':
                control.request_stop()
                break
        if control.stop_requested or control.restart_requested:
            break
        time.sleep(KEY_SLEEP_INTERVAL)


# ═══════════════════════════════════════════════════════════════════════════════
# PING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def ping_host_multiple(
    ip: str,
    count: int = DEFAULT_PING_COUNT,
    lt: Optional[LiveTable] = None,
    ctrl: Optional[ScannerControl] = None,
    local_ip: str = None,
    local_mac: str = None
) -> Device:
    """Ping a host multiple times and return a Device with collected stats."""
    system = platform.system()
    mac = get_mac_address(ip, system, local_ip, local_mac)
    host = get_hostname(ip)

    lats: List[float] = []
    succ = 0
    dev = Device(ip=ip, mac_address=mac, hostname=host, target_pings=count, current_pings=0)

    if lt:
        lt.update_device(dev)

    for i in range(count):
        if ctrl and ctrl.should_exit_task():
            break
        if ctrl:
            ctrl.wait_if_paused()

        timeout_arg = WINDOWS_PING_TIMEOUT_MS if system == "Windows" else UNIX_PING_TIMEOUT_S
        cmd = [
            "ping",
            "-n" if system == "Windows" else "-c", "1",
            "-w" if system == "Windows" else "-W", str(timeout_arg),
            ip
        ]

        try:
            res = _run(cmd, timeout=PING_TIMEOUT_SECONDS)
            dev.current_pings = i + 1

            if res.returncode == 0:
                succ += 1
                dev.ping_status = True
                m = re.search(r'time[=<:]\s*([\d.]+)\s*ms', res.stdout, re.IGNORECASE)
                if m:
                    latency = float(m.group(1))
                    lats.append(latency)
                    dev.latency_ms = sum(lats) / len(lats)
                    dev.ping_stats = {
                        'min': min(lats),
                        'max': max(lats),
                        'avg': sum(lats) / len(lats),
                        'count': succ
                    }

            if lt:
                lt.update_device(dev)
        except Exception:
            dev.current_pings = i + 1
            if lt:
                lt.update_device(dev)
            continue

    return dev


def ping_internet_hosts(live_table: LiveTable, hosts: List[str], count: int = DEFAULT_PING_COUNT):
    """Ping internet hosts in parallel and update latency. Each host gets its own thread."""
    def _ping_one(host: str):
        system = platform.system()
        lats: List[float] = []
        succ = 0

        for _ in range(count):
            timeout_arg = WINDOWS_PING_TIMEOUT_MS if system == "Windows" else UNIX_PING_TIMEOUT_S
            cmd = [
                "ping",
                "-n" if system == "Windows" else "-c", "1",
                "-w" if system == "Windows" else "-W", str(timeout_arg),
                host
            ]

            try:
                res = _run(cmd, timeout=PING_TIMEOUT_SECONDS)
                if res.returncode == 0:
                    m = re.search(r'time[=<:]\s*([\d.]+)\s*ms', res.stdout, re.IGNORECASE)
                    if m:
                        lats.append(float(m.group(1)))
                        succ += 1
            except Exception:
                pass

        if lats:
            live_table.set_public_latency(host, {
                'min': min(lats),
                'max': max(lats),
                'avg': sum(lats) / len(lats),
                'count': succ
            })

    threads = [threading.Thread(target=_ping_one, args=(h,), daemon=True) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ═══════════════════════════════════════════════════════════════════════════════
# SUBNET SCAN
# ═══════════════════════════════════════════════════════════════════════════════

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
    file_output: bool = True
) -> LiveTable:
    """Scan a subnet and ping all devices."""
    live_table = live_table_obj if live_table_obj else LiveTable()
    ip_range = [f"{subnet}.{i}" for i in range(SUBNET_FIRST_IP, SUBNET_LAST_IP + 1)]
    live_table.total_count = len(ip_range)

    live_table.start_refresh_timer()
    last_group_calc = time.time()

    # Calculate total pings for progress bar
    _internet_hosts = internet_hosts if internet_hosts else []
    discovery_pings = len(ip_range) * DISCOVERY_PING_COUNT
    analysis_pings = len(ip_range) * ping_count if ping_count > 0 else 0
    internet_pings = len(_internet_hosts) * ping_count
    live_table.set_total_pings(0, discovery_pings + analysis_pings + internet_pings)

    live_table.set_phase("Discovery", DISCOVERY_PING_COUNT)
    live_table._render(force=True)

    # Start internet pings in a separate thread immediately
    internet_thread = None
    if _internet_hosts and ping_count > 0:
        internet_thread = threading.Thread(
            target=ping_internet_hosts, args=(live_table, _internet_hosts, ping_count), daemon=True
        )
        internet_thread.start()

    if high_pressure:
        # High pressure: all devices simultaneously, up to N subthreads per device
        max_workers = min(MAX_WORKERS_INIT, len(ip_range) * HIGH_PRESSURE_SUBTHREADS_PER_DEVICE)
        executor = ThreadPoolExecutor(max_workers=max_workers)
        futures = {
            executor.submit(
                ping_host_multiple, ip, ping_count, live_table, control, local_ip, local_mac
            ): ip for ip in ip_range
        }
        completed = 0

        for dev in as_completed(futures):
            if control and control.should_exit_task():
                break
            if control:
                control.wait_if_paused()
            completed += 1
            total_done = completed * ping_count
            live_table.set_total_pings(total_done, analysis_pings + internet_pings)
            if time.time() - last_group_calc > GROUP_CALC_INTERVAL_SECONDS:
                live_table.calculate_groups()
                last_group_calc = time.time()
            live_table.set_completed(completed)
            live_table._try_render()

        executor.shutdown(wait=False)
    else:
        # Standard mode: Discovery phase (1 ping each)
        executor = ThreadPoolExecutor(max_workers=init_workers)
        futures = {
            executor.submit(
                ping_host_multiple, ip, DISCOVERY_PING_COUNT, live_table, control, local_ip, local_mac
            ): ip for ip in ip_range
        }
        completed = 0

        for dev in as_completed(futures):
            if control and control.should_exit_task():
                break
            if control:
                control.wait_if_paused()
            completed += 1
            live_table.set_total_pings(completed * DISCOVERY_PING_COUNT, discovery_pings + analysis_pings + internet_pings)
            if time.time() - last_group_calc > GROUP_CALC_INTERVAL_SECONDS:
                live_table.calculate_groups()
                last_group_calc = time.time()
            live_table.set_completed(completed)
            live_table._try_render()

        executor.shutdown(wait=False)

        # Analysis phase (full ping_count per device)
        if ping_count > 0 and not (control and control.should_exit_task()):
            live_table.set_phase("Analysis", ping_count)
            live_table.set_completed(0, force_render=True)
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        ping_host_multiple, ip, ping_count, live_table, control, local_ip, local_mac
                    ): ip for ip in ip_range
                }
                completed = 0
                for dev in as_completed(futures):
                    if control and control.should_exit_task():
                        break
                    if control:
                        control.wait_if_paused()
                    completed += 1
                    total_done = discovery_pings + internet_pings + (completed * ping_count)
                    live_table.set_total_pings(total_done, discovery_pings + analysis_pings + internet_pings)
                    if time.time() - last_group_calc > GROUP_CALC_INTERVAL_SECONDS:
                        live_table.calculate_groups()
                        last_group_calc = time.time()
                    live_table.set_completed(completed)
                    live_table._try_render()

    live_table.calculate_groups()

    # Enrich online devices with MAC/hostname from previous scan (same router/network).
    # Offline-only previous devices are intentionally not merged — we only show
    # devices that responded in the current scan.
    gateway_mac = None
    if live_table.gateway_ip and live_table.gateway_ip in live_table.devices:
        gateway_mac = live_table.devices[live_table.gateway_ip].mac_address
    previous_devices = load_previous_devices(output_dir, gateway_mac)
    with live_table.lock:
        for prev_dev in previous_devices:
            if prev_dev.ip in live_table.devices:
                curr = live_table.devices[prev_dev.ip]
                # Only enrich devices that are ONLINE in the current scan
                if not curr.ping_status:
                    continue
                if (curr.mac_address is None or curr.mac_address == UNKNOWN_VALUE) and prev_dev.mac_address and prev_dev.mac_address != UNKNOWN_VALUE:
                    curr.mac_address = prev_dev.mac_address
                if (curr.hostname is None or curr.hostname == UNKNOWN_VALUE) and prev_dev.hostname and prev_dev.hostname != UNKNOWN_VALUE:
                    curr.hostname = prev_dev.hostname

    live_table.calculate_groups()
    # Ensure progress bar shows 100% at end
    live_table.set_total_pings(live_table.total_pings_target, live_table.total_pings_target)
    live_table.stop_refresh_timer()
    live_table._render(force=True)
    return live_table


# ═══════════════════════════════════════════════════════════════════════════════
# SAVE RESULTS
# ═══════════════════════════════════════════════════════════════════════════════

def save_results(live_table: LiveTable, network_info: Dict, output_dir: str = ".") -> str:
    """Save scan results to a text file."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"network_scan_{timestamp}.txt")

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
    lines.append(f"IP Address:     {network_info.get('ip', UNKNOWN_VALUE)}")

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


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

def main(ping_count: int = DEFAULT_PING_COUNT, high_pressure: bool = False) -> str:
    """Run a network scan."""
    _ensure_conf_template()
    cfg = load_config_manager()
    cfg.print_warnings()       # Show any range/type corrections immediately
    print_config_info(cfg)

    cfg_ping_count = cfg.get_int('ping_count', DEFAULT_PING_COUNT, 'scanning')
    if ping_count == DEFAULT_PING_COUNT and cfg_ping_count != DEFAULT_PING_COUNT:
        ping_count = cfg_ping_count
    cfg_high_pressure = cfg.get_bool('high_pressure_mode', False, 'scanning')
    if not high_pressure and cfg_high_pressure:
        high_pressure = True

    interface = get_ethernet_interface() or "eth0"
    network_info = get_network_info(interface)
    ip = network_info.get('ip')
    cfg_subnet = cfg.get_str('subnet', '', 'network')
    # Strip CIDR suffix if present (e.g. "192.168.2.0/24" → "192.168.2")
    if cfg_subnet and '/' in cfg_subnet:
        cfg_subnet = '.'.join(cfg_subnet.split('/')[0].split('.')[:SUBNET_OCTET_COUNT])
    subnet = cfg_subnet if cfg_subnet else get_subnet(ip)

    if not subnet:
        print("Error: Could not determine subnet")
        return 'exit'

    control = ScannerControl()
    listener = threading.Thread(target=input_listener, args=(control,), daemon=True)
    listener.start()

    live_table = LiveTable()
    live_table.render_throttle = cfg.get_float('refresh_rate', RENDER_THROTTLE_SECONDS, 'scanning')
    live_table.set_network_info(network_info)
    gateway = network_info.get('gateway')
    if gateway:
        live_table.set_gateway(gateway)

    # Initial internet latency check
    cfg_enable_inet = cfg.get_bool('enable_internet_ping', True, 'internet')
    internet_unreachable = False
    if cfg_enable_inet:
        raw_hosts = cfg.get_str('internet_hosts', '', 'internet')
        internet_hosts = [h.strip() for h in raw_hosts.split(',') if h.strip()] if raw_hosts else INTERNET_PING_HOSTS
        for host_ip in internet_hosts:
            lats: List[float] = []
            for _ in range(INITIAL_INTERNET_PING_COUNT):
                try:
                    timeout_arg = WINDOWS_PING_TIMEOUT_MS if platform.system() == "Windows" else UNIX_PING_TIMEOUT_S
                    cmd = [
                        "ping",
                        "-n" if platform.system() == "Windows" else "-c", "1",
                        "-w" if platform.system() == "Windows" else "-W", str(timeout_arg),
                        host_ip
                    ]
                    res = _run(cmd, timeout=PING_TIMEOUT_SECONDS)
                    if res.returncode == 0:
                        m = re.search(r'time[=<:]\s*([\d.]+)\s*ms', res.stdout, re.IGNORECASE)
                        if m:
                            lats.append(float(m.group(1)))
                except Exception:
                    pass
            if lats:
                live_table.set_public_latency(host_ip, {
                    'min': min(lats),
                    'max': max(lats),
                    'avg': sum(lats) / len(lats)
                })
            else:
                internet_unreachable = True
    else:
        internet_hosts = []

    live_table = scan_subnet(
        subnet,
        ping_count=ping_count,
        max_workers=cfg.get_int('ping_threads', MAX_WORKERS_ANALYSIS, 'scanning'),
        init_workers=cfg.get_int('init_ping_threads', MAX_WORKERS_INIT, 'scanning') or MAX_WORKERS_INIT,
        control=control,
        live_table_obj=live_table,
        local_ip=ip,
        local_mac=network_info.get('mac'),
        high_pressure=high_pressure,
        internet_hosts=internet_hosts if cfg_enable_inet else [],
        output_dir=cfg.get_str('output_directory', '.', 'output'),
        file_output=cfg.get_bool('file_output', True, 'output')
    )

    control.shutdown = True
    if control.restart_requested:
        return 'restart'

    # Internet reachability warning
    if cfg_enable_inet and internet_unreachable:
        print(f"\n{COLOR_YELLOW}Warning: Some internet hosts were unreachable. Check your network connection.{COLOR_RESET}")

    # Phase 3: Save TXT
    cfg_file_output = cfg.get_bool('file_output', True, 'output')
    if cfg_file_output:
        live_table.set_phase("Save TXT", 0)
        filename = save_results(live_table, network_info, cfg.get_str('output_directory', '.', 'output'))
        print(f"\nResults saved to: {COLOR_GREEN}{filename}{COLOR_RESET}")

    # Phase 4: Ready
    live_table.set_phase("Ready", 0)
    live_table._render(force=True, move_home=False)
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
    col_w = 25
    cols = 4

    # Row 1: [1] 10 pings, [2] 100 pings, [3] 1.000 pings, [4] 10.000 pings
    row1 = [
        f"[{k}1{r}] {b}{PING_COUNT_OPTIONS[0]:,}{r} pings",
        f"[{k}2{r}] {b}{PING_COUNT_OPTIONS[1]:,}{r} pings",
        f"[{k}3{r}] {b}{PING_COUNT_OPTIONS[2]:,}{r} pings",
        f"[{k}4{r}] {b}{PING_COUNT_OPTIONS[3]:,}{r} pings",
    ]
    # Row 2: [5] 100.000 pings, [6] 1.000.000 pings, [h] HIGH PRESSURE, [q/ESC] Quit
    row2 = [
        f"[{k}5{r}] {b}{PING_COUNT_OPTIONS[4]:,}{r} pings",
        f"[{k}6{r}] {b}{PING_COUNT_OPTIONS[5]:,}{r} pings",
        f"[{k}h{r}] {rd}HIGH PRESSURE{r}",
        f"[{k}q{r}/ESC{r}] Quit",
    ]

    for row in [row1, row2]:
        parts = []
        for item in row:
            pad = max(0, col_w - get_visible_len(item))
            parts.append(item + " " * pad)
        line = "".join(parts)
        vis_len = get_visible_len(line)
        indent = (TABLE_WIDTH - vis_len) // 2
        print(" " * max(0, indent) + line)

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
                if ch in ('1', '2', '3', '4', '5', '6', 'h', 'q'):
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
                for key in ['1', '2', '3', '4', '5', '6', 'h', 'q']:
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
    cp = DEFAULT_PING_COUNT
    high_pressure = False
    while True:
        status = main(ping_count=cp, high_pressure=high_pressure)
        if status == 'restart':
            cp = DEFAULT_PING_COUNT
            high_pressure = False
            continue
        elif status == 'exit':
            break

        if sys.stdin.isatty():
            choice = show_restart_options()
            if choice == '1':
                cp = PING_COUNT_OPTIONS[0]
                high_pressure = False
                continue
            elif choice == '2':
                cp = PING_COUNT_OPTIONS[1]
                high_pressure = False
                continue
            elif choice == '3':
                cp = PING_COUNT_OPTIONS[2]
                high_pressure = False
                continue
            elif choice == '4':
                cp = PING_COUNT_OPTIONS[3]
                high_pressure = False
                continue
            elif choice == '5':
                cp = PING_COUNT_OPTIONS[4]
                high_pressure = False
                continue
            elif choice == '6':
                cp = PING_COUNT_OPTIONS[5]
                high_pressure = False
                continue
            elif choice == 'h':
                cp = PING_COUNT_OPTIONS[0]
                high_pressure = True
                continue
            elif choice == 'q':
                print("\nExiting... Goodbye!")
                break
        else:
            break
