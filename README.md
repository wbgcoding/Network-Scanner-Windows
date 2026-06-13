# Network Scanner

Pings every host on your `/24` subnet and tracks live latency — min, max, average, last — in a terminal table that updates in place. Runs on Windows, no admin rights required.


---

## Download

Download the latest zip from the [releases page](https://github.com/wbgcoding/Network-Scanner/releases/latest), unzip it, run `NetworkScanner.exe`.

First launch may trigger a SmartScreen prompt ("Windows protected your PC"). Click **More info → Run anyway**. The app removes the download flag on startup, so it only appears once.

---

## From source

Python 3.8 or later:

```
python network_scanner.py
```

---

## How it works

Sends a single discovery ping to all 254 addresses in your subnet. Hosts that reply go straight into latency analysis while the rest of the scan is still running. It auto-detects your IP, gateway, subnet mask, MAC and DNS — no arguments needed.

Hostnames come from reverse DNS and NetBIOS lookups; vendor names from the MAC OUI prefix as a fallback. Devices seen on previous runs are loaded from a local SQLite database so they appear immediately, including any that are currently offline.

Internet hosts (Google, Cloudflare, Quad9) are pinged alongside local devices so you can compare LAN and WAN latency in the same view.

---

## Controls

During a scan:

| Key | Action |
|-----|--------|
| `P` | Pause / resume |
| `Q` | Stop, save results, show final screen |
| `ESC` | Quit immediately |
| `+` / `-` | Increase / decrease ping interval by 100 ms |

After a scan finishes:

| Key | Action |
|-----|--------|
| `1`–`5` | Re-run with 10 / 100 / 1k / 10k / 100k pings |
| `8` | Unlimited — keep pinging until you stop it |
| `H` | High-pressure mode (all hosts at once) |
| `Q` / `ESC` | Quit |

---

## Configuration

Works without a config file. To change settings, copy the template and edit it:

```
copy network_scanner.conf.template network_scanner.conf
```

Common options:

| Option | Default | Description |
|--------|---------|-------------|
| `ping_count` | `10` | Pings per device per run |
| `ping_interval_ms` | `100` | Delay between pings to the same host (ms) |
| `offline_after_failed_pings` | `5` | Mark a device offline after N consecutive misses |
| `pinned_ips` | *(none)* | IPs to always show at the top, even when offline |
| `subnet` | auto | Override the detected subnet |
| `export_csv` | `false` | Write a `.csv` alongside the text report |

Full list in `network_scanner.conf.template`.

---

## Output

Each run writes a `network_scan_YYYYMMDD_HHMMSS.txt` file next to the exe. Enable `export_csv = true` in the config to also get a `.csv`.

---

## Display

The window resizes itself to fit the table on every update. On screens below 1920×1080, or with Windows DPI scaling above 100 %, the font shrinks automatically to keep the table intact. If it still wraps or clips, lower the font size in the config:

```ini
[display]
console_font_size = 10
```

Set to `0` to disable automatic font and window sizing.

---

## Build

```
build_exe.bat
```

Produces `dist\NetworkScanner.exe` as a single self-contained file. The config, database and `Scans/` folder are created next to it on first run.
