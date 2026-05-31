# Network Scanner v1.5

A fast, single-window network scanner for Windows. Download `NetworkScanner-v1.5.zip`
below, unzip, and run `NetworkScanner.exe` — no install, no dependencies.

## Highlights since v1.3

### Startup & detection
- **Near-instant start** — local IP, gateway, MAC, subnet mask and DNS are read
  directly from the Windows IP Helper API instead of slow PowerShell queries.
- **Reliable MAC / MASK / DNS** for the local host (no more "Unknown").
- **Known devices appear immediately** from the database and start pinging in the
  first sweep.

### Scanning
- **Offline after N misses** — a device is shown OFFLINE after N consecutive pings
  with no reply (configurable, default 5); it recovers automatically if it answers
  again, and stays listed instead of vanishing.
- **Offline re-probe** — offline devices are re-checked during the run and promoted
  back online the moment they respond.
- **Pinned IPs** — list any IPs in the config to always ping them and pin them to
  the top of the list, even while offline.
- **Internet hosts** are pinged as often as local devices (including ∞).

### Live controls (footer)
- `P` pause · `Q` stop + save · `ESC` quit · **`+ / -` adjust the ping interval
  live (±100 ms)** with the current value shown.

### Display
- Per-column **red (slowest) / green (fastest)** markers in the ping columns,
  without shifting the values.
- Skipped pings (offline) shown **gray**, failed pings **red** on the ping bar.
- Large counts abbreviated (`1k`, `1M`); the running value stays exact, finished
  bars read cleanly (`1k/1k`).
- ∞ shown in purple in unlimited mode.
- The window auto-fits its width to the content on every update.

### Packaging
- Single standalone **`NetworkScanner.exe`** with its own application icon.
- The config, database and `Scans/` folder are created next to the `.exe` at
  runtime and can be edited without rebuilding.

## Configuration
All settings are optional — the scanner runs on sensible defaults. Copy
`network_scanner.conf.template` to `network_scanner.conf` to customise (subnets,
`pinned_ips`, `ping_count`, `offline_after_failed_pings`, internet hosts, …).
