# Network Scanner v1.3

This release is mostly about how the scan feels while it runs, plus two things
people kept asking for: remembering devices between runs, and a CSV export.

## New

- **Known-devices database.** The scanner now keeps a local SQLite file
  (`known_devices.db`) of every device it sees, keyed by the network's gateway MAC.
  When it recognises the same router again it lists the devices it knows about —
  including the ones that are offline right now — so you can tell what's missing.
  The database fills up on every run. Toggle with `known_devices_db` in the config.
- **CSV export.** Set `export_csv = true` to drop a machine-readable `.csv` next to
  the text report (one row per device, dot-decimal numbers, parses anywhere).
- **Unlimited mode (`8`).** Picks ∞ from the menu and keeps pinging until you stop.
  Handy for leaving a latency monitor running on a link.
- **`ping_interval_ms`** (default 100 ms). A fixed pause between two pings to the
  same host. Without it a high ping count finished almost instantly on a fast LAN;
  now a run takes a sensible amount of time and the bar moves at a readable pace.

## Notes

The config gained `ping_interval_ms`, `export_csv` and `known_devices_db` — see
`network_scanner.conf.template`.
