# WLAN Monitor

**See at a glance which devices are on your local Wi-Fi network, how strong your signal is, and how much traffic is flowing.**

WLAN Monitor is a lightweight Omarchy bar widget and popup panel that discovers and lists devices on your local WLAN without requiring root privileges or extra packages.

- **Bar indicator:** a radar chip icon (`󰐻`). Dim while disconnected; when connected it shows the number of online devices on your WLAN (e.g. `󰐻 8`) with a thin signal-quality bar underneath. It pulses gently while actively scanning the subnet.
- **Signal colours:** the chip and signal bar use the named colours of your active Omarchy theme: **green** (70 %+), **yellow** (50 %+), **orange** (30 %+) and **red** (below 30 %).
- **Detail panel (left click):**
  - **WLAN link:** local IPv4 address/prefix, interface, gateway IP, Wi-Fi band, channel, channel width, TX/RX link bitrates and signal strength in dBm / %.
  - **Traffic:** live download and upload throughput (`↓` / `↑`) plus session RX/TX totals.
  - **Devices on WLAN:** every discovered device on the local subnet, sorted with your router and this PC first, followed by online devices and sleeping DHCP leases:
    - Solid accent dot (`●`) for online devices answering ARP/ICMP; outlined dot (`○`) for sleeping devices known via mDNS or router reverse DNS.
    - Friendly device name (from mDNS / Zeroconf or router reverse DNS), IP address, hardware manufacturer (from the local IEEE OUI database), device model and MAC address.
  - **Rescan WLAN** button for an immediate active subnet + mDNS refresh, plus a **Network** shortcut.
- **Right click:** triggers an immediate WLAN rescan.

## Install

Requires Omarchy's plugin-capable Quickshell and `python3` (standard library only, no extra packages). No setup script or root permissions are needed.

```sh
omarchy plugin add https://github.com/uBruckhaus/omarchy-wlan-monitor
omarchy plugin enable ubruckhaus.wlan-monitor
```

## How it works

A collector (`scripts/wlan-monitor.py`) runs while the widget is loaded and streams one JSON snapshot every three seconds.

- **Unprivileged local discovery:**
  - Periodically sends paced, non-blocking unprivileged ICMP echo probes across the local private IPv4 `/24` subnet so online devices populate the kernel neighbor table (`ip -4 neigh show`).
  - Queries the local router's reverse DNS (`PTR` records) over bounded UDP sockets to resolve hostnames and spot sleeping DHCP leases (such as phones or laptops in Wi-Fi power-save mode).
  - Reads local mDNS / Zeroconf service announcements via `avahi-browse` when available to pick up human-friendly device names (e.g. TV, soundbar, bridge) and model strings.
  - Maps MAC prefixes against the system's local IEEE OUI database (`/usr/lib/udev/hwdb.d/20-OUI.hwdb` or `/usr/share/hwdata/oui.txt`).
- **Sanitized untrusted text:** All SSIDs, hostnames, mDNS strings and vendor names are stripped of `<`, `>`, `&` and control characters before output, and all QML `Text` items render in `Text.PlainText` mode.

## Update or remove

```sh
omarchy plugin update ubruckhaus.wlan-monitor
```

```sh
omarchy plugin disable ubruckhaus.wlan-monitor
omarchy plugin remove ubruckhaus.wlan-monitor
```

The plugin creates no files, services or settings outside its own folder, so nothing else needs cleaning up.

## Development

```sh
python3 scripts/wlan-monitor.py --once | python3 -m json.tool
python3 -m unittest discover -s tests -v
omarchy plugin validate .
```

Licensed under [MIT](LICENSE).
