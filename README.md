# WLAN Monitor

**See at a glance which devices are on your local Wi-Fi network, how strong your signal is, and how much traffic is flowing.**

WLAN Monitor is a lightweight Omarchy bar widget and popup panel that discovers and lists devices on your local WLAN without requiring root privileges or extra packages.

- **Bar indicator:** a radar chip icon (`󰐻`). Dim while disconnected; when connected it shows the number of online devices on your WLAN (e.g. `󰐻 8`) with a thin signal-quality bar underneath. It pulses gently while actively scanning the subnet.
- **Signal colours:** the chip and signal bar use the named colours of your active Omarchy theme: **green** (70 %+), **yellow** (50 %+), **orange** (30 %+) and **red** (below 30 %).
- **Detail panel (left click):**
  - **WLAN link:** local IPv4 address/prefix, interface, gateway IP, Wi-Fi band, channel, channel width, TX/RX link bitrates and signal strength in dBm / %.
  - **Traffic:** live download and upload throughput (`↓` / `↑`) plus session RX/TX totals.
  - **Devices on WLAN:** every discovered device on the local subnet, sorted with your router and this PC first, followed by online, idle and sleeping devices:
    - Solid accent dot (`●`) for devices confirmed online (the kernel verified them, or they answered a probe within the last 45 s).
    - Outlined dot (`○`) and **idle** for devices still in the kernel's neighbor cache that have not been confirmed recently, and **sleeping** for devices that went away or are only known from mDNS / router reverse DNS (e.g. phones in Wi-Fi sleep). Gone devices are dropped after 10 minutes.
    - Friendly device name (from mDNS / Zeroconf or router reverse DNS), IP address, hardware manufacturer (from the local IEEE OUI database), device model and MAC address.
  - **Open web interfaces:** devices with a web UI show a `󰖟` mark. Click the row to open it in your default browser. This covers the router (e.g. the FRITZ!Box at `http://192.168.178.1/`), devices announcing `_http._tcp` / `_https._tcp` over mDNS, and printer/scanner admin pages (`adminurl`). The **Router** button opens the router directly.
  - **Rescan**, **Trust / Untrust** (see below) and a **Network** button that opens Omarchy's built-in Network panel.
- **Right click:** triggers an immediate WLAN rescan.

## Trusted networks and scanning

Discovery is **passive** on every network by default: the kernel neighbor table, mDNS announcements and single reverse-DNS lookups for devices that are already visible. Nothing probes the subnet, so the widget behaves well on hotel, café and office Wi-Fi.

Click **Trust** in the panel to allow **active** scanning on the current network (identified by SSID and router MAC address):

- a full sweep every 2 minutes (and when you open the panel, if the last one is older than 30 s): paced ICMP echo to the local `/24` plus a reverse-DNS (PTR) query per address to the router, which also finds sleeping DHCP leases;
- every 15 s a unicast probe of the devices already known, so the online state stays accurate without broadcast ARP traffic.

**Rescan** (or right click) runs one active sweep on demand, on any network. Trusted networks are stored in `~/.config/ubruckhaus-wlan-monitor/trusted-networks.json` (directory `0700`, file `0600`), written only when you click Trust or Untrust.

Optional environment variables for the shell: `WLAN_MONITOR_INTERVAL` (seconds between snapshots while the panel is open, default 3), `WLAN_MONITOR_INTERVAL_CLOSED` (default 6) and `WLAN_MONITOR_FULL_SCAN_EVERY` (full sweep interval on trusted networks, default 120, minimum 30).

## Install

Requires Omarchy's plugin-capable Quickshell and `python3` (standard library only, no extra packages). No setup script or root permissions are needed.

```sh
omarchy plugin add https://github.com/uBruckhaus/omarchy-wlan-monitor
omarchy plugin enable ubruckhaus.wlan-monitor
```

## How it works

A collector (`scripts/wlan-monitor.py`) runs while the widget is loaded and streams one JSON snapshot every 3 s while the panel is open (6 s while closed). The bar widget sends it commands over stdin (`rescan`, `open` / `closed`, `trust` / `untrust`).

- **Light on the system:** routes, signal level and traffic come from `/proc`; `iw` and `ip addr` run only every 12 / 30 s (or when the network changes). All external commands run as fixed argv lists with bounded output and timeouts.
- **Unprivileged local discovery:**
  - Reads the kernel neighbor table (`ip -4 neigh show`). On trusted networks, sends paced unprivileged ICMP echo probes (see above) so online devices show up there.
  - Queries the router's reverse DNS (`PTR` records) over bounded UDP sockets. Replies are only accepted from the router's address and port 53 with a random, outstanding query ID. The router's local domain (e.g. `fritz.box`, `speedport.ip`, `home.arpa`, or one learned from the PTR answers / `resolv.conf`) is removed from names.
  - Reads mDNS / Zeroconf service announcements via `avahi-browse` when available, for human-friendly device names (e.g. TV, soundbar, bridge), model strings and web interfaces.
  - Maps MAC prefixes against the system's local IEEE OUI database (`/usr/lib/udev/hwdb.d/20-OUI.hwdb` or `/usr/share/hwdata/oui.txt`).
- **Network changes:** everything learned (devices, names, caches) is cleared when the interface, gateway, subnet, SSID or router MAC changes, so devices from your home network never appear on another one.
- **Sanitized untrusted text:** All SSIDs, hostnames, mDNS strings and vendor names are stripped of `<`, `>`, `&` and control characters before output, and all QML `Text` items render in `Text.PlainText` mode.
- **Safe web links:** web UI URLs are built only from the device's private IPv4 address inside the local subnet, a numeric port and a plain path (`[A-Za-z0-9._~/-]`, no `..`). Advertised services are offered only after a TCP connect check succeeds. The panel checks the URL shape again and opens it in your default browser with `omarchy-launch-browser` as a single argument, with no shell.

## Update or remove

```sh
omarchy plugin update ubruckhaus.wlan-monitor
```

```sh
omarchy plugin disable ubruckhaus.wlan-monitor
omarchy plugin remove ubruckhaus.wlan-monitor
```

The plugin creates no services. The only file outside its folder is the trusted network list in `~/.config/ubruckhaus-wlan-monitor/`, created when you first click **Trust**. Delete that directory to remove it.

## Development

```sh
python3 scripts/wlan-monitor.py --once | python3 -m json.tool
python3 -m unittest discover -s tests -v
omarchy plugin validate .
```

Licensed under [MIT](LICENSE).
