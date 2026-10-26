#!/usr/bin/env python3
"""Stream local WLAN status and discovered devices as one JSON line per interval (stdlib only).

Reads wireless link metrics from /proc/net/route, /proc/net/wireless, /proc/net/dev,
/sys/class/net and `iw`, then discovers devices on the local IPv4 subnet without root
privileges:

- Passive (every network): the kernel neighbor table (`ip -4 neigh show`), mDNS /
  Zeroconf announcements (`avahi-browse`) and single reverse-DNS lookups for
  neighbors that are already known.
- Active (only on networks the user marked as trusted, or on an explicit rescan):
  paced unprivileged ICMP echo probes across the subnet plus a router reverse-DNS
  (PTR) sweep that also finds sleeping DHCP leases. Between full sweeps only the
  already known devices are probed, by unicast.
- Local IEEE OUI hardware database (`/usr/lib/udev/hwdb.d/20-OUI.hwdb` or
  `/usr/share/hwdata/oui.txt`) for manufacturer identification.

Commands are read from stdin, one per line: `rescan`, `open` / `closed` (panel
state), `trust` / `untrust` (the current network), `known_all`, or a JSON object for
per-device settings: `{"cmd": "rename" | "pin" | "hide" | "known", "mac": ..., "name" | "on": ...}`
and `{"cmd": "alerts", "on": true | false}`.

Friendly names, pins and hidden flags are stored per network (router MAC + SSID) in
`~/.config/ubruckhaus-wlan-monitor/devices.json`. On trusted networks the MAC addresses
seen there are remembered too, so devices joining later can be flagged as new.

FRITZ!Box routers: the model name comes from the unauthenticated TR-064 description
(`http://<router>:49000/tr64desc.xml`). With an optional login (`fritz_login` command with the
`net_id` from `link` it was typed for, refused unless that network is still current,
stored owner-only and bound to that router's MAC) a background thread reads the mesh
list over TR-064 HTTPS (port 49443, certificate pinned at login) to show which access
point, band and speed each device uses.
"""
import contextlib
import fcntl
import hashlib
import http.client
import ipaddress
import json
import math
import os
import pty
import random
import re
import secrets
import select
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse


def env_float(name, default, minimum):
    try:
        return max(minimum, float(os.environ.get(name, default)))
    except ValueError:
        return float(default)


INTERVAL_OPEN = env_float("WLAN_MONITOR_INTERVAL", 3, 1)  # snapshot interval while the panel is open
INTERVAL_CLOSED = env_float("WLAN_MONITOR_INTERVAL_CLOSED", 6, 1)  # ... and while it is closed
FULL_SCAN_EVERY = env_float("WLAN_MONITOR_FULL_SCAN_EVERY", 120, 30)  # full subnet sweep (trusted networks)
FULL_SCAN_ON_OPEN = 30.0  # opening the panel sweeps when the last full sweep is older than this
KNOWN_SCAN_EVERY = 15.0  # unicast probe of already known devices (trusted networks)
MDNS_EVERY_OPEN = 15.0
MDNS_EVERY_CLOSED = 60.0
IW_EVERY = 12.0  # full `iw dev link` refresh while the panel is closed (signal comes from /proc)
ADDR_EVERY = 30.0  # `ip addr` refresh unless the default routes change
ONLINE_GRACE = 45.0  # a STALE neighbor counts as online this long after it was last confirmed
SLEEPING_KEEP = 600.0  # keep devices that went away listed as sleeping this long
SWEEP_MAX_SECONDS = 6.0  # hard time budget for one sweep, including draining replies
SWEEP_MAX_REPLIES = 4    # replies read per probe sent (ICMP and DNS each), plus a small allowance
DNS_TTL = 60.0
DNS_NEGATIVE_TTL = 300.0
WEB_OK_TTL = 600.0       # re-check an advertised web UI after this long
WEB_FAIL_TTL = 120.0     # ... or after this long if it refused the connection
WEB_CHECKS_PER_SNAPSHOT = 6   # TCP checks of newly advertised web UIs per snapshot
MAX_WEB_CACHE = 256
MDNS_MAX_NAMES = 8       # per host, from service names and TXT fn/name
MDNS_MAX_SERVICES = 24   # per host
MDNS_MAX_WEB = 4         # advertised web UIs kept per host

ACTIVE_NEIGH_STATES = {"REACHABLE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
DEFAULT_DOMAINS = ("home.arpa", "fritz.box", "speedport.ip", "localdomain", "local", "lan", "home", "internal")
WEB_SERVICE_TYPES = {"_http._tcp": "http", "_https._tcp": "https"}
ADMIN_URL_SERVICE_TYPES = {"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp"}
COMMANDS = {"rescan", "open", "closed", "trust", "untrust", "known_all", "fritz_logout"}
JSON_COMMANDS = {"rename", "pin", "hide", "known", "alerts", "view", "fritz_login", "lang"}
# Interface languages the panel offers; the language arrives from the bar widget ("lang" command).
LANGS = ("en", "de", "fr", "es", "it", "pt", "nl", "pl")
MAX_COMMAND_BYTES = 1024
VIEW_MODES = ("list", "platform", "type", "band", "ap")
GROUP_ID_RE = re.compile(r"^([a-z]{2,12}|([0-9a-f]{2}:){5}[0-9a-f]{2})$")
MAX_COLLAPSED = 32
FRITZ_FILE = "fritzbox.json"
# Shared by every collector (one per screen): an interprocess lock around the saved login and a
# revision that every Disconnect replaces, so a login still in flight elsewhere is never saved after it.
FRITZ_LOCK_FILE = "fritzbox.lock"
FRITZ_REV_FILE = "fritzbox-rev.json"
FRITZ_LOCK_WAIT = 2.0
FRITZ_REVOKE_RETRY = 5.0
FRITZ_USER_RE = re.compile(r"^[A-Za-z0-9._@-]{0,64}$")
# The collector's id for the network it talks to right now: a random per-process part and a
# counter that changes with every gateway change (stats.link.net_id, fritz_login "net").
NET_ID_RE = re.compile(r"^[0-9a-f]{12}-[0-9]{1,12}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,14}$")
SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)
FRITZ_PASSWORD_MAX = 128
FRITZ_DESC_PORT = 49000
FRITZ_TLS_PORT = 49443
FRITZ_TIMEOUT = 4.0
FRITZ_POLL_OPEN = 30.0
FRITZ_POLL_CLOSED = 300.0
FRITZ_RETRY_ERROR = 120.0
FRITZ_MAX_SOAP = 65536
FRITZ_MAX_MESH = 2 * 1048576
FRITZ_MAX_NODES = 512
MESH_PATH_RE = re.compile(r"^/meshlist\.lua\?sid=[0-9a-f]{16}$")
TRUST_FILE = "trusted-networks.json"
TRUST_LOCK_FILE = "trusted-networks.lock"
MAX_TRUSTED = 64
DEVICES_FILE = "devices.json"
DEVICES_LOCK_FILE = "devices.lock"
MAX_STORE_TIME = 2 ** 33  # seconds since 1970 (year 2242): any later, negative or odd time is dropped
MAX_STORE_BYTES = 8 * 1024 * 1024  # holds the largest valid store (32 x 512 records, 40-char names)
MAX_STORE_NETWORKS = 32
MAX_STORE_DEVICES = 512  # per network
NAME_MAX = 40
BASELINE_SECONDS = 600   # devices first seen this soon after tracking starts are not "new"
ALERT_MAX_NAMES = 3

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$",
    re.I,
)
BARE_MAC_RE = re.compile(r"^[0-9a-f]{12}$", re.I)
MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", re.I)
IP_DASH_RE = re.compile(r"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$")
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._~/-]{0,100}$")
DOMAIN_RE = re.compile(r"^[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63}){0,4}$")


def clean(text, limit=120):
    """Sanitize strings from network/mDNS/DNS/proc so Qt never sees markup or control chars."""
    text = "".join(ch for ch in str(text or "") if ch.isprintable() and ch not in "<>&")
    return text.strip()[:limit]


def read(path, default="", max_bytes=65536):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(max_bytes)
    except OSError:
        return default


def run_cmd(argv, timeout=1.5, max_bytes=262144):
    """Run an external command (argv list, no shell) and read at most `max_bytes` before `timeout`."""
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError:
        return ""
    chunks = []
    size = 0
    deadline = time.monotonic() + timeout
    fd = proc.stdout.fileno()
    try:
        while size < max_bytes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                break
            chunk = os.read(fd, min(65536, max_bytes - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError:
        pass
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        try:
            proc.wait(timeout=0.5)
        except subprocess.SubprocessError:
            pass
    return b"".join(chunks).decode("utf-8", "replace")


# --- IEEE OUI Vendor Database -------------------------------------------------

_oui_db = None


def load_oui_db():
    """Load MAC prefix -> vendor mapping from system hwdb or hwdata (cached)."""
    global _oui_db
    if _oui_db is not None:
        return _oui_db
    db = {}
    hwdb_path = "/usr/lib/udev/hwdb.d/20-OUI.hwdb"
    if os.path.exists(hwdb_path):
        try:
            prefix = None
            with open(hwdb_path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if line.startswith("OUI:"):
                        prefix = line[4:10].upper()
                    elif prefix and "ID_OUI_FROM_DATABASE=" in line:
                        db[prefix] = clean(line.split("=", 1)[1], 60)
                        prefix = None
        except OSError:
            pass
    if not db and os.path.exists("/usr/share/hwdata/oui.txt"):
        try:
            with open("/usr/share/hwdata/oui.txt", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if "(base 16)" in line:
                        parts = line.split("(base 16)", 1)
                        prefix = parts[0].strip().upper()
                        if len(prefix) == 6:
                            db[prefix] = clean(parts[1], 60)
        except OSError:
            pass
    _oui_db = db
    return db


def shorten_vendor(vendor):
    """Keep manufacturer names concise and readable in the panel."""
    if not vendor:
        return ""
    cleaned = re.sub(
        r"\b(Incorporated|Inc\.?|Corporation|Corp\.?|Co\.?,?\s*Ltd\.?|Ltd\.?|Pte\.?|GmbH|B\.?V\.?|S\.?A\.?|AG|LLC|PLC)\b\.?",
        "",
        vendor,
        flags=re.I,
    )
    cleaned = re.sub(r"[,\s.]+$", "", re.sub(r"\s{2,}", " ", cleaned)).strip()
    aliases = {
        "Sonova Consumer Hearing": "Sennheiser (Sonova)",
        "Versuni": "Philips (Versuni)",
        "Signify": "Philips Hue (Signify)",
        "LG Innotek": "LG Electronics",
        "CLOUD NETWORK TECHNOLOGY SINGAPORE": "Foxconn / MediaTek",
        "AVM Audiovisuelles Marketing und Computersysteme": "AVM FRITZ!",
    }
    if cleaned in aliases:
        return aliases[cleaned]
    if cleaned.isupper() and len(cleaned) > 4:
        cleaned = cleaned.title()
    return cleaned or vendor


def lookup_vendor(mac):
    if not mac or len(mac) < 8:
        return ""
    hex_mac = mac.replace(":", "").replace("-", "").upper()
    if len(hex_mac) < 6:
        return ""
    vendor = load_oui_db().get(hex_mac[:6], "")
    if vendor:
        return shorten_vendor(vendor)
    # Locally administered MAC address bit (second hex char is 2, 6, A, or E)
    if hex_mac[1] in ("2", "6", "A", "E"):
        return "Private MAC"
    return ""


# --- Wireless Interface & Link Metrics ----------------------------------------

def freq_to_band_channel(freq_mhz):
    """Convert Wi-Fi frequency in MHz to band label (2.4 / 5 / 6 GHz) and channel number."""
    if not freq_mhz:
        return "", None
    f = int(round(freq_mhz))
    if 2412 <= f <= 2484:
        ch = 14 if f == 2484 else (f - 2407) // 5
        return "2.4 GHz", ch
    if 5170 <= f <= 5895:
        return "5 GHz", (f - 5000) // 5
    if 5925 <= f <= 7125:
        return "6 GHz", (f - 5950) // 5
    return f"{freq_mhz:.0f} MHz", None


def dbm_to_quality(signal_dbm):
    """Convert RSSI in dBm to 0..100% quality (linear: -100 dBm = 0%, -50 dBm or better = 100%)."""
    if signal_dbm is None:
        return None
    return max(0, min(100, round(2 * (signal_dbm + 100))))


def parse_default_routes(text):
    """Parse /proc/net/route into ({iface: gateway_ip_or_None}, primary_iface) for default routes."""
    routes = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        try:
            dest, gateway, flags = int(fields[1], 16), int(fields[2], 16), int(fields[3], 16)
            metric, mask = int(fields[6]), int(fields[7], 16)
        except ValueError:
            continue
        if dest != 0 or mask != 0 or not flags & 0x1:  # default route, RTF_UP
            continue
        gw_ip = socket.inet_ntoa(struct.pack("<I", gateway)) if flags & 0x2 and gateway else None
        if fields[0] not in routes or metric < routes[fields[0]][1]:
            routes[fields[0]] = (gw_ip, metric)
    primary = min(routes, key=lambda name: routes[name][1]) if routes else None
    return {name: value[0] for name, value in routes.items()}, primary


def detect_interface(cache):
    """Find the active wireless (or default route) interface, its IPv4 CIDR and its own gateway."""
    routes, primary = parse_default_routes(read("/proc/net/route"))
    now = time.monotonic()
    if cache.get("routes") != routes or now - cache.get("time", -math.inf) >= ADDR_EVERY:
        cache["addr_out"] = run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"])
        cache["routes"] = routes
        cache["time"] = now

    candidates = []
    for line in cache.get("addr_out", "").splitlines():
        parts = line.split()
        if len(parts) >= 4 and "inet" in parts:
            iface = parts[1]
            if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,32}", iface):
                continue
            cidr = parts[parts.index("inet") + 1]
            is_wireless = os.path.isdir(f"/sys/class/net/{iface}/wireless") or os.path.isdir(
                f"/sys/class/net/{iface}/phy80211"
            )
            candidates.append(((is_wireless, iface in routes, iface == primary), iface, cidr, is_wireless))

    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    _, iface, cidr, is_wireless = candidates[0]
    gateway = routes.get(iface)
    mac = clean(read(f"/sys/class/net/{iface}/address").strip().lower(), 20)
    try:
        prefix = int(cidr.split("/")[1]) if "/" in cidr else 24
    except ValueError:
        prefix = 24
    return {
        "iface": clean(iface, 32),
        "is_wireless": is_wireless,
        "cidr": clean(cidr, 32),
        "ip": cidr.split("/")[0],
        "prefix": prefix,
        "gateway": clean(gateway, 32) if gateway else None,
        "mac": mac,
    }


def proc_wireless_signal(iface, text=None):
    """Signal level in dBm for `iface` from /proc/net/wireless, or None."""
    text = read("/proc/net/wireless") if text is None else text
    for line in text.splitlines()[2:]:
        name, _, rest = line.partition(":")
        if name.strip() != iface:
            continue
        fields = rest.split()
        if len(fields) >= 3:
            try:
                level = float(fields[2].rstrip("."))
            except ValueError:
                return None
            return int(level) if level < 0 else None
    return None


def wireless_details(iface):
    """Read SSID, BSSID, signal, frequency, channel, width and bitrates via `iw`."""
    info = {
        "ssid": "",
        "bssid": "",
        "signal_dbm": None,
        "quality": None,
        "freq_mhz": None,
        "band": "",
        "channel": None,
        "width_mhz": None,
        "tx_mbps": None,
        "rx_mbps": None,
    }
    if not iface or not shutil.which("iw"):
        return info
    out = run_cmd(["iw", "dev", iface, "link"])
    if not out or "Not connected" in out:
        return info
    m_bssid = re.search(r"Connected to ([0-9a-fA-F:]{17})", out)
    if m_bssid:
        info["bssid"] = m_bssid.group(1).lower()
    m_ssid = re.search(r"^\s*SSID:\s*(.+)$", out, re.M)
    if m_ssid:
        info["ssid"] = clean(m_ssid.group(1), 64)
    m_freq = re.search(r"^\s*freq:\s*([0-9.]+)", out, re.M)
    if m_freq:
        try:
            info["freq_mhz"] = float(m_freq.group(1))
            info["band"], info["channel"] = freq_to_band_channel(info["freq_mhz"])
        except ValueError:
            pass
    m_sig = re.search(r"^\s*signal:\s*(-?\d+)\s*dBm", out, re.M)
    if m_sig:
        try:
            info["signal_dbm"] = int(m_sig.group(1))
            info["quality"] = dbm_to_quality(info["signal_dbm"])
        except ValueError:
            pass
    m_rx = re.search(r"^\s*rx bitrate:\s*([0-9.]+)\s*MBit/s(?:\s+(\d+)MHz)?", out, re.M)
    if m_rx:
        try:
            info["rx_mbps"] = round(float(m_rx.group(1)))
            if m_rx.group(2):
                info["width_mhz"] = int(m_rx.group(2))
        except ValueError:
            pass
    m_tx = re.search(r"^\s*tx bitrate:\s*([0-9.]+)\s*MBit/s(?:\s+(\d+)MHz)?", out, re.M)
    if m_tx:
        try:
            info["tx_mbps"] = round(float(m_tx.group(1)))
            if m_tx.group(2) and not info["width_mhz"]:
                info["width_mhz"] = int(m_tx.group(2))
        except ValueError:
            pass
    return info


def read_traffic(iface):
    """Total (rx_bytes, tx_bytes) for `iface` from /proc/net/dev."""
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        if name.strip() == iface:
            fields = rest.split()
            if len(fields) >= 9:
                try:
                    return int(fields[0]), int(fields[8])
                except ValueError:
                    pass
            break
    return 0, 0


# --- Active Subnet Probe, Neighbor Table, mDNS & Reverse DNS ------------------

def subnet_hosts(ip_str, prefix):
    """Return up to 254 host IPs in the local subnet around `ip_str`."""
    try:
        eff_prefix = max(24, min(30, int(prefix)))
        net = ipaddress.IPv4Network(f"{ip_str}/{eff_prefix}", strict=False)
        if not (net.is_private or net.is_link_local):
            return []
        return [str(host) for host in net.hosts()]
    except ValueError:
        return []


def build_dns_ptr_packet(qid, ip):
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    qname = b"".join(bytes([len(p)]) + p.encode("ascii", "ignore") for p in rev.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", qid & 0xFFFF, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 12, 1)


def parse_dns_ptr_packet(data):
    """Parse a UDP DNS PTR response into (qid, [fqdn, ...])."""
    if len(data) < 12:
        return None, []
    qid, _flags, _qdcount, ancount = struct.unpack("!HHHH", data[:8])
    if ancount == 0:
        return qid, []

    def read_name(buf, offset, depth=0):
        parts = []
        while offset < len(buf) and depth < 10:
            length = buf[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                if offset + 2 > len(buf):
                    break
                ptr = struct.unpack("!H", buf[offset : offset + 2])[0] & 0x3FFF
                sub, _ = read_name(buf, ptr, depth + 1)
                parts.extend(sub)
                offset += 2
                break
            offset += 1
            parts.append(buf[offset : offset + length].decode("utf-8", "replace"))
            offset += length
        return parts, offset

    _, off = read_name(data, 12)
    off += 4
    names = []
    for _ in range(ancount):
        if off >= len(data):
            break
        _, off = read_name(data, off)
        if off + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[off : off + 10])
        off += 10
        if rtype == 12 and off + rdlen <= len(data):
            pts, _ = read_name(data, off)
            if pts:
                names.append(clean(".".join(pts), 80))
        off += rdlen
    return qid, names


def match_dns_reply(data, addr, server, qid_to_ip):
    """Accept a PTR reply only from `server`:53 with an outstanding query ID; returns (ip, names)."""
    if not addr or addr[0] != server or addr[1] != 53:
        return None, []
    qid, names = parse_dns_ptr_packet(data)
    ip = qid_to_ip.pop(qid, None) if qid is not None else None
    return ip, (names if ip else [])


def resolv_search_domains(text=None):
    """Search domains from /etc/resolv.conf (ignoring the root domain)."""
    text = read("/etc/resolv.conf") if text is None else text
    found = []
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] in ("search", "domain"):
            for domain in parts[1:]:
                domain = domain.strip(".").lower()
                if domain and DOMAIN_RE.match(domain) and domain not in found:
                    found.append(domain)
    return found


def learn_domain(fqdns):
    """Guess the router's local DNS domain: the suffix after the first label shared by most PTR names."""
    counts = {}
    for fqdn in fqdns:
        labels = fqdn.rstrip(".").lower().split(".")
        if len(labels) >= 2 and not fqdn.lower().rstrip(".").endswith(".arpa"):
            suffix = ".".join(labels[1:])
            if DOMAIN_RE.match(suffix):
                counts[suffix] = counts.get(suffix, 0) + 1
    if not counts:
        return ""
    suffix, count = max(counts.items(), key=lambda item: (item[1], len(item[0])))
    return suffix if count >= 2 else ""


def strip_domain(fqdn, domains):
    """Remove the longest matching local domain. Returns (name, is_the_domain_itself)."""
    name = fqdn.rstrip(".")
    low = name.lower()
    for domain in sorted({d.lower() for d in domains if d}, key=len, reverse=True):
        if low == domain:
            return name, True
        if low.endswith("." + domain):
            return name[: -len(domain) - 1], False
    return name, False


def select_best_hostname(raw_names, domains=DEFAULT_DOMAINS):
    """Choose the cleanest short hostname from a list of PTR FQDNs."""
    best = ""
    fallback = ""
    for fqdn in raw_names:
        short, is_domain = strip_domain(fqdn, domains)
        if is_domain:  # e.g. the FRITZ!Box answers with its domain name "fritz.box"
            return clean(short, 64)
        if UUID_RE.match(short) or IP_DASH_RE.match(short):
            continue
        if BARE_MAC_RE.match(short):
            fallback = fallback or short
            continue
        if not best or (len(short) < len(best) and not short.startswith(best)):
            best = short
    return clean(best or fallback, 64)


def sweep(targets, dns_server=None, settle=0.22):
    """Paced ICMP echo probe of `targets`, plus a PTR query per target to `dns_server` if given.

    Returns ({ip: [fqdn, ...]}, {responding ips}). DNS replies are only accepted from
    `dns_server`:53 with a random, still outstanding query ID.
    """
    targets = list(dict.fromkeys(targets))
    if not targets:
        return {}, set()
    target_set = set(targets)
    # A busy or hostile LAN peer must not keep the drain loop busy: one overall deadline
    # and a fixed number of datagrams read per socket.
    sweep_deadline = time.monotonic() + SWEEP_MAX_SECONDS
    budget = {"icmp": SWEEP_MAX_REPLIES * len(targets) + 16, "dns": SWEEP_MAX_REPLIES * len(targets) + 16}

    icmp_sock = None
    icmp_payload = b""
    icmp_port = 0
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        icmp_payload = struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"wlanmon"
    except OSError:
        try:
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            icmp_port = 33434
        except OSError:
            icmp_sock = None
    if icmp_sock:
        icmp_sock.setblocking(False)

    dns_sock = None
    qid_to_ip = {}
    if dns_server:
        try:
            dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            dns_sock.setblocking(False)
            dns_sock.connect((dns_server, 53))  # kernel drops datagrams from any other source
            qids = random.SystemRandom().sample(range(1, 65536), len(targets))
        except (OSError, ValueError):
            if dns_sock:
                dns_sock.close()
            dns_sock = None

    ptr_names = {}
    responders = set()

    def drain():
        while icmp_sock and icmp_payload and budget["icmp"] > 0 and time.monotonic() < sweep_deadline:
            try:
                data, addr = icmp_sock.recvfrom(256)
            except OSError:
                break
            budget["icmp"] -= 1
            # Echo replies count only from addresses this sweep actually probed.
            if data and data[0] == 0 and addr[0] in target_set:
                responders.add(addr[0])
        while dns_sock and budget["dns"] > 0 and time.monotonic() < sweep_deadline:
            try:
                data, addr = dns_sock.recvfrom(512)
            except OSError:
                break
            budget["dns"] -= 1
            ip, names = match_dns_reply(data, addr, dns_server, qid_to_ip)
            if ip and names:
                ptr_names[ip] = names

    try:
        for idx, ip in enumerate(targets):
            if time.monotonic() >= sweep_deadline:
                break
            if icmp_sock:
                try:
                    icmp_sock.sendto(icmp_payload, (ip, icmp_port))
                except OSError:
                    pass
            if dns_sock:
                qid = qids[idx]
                qid_to_ip[qid] = ip
                try:
                    dns_sock.send(build_dns_ptr_packet(qid, ip))
                except OSError:
                    pass
            if (idx + 1) % 6 == 0:
                time.sleep(0.007)
                drain()
        deadline = min(time.monotonic() + settle, sweep_deadline)
        while time.monotonic() < deadline:
            time.sleep(0.03)
            drain()
    finally:
        if icmp_sock:
            icmp_sock.close()
        if dns_sock:
            dns_sock.close()
    return ptr_names, responders


def lookup_ptr(ip, servers, timeout=0.1):
    """Single PTR lookup; returns the FQDN list from the first server that answers."""
    for server in servers:
        if not server:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.connect((server, 53))
                qid = random.SystemRandom().randrange(1, 65536)
                sock.send(build_dns_ptr_packet(qid, ip))
                deadline = time.monotonic() + timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    data = sock.recv(512)
                    reply_qid, names = parse_dns_ptr_packet(data)
                    if reply_qid == qid:
                        return names
        except OSError:
            continue
    return []


def read_neighbors(iface):
    """Parse `ip -4 neigh show dev <iface>` into {ip: {mac, state}}; FAILED/INCOMPLETE are skipped."""
    out = run_cmd(["ip", "-4", "neigh", "show", "dev", iface])
    return parse_neighbors(out)


def neighbor_mac(ip, iface, timeout=1.5):
    """The MAC the kernel holds for `ip` on `iface` right now ("" if none): read again just before
    a login's password response is sent, so a router that took over the address in between gets
    nothing. Scoped to the interface: the same address on another network says nothing here."""
    if not IFACE_RE.match(iface or ""):
        return ""
    out = run_cmd(["ip", "-4", "neigh", "show", "to", ip, "dev", iface], timeout=timeout)
    return parse_neighbors(out).get(ip, {}).get("mac", "")


def parse_neighbors(out):
    neighbors = {}
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        ip = parts[0]
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        state = parts[-1].upper()
        if state in ("FAILED", "INCOMPLETE"):
            continue
        mac = ""
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts) and MAC_RE.match(parts[idx + 1]):
                mac = parts[idx + 1].lower()
        if mac:
            neighbors[ip] = {"mac": mac, "state": clean(state, 20)}
    return neighbors


def prune_web_cache(web_ok, mdns_hosts, now, limit=MAX_WEB_CACHE):
    """Keep only unexpired results for web UIs that are still advertised, at most `limit`."""
    advertised = {url for entry in mdns_hosts.values() for url in entry.get("web", [])[:MDNS_MAX_WEB]}
    kept = {url: v for url, v in web_ok.items() if url in advertised and v[0] > now}
    if len(kept) > limit:
        kept = dict(sorted(kept.items(), key=lambda item: item[1][0], reverse=True)[:limit])
    return kept


def prune_reachable(last_reachable, now, keep_ip, grace=ONLINE_GRACE):
    """Drop entries that are too old to matter or outside the local subnet."""
    return {ip: t for ip, t in last_reachable.items() if now - t <= grace and keep_ip(ip)}


def neighbor_online(ip, state, now, last_reachable, grace=ONLINE_GRACE):
    """A neighbor is online when the kernel is verifying/has verified it, or it was confirmed recently."""
    if state in ACTIVE_NEIGH_STATES:
        return True
    if state == "STALE":
        return now - last_reachable.get(ip, -math.inf) <= grace
    return False


def unescape_avahi(text):
    """Decode avahi-browse `-p` escape sequences like `\\032` (space) and `\\091` (`[`)."""
    if not text:
        return ""
    out = re.sub(
        r"\\(\d{3})",
        lambda m: chr(int(m.group(1))) if 32 <= int(m.group(1)) <= 126 else " ",
        text,
    )
    out = out.replace(r"\.", ".").replace(r"\\", "\\")
    if "%" in out:
        try:
            out = urllib.parse.unquote(out)
        except Exception:
            pass
    return clean(out, 80)


def friendly_mdns_label(raw_name):
    """Clean noisy UUIDs or MAC prefixes from mDNS service instance names."""
    name = unescape_avahi(raw_name)
    if not name:
        return ""
    if "@" in name:
        prefix, rest = name.split("@", 1)
        if re.fullmatch(r"[0-9A-Fa-f]{12}", prefix.strip()) and rest.strip():
            name = rest.strip()
    name = re.sub(
        r"-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$",
        "",
        name,
    )
    name = re.sub(r"-[0-9a-fA-F]{32}$", "", name)
    if UUID_RE.match(name) or BARE_MAC_RE.match(name) or IP_DASH_RE.match(name):
        return ""
    if re.fullmatch(r"[0-9A-F]{16}-[0-9A-F]{16}", name):
        return ""
    return clean(name, 64)


def make_web_url(scheme, ip, port=None, path="/", subnet=None):
    """Build an http(s) URL for a device's web UI from validated parts, or "" if anything is off.

    Only private/link-local IPv4 literals (inside `subnet` when given), numeric ports and
    plain paths are allowed, so nothing from the network can choose the host or inject text.
    """
    if scheme not in ("http", "https"):
        return ""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return ""
    if addr.is_loopback or addr.is_multicast or not (addr.is_private or addr.is_link_local):
        return ""
    if subnet is not None and addr not in subnet:
        return ""
    if port in (None, ""):
        port = None
    else:
        try:
            port = int(port)
        except (TypeError, ValueError):
            return ""
        if not 1 <= port <= 65535:
            return ""
    path = str(path or "/").split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    if not SAFE_PATH_RE.match(path) or ".." in path:
        path = "/"
    default_port = 80 if scheme == "http" else 443
    netloc = str(addr) if port in (None, default_port) else f"{addr}:{port}"
    return f"{scheme}://{netloc}{path}"


def parse_admin_url(url, ip, host):
    """Accept a printer/scanner `adminurl` TXT value only if it points at the advertising device."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    scheme = (parts.scheme or "").lower()
    hostname = (parts.hostname or "").lower().rstrip(".")
    allowed = {ip}
    if host:
        allowed |= {host.lower(), host.lower() + ".local"}
    if scheme not in ("http", "https") or hostname not in allowed:
        return None
    return scheme, port, parts.path or "/"


def parse_mdns_lines(lines, iface, subnet_net):
    """Collect mDNS hostnames, friendly names, models, MAC hints and web UIs from `avahi-browse -kprt` lines."""
    hosts = {}
    for line in lines:
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 9:
            continue
        _, line_iface, proto, raw_service, stype, _domain, raw_host, address, raw_port = parts[:9]
        if iface and line_iface != iface:
            continue
        if proto != "IPv4":
            continue
        try:
            ip_obj = ipaddress.IPv4Address(address)
            if subnet_net and ip_obj not in subnet_net:
                continue
        except ValueError:
            continue

        entry = hosts.setdefault(
            address,
            {"names": [], "host": "", "model": "", "mac": "", "services": [], "web": []},
        )
        host_clean = clean(raw_host.removesuffix(".local"), 64)
        if host_clean and not UUID_RE.match(host_clean) and not IP_DASH_RE.match(host_clean):
            if not entry["host"] or BARE_MAC_RE.match(entry["host"]):
                entry["host"] = host_clean

        svc_label = friendly_mdns_label(raw_service)
        if svc_label and svc_label not in entry["names"] and len(entry["names"]) < MDNS_MAX_NAMES:
            entry["names"].append(svc_label)

        txt = {}
        for key, val in re.findall(r'"([^"=]+)=([^"]*)"', ";".join(parts[9:])):
            value = unescape_avahi(val)
            if value:
                txt.setdefault(key.strip().lower(), value)
        for key in ("fn", "name"):
            value = txt.get(key, "")
            if value and not UUID_RE.match(value) and value not in entry["names"]:
                entry["names"].insert(0, value)
                del entry["names"][MDNS_MAX_NAMES:]
        if not entry["model"]:
            for key in ("md", "model", "am", "modelid", "device type"):
                # Some services put flags such as "0,1,2" here; a model name has letters.
                if re.search(r"[A-Za-z]{2}", txt.get(key, "")):
                    entry["model"] = clean(txt[key], 48)
                    break
        if not entry["mac"]:
            for key in ("deviceid", "bs"):
                if MAC_RE.match(txt.get(key, "")):
                    entry["mac"] = txt[key].lower()
                    break

        stype_clean = clean(stype, 32)
        web = None
        if stype_clean in WEB_SERVICE_TYPES:
            web = (WEB_SERVICE_TYPES[stype_clean], raw_port, txt.get("path", "/"))
        elif stype_clean in ADMIN_URL_SERVICE_TYPES and txt.get("adminurl"):
            web = parse_admin_url(txt["adminurl"], address, host_clean)
        if web:
            url = make_web_url(web[0], address, web[1], web[2], subnet=subnet_net)
            if url and url not in entry["web"] and len(entry["web"]) < MDNS_MAX_WEB:
                entry["web"].append(url)

        if stype_clean and stype_clean not in entry["services"] and len(entry["services"]) < MDNS_MAX_SERVICES:
            entry["services"].append(stype_clean)
    return hosts


def query_mdns(iface, subnet_net):
    """Run avahi-browse for ~1.4 s (bounded output) and parse the resolved services."""
    if not shutil.which("avahi-browse"):
        return None
    master = slave = None
    proc = None
    lines = []
    try:
        # A pty keeps avahi-browse line-buffered so partial results arrive before we stop it.
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            ["avahi-browse", "-a", "-r", "-p", "-k"],
            stdin=slave,
            stdout=slave,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        os.close(slave)
        slave = None

        buf = b""
        deadline = time.monotonic() + 1.4
        while time.monotonic() < deadline:
            wait = 0.45 if not buf else 0.25
            ready, _, _ = select.select([master], [], [], min(wait, max(0.01, deadline - time.monotonic())))
            if not ready:
                break
            chunk = os.read(master, 65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 262144:
                break
        lines = buf.decode("utf-8", "replace").splitlines()
    except OSError:
        pass
    finally:
        for fd in (slave, master):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=0.2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    return parse_mdns_lines(lines, iface, subnet_net)


# --- VPN detection ------------------------------------------------------------------

# Interface name prefixes of common VPN clients -> name shown to the user, and the hint
# for letting the VPN reach the local network.
VPN_NAMES = (
    ("nordlynx", "NordVPN"), ("nordtun", "NordVPN"), ("tailscale", "Tailscale"),
    ("proton", "Proton VPN"), ("pvpn", "Proton VPN"), ("wg-mullvad", "Mullvad"), ("mullvad", "Mullvad"),
    ("zt", "ZeroTier"), ("wg", "WireGuard"), ("tun", "VPN"), ("tap", "VPN"), ("ppp", "VPN"),
    ("ipsec", "IPsec VPN"), ("vti", "IPsec VPN"),
)
VPN_HINTS = {
    "NordVPN": "Allow it with: nordvpn set lan-discovery enable",
    "Mullvad": "Allow it with: mullvad lan set allow",
    "Proton VPN": "Turn on \u201cAllow LAN connections\u201d in Proton VPN.",
}
VPN_LINK_TYPES = {"65534", "512"}  # ARPHRD_NONE (tun, WireGuard), ARPHRD_PPP
LAN_CHECK_EVERY = 30.0   # router check while a VPN lets the home network through
GATEWAY_POKE_EVERY = 10.0  # at most this often: one empty datagram that renews the router's ARP entry
GATEWAY_POKE_WAIT = (0.1, 0.1, 0.1)  # rereads of the router's MAC after a poke when it was missing
GATEWAY_POKE_BUDGET = 0.6  # seconds the whole reread may take, `ip` included
LAN_CHECK_BLOCKED = 8.0  # ... and while it blocks it, so a fix shows up quickly


def detect_vpn(active_iface, base="/sys/class/net"):
    """The first VPN-like interface that is up (other than the Wi-Fi/LAN one), or None."""
    try:
        names = sorted(os.listdir(base))[:256]
    except OSError:
        return None
    for name in names:
        if name in ("lo", active_iface) or not re.fullmatch(r"[A-Za-z0-9._-]{1,15}", name):
            continue
        try:
            flags = int(read(os.path.join(base, name, "flags"), "0", 32).strip() or "0", 16)
        except ValueError:
            continue
        if not flags & 0x1:  # IFF_UP
            continue
        label = next((label for prefix, label in VPN_NAMES if name.startswith(prefix)), "")
        if label or read(os.path.join(base, name, "type"), "", 32).strip() in VPN_LINK_TYPES:
            label = label or "VPN"
            return {"iface": name, "name": label, "hint": VPN_HINTS.get(label, "Allow local network (LAN) access in your VPN settings.")}
    return None


def poke_neighbor(ip, iface):
    """One empty UDP datagram to `ip` (discard port 9), out of `iface` only: the kernel resolves or
    confirms the router's MAC, so trust never lapses only because nothing else talked to the router
    (all traffic in a VPN, say). Only a private address on a valid interface name; never raises."""
    try:
        if not ipaddress.IPv4Address(ip).is_private or not IFACE_RE.match(iface or ""):
            return False
    except ValueError:
        return False
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
        sock.sendto(b"", (ip, 9))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def gateway_reachable(ip, ports=(80, 53, 443), timeout=0.4):
    """True if the router answers on any usual port; a refusal counts as an answer.

    VPN firewalls that block the home network silently drop these packets (timeouts).
    Only a private gateway address is ever contacted.
    """
    try:
        if not ipaddress.IPv4Address(ip).is_private:
            return True  # not a home router; nothing to check
    except ValueError:
        return True
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False


def tcp_open(ip, port, timeout=0.35):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def probe_web(ip):
    """Return "http" or "https" if the host accepts TCP on 80 / 443, else ""."""
    for port, scheme in ((80, "http"), (443, "https")):
        if tcp_open(ip, port):
            return scheme
    return ""


def url_reachable(url):
    """TCP-connect check for an advertised web UI (many devices announce _http._tcp but refuse it)."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return False
    return bool(parts.hostname) and tcp_open(parts.hostname, port)


# --- Trusted networks ----------------------------------------------------------

def config_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "ubruckhaus-wlan-monitor")


def open_config_dir():
    """(fd, missing): an open handle on the config directory when it is a real directory (not a
    symlink), owned by us and not writable by group or others; else (None, True) when there is
    none yet and (None, False) when it is refused. Every file in it is opened relative to it."""
    try:
        fd = os.open(config_dir(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None, True
    except OSError:
        return None, False
    try:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022:
            return fd, False
    except OSError:
        pass
    os.close(fd)
    return None, False


def private_config_dir():
    """The config directory, created 0700 if missing (and made 0700 if it is ours but more open);
    None unless it is a real directory of ours."""
    directory = config_dir()
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return None
        if info.st_mode & 0o077:
            os.fchmod(fd, 0o700)
        return directory
    except OSError:
        return None
    finally:
        os.close(fd)


def load_private_json(filename, max_bytes=65536, secret=False):
    """Read a JSON file from the config directory (checked first, open_config_dir); refuses
    symlinks, special, foreign or oversized files, files group or others may write, and for a
    `secret` file (the FRITZ!Box password) any group or other access at all."""
    dfd, _missing = open_config_dir()
    if dfd is None:
        return None
    try:
        # O_NONBLOCK: a FIFO in its place is refused below instead of blocking the collector.
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except OSError:
        return None
    finally:
        os.close(dfd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > max_bytes
                or info.st_mode & (0o077 if secret else 0o022)):
            return None
        chunks, size = [], 0
        while size <= max_bytes:
            chunk = os.read(fd, min(1 << 20, max_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > max_bytes:
            return None
        return json.loads(b"".join(chunks).decode("utf-8", "replace"))
    except (OSError, ValueError, RecursionError):
        return None
    finally:
        os.close(fd)


def save_private_json(filename, data, max_bytes=None, compact=False):
    """Atomically write a JSON file into the private (0700) config directory as 0600. With
    `max_bytes`, a file its reader would refuse is never written (the old one stays)."""
    if compact:
        text = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    else:
        text = json.dumps(data, indent=2)
    if max_bytes is not None and len(text.encode("utf-8")) > max_bytes:
        return False
    directory = private_config_dir()
    if not directory:
        return False
    tmp = None
    try:
        # Exclusive, unpredictable temp file, private before anything is written (credentials too).
        fd, tmp = tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=directory)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, os.path.join(directory, filename))
        return True
    except OSError:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return False


def load_trusted():
    """Read the trusted network list, keeping only well-formed entries."""
    data = load_private_json(TRUST_FILE)
    networks = []
    items = data.get("networks") if isinstance(data, dict) else None
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        mac = item.get("gateway_mac")
        ssid = item.get("ssid", "")
        if isinstance(mac, str) and MAC_RE.match(mac) and isinstance(ssid, str):
            networks.append({"ssid": clean(ssid, 64), "gateway_mac": mac.lower()})
    return networks[:MAX_TRUSTED]


def save_trusted(networks):
    return save_private_json(TRUST_FILE, {"networks": networks[:MAX_TRUSTED]})


def is_trusted(identity, trusted):
    return bool(identity.get("gateway_mac")) and any(
        entry["gateway_mac"] == identity["gateway_mac"] and entry["ssid"] == identity.get("ssid", "")
        for entry in trusted
    )


def same_network(old, new):
    """Same interface/gateway/subnet, and no conflicting SSID or gateway MAC once both are known."""
    if old is None or old["base"] != new["base"]:
        return False
    return all(not (old[key] and new[key] and old[key] != new[key]) for key in ("ssid", "gateway_mac"))


def clean_name(value):
    """A user-chosen device name: plain printable text, single spaces, at most NAME_MAX chars."""
    if not isinstance(value, str):
        return ""
    return re.sub(r"\s+", " ", clean(value, 200))[:NAME_MAX].strip()


def parse_command(line):
    """A plain command word, a validated per-device command dict, or "" when invalid."""
    text = line.strip()
    if not text.startswith("{"):
        command = text.lower()
        return command if command in COMMANDS else ""
    if len(text) > MAX_COMMAND_BYTES:
        return ""
    try:
        data = json.loads(text)
    except ValueError:
        return ""
    if not isinstance(data, dict) or not isinstance(data.get("cmd"), str) or data["cmd"] not in JSON_COMMANDS:
        return ""
    cmd = data["cmd"]
    if cmd == "alerts":
        return {"cmd": cmd, "on": data["on"]} if isinstance(data.get("on"), bool) else ""
    if cmd == "lang":
        lang = data.get("lang")
        if not isinstance(lang, str):
            return ""
        return {"cmd": cmd, "lang": lang if lang in LANGS else "en"}
    if cmd == "view":
        mode = data.get("mode")
        collapsed = data.get("collapsed")
        if mode not in VIEW_MODES or not isinstance(collapsed, list):
            return ""
        if not all(isinstance(g, str) for g in collapsed):
            return ""  # a wrong type anywhere refuses the whole command
        ids = [g for g in collapsed if GROUP_ID_RE.match(g)]
        return {"cmd": cmd, "mode": mode, "collapsed": list(dict.fromkeys(ids))[:MAX_COLLAPSED]}
    if cmd == "fritz_login":
        user, password = data.get("user", ""), data.get("password")
        if not isinstance(user, str) or not FRITZ_USER_RE.match(user):
            return ""
        if not isinstance(password, str) or not 0 < len(password) <= FRITZ_PASSWORD_MAX or not password.isprintable():
            return ""
        net = data.get("net", "")
        if not isinstance(net, str) or (net and not NET_ID_RE.match(net)):
            return ""
        return {"cmd": cmd, "user": user, "password": password, "net": net}
    mac = data.get("mac")
    if not isinstance(mac, str) or not MAC_RE.match(mac):
        return ""
    if cmd == "rename":
        name = data.get("name", "")
        return {"cmd": cmd, "mac": mac.lower(), "name": clean_name(name)} if isinstance(name, str) else ""
    return {"cmd": cmd, "mac": mac.lower(), "on": data["on"]} if isinstance(data.get("on"), bool) else ""


# --- Per-network device store (names, pins, hidden, seen devices) ------------------

def network_key(identity):
    mac = identity.get("gateway_mac", "")
    return f"{mac}|{identity.get('ssid', '')}" if mac else ""


def store_time(value):
    """A saved time: a finite number of seconds within 0..MAX_STORE_TIME, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, int) and not 0 <= value <= MAX_STORE_TIME:
        return None  # checked before any float conversion: a 400-digit integer never overflows
    if isinstance(value, float) and not (math.isfinite(value) and 0 <= value <= MAX_STORE_TIME):
        return None
    return value


def store_stamp():
    """What identifies the current devices.json (inode, size, mtime); None when there is none."""
    dfd, _missing = open_config_dir()
    if dfd is None:
        return None
    try:
        info = os.stat(DEVICES_FILE, dir_fd=dfd, follow_symlinks=False)
    except OSError:
        return None
    finally:
        os.close(dfd)
    return (info.st_ino, info.st_size, info.st_mtime_ns)


def load_store():
    """Read devices.json, keeping only well-formed networks and device records (bounded)."""
    data = load_private_json(DEVICES_FILE, MAX_STORE_BYTES)
    store = {"alerts": True, "view": {"mode": "list", "collapsed": []}, "networks": {}}
    if not isinstance(data, dict):
        return store
    store["alerts"] = data.get("alerts", True) is not False
    view = data.get("view")
    if isinstance(view, dict) and view.get("mode") in VIEW_MODES:
        collapsed = view.get("collapsed") if isinstance(view.get("collapsed"), list) else []
        store["view"] = {
            "mode": view["mode"],
            "collapsed": [g for g in collapsed if isinstance(g, str) and GROUP_ID_RE.match(g)][:MAX_COLLAPSED],
        }
    networks = data.get("networks")
    for key, net in list(networks.items() if isinstance(networks, dict) else [])[:MAX_STORE_NETWORKS]:
        if not isinstance(key, str) or not isinstance(net, dict) or "|" not in key:
            continue
        mac, ssid = key.split("|", 1)
        if not MAC_RE.match(mac) or ssid != clean(ssid, 64):
            continue
        entry = {"since": store_time(net.get("since")), "devices": {}}
        devices = net.get("devices")
        for dev_mac, rec in list(devices.items() if isinstance(devices, dict) else [])[:MAX_STORE_DEVICES]:
            if not isinstance(dev_mac, str) or not MAC_RE.match(dev_mac) or not isinstance(rec, dict):
                continue
            entry["devices"][dev_mac.lower()] = {
                "name": clean_name(rec.get("name", "")),
                "pinned": rec.get("pinned") is True,
                "hidden": rec.get("hidden") is True,
                "new": rec.get("new") is True,
                "first": store_time(rec.get("first")) or 0,
            }
        store["networks"][mac.lower() + "|" + ssid] = entry
    return store


def save_store(store):
    return save_private_json(DEVICES_FILE, store, MAX_STORE_BYTES, compact=True)


def store_network(store, key, create=True):
    """The store entry for one network, created on demand (oldest network dropped when full)."""
    nets = store["networks"]
    if key not in nets:
        if not create:
            return None
        while len(nets) >= MAX_STORE_NETWORKS:
            oldest = min(nets, key=lambda k: nets[k].get("since") or 0)
            del nets[oldest]
        nets[key] = {"since": None, "devices": {}}
    return nets[key]


def store_device(net, mac, now_wall):
    """The record for one device, created on demand; evicts the oldest plain records when full."""
    devices = net["devices"]
    if mac not in devices:
        if len(devices) >= MAX_STORE_DEVICES:
            plain = [m for m, r in devices.items() if not (r["name"] or r["pinned"] or r["hidden"])]
            victims = sorted(plain or devices, key=lambda m: devices[m]["first"])
            for victim in victims[: len(devices) - MAX_STORE_DEVICES + 1]:
                del devices[victim]
        devices[mac] = {"name": "", "pinned": False, "hidden": False, "new": False, "first": now_wall}
    return devices[mac]


# New-device notification texts per interface language: one device, several, "and N more", "your network".
NOTIFY_TEXT = {
    "en": ("New device on {net}", "{n} new devices on {net}", " and {n} more", "your network"),
    "de": ("Neues Gerät in {net}", "{n} neue Geräte in {net}", " und {n} weitere", "deinem Netzwerk"),
    "fr": ("Nouvel appareil sur {net}", "{n} nouveaux appareils sur {net}", " et {n} de plus", "votre réseau"),
    "es": ("Nuevo dispositivo en {net}", "{n} dispositivos nuevos en {net}", " y {n} más", "tu red"),
    "it": ("Nuovo dispositivo su {net}", "{n} nuovi dispositivi su {net}", " e altri {n}", "la tua rete"),
    "pt": ("Novo dispositivo em {net}", "{n} novos dispositivos em {net}", " e mais {n}", "sua rede"),
    "nl": ("Nieuw apparaat op {net}", "{n} nieuwe apparaten op {net}", " en nog {n}", "je netwerk"),
    "pl": ("Nowe urządzenie w {net}", "Nowe urządzenia ({n}) w {net}", " i {n} więcej", "twojej sieci"),
}


def notify_new_devices(ssid, names, lang="en"):
    """Desktop notification for devices that joined a trusted network (fixed argv, no shell)."""
    if not names or not shutil.which("notify-send"):
        return
    one, many, more_text, your_net = NOTIFY_TEXT.get(lang, NOTIFY_TEXT["en"])
    shown = names[:ALERT_MAX_NAMES]
    more = len(names) - len(shown)
    body = ", ".join(shown) + (more_text.format(n=more) if more > 0 else "")
    net = clean(ssid, 40) or your_net
    title = one.format(net=net) if len(names) == 1 else many.format(n=len(names), net=net)
    run_cmd(["notify-send", "-a", "WLAN Monitor", "-i", "network-wireless", "--", title, clean(body, 200)], timeout=2)


# --- Device Discovery & Merging -----------------------------------------------

KIND_LABELS = {
    "router": "Router", "computer": "Computer", "laptop": "Laptop", "phone": "Phone",
    "tablet": "Tablet", "watch": "Watch", "tv": "TV", "speaker": "Speaker",
    "printer": "Printer", "console": "Game console", "camera": "Camera", "light": "Lighting",
    "nas": "Storage / server", "appliance": "Appliance", "smarthome": "Smart-home device",
    "unknown": "Device",
}
# Checked in order against the device's name, hostname and model.
KIND_NAME_RULES = (
    ("router", r"repeater|fritz!?box|fritz!?repeater|mesh|access ?point|router"),
    ("phone", r"iphone|android|galaxy|pixel|smartphone|handy|phone"),
    ("tablet", r"ipad|tablet|kindle|fire ?hd"),
    ("watch", r"watch"),
    ("laptop", r"macbook|laptop|notebook|thinkpad|surface|chromebook"),
    ("computer", r"imac|\bmac\b|mac ?mini|mac ?studio|mac ?pro|desktop|\bpc\b|workstation|omarchy|raspberry"),
    ("tv", r"\btv\b|webos|bravia|fire ?tv|chromecast|roku|television|tizen|android ?tv|shield"),
    ("speaker", r"soundbar|speaker|sonos|homepod|\becho\b|alexa|ambeo|\bbose\b|nest (audio|mini)|google home"),
    ("printer", r"printer|drucker|laserjet|officejet|deskjet|\bepson|\bbrother|\bcanon|\bhl-|\bmfc-"),
    ("console", r"playstation|\bps[345]\b|xbox|nintendo"),
    ("camera", r"camera|\bcam\b|doorbell|reolink|eufy|arlo|hikvision"),
    ("light", r"\bhue\b|tradfri|nanoleaf|\bwiz\b|lamp|light|bulb"),
    ("nas", r"\bnas\b|synology|diskstation|qnap|truenas|unraid|server"),
    ("appliance", r"coffee|kaffee|espresso|\bep\d{4}|washer|dryer|dishwasher|fridge|oven|vacuum|roborock|roomba|stove|ofen"),
)
KIND_SERVICE_RULES = (
    ("printer", {"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp", "_scanner._tcp"}),
    ("light", {"_hue._tcp"}),
    ("tv", {"_googlecast._tcp", "_androidtvremote2._tcp", "_lgwebos._tcp"}),
    ("speaker", {"_spotify-connect._tcp", "_raop._tcp", "_sonos._tcp", "_airplay._tcp"}),
    ("smarthome", {"_hap._tcp", "_matter._tcp", "_matterc._udp", "_esphomelib._tcp", "_shelly._tcp", "_miio._udp"}),
    ("nas", {"_smb._tcp", "_afpovertcp._tcp", "_adisk._tcp", "_nfs._tcp"}),
    ("computer", {"_workstation._tcp", "_ssh._tcp", "_sftp-ssh._tcp"}),
)
KIND_VENDOR_RULES = (
    ("smarthome", r"espressif|tuya|shelly|allterco|microchip|silicon lab|itead|sonoff|meross|particle|texas instruments|nordic|beken|bouffalo"),
    ("light", r"signify|philips hue|lumi united|nanoleaf"),
    ("speaker", r"sonos|sennheiser|sonova|bose|harman|denon|yamaha|bang|bluesound"),
    ("console", r"nintendo|sony interactive"),
    ("printer", r"brother|epson|canon|hewlett|hp inc|kyocera|lexmark|xerox"),
    ("nas", r"synology|qnap|western digital"),
    ("appliance", r"versuni|miele|bsh|irobot|roborock|dreame|ecovacs"),
    ("router", r"\bavm\b|fritz|ubiquiti|netgear|linksys|ruckus|eero|zyxel|mikrotik"),
    ("computer", r"raspberry|intel|foxconn|mediatek|liteon|azurewave|framework"),
)


def device_kind(name, hostname, model, vendor, services, is_gateway=False, is_self=False):
    """Guess what kind of device this is (for the icon and vendor-only names)."""
    if is_gateway:
        return "router"
    if is_self:
        return "computer"
    text = " ".join((name or "", hostname or "", model or "")).lower().replace("_", " ").replace("-", " ")
    for kind, pattern in KIND_NAME_RULES:
        if re.search(pattern, text):
            return kind
    found = set(services or [])
    for kind, types in KIND_SERVICE_RULES:
        if found & types:
            return kind
    vendor_text = (vendor or "").lower()
    for kind, pattern in KIND_VENDOR_RULES:
        if re.search(pattern, vendor_text):
            return kind
    return "unknown"


def tidy_name(name):
    """Make machine-style names readable: `PHILIPS_EP8757_20_392985` -> `Philips EP8757`,
    `MacBook-Pro-von-Uwe` -> `MacBook Pro von Uwe`, `Hue Bridge - C9B46D` -> `Hue Bridge`."""
    text = re.sub(r"\s+-\s+[0-9A-Fa-f]{6}$", "", name or "").strip()
    if " " in text or IP_DASH_RE.match(text) or BARE_MAC_RE.match(text):
        return text or name
    if "_" in text:
        tokens = [t for t in text.split("_") if t]
        kept = [t for t in tokens if not (t.isdigit() or (len(t) >= 6 and re.fullmatch(r"[0-9A-Fa-f]+", t) and re.search(r"\d", t)))]
        kept = [t.title() if t.isalpha() and t.isupper() and len(t) > 3 else t for t in kept]
        return " ".join(kept) or text
    if "-" in text and re.search(r"[A-Za-z]{2}", text):
        tokens = [t for t in text.split("-") if t]
        if len(tokens) > 1 and re.fullmatch(r"[0-9A-F]{6}", tokens[-1]) and re.search(r"\d", tokens[-1]):
            tokens.pop()  # serial suffix such as SwitchBot-HubMiniMatter-47DBEC
        return " ".join(tokens)
    return text


def choose_device_name(ip, is_self, is_gateway, dns_name, mdns_info, vendor):
    """Pick the clearest display name for a device on the WLAN."""
    if is_self:
        return clean(socket.gethostname(), 48) or "This PC"
    if is_gateway:
        return "Router"
    if mdns_info:
        for candidate in mdns_info.get("names", []):
            if candidate and not UUID_RE.match(candidate) and not BARE_MAC_RE.match(candidate):
                return tidy_name(candidate)
        host = mdns_info.get("host", "")
        if host and not BARE_MAC_RE.match(host):
            return tidy_name(host)
    if dns_name and not BARE_MAC_RE.match(dns_name):
        return tidy_name(dns_name)
    if vendor and vendor != "Private MAC":
        kind = device_kind("", "", mdns_info.get("model", "") if mdns_info else "", vendor,
                           mdns_info.get("services", []) if mdns_info else [])
        return f"{KIND_LABELS[kind]} ({vendor})" if kind != "unknown" else f"{vendor} device"
    if dns_name:
        return dns_name
    return ip


def devices_revision(devices):
    """Short hash that changes only when the visible device list changes."""
    return hashlib.sha1(json.dumps(devices, sort_keys=True).encode()).hexdigest()[:12]


APPLE_SERVICES = {"_companion-link._tcp", "_apple-mobdev2._tcp", "_rdlink._tcp", "_sleep-proxy._udp", "_apple-pairable._tcp"}
ANDROID_SERVICES = {"_adb-tls-connect._tcp", "_adb-tls-pairing._tcp"}
ANDROID_NAME_RE = re.compile(r"android|galaxy|pixel|oneplus|xiaomi|redmi|huawei|\boppo|motorola|\bsm-[a-z]\d", re.I)
ANDROID_VENDOR_RE = re.compile(r"samsung|google|xiaomi|huawei|oneplus|oppo|vivo|motorola|realme|nothing tech", re.I)
APPLE_NAME_RE = re.compile(r"^(iphone|ipad|macbook|imac|mac|apple|homepod|airport|watch)\b|apple ?tv|\bmacbook|\biphone|\bipad", re.I)
KIND_GROUPS = {
    "router": "network", "phone": "mobile", "tablet": "mobile", "watch": "mobile",
    "computer": "computers", "laptop": "computers", "tv": "media", "speaker": "media",
    "console": "media", "smarthome": "smarthome", "light": "smarthome", "appliance": "smarthome",
    "camera": "smarthome", "printer": "office", "nas": "office",
}


def device_group(kind, vendor, name, hostname, services):
    """Platform group for the grouped view: apple, android, then by type (mobile, computers, ...)."""
    if kind == "router":
        return "network"
    found = set(services or [])
    text = f"{name or ''} {hostname or ''}"
    if vendor == "Apple" or found & APPLE_SERVICES or APPLE_NAME_RE.search(text):
        return "apple"
    if found & ANDROID_SERVICES or ANDROID_NAME_RE.search(text) or (
            ANDROID_VENDOR_RE.search(vendor or "") and kind in ("phone", "tablet", "watch", "unknown")):
        return "android"
    return KIND_GROUPS.get(kind, "other")


def generic_name(name, ip, vendor):
    """True for names that only say what the device is made of (vendor fallback or bare IP)."""
    return not name or name == ip or name.endswith(" device") or bool(vendor and name.endswith(f"({vendor})"))


def bssid_owner(bssid, devices):
    """The router or mesh node whose MAC shares the middle four bytes with the Wi-Fi BSSID.

    Access points derive their BSSIDs from the device MAC (first byte with the local bit,
    last byte counting up), so this finds which node this PC is connected to without login.
    """
    if not bssid or not MAC_RE.match(bssid):
        return None
    middle = bssid.lower().split(":")[1:5]
    for dev in devices:
        mac = (dev.get("mac") or "").lower()
        if MAC_RE.match(mac) and (dev.get("is_gateway") or dev.get("kind") == "router") and mac.split(":")[1:5] == middle:
            return dev
    return None


# --- FRITZ!Box TR-064 (optional mesh details) ----------------------------------------

def is_fritz_vendor(vendor):
    return bool(re.search(r"fritz|\bavm\b", vendor or "", re.I))


def fritz_maker(vendor, trusted):
    """What the router's maker says for FritzMesh: True a FRITZ!Box, None unknown (a MAC prefix the
    database lacks, or a private one) on a trusted network, where the router's TR-064 description
    is asked once to tell; False for everything else, which is never asked."""
    if is_fritz_vendor(vendor):
        return True
    return None if trusted and vendor in ("", "Private MAC") else False


def connect_bound(address, timeout, source_address, iface):
    """A TCP connection that leaves only through `iface` (SO_BINDTODEVICE, unprivileged since
    Linux 5.7). If the binding is refused, nothing is connected."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, iface.encode())
        if timeout is not None and timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
            sock.settimeout(timeout)
        if source_address:
            sock.bind(source_address)
        sock.connect(address)
        return sock
    except BaseException:
        sock.close()
        raise


def bounded_http(ip, port, method, path, body=None, headers=None, tls=False, pin=None,
                 max_body=FRITZ_MAX_SOAP, timeout=FRITZ_TIMEOUT, iface=None):
    """One HTTP(S) request to the router with an overall deadline and a body size cap.

    Returns (status, headers, body_bytes, cert_sha256). With `pin`, the TLS certificate
    must match it before anything is sent (FRITZ!Box certificates are self-signed).
    """
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # self-signed; pinned below instead
        conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    if iface is not None:
        # Only through the monitored interface: the same address on another network is not used.
        if not IFACE_RE.match(iface):
            raise OSError("bad interface")
        conn._create_connection = lambda address, t=None, source=None: connect_bound(address, t, source, iface)
    expired = threading.Event()
    # The connected socket, kept here: after a "Connection: close" reply http.client drops
    # conn.sock while the response still reads from it, and the deadline must still cut it.
    held = []

    def cut():
        expired.set()
        for sock in [conn.sock] + held:
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
    watchdog = threading.Timer(timeout, cut)
    watchdog.daemon = True
    watchdog.start()
    resp = None
    try:
        conn.connect()
        held.append(conn.sock)
        if expired.is_set():
            raise OSError("timed out")
        cert = ""
        if tls:
            cert = hashlib.sha256(conn.sock.getpeercert(binary_form=True) or b"").hexdigest()
            if pin is not None and cert != pin:
                raise PermissionError("certificate changed")
        conn.request(method, path, body=body, headers=headers or {})
        resp = conn.getresponse()
        length = resp.getheader("Content-Length")
        if length is not None and (not length.strip().isdigit() or int(length) > max_body):
            raise OSError("reply too large")
        chunks, size = [], 0
        while size <= max_body:
            if expired.is_set():
                raise OSError("timed out")
            chunk = resp.read1(65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > max_body:
            raise OSError("reply too large")
        if expired.is_set():
            raise OSError("timed out")
        return resp.status, {k.lower(): v for k, v in resp.getheaders()}, b"".join(chunks), cert
    finally:
        watchdog.cancel()
        if resp is not None:
            resp.close()
        conn.close()


def fritz_model(ip, iface=None):
    """Model name from the unauthenticated TR-064 description, e.g. "FRITZ!Box 5690 Pro"."""
    try:
        status, _, body, _ = bounded_http(ip, FRITZ_DESC_PORT, "GET", "/tr64desc.xml", timeout=2.0, iface=iface)
    except (OSError, http.client.HTTPException, ValueError):
        return ""
    if status != 200:
        return ""
    match = re.search(r"<modelName>([^<]{1,60})</modelName>", body.decode("utf-8", "replace"))
    model = clean(match.group(1), 48) if match else ""
    return model if is_fritz_vendor(model) else ""


def parse_digest_challenge(header):
    if not header or not header.lower().startswith("digest "):
        return None
    fields = dict(re.findall(r'(\w+)="?([^",]*)"?', header[7:]))
    if not fields.get("nonce") or not fields.get("realm"):
        return None
    return fields


def digest_authorization(user, password, method, uri, challenge, cnonce, nc=1):
    """RFC 2617 Digest (MD5, qop=auth) as used by TR-064."""
    def md5(text):
        return hashlib.md5(text.encode("utf-8")).hexdigest()
    realm, nonce = challenge["realm"], challenge["nonce"]
    ha1 = md5(f"{user}:{realm}:{password}")
    ha2 = md5(f"{method}:{uri}")
    nc_text = f"{nc:08x}"
    if "auth" in challenge.get("qop", ""):
        response = md5(f"{ha1}:{nonce}:{nc_text}:{cnonce}:auth:{ha2}")
        extra = f', qop=auth, nc={nc_text}, cnonce="{cnonce}"'
    else:
        response = md5(f"{ha1}:{nonce}:{ha2}")
        extra = ""
    opaque = f', opaque="{challenge["opaque"]}"' if challenge.get("opaque") else ""
    return (f'Digest username="{user}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
            f'response="{response}", algorithm=MD5{extra}{opaque}')


class FritzError(Exception):
    """A user-facing reason the FRITZ!Box could not be read.

    `code` (and `args_` for placeholders) let the panel show it in its language;
    the English text stays the message for logs and older panels.
    """

    def __init__(self, code, text, *args):
        super().__init__(text % args if args else text)
        self.code = code
        self.args_ = [str(a) for a in args]


def fritz_soap(ip, user, password, pin, service, control, action, still_ok=None, iface=None):
    """Call one TR-064 action with Digest auth over pinned HTTPS; returns (body_text, cert).

    `still_ok` is called after the challenge arrives and before the password-derived response is
    sent; when it returns False nothing is sent (fzNetworkChanged)."""
    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" '
        'xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
        f'<u:{action} xmlns:u="{service}"></u:{action}></s:Body></s:Envelope>'
    ).encode()
    headers = {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'}
    try:
        status, hdrs, body, cert = bounded_http(ip, FRITZ_TLS_PORT, "POST", control, envelope, headers, tls=True, pin=pin,
                                                iface=iface)
        if status == 401:
            challenge = parse_digest_challenge(hdrs.get("www-authenticate", ""))
            if not challenge:
                raise FritzError("fzMethod", "The FRITZ!Box asked for an unsupported login method.")
            if still_ok is not None and not still_ok():
                raise FritzError("fzNetworkChanged", "The network changed before the login was sent.")
            auth = dict(headers, Authorization=digest_authorization(
                user, password, "POST", control, challenge, os.urandom(8).hex()))
            status, hdrs, body, cert = bounded_http(ip, FRITZ_TLS_PORT, "POST", control, envelope, auth, tls=True, pin=cert,
                                                    iface=iface)
    except PermissionError:
        raise FritzError("fzCert", "The FRITZ!Box certificate changed. Connect again to trust the new one.")
    except ConnectionRefusedError:
        raise FritzError("fzAppAccess", "The FRITZ!Box does not accept app access. Turn on “Allow access for applications” "
                         "under Home Network › Network › Network Settings.")
    except (OSError, http.client.HTTPException, ValueError):
        raise FritzError("fzNoAnswer", "The FRITZ!Box did not answer.")
    text = body.decode("utf-8", "replace")
    if status == 401:
        raise FritzError("fzWrongLogin", "Wrong user name or password.")
    if status != 200:
        code = re.search(r"<errorCode>(\d{1,4})</errorCode>", text)
        if code and code.group(1) == "606":
            raise FritzError("fzNoRight", "This FRITZ!Box user may not read the home network. Give it the right “FRITZ!Box settings”.")
        raise FritzError("fzRefused", "The FRITZ!Box refused the request (error %s).", code.group(1) if code else status)
    return text, cert


def fritz_band(iface_name):
    name = iface_name.upper() if isinstance(iface_name, str) else ""
    for tag, band in (("6G", "6 GHz"), ("5G", "5 GHz"), ("2G", "2.4 GHz")):
        if f":{tag}" in name:
            return band
    if name.startswith("LAN"):
        return "LAN"
    return ""


def rcpi_dbm(value):
    """Link signal: newer FRITZ!OS reports dBm directly, older ones RCPI (0..220); 255 = unknown."""
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    if -110 <= value < 0:
        return round(value)
    if 0 < value <= 220:
        return round(value / 2 - 110)
    return None


def parse_mesh(data):
    """Mesh list JSON -> ({mac: info}, [access points]); bounded and defensive.

    info: {"box_name", "via", "via_mac", "band", "rate_mbps", "signal_dbm", "role"}.
    """
    nodes = data.get("nodes") if isinstance(data, dict) else None
    if not isinstance(nodes, list):
        return {}, []

    def items(value):
        return value if isinstance(value, list) else []

    def text(value):
        return value if isinstance(value, str) else ""
    by_uid, iface_owner = {}, {}
    for node in nodes[:FRITZ_MAX_NODES]:
        if not isinstance(node, dict) or not isinstance(node.get("uid"), str):
            continue
        by_uid[node["uid"]] = node
        for iface in items(node.get("node_interfaces")):
            if isinstance(iface, dict) and isinstance(iface.get("uid"), str):
                iface_owner[iface["uid"]] = (node["uid"], iface)

    def is_ap(node):
        return node.get("mesh_role") in ("master", "slave")

    def node_name(node):
        return clean(text(node.get("device_friendly_name")) or text(node.get("device_name")), 48)

    def node_mac(node):
        mac = text(node.get("device_mac_address")).lower()
        return mac if MAC_RE.match(mac) else ""

    info = {}
    aps = []
    for uid, node in by_uid.items():
        mac = node_mac(node)
        if not mac:
            continue
        entry = {"box_name": node_name(node), "via": "", "via_mac": "", "band": "",
                 "rate_mbps": None, "signal_dbm": None, "role": node.get("mesh_role") if is_ap(node) else "client"}
        best = None
        for iface in items(node.get("node_interfaces")):
            if not isinstance(iface, dict):
                continue
            for link in items(iface.get("node_links")):
                if not isinstance(link, dict) or link.get("state") != "CONNECTED":
                    continue
                if link.get("node_1_uid") == uid:
                    other_uid, other_iface_uid = link.get("node_2_uid"), link.get("node_interface_2_uid")
                else:
                    other_uid, other_iface_uid = link.get("node_1_uid"), link.get("node_interface_1_uid")
                other = by_uid.get(text(other_uid))
                if not other or not is_ap(other):
                    continue
                # A repeater's uplink goes to the master; a client's link to any access point.
                if entry["role"] == "master" or (entry["role"] == "slave" and other.get("mesh_role") != "master"):
                    continue
                _, other_iface = iface_owner.get(text(other_iface_uid), (None, {}))
                band = fritz_band(other_iface.get("name")) or ("LAN" if iface.get("type") == "LAN" else "")
                rates = [r for r in (link.get("cur_data_rate_rx"), link.get("cur_data_rate_tx"))
                         if isinstance(r, (int, float)) and 0 < r < 100000000]
                candidate = {
                    "via": node_name(other), "via_mac": node_mac(other), "band": band,
                    "rate_mbps": round(max(rates) / 1000) if rates else None,
                    "signal_dbm": rcpi_dbm(link.get("rx_rcpi")),
                }
                if best is None or (candidate["rate_mbps"] or 0) > (best["rate_mbps"] or 0):
                    best = candidate
        if best:
            entry.update(best)
        if entry["role"] == "client" and not best:
            continue  # known to the box but not connected now
        info[mac] = entry
        if is_ap(node):
            aps.append({"mac": mac, "name": entry["box_name"], "role": entry["role"], "via": entry["via"],
                        "via_mac": entry["via_mac"],
                        "band": entry["band"], "model": clean(text(node.get("device_model")), 48)})
    counts = {}
    for entry in info.values():
        if entry["role"] == "client" and entry["via_mac"]:
            counts[entry["via_mac"]] = counts.get(entry["via_mac"], 0) + 1
    for ap in aps:
        ap["clients"] = counts.get(ap["mac"], 0)
    aps.sort(key=lambda ap: (ap["role"] != "master", ap["name"].lower()))
    return info, aps


def load_fritz():
    """The saved login, only while it was saved under the current revision: once any collector's
    Disconnect renewed the revision it is used nowhere, even if the file could not be deleted."""
    data = load_private_json(FRITZ_FILE, 4096, secret=True)
    if not isinstance(data, dict):
        return None
    mac, user, password, pin = (data.get(k) for k in ("gateway_mac", "user", "password", "pin"))
    rev = data.get("rev", "")  # saved before any Disconnect (or by 0.8.0 and older): ""
    if not (isinstance(mac, str) and MAC_RE.match(mac) and isinstance(user, str) and FRITZ_USER_RE.match(user)
            and isinstance(password, str) and 0 < len(password) <= FRITZ_PASSWORD_MAX
            and isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin)
            and isinstance(rev, str) and rev == fritz_revision()):
        return None
    return {"gateway_mac": mac.lower(), "user": user, "password": password, "pin": pin, "rev": rev}


def remove_fritz():
    """Delete the saved login; True once it is gone (or was never there)."""
    dfd, missing = open_config_dir()
    if dfd is None:
        return missing
    try:
        os.unlink(FRITZ_FILE, dir_fd=dfd)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    finally:
        os.close(dfd)
    return True


@contextlib.contextmanager
def private_file_lock(name, wait=None):
    """Exclusive lock shared by all collectors, held only for quick file work. Yields True while
    held and False if it could not be taken within FRITZ_LOCK_WAIT (callers then fail closed);
    the lock file is private, never followed through a symlink and never anything but a file."""
    fd = None
    try:
        dfd = None
        if private_config_dir():
            dfd, _missing = open_config_dir()
        if dfd is not None:
            try:
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600,
                             dir_fd=dfd)
            finally:
                os.close(dfd)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise PermissionError("not a private lock file")
            if info.st_mode & 0o077:
                os.fchmod(fd, 0o600)
            deadline = time.monotonic() + (FRITZ_LOCK_WAIT if wait is None else wait)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.02)
    except OSError:
        if fd is not None:
            os.close(fd)
        fd = None
    try:
        yield fd is not None
    finally:
        if fd is not None:
            os.close(fd)  # releases the lock


def fritz_file_lock():
    return private_file_lock(FRITZ_LOCK_FILE)


def fritz_revision():
    """The saved login's revision: "" before the first Disconnect, a new one on every Disconnect,
    None when the file is there but unreadable (never taken for any revision)."""
    data = load_private_json(FRITZ_REV_FILE, 256)
    rev = data.get("rev") if isinstance(data, dict) else None
    if isinstance(rev, str) and re.fullmatch(r"[0-9a-f]{32}", rev):
        return rev
    dfd, missing = open_config_dir()
    if dfd is None:
        return "" if missing else None
    try:
        os.stat(FRITZ_REV_FILE, dir_fd=dfd, follow_symlinks=False)
        return None
    except FileNotFoundError:
        return ""
    except OSError:
        return None
    finally:
        os.close(dfd)


def fritz_new_revision():
    rev = secrets.token_hex(16)
    return rev if save_private_json(FRITZ_REV_FILE, {"rev": rev}) else None


def fritz_revoke():
    """Disconnect for every collector: a new revision makes the saved login (saved with the old
    one) unusable everywhere, and a login being saved in any collector (under the same lock)
    sees it. The file is then deleted unless it already holds a newer login. True once the new
    revision is written; the deletion is only tidying up."""
    # Only under the lock that login()'s repair of an unreadable revision takes too, so neither
    # can overwrite the other; without the lock the Disconnect stays pending and is retried.
    with fritz_file_lock() as held:
        if not held or fritz_new_revision() is None:
            return False
        if load_fritz() is None:
            remove_fritz()
    return True


class FritzMesh:
    """Background reader for the FRITZ!Box: model name always, mesh list only after login."""

    def __init__(self):
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.creds = load_fritz()
        # (gateway ip, gateway mac, maker): True a FRITZ!Box by its maker, None maker unknown on a
        # trusted network (its TR-064 description is asked once), False anything else.
        self.network = (None, "", False)
        self.iface = ""  # the interface the gateway is reached through (all FRITZ!Box traffic is bound to it)
        self.panel_open = False
        self.model = ""
        self.model_for = None
        self.state = "off"
        self.message = ""
        self.message_code = ""
        self.message_args = []
        self.clients = {}
        self.aps = []
        self.updated = 0.0
        self.pending_login = None
        self.revoke_pending = False  # a Disconnect whose file work failed: retried, nothing used meanwhile
        self.generation = 0  # +1 on every gateway change or logout; work begun before it is dropped
        self.nonce = secrets.token_hex(6)
        self.net_seq = 0  # +1 on every gateway change only (net_id)
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.worker, daemon=True)
        self.thread.start()

    def set_network(self, ip, mac, is_fritz, panel_open, iface):
        # Only a private gateway address on a plainly named interface is ever contacted.
        try:
            if not ip or not ipaddress.IPv4Address(ip).is_private:
                ip = None
        except ValueError:
            ip = None
        if not isinstance(iface, str) or not IFACE_RE.match(iface):
            ip, iface = None, ""
        with self.lock:
            if (ip, mac, iface) != (self.network[0], self.network[1], self.iface):
                self.generation += 1
                self.net_seq += 1
                if iface != self.iface:
                    self.model_for = None
                self.iface = iface
                self.clients, self.aps, self.updated = {}, [], 0.0
                self.state, self.message = "off", ""
                if self.pending_login is not None:
                    # A login typed for the old gateway never goes to the new one.
                    self.pending_login = None
                    self.state, self.message = "error", "The network changed before the login was sent."
                    self.message_code, self.message_args = "fzNetworkChanged", []
            self.network = (ip, mac, is_fritz)
            wake = panel_open and not self.panel_open
            self.panel_open = panel_open
        if wake:
            self.wake.set()

    @property
    def net_id(self):
        """Id of the gateway the collector sees now; the panel sends it back with a login."""
        return f"{self.nonce}-{self.net_seq}"

    def login(self, user, password, net_id):
        """Queue a login for the network its form was opened for (net_id, from stats.link). It is
        refused unless that is still the collector's current gateway, bound to that gateway's
        address and MAC, dropped when the network changes, and sent nowhere else (step)."""
        # The revision of the saved login now: if any collector disconnects before this login is
        # saved, the revision changes and the login is dropped (step). An unreadable one is renewed.
        revision = fritz_revision()
        cancelled = False
        if revision is None:
            with fritz_file_lock() as held:
                # Repaired only under the lock and only while still unreadable: a revision written
                # by a Disconnect meanwhile is never replaced, and this login is dropped instead.
                again = fritz_revision() if held else None
                if not held:
                    revision = None
                elif again is None:
                    revision = fritz_new_revision()
                else:
                    cancelled = True
        with self.lock:
            if cancelled:
                self.pending_login = None
                self.state, self.message = "off", ""
                self.message_code, self.message_args = "", []
                return
            if self.revoke_pending or revision is None:
                # The last Disconnect is not done yet (or the settings folder is unusable): no login.
                self.pending_login = None
                self.state, self.message = "error", "The login could not be stored in the settings folder."
                self.message_code, self.message_args = "fzNotStored", []
                return
            ip, mac, _is_fritz = self.network
            if (not ip or not mac or not net_id or net_id != f"{self.nonce}-{self.net_seq}"
                    or not self.looks_like_fritz()):
                self.pending_login = None
                self.state, self.message = "error", "The network changed before the login was sent."
                self.message_code, self.message_args = "fzNetworkChanged", []
                return
            self.pending_login = (user, password, ip, mac, self.generation, revision)
            self.state, self.message = "connecting", "Connecting to the FRITZ!Box…"
            self.message_code, self.message_args = "fzConnecting", []
        self.wake.set()

    def logout(self):
        with self.lock:
            self.creds = None
            self.pending_login = None
            self.generation += 1
            self.clients, self.aps, self.updated = {}, [], 0.0
            self.state, self.message = "off", ""
            self.message_code, self.message_args = "", []
            self.revoke_pending = True
        self.revoke()

    def revoke(self):
        """Finish a Disconnect (fritz_revoke); until it succeeds nothing saved is used and it is
        retried (step)."""
        done = fritz_revoke()
        with self.lock:
            if not self.revoke_pending:
                return
            self.creds = None
            if done:
                self.revoke_pending = False
                self.state, self.message = "off", ""
                self.message_code, self.message_args = "", []
            else:
                self.state = "error"
                self.message = "The saved login could not be deleted yet. WLAN Monitor keeps trying and does not use it."
                self.message_code, self.message_args = "fzNotDeleted", []

    def looks_like_fritz(self):
        """The current gateway is a FRITZ!Box (its maker, or a model probed on this very gateway).
        Called with the lock held."""
        ip, mac, is_fritz = self.network
        return bool(ip and mac and (is_fritz is True or (self.model and self.model_for == (ip, mac))))

    def snapshot(self):
        with self.lock:
            ip, mac, is_fritz = self.network
            bound = bool(self.creds and self.creds["gateway_mac"] == mac)
            return {
                "available": self.looks_like_fritz(),
                "model": self.model if self.model_for == (ip, mac) else "",
                "state": self.state if (bound or self.state in ("connecting", "error")) else "off",
                "message": self.message,
                "message_code": self.message_code if self.message else "",
                "message_args": self.message_args if self.message else [],
                "user": self.creds["user"] if bound else "",
                "aps": list(self.aps),
                "updated": int(self.updated),
            }, dict(self.clients)

    def current(self, ip, mac, generation):
        """True while the gateway is still the one the work began with (no change, no logout, no
        Disconnect still being finished)."""
        with self.lock:
            return self.network[:2] == (ip, mac) and self.generation == generation and not self.revoke_pending

    def refresh(self, ip, creds, still_ok=None, iface=None):
        text, _ = fritz_soap(ip, creds["user"], creds["password"], creds["pin"],
                             "urn:dslforum-org:service:Hosts:1", "/upnp/control/hosts", "X_AVM-DE_GetMeshListPath",
                             still_ok, iface)
        match = re.search(r"<NewX_AVM-DE_MeshListPath>([^<]{1,200})</NewX_AVM-DE_MeshListPath>", text)
        path = match.group(1).replace("&amp;", "&") if match else ""
        if not MESH_PATH_RE.match(path):
            raise FritzError("fzNoMesh", "The FRITZ!Box sent no mesh list.")
        if still_ok is not None and not still_ok():
            raise FritzError("fzNetworkChanged", "The network changed before the login was sent.")
        try:
            status, _, body, _ = bounded_http(ip, FRITZ_TLS_PORT, "GET", path, tls=True, pin=creds["pin"],
                                              max_body=FRITZ_MAX_MESH, iface=iface)
            data = json.loads(body.decode("utf-8", "replace")) if status == 200 else None
        except PermissionError:
            raise FritzError("fzCert", "The FRITZ!Box certificate changed. Connect again to trust the new one.")
        except (OSError, http.client.HTTPException, ValueError):
            raise FritzError("fzMeshUnreadable", "The FRITZ!Box mesh list could not be read.")
        try:
            clients, aps = parse_mesh(data)
        except Exception:  # an odd reply is an unreadable list, never a stuck login
            raise FritzError("fzMeshUnreadable", "The FRITZ!Box mesh list could not be read.")
        if not clients:
            raise FritzError("fzMeshEmpty", "The FRITZ!Box mesh list was empty.")
        return clients, aps

    def step(self):
        """One unit of work; returns seconds until the next one is due."""
        with self.lock:
            revoke = self.revoke_pending
        if revoke:
            self.revoke()
            with self.lock:
                if self.revoke_pending:
                    return FRITZ_REVOKE_RETRY
        with self.lock:
            if self.revoke_pending:  # a Disconnect began meanwhile: nothing saved is used
                return FRITZ_REVOKE_RETRY
            ip, mac, is_fritz = self.network
            iface = self.iface
            pending, self.pending_login = self.pending_login, None
            generation = self.generation
            creds = self.creds
            interval = FRITZ_POLL_OPEN if self.panel_open else FRITZ_POLL_CLOSED
            age = time.time() - self.updated
            state = self.state
        if not ip or not mac or not iface:
            return 5.0
        if is_fritz is not False and self.model_for != (ip, mac):   # once per gateway
            model = fritz_model(ip, iface)
            with self.lock:
                if self.generation == generation:  # probed while the network changed: kept for nobody
                    self.model, self.model_for = model, (ip, mac)
        if pending and pending[2:5] != (ip, mac, generation):
            # Queued for another gateway (the network changed in between): never sent here.
            with self.lock:
                self.state, self.message = "error", "The network changed before the login was sent."
                self.message_code, self.message_args = "fzNetworkChanged", []
            return 5.0
        if pending:
            # The probe above took time: the gateway may have changed since the snapshot. The
            # password-derived response goes out only while this is still the gateway the login
            # was typed for (same generation, and the kernel still has its MAC at this address),
            # checked once more right before it is sent.
            def still_ok():
                # ...and while no collector disconnected since the login was queued.
                return (self.current(ip, mac, generation) and neighbor_mac(ip, iface) == mac
                        and fritz_revision() == pending[5])
            try:
                if not still_ok():
                    raise FritzError("fzNetworkChanged", "The network changed before the login was sent.")
                # Trust on first use: remember the certificate seen while the user logs in.
                _, cert = fritz_soap(ip, pending[0], pending[1], None, "urn:dslforum-org:service:Hosts:1",
                                     "/upnp/control/hosts", "X_AVM-DE_GetMeshListPath", still_ok, iface)
                creds = {"gateway_mac": mac, "user": pending[0], "password": pending[1], "pin": cert,
                         "rev": pending[5]}
                clients, aps = self.refresh(ip, creds, still_ok, iface)
            except FritzError as exc:
                revoked = fritz_revision() != pending[5]
                with self.lock:
                    if revoked:  # Disconnect on another screen meanwhile: it stays disconnected
                        if self.generation == generation:
                            self.state, self.message = "off", ""
                            self.message_code, self.message_args = "", []
                    elif self.generation == generation or exc.code == "fzNetworkChanged":
                        self.state, self.message = "error", str(exc)
                        self.message_code, self.message_args = exc.code, exc.args_
                return 5.0
            except Exception:  # anything unexpected ends the login too: never stuck at "connecting"
                with self.lock:
                    if self.generation == generation:
                        self.state, self.message = "error", "The FRITZ!Box did not answer."
                        self.message_code, self.message_args = "fzNoAnswer", []
                return 5.0
            # Saved under the lock every collector's Disconnect takes, and only while no Disconnect
            # happened anywhere since the login was queued (same revision, before and after saving).
            with fritz_file_lock() as held:
                unchanged = held and pending[5] is not None and fritz_revision() == pending[5]
                with self.lock:
                    if self.network[:2] != (ip, mac) or self.generation != generation:
                        # Changed while the login was in flight: nothing from it is kept or saved.
                        self.state, self.message = "error", "The network changed before the login was sent."
                        self.message_code, self.message_args = "fzNetworkChanged", []
                        return 5.0
                    if not unchanged:
                        # Disconnected on another screen meanwhile (or the lock is unusable): it stays so.
                        self.state, self.message = "off", ""
                        self.message_code, self.message_args = "", []
                        return 5.0
                    saved = save_private_json(FRITZ_FILE, creds)
                    if saved and fritz_revision() != pending[5]:
                        # Defensive (revisions change only under this lock): a newer revision wins.
                        remove_fritz()
                        self.state, self.message = "off", ""
                        self.message_code, self.message_args = "", []
                        return 5.0
                    if not saved:
                        self.state, self.message = "error", "The login could not be stored in the settings folder."
                        self.message_code, self.message_args = "fzNotStored", []
                        return 5.0
                    self.creds = creds
                    self.clients, self.aps, self.updated = clients, aps, time.time()
                    self.state, self.message = "connected", ""
                    self.message_code, self.message_args = "", []
            return interval
        # Every screen runs its own collector and they share the saved login: one deleted or
        # replaced by another collector (Disconnect there, or a new login) is followed here
        # before anything is sent.
        disk = load_fritz()
        if disk != creds:
            with self.lock:
                if self.generation != generation or self.revoke_pending:
                    return 5.0
                self.creds, creds = disk, disk
                self.generation += 1
                generation = self.generation
                self.clients, self.aps, self.updated = {}, [], 0.0
                self.state, self.message = "off", ""
                age = time.time() - self.updated
        if not creds or creds["gateway_mac"] != mac:
            return 5.0
        due = interval if state != "error" else FRITZ_RETRY_ERROR
        if age < due:
            return min(5.0, due - age)
        def still_saved():
            # A gateway change or a Disconnect on any screen in between stops the request before
            # the password-derived response (or the mesh list request) is sent.
            return self.current(ip, mac, generation) and load_fritz() == creds
        try:
            # Saved credentials go only to the pinned certificate.
            clients, aps = self.refresh(ip, creds, still_saved, iface)
        except FritzError as exc:
            if load_fritz() != creds:
                return 5.0  # disconnected or replaced elsewhere: followed on the next step
            with self.lock:
                if self.generation == generation:
                    self.state, self.message, self.updated = "error", str(exc), time.time()
                    self.message_code, self.message_args = exc.code, exc.args_
            return 5.0
        if load_fritz() != creds:
            return 5.0  # disconnected elsewhere while it was read: never shown
        with self.lock:
            if self.generation != generation:
                return 5.0  # the old gateway's mesh list is never shown for the new one
            self.clients, self.aps, self.updated = clients, aps, time.time()
            self.state, self.message = "connected", ""
            self.message_code, self.message_args = "", []
        return interval

    def worker(self):
        while True:
            try:
                wait = self.step()
            except Exception:  # never let the reader thread die
                wait = 30.0
            self.wake.wait(max(0.5, wait))
            self.wake.clear()


class Monitor:
    def __init__(self):
        self.lang = "en"  # set by the bar widget ("lang" command); used for notifications
        self.trusted = load_trusted()
        self.untrusted_here = set()  # untrusted here while the shared list could not be saved
        self.store_stamp = store_stamp()
        self.store = load_store()
        self.fritz = FritzMesh()
        self.panel_open = False
        self.force_next = False
        self.iface_cache = {}
        self.identity = None
        self.trust_identity = {"ssid": "", "gateway_mac": ""}
        self.gateway_poked = -math.inf
        self.reset_network(None)

    def refresh_gateway(self, neighbors, gateway_ip, iface, now):
        """Trust needs the router's MAC from the kernel right now. Its entry ages out when nothing
        talks to the router through this interface, so renew it (bounded, at most every
        GATEWAY_POKE_EVERY seconds) and, when it was gone, read it again for a moment."""
        entry = neighbors.get(gateway_ip)
        if entry is not None and entry["state"] in ACTIVE_NEIGH_STATES:
            return
        if now - self.gateway_poked < GATEWAY_POKE_EVERY:
            return
        self.gateway_poked = now
        if not poke_neighbor(gateway_ip, iface) or entry is not None:
            return
        deadline = time.monotonic() + GATEWAY_POKE_BUDGET
        for pause in GATEWAY_POKE_WAIT:
            time.sleep(pause)
            left = deadline - time.monotonic()
            if left <= 0.05:
                return
            mac = neighbor_mac(gateway_ip, iface, timeout=left)
            if mac:
                neighbors[gateway_ip] = {"mac": mac, "state": "REACHABLE"}
                return

    def reset_network(self, identity):
        """Forget everything learned about the previous network."""
        self.identity = identity
        self.known = {}  # ip -> device dict (plus internal last_seen)
        self.ptr_names = {}  # ip -> [fqdn] from the last full PTR sweep
        self.dns_cache = {}  # ip -> (expires, [fqdn])
        self.mdns_hosts = {}
        self.mdns_time = -math.inf
        self.last_reachable = {}
        self.last_full_scan = -math.inf
        self.last_known_scan = -math.inf
        self.domain = ""
        self.gateway_web = None  # None: not probed yet
        self.web_ok = {}  # advertised web UI url -> (expires, reachable); pruned every snapshot
        self.iw_info = {}
        self.lan_check = (None, -math.inf, True)  # (vpn iface, checked at, router reachable)
        self.lan_recheck = False
        self.iw_time = -math.inf
        self.traffic_prev = None

    # -- commands from the bar widget --
    def handle(self, command):
        """Apply a stdin command; returns True when a fresh snapshot should be sent right away."""
        if isinstance(command, dict):
            if command["cmd"] == "lang":
                self.lang = command["lang"]
                return False
            if command["cmd"] == "view":
                view = {"mode": command["mode"], "collapsed": list(command["collapsed"])}

                def change(store):
                    store["view"] = dict(view, collapsed=list(view["collapsed"]))
                self.update_store(change)
                return True
            if command["cmd"] == "fritz_login":
                self.fritz.login(command["user"], command["password"], command["net"])
                return True
            return self.handle_device(command)
        if command == "fritz_logout":
            self.fritz.logout()
            return True
        if command == "known_all":
            key = network_key(self.trust_identity)
            self.reload_store()
            if not self.store["networks"].get(key):
                return False

            def change(store):
                for rec in (store["networks"].get(key) or {"devices": {}})["devices"].values():
                    rec["new"] = False
            self.update_store(change)
            return True
        if command == "open":
            self.panel_open = True
            self.lan_recheck = True  # show the current VPN state when the panel opens
            return True
        if command == "closed":
            self.panel_open = False
            return False
        if command == "rescan":
            self.force_next = True
            return True
        if command in ("trust", "untrust"):
            ident = dict(self.trust_identity)
            if not ident.get("gateway_mac"):
                return False
            key = (ident["gateway_mac"], ident["ssid"])
            saved = self.update_trusted(key, command == "trust")
            if command == "untrust" and not saved:
                # Never scanned actively here, whatever the file says; written later (shared_trusted).
                self.untrusted_here.add(key)
            else:
                self.untrusted_here.discard(key)
                if command == "trust" and saved:
                    self.last_full_scan = -math.inf
            self.trusted = self.shared_trusted()
            return True
        return False

    @staticmethod
    def update_trusted(key, trust, wait=None):
        """Read, change and write the shared trusted list under the lock all collectors share, so
        one screen's change never undoes another's. Nothing is written without the lock."""
        with private_file_lock(TRUST_LOCK_FILE, wait) as held:
            if not held:
                return False
            networks = [entry for entry in load_trusted() if (entry["gateway_mac"], entry["ssid"]) != key]
            if trust:
                networks.insert(0, {"ssid": key[1], "gateway_mac": key[0]})
            return save_trusted(networks)

    def shared_trusted(self):
        """The trusted list as all collectors share it now (Untrust on another screen counts here);
        an Untrust that could not be written yet is retried without waiting for the lock."""
        for key in list(self.untrusted_here):
            if self.update_trusted(key, False, wait=0):
                self.untrusted_here.discard(key)
        return [entry for entry in load_trusted()
                if (entry["gateway_mac"], entry["ssid"]) not in self.untrusted_here]

    def reload_store(self):
        """Pick up devices.json written by another screen's collector (only when it changed)."""
        stamp = store_stamp()
        if stamp != self.store_stamp:
            self.store_stamp = stamp
            self.store = load_store()

    def update_store(self, change):
        """Apply one change to devices.json as all collectors share it: re-read under the lock
        they share, change only what this command or scan changes, write atomically. Without the
        lock nothing is written; the change then lasts here until the file changes."""
        with private_file_lock(DEVICES_LOCK_FILE) as held:
            if not held:
                change(self.store)
                return False
            fresh = load_store()
            change(fresh)
            saved = save_store(fresh)
            self.store = fresh
            self.store_stamp = store_stamp() if saved else self.store_stamp
            return saved

    def handle_device(self, command):
        """Rename, pin, hide or acknowledge one device on the current network, or toggle alerts."""
        if command["cmd"] == "alerts":
            on = command["on"]

            def set_alerts(store):
                store["alerts"] = on
            self.update_store(set_alerts)
            return True
        key = network_key(self.trust_identity)
        # Only devices currently listed on this network can be changed.
        if not key or command["mac"] not in {dev.get("mac") for dev in self.known.values()}:
            return False
        cmd, mac, now_wall = command["cmd"], command["mac"], time.time()

        def change(store):
            rec = store_device(store_network(store, key), mac, now_wall)
            if cmd == "rename":
                rec["name"] = command["name"]
            elif cmd == "pin":
                rec["pinned"] = command["on"]
                if command["on"]:
                    rec["hidden"] = False
            elif cmd == "hide":
                rec["hidden"] = command["on"]
                if command["on"]:
                    rec["pinned"] = False
            elif cmd == "known":
                rec["new"] = not command["on"]
        self.update_store(change)
        return True

    def apply_store(self, devices, trusted, ssid):
        """Overlay saved names / pins / hidden flags; on trusted networks remember MACs and flag new ones."""
        key = network_key(self.trust_identity)
        tracking = bool(trusted and key)
        now_wall = time.time()
        changed = False
        self.reload_store()
        net = store_network(self.store, key, create=tracking) if key else None
        if tracking and net["since"] is None:
            net["since"] = now_wall
            changed = True
        added = {}  # mac -> record first seen in this scan (merged into the shared file below)
        new_names = {}  # mac -> name of a device that is new on this network
        for dev in devices:
            mac = dev["mac"] if MAC_RE.match(dev.get("mac") or "") else ""
            rec = net["devices"].get(mac) if net and mac else None
            if tracking and mac and rec is None and not dev["is_self"]:
                rec = store_device(net, mac, now_wall)
                if now_wall - net["since"] > BASELINE_SECONDS:
                    rec["new"] = True
                    new_names[mac] = dev["name"]
                added[mac] = dict(rec)
                changed = True
            dev["auto_name"] = dev["name"]
            dev["custom_name"] = bool(rec and rec["name"])
            if dev["custom_name"]:
                dev["name"] = rec["name"]
            dev["pinned"] = bool(rec and rec["pinned"])
            dev["hidden"] = bool(rec and rec["hidden"])
            dev["new"] = bool(rec and rec["new"])
            dev["can_edit"] = bool(mac and key)
        alert = list(new_names.values())
        if changed:
            since = net["since"]
            inserted = []

            def change(store):
                fresh = store_network(store, key)
                if fresh["since"] is None:
                    fresh["since"] = since
                inserted.clear()
                for mac, rec in added.items():
                    if mac not in fresh["devices"]:
                        store_device(fresh, mac, rec["first"]).update(rec)
                        inserted.append(mac)
            if self.update_store(change):
                # Written to the shared file: only devices this collector added there are announced,
                # so another screen that saw the same device first does not announce it twice.
                alert = [new_names[mac] for mac in inserted if mac in new_names]
        if alert and self.store["alerts"]:
            notify_new_devices(ssid, alert, self.lang)
        return tracking

    def domains(self):
        found = list(DEFAULT_DOMAINS) + resolv_search_domains()
        if self.domain:
            found.append(self.domain)
        return found

    def wireless(self, iface, now, force=False):
        if force or self.panel_open or now - self.iw_time >= IW_EVERY:
            self.iw_info = wireless_details(iface)
            self.iw_time = now
        info = dict(self.iw_info)
        signal = proc_wireless_signal(iface)
        if signal is not None and info.get("ssid"):
            info["signal_dbm"] = signal
            info["quality"] = dbm_to_quality(signal)
        return info

    def traffic(self, iface, now):
        rx_bytes, tx_bytes = read_traffic(iface)
        prev = self.traffic_prev
        rx_rate = tx_rate = None
        if prev and prev[0] == iface and now > prev[1]:
            dt = now - prev[1]
            rx_rate = max(0.0, (rx_bytes - prev[2]) / dt)
            tx_rate = max(0.0, (tx_bytes - prev[3]) / dt)
        self.traffic_prev = (iface, now, rx_bytes, tx_bytes)
        return {
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "rx_rate": round(rx_rate, 1) if rx_rate is not None else None,
            "tx_rate": round(tx_rate, 1) if tx_rate is not None else None,
        }

    def hostname_for(self, ip, gateway, now, allow_lookup):
        names = self.ptr_names.get(ip)
        if names is None:
            cached = self.dns_cache.get(ip)
            if cached and cached[0] > now:
                names = cached[1]
            elif allow_lookup:
                names = lookup_ptr(ip, (gateway, "127.0.0.53"))
                self.dns_cache[ip] = (now + (DNS_TTL if names else DNS_NEGATIVE_TTL), names)
            else:
                names = []
        return select_best_hostname(names, self.domains()) if names else ""

    def snapshot(self, force_scan=False, emit=None):
        now = time.monotonic()
        self.reload_store()  # names, pins, alerts or view changed on another screen
        force_scan = force_scan or self.force_next
        self.force_next = False

        net = detect_interface(self.iface_cache)
        if not net:
            # Disconnected: forget the network (and its FRITZ!Box) so nothing of it carries over.
            if self.identity is not None:
                self.reset_network(None)
                self.trust_identity = {"ssid": "", "gateway_mac": ""}
            self.fritz.set_network(None, "", False, self.panel_open, "")
            return {
                "time": int(time.time()),
                "active": False,
                "scanning": False,
                "link": None,
                "traffic": None,
                "devices": [],
                "devices_rev": "",
                "online_count": 0,
                "total_count": 0,
            }

        iface = net["iface"]
        local_ip = net["ip"]
        gateway_ip = net["gateway"]
        try:
            subnet_net = ipaddress.IPv4Network(f"{local_ip}/{max(24, net['prefix'])}", strict=False)
        except ValueError:
            subnet_net = None

        base = (iface, gateway_ip, str(subnet_net))
        base_changed = self.identity is None or self.identity["base"] != base
        neighbors = read_neighbors(iface)
        if gateway_ip:
            self.refresh_gateway(neighbors, gateway_ip, iface, now)
        wlan = self.wireless(iface, now, force=base_changed) if net["is_wireless"] else {}
        gateway_mac = neighbors.get(gateway_ip, {}).get("mac", "") if gateway_ip else ""
        identity = {"base": base, "ssid": wlan.get("ssid", ""), "gateway_mac": gateway_mac}
        if not same_network(self.identity, identity):
            self.reset_network(identity)
            if net["is_wireless"]:
                wlan = self.wireless(iface, now, force=True)
        for key in ("ssid", "gateway_mac"):
            if identity[key]:
                self.identity[key] = identity[key]
        self.trust_identity = {
            "ssid": self.identity["ssid"] if net["is_wireless"] else "",
            "gateway_mac": self.identity["gateway_mac"],
        }
        # Trust needs the router seen now (and the SSID on Wi-Fi), not values kept from before:
        # an unknown gateway on the same address and subnet never inherits a trusted network.
        evidence = bool(identity["gateway_mac"]) and (bool(identity["ssid"]) or not net["is_wireless"])
        self.trusted = self.shared_trusted()
        trusted = evidence and is_trusted(self.trust_identity, self.trusted)

        # A VPN that blocks the home network makes every device look idle: say so instead.
        vpn = detect_vpn(iface)
        lan_blocked = False
        if vpn and gateway_ip:
            checked_iface, checked_at, reachable = self.lan_check
            every = LAN_CHECK_EVERY if reachable else LAN_CHECK_BLOCKED
            if checked_iface != vpn["iface"] or now - checked_at >= every or force_scan or self.lan_recheck:
                reachable = gateway_reachable(gateway_ip)
                if reachable and not self.lan_check[2]:
                    self.last_full_scan = -math.inf  # just unblocked: look for devices right away
                self.lan_check = (vpn["iface"], now, reachable)
            lan_blocked = not reachable
        else:
            self.lan_check = (None, -math.inf, True)
        self.lan_recheck = False

        # Only the router's MAC seen now: one remembered from before never keeps the login offered
        # (or a typed login queued) on a network whose router cannot be told apart right now.
        self.fritz.set_network(None if lan_blocked else gateway_ip, gateway_mac,
                               fritz_maker(lookup_vendor(gateway_mac), trusted),
                               self.panel_open, iface)
        fritz_info, mesh = self.fritz.snapshot()
        if lan_blocked:
            mesh = {}
            fritz_info = dict(fritz_info, aps=[], state="paused" if fritz_info["user"] else fritz_info["state"],
                              message="Paused while the VPN blocks the home network.",
                              message_code="fzPaused", message_args=[])

        # Active scans only on trusted networks, unless the user explicitly asked for one.
        since_full = now - self.last_full_scan
        do_full = force_scan or (
            trusted and (since_full >= FULL_SCAN_EVERY or (self.panel_open and since_full >= FULL_SCAN_ON_OPEN))
        )
        do_known = not do_full and trusted and self.known and now - self.last_known_scan >= KNOWN_SCAN_EVERY
        if lan_blocked:  # probes would only be dropped by the VPN firewall
            do_full = do_known = False

        mdns_every = MDNS_EVERY_OPEN if self.panel_open else MDNS_EVERY_CLOSED
        if do_full or now - self.mdns_time >= mdns_every:
            if do_full and emit:
                emit({"event": "scanning"})
            hosts = query_mdns(iface, subnet_net)
            if hosts is not None:
                # Some devices answer only part of the browse window; keep web UIs found earlier.
                for ip, entry in hosts.items():
                    if not entry["web"]:
                        entry["web"] = self.mdns_hosts.get(ip, {}).get("web", [])
                self.mdns_hosts = hosts
            self.mdns_time = now

        responders = set()
        if do_full:
            targets = subnet_hosts(local_ip, net["prefix"]) + list(self.mdns_hosts.keys())
            ptr_names, responders = sweep(targets, dns_server=gateway_ip)
            if ptr_names:
                self.ptr_names = ptr_names
                self.domain = learn_domain([n for names in ptr_names.values() for n in names]) or self.domain
            self.last_full_scan = self.last_known_scan = now
        elif do_known:
            targets = [ip for ip, dev in self.known.items() if dev.get("mac") and not dev.get("is_self")]
            _, responders = sweep(targets)
            self.last_known_scan = now
        if do_full or do_known:
            neighbors = read_neighbors(iface)

        def in_subnet(ip):
            if subnet_net is None:
                return False
            try:
                return ipaddress.IPv4Address(ip) in subnet_net
            except ValueError:
                return False

        # Only local-subnet addresses are tracked, and entries expire once they can no
        # longer count (ONLINE_GRACE), so the map stays bounded by the subnet size.
        responders = {ip for ip in responders if in_subnet(ip)}
        for ip, neigh in neighbors.items():
            if neigh["state"] in ACTIVE_NEIGH_STATES and in_subnet(ip):
                self.last_reachable[ip] = now
        for ip in responders:
            self.last_reachable[ip] = now
        self.last_reachable = prune_reachable(self.last_reachable, now, in_subnet)

        if gateway_ip and self.gateway_web is None:
            self.gateway_web = probe_web(gateway_ip)

        traffic = self.traffic(iface, now)
        all_ips = set(neighbors) | set(self.mdns_hosts) | set(self.ptr_names) | set(responders)
        all_ips.add(local_ip)
        if gateway_ip:
            all_ips.add(gateway_ip)

        devices = []
        web_checks = WEB_CHECKS_PER_SNAPSHOT
        for ip in all_ips:
            if subnet_net is not None:
                try:
                    if ipaddress.IPv4Address(ip) not in subnet_net:
                        continue
                except ValueError:
                    continue
            is_self = ip == local_ip
            is_gateway = ip == gateway_ip
            neigh = neighbors.get(ip, {})
            mdns = self.mdns_hosts.get(ip, {})
            prev = self.known.get(ip, {})

            mac = (net["mac"] if is_self else "") or neigh.get("mac") or mdns.get("mac") or prev.get("mac") or ""
            vendor = lookup_vendor(mac) or prev.get("vendor") or ""
            if is_self:
                dns_name = clean(socket.gethostname(), 48)
            else:
                # Single lookups only for devices we can already see (normal DNS traffic).
                dns_name = self.hostname_for(ip, gateway_ip, now, allow_lookup=bool(neigh) or is_gateway)
                dns_name = dns_name or prev.get("hostname") or ""
            model = mdns.get("model") or prev.get("model") or ""
            real_model = model if model != wlan.get("ssid") else ""
            if is_gateway and wlan.get("ssid") and not model:
                model = wlan["ssid"]

            online = bool(
                is_self or is_gateway or ip in responders
                or (neigh and neighbor_online(ip, neigh["state"], now, self.last_reachable))
            )
            if online:
                last_seen = now
                state = "this PC" if is_self else ("router" if is_gateway else "online")
            elif neigh:
                # Still in the kernel's neighbor cache (STALE) but not confirmed recently;
                # without active probes (untrusted network) we cannot tell online from asleep.
                last_seen = now
                state = "idle"
            else:
                last_seen = prev.get("last_seen", now)
                state = "sleeping"

            name = choose_device_name(ip, is_self, is_gateway, dns_name, mdns, vendor)
            mesh_entry = mesh.get(mac.lower()) if mac else None
            box_name = mesh_entry["box_name"] if mesh_entry else ""
            if box_name and not is_self and not is_gateway and generic_name(name, ip, vendor) \
                    and not re.match(r"^PC(-\d{1,3}){4}$", box_name):
                name = tidy_name(box_name)  # the name given in the FRITZ!Box
            router_model = fritz_info["model"] or real_model
            if is_gateway:
                # The Wi-Fi name is what people see in their Wi-Fi settings (e.g. "FRITZ!Box 7690 ML"),
                # even when the real model differs; the model stays in the details.
                label = wlan.get("ssid") or router_model or vendor or dns_name
                name = f"Router ({label})" if label else "Router"
            if not vendor and re.match(r"^(iPhone|iPad|MacBook|iMac|Mac|Apple|HomePod|AirPort)", name, re.I):
                vendor = "Apple"
            services = mdns.get("services", [])
            kind = device_kind(name, dns_name or mdns.get("host", ""), model, vendor, services, is_gateway, is_self)
            if mesh_entry and mesh_entry["role"] in ("master", "slave"):
                kind = "router"
            if is_gateway and router_model:
                model = router_model
            if model and model.lower() == name.lower():
                model = ""

            web_url = ""
            if is_gateway and self.gateway_web:
                web_url = make_web_url(self.gateway_web, ip, subnet=subnet_net)
            elif not is_self and online:
                for url in mdns.get("web", [])[:MDNS_MAX_WEB]:
                    cached = self.web_ok.get(url)
                    if cached is None or cached[0] <= now:
                        if web_checks <= 0:
                            continue  # checked in a later snapshot
                        web_checks -= 1
                        ok = url_reachable(url)
                        cached = (now + (WEB_OK_TTL if ok else WEB_FAIL_TTL), ok)
                        self.web_ok[url] = cached
                    if cached[1]:
                        web_url = url
                        break

            dev = {
                "ip": ip,
                "name": clean(name, 64),
                "hostname": clean(dns_name or mdns.get("host", ""), 64),
                "mac": clean(mac, 20),
                "vendor": clean(vendor, 48),
                "model": clean(model, 48),
                "online": online,
                "state": state,
                "is_self": is_self,
                "is_gateway": is_gateway,
                "web_url": web_url,
                "kind": kind,
                "group": device_group(kind, vendor, name, dns_name or mdns.get("host", ""), services),
                "mesh": {k: mesh_entry[k] for k in ("via", "via_mac", "band", "rate_mbps", "signal_dbm", "role")}
                if mesh_entry else None,
                "seen_min": int((now - last_seen) // 60) if state == "sleeping" else None,
            }
            self.known[ip] = dict(dev, last_seen=last_seen)
            devices.append(dev)

        self.web_ok = prune_web_cache(self.web_ok, self.mdns_hosts, now)
        self.dns_cache = {ip: entry for ip, entry in self.dns_cache.items() if entry[0] > now}

        # Keep recently seen devices listed as sleeping; forget them after SLEEPING_KEEP.
        for ip, prev in list(self.known.items()):
            if ip in all_ips:
                continue
            if now - prev.get("last_seen", 0) <= SLEEPING_KEEP:
                sleeping = {k: v for k, v in prev.items() if k != "last_seen"}
                devices.append(dict(sleeping, online=False, state="sleeping",
                                    seen_min=int((now - prev.get("last_seen", now)) // 60)))
            else:
                del self.known[ip]
                self.last_reachable.pop(ip, None)

        tracking = self.apply_store(devices, trusted, wlan.get("ssid", ""))

        def sort_key(dev):
            try:
                ip_num = int(ipaddress.IPv4Address(dev["ip"]))
            except ValueError:
                ip_num = 0
            rank = (0 if dev["is_gateway"] else 1 if dev["is_self"] else 2 if dev["pinned"]
                    else 3 if dev["online"] else 4 if dev["state"] == "idle" else 5)
            return (rank, ip_num)

        devices.sort(key=sort_key)
        # Access points carry their FRITZ!Box names ("fritz.box"); show the names used here instead.
        ap_names = {d["mac"]: d["name"] for d in devices if d.get("kind") == "router" and d.get("mac")}
        for dev in devices:
            if dev.get("mesh") and dev["mesh"]["via_mac"] in ap_names:
                dev["mesh"] = dict(dev["mesh"], via=ap_names[dev["mesh"]["via_mac"]])
        fritz_info = dict(fritz_info, aps=[dict(ap, name=ap_names.get(ap["mac"], ap["name"]),
                                                via=ap_names.get(ap.get("via_mac", ""), ap["via"]))
                                           for ap in fritz_info["aps"]])
        self_mesh = mesh.get((net["mac"] or "").lower())
        if self_mesh and self_mesh["via"]:
            via, via_band = ap_names.get(self_mesh["via_mac"], self_mesh["via"]), self_mesh["band"]
        else:
            owner = bssid_owner(wlan.get("bssid", ""), devices)
            via, via_band = (owner["name"], wlan.get("band") or "") if owner else ("", "")
        online_count = sum(1 for d in devices if d["online"])
        idle_count = sum(1 for d in devices if d["state"] == "idle")

        return {
            "time": int(time.time()),
            "active": True,
            "scanning": False,
            "link": {
                "iface": iface,
                "is_wireless": net["is_wireless"],
                "ip": local_ip,
                "prefix": net["prefix"],
                "cidr": net["cidr"],
                "gateway": gateway_ip,
                # The router the collector talks to now (not from the device list, which the
                # panel freezes while a name is edited) and its network id for fritz_login.
                "gateway_mac": self.identity["gateway_mac"],
                "net_id": self.fritz.net_id,
                "mac": net["mac"],
                "ssid": wlan.get("ssid") or ("Ethernet" if not net["is_wireless"] else iface),
                "bssid": wlan.get("bssid") or "",
                "signal_dbm": wlan.get("signal_dbm"),
                "quality": wlan.get("quality"),
                "freq_mhz": wlan.get("freq_mhz"),
                "band": wlan.get("band") or "",
                "channel": wlan.get("channel"),
                "width_mhz": wlan.get("width_mhz"),
                "tx_mbps": wlan.get("tx_mbps"),
                "rx_mbps": wlan.get("rx_mbps"),
                "domain": clean(self.domain, 64),
                "trusted": trusted,
                "can_trust": bool(self.trust_identity["gateway_mac"]),
                "scan_mode": "active" if trusted else "passive",
                "via": clean(via, 64) if not lan_blocked else "",
                "vpn": dict(vpn, name=clean(vpn["name"], 32), iface=clean(vpn["iface"], 16), lan_blocked=lan_blocked)
                if vpn else None,
                "via_band": via_band,
            },
            "traffic": traffic,
            "devices": devices,
            "devices_rev": devices_revision(devices),
            "online_count": online_count,
            "idle_count": idle_count,
            "total_count": len(devices),
            "hidden_count": sum(1 for d in devices if d["hidden"]),
            "new_count": sum(1 for d in devices if d["new"] and not d["hidden"]),
            "named_count": sum(1 for d in devices if d["custom_name"]),
            "tracking": tracking,
            "alerts": self.store["alerts"],
            "view": self.store["view"],
            "fritz": fritz_info,
            "mesh_active": bool(mesh),
        }


def emit(obj):
    print(json.dumps(obj), flush=True)


def handle_line(monitor, line):
    """Parse and apply one stdin line. A command that fails is dropped: it never ends the collector."""
    try:
        return monitor.handle(parse_command(line))
    except Exception:
        return False


def main():
    monitor = Monitor()
    if "--once" in sys.argv:
        net = detect_interface(monitor.iface_cache)
        if net:
            monitor.traffic(net["iface"], time.monotonic())
        time.sleep(0.25)
        monitor.snapshot(force_scan=True)  # learns the network for the FRITZ!Box reader
        monitor.fritz.step()
        emit(monitor.snapshot())
        return 0
    monitor.fritz.start()

    stdin_fd = sys.stdin.fileno() if sys.stdin else None
    pending = b""
    next_tick = 0.0
    while True:
        run_now = False
        timeout = max(0.0, next_tick - time.monotonic())
        if stdin_fd is not None:
            try:
                ready, _, _ = select.select([stdin_fd], [], [], timeout)
                data = os.read(stdin_fd, 1024) if ready else None
            except (OSError, ValueError):
                ready, data = [], b""
            if ready:
                if not data:  # EOF: keep running, stop listening
                    stdin_fd = None
                else:
                    pending = (pending + data)[-4096:]
                    *lines, pending = pending.split(b"\n")
                    for line in lines:
                        run_now = handle_line(monitor, line.decode("utf-8", "replace")) or run_now
                if not run_now and time.monotonic() < next_tick:
                    continue
        elif timeout:
            time.sleep(timeout)

        try:
            emit(monitor.snapshot(emit=emit))
        except BrokenPipeError:
            return 0
        except Exception as exc:
            try:
                emit({"error": clean(str(exc), 200)})
            except BrokenPipeError:
                return 0
        next_tick = time.monotonic() + (INTERVAL_OPEN if monitor.panel_open else INTERVAL_CLOSED)


if __name__ == "__main__":
    sys.exit(main())
