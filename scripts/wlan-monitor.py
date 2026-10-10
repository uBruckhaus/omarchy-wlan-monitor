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
state), `trust` / `untrust` (the current network).
"""
import hashlib
import ipaddress
import json
import math
import os
import pty
import random
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import sys
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

ACTIVE_NEIGH_STATES = {"REACHABLE", "DELAY", "PROBE", "PERMANENT", "NOARP"}
DEFAULT_DOMAINS = ("home.arpa", "fritz.box", "speedport.ip", "localdomain", "local", "lan", "home", "internal")
WEB_SERVICE_TYPES = {"_http._tcp": "http", "_https._tcp": "https"}
ADMIN_URL_SERVICE_TYPES = {"_ipp._tcp", "_ipps._tcp", "_printer._tcp", "_pdl-datastream._tcp", "_uscan._tcp"}
COMMANDS = {"rescan", "open", "closed", "trust", "untrust"}
TRUST_FILE = "trusted-networks.json"
MAX_TRUSTED = 64

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
        if svc_label and svc_label not in entry["names"]:
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
        if not entry["model"]:
            for key in ("md", "model", "am", "modelid", "device type"):
                if txt.get(key):
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
            if url and url not in entry["web"]:
                entry["web"].append(url)

        if stype_clean and stype_clean not in entry["services"]:
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


def load_trusted():
    """Read the trusted network list; refuses symlinks, foreign or oversized files."""
    path = os.path.join(config_dir(), TRUST_FILE)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return []
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 65536:
            return []
        data = json.loads(os.read(fd, 65536).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return []
    finally:
        os.close(fd)
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
    """Atomically write the trusted network list into a private (0700) config directory."""
    directory = config_dir()
    tmp = None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            return False
        if info.st_mode & 0o077:
            os.chmod(directory, 0o700)
        tmp = os.path.join(directory, f".{TRUST_FILE}.{os.getpid()}.{random.randrange(1 << 30)}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"networks": networks[:MAX_TRUSTED]}, handle, indent=2)
        os.replace(tmp, os.path.join(directory, TRUST_FILE))
        return True
    except OSError:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        return False


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


def parse_command(line):
    command = line.strip().lower()
    return command if command in COMMANDS else ""


# --- Device Discovery & Merging -----------------------------------------------

def choose_device_name(ip, is_self, is_gateway, dns_name, mdns_info, vendor):
    """Pick the clearest display name for a device on the WLAN."""
    if is_self:
        return clean(socket.gethostname(), 48) or "This PC"
    if mdns_info:
        for candidate in mdns_info.get("names", []):
            if candidate and not UUID_RE.match(candidate) and not BARE_MAC_RE.match(candidate):
                return candidate
        host = mdns_info.get("host", "")
        if host and not BARE_MAC_RE.match(host):
            return host
    if dns_name and not BARE_MAC_RE.match(dns_name):
        return dns_name
    if is_gateway:
        return dns_name or "Router / Gateway"
    if vendor and vendor != "Private MAC":
        return f"{vendor} device"
    if dns_name:
        return dns_name
    return ip


def devices_revision(devices):
    """Short hash that changes only when the visible device list changes."""
    return hashlib.sha1(json.dumps(devices, sort_keys=True).encode()).hexdigest()[:12]


class Monitor:
    def __init__(self):
        self.trusted = load_trusted()
        self.panel_open = False
        self.force_next = False
        self.iface_cache = {}
        self.identity = None
        self.trust_identity = {"ssid": "", "gateway_mac": ""}
        self.reset_network(None)

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
        self.web_ok = {}  # advertised web UI url -> reachable (checked once per network)
        self.iw_info = {}
        self.iw_time = -math.inf
        self.traffic_prev = None

    # -- commands from the bar widget --
    def handle(self, command):
        """Apply a stdin command; returns True when a fresh snapshot should be sent right away."""
        if command == "open":
            self.panel_open = True
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
            self.trusted = [
                entry for entry in self.trusted
                if not (entry["gateway_mac"] == ident["gateway_mac"] and entry["ssid"] == ident["ssid"])
            ]
            if command == "trust":
                self.trusted.insert(0, ident)
                self.last_full_scan = -math.inf
            self.trusted = self.trusted[:MAX_TRUSTED]
            save_trusted(self.trusted)
            return True
        return False

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
        force_scan = force_scan or self.force_next
        self.force_next = False

        net = detect_interface(self.iface_cache)
        if not net:
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
        trusted = is_trusted(self.trust_identity, self.trusted)

        # Active scans only on trusted networks, unless the user explicitly asked for one.
        since_full = now - self.last_full_scan
        do_full = force_scan or (
            trusted and (since_full >= FULL_SCAN_EVERY or (self.panel_open and since_full >= FULL_SCAN_ON_OPEN))
        )
        do_known = not do_full and trusted and self.known and now - self.last_known_scan >= KNOWN_SCAN_EVERY

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
            if not vendor and re.match(r"^(iPhone|iPad|MacBook|iMac|Mac|Apple|HomePod|AirPort)", name, re.I):
                vendor = "Apple"
            if model and model.lower() == name.lower():
                model = ""

            web_url = ""
            if is_gateway and self.gateway_web:
                web_url = make_web_url(self.gateway_web, ip, subnet=subnet_net)
            elif not is_self and online:
                for url in mdns.get("web", []):
                    if url not in self.web_ok:
                        self.web_ok[url] = url_reachable(url)
                    if self.web_ok[url]:
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
            }
            self.known[ip] = dict(dev, last_seen=last_seen)
            devices.append(dev)

        # Keep recently seen devices listed as sleeping; forget them after SLEEPING_KEEP.
        for ip, prev in list(self.known.items()):
            if ip in all_ips:
                continue
            if now - prev.get("last_seen", 0) <= SLEEPING_KEEP:
                sleeping = {k: v for k, v in prev.items() if k != "last_seen"}
                devices.append(dict(sleeping, online=False, state="sleeping"))
            else:
                del self.known[ip]
                self.last_reachable.pop(ip, None)

        def sort_key(dev):
            try:
                ip_num = int(ipaddress.IPv4Address(dev["ip"]))
            except ValueError:
                ip_num = 0
            rank = 0 if dev["is_gateway"] else (1 if dev["is_self"] else (2 if dev["online"] else (3 if dev["state"] == "idle" else 4)))
            return (rank, ip_num)

        devices.sort(key=sort_key)
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
            },
            "traffic": traffic,
            "devices": devices,
            "devices_rev": devices_revision(devices),
            "online_count": online_count,
            "idle_count": idle_count,
            "total_count": len(devices),
        }


def emit(obj):
    print(json.dumps(obj), flush=True)


def main():
    monitor = Monitor()
    if "--once" in sys.argv:
        net = detect_interface(monitor.iface_cache)
        if net:
            monitor.traffic(net["iface"], time.monotonic())
        time.sleep(0.25)
        emit(monitor.snapshot(force_scan=True))
        return 0

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
                        run_now = monitor.handle(parse_command(line.decode("utf-8", "replace"))) or run_now
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
