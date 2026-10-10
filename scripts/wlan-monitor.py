#!/usr/bin/env python3
"""Stream local WLAN status and discovered devices as one JSON line per interval (stdlib only).

Reads wireless link metrics from /proc/net/wireless, /proc/net/dev, /sys/class/net
and `iw`, then discovers devices on the local IPv4 subnet without root privileges:

- Paced unprivileged ICMP echo probes (with UDP fallback) to populate the kernel
  ARP/neighbor table (`ip -4 neigh show`).
- Paced bounded UDP reverse-DNS (PTR) queries to the local router/DNS server to
  resolve hostnames and detect sleeping DHCP leases (e.g. phones/laptops in Wi-Fi sleep).
- mDNS / Zeroconf service announcements (`avahi-browse`) for friendly names and
  device models.
- Local IEEE OUI hardware database (`/usr/lib/udev/hwdb.d/20-OUI.hwdb` or
  `/usr/share/hwdata/oui.txt`) for manufacturer identification.
"""
import ipaddress
import json
import os
import pty
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.parse

INTERVAL = float(os.environ.get("WLAN_MONITOR_INTERVAL", "3"))
SCAN_EVERY = int(os.environ.get("WLAN_MONITOR_SCAN_EVERY", "5"))  # active sweep every N snapshots (~15s)

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$",
    re.I,
)
BARE_MAC_RE = re.compile(r"^[0-9a-f]{12}$", re.I)
IP_DASH_RE = re.compile(r"^\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}$")


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
    """Run an external command with an explicit argv list and bounded output."""
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (proc.stdout or "")[:max_bytes]
    except (OSError, subprocess.SubprocessError):
        return ""


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

_last_net = {}


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
    """Convert RSSI in dBm (-90..-30) to 0..100% quality."""
    if signal_dbm is None:
        return None
    return max(0, min(100, round(2 * (signal_dbm + 100))))


def detect_interface():
    """Find the active wireless (or default route) network interface, IPv4 CIDR and gateway."""
    route_out = run_cmd(["ip", "-4", "route", "show", "default"])
    gateway = None
    route_iface = None
    for line in route_out.splitlines():
        parts = line.split()
        if "via" in parts:
            gateway = parts[parts.index("via") + 1]
        if "dev" in parts:
            route_iface = parts[parts.index("dev") + 1]
        if gateway or route_iface:
            break

    addr_out = run_cmd(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    candidates = []
    for line in addr_out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and "inet" in parts:
            iface = parts[1]
            cidr = parts[parts.index("inet") + 1]
            is_wireless = os.path.isdir(f"/sys/class/net/{iface}/wireless") or os.path.isdir(
                f"/sys/class/net/{iface}/phy80211"
            )
            candidates.append((is_wireless, iface == route_iface, iface, cidr))

    if not candidates:
        return None
    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    is_wireless, _, iface, cidr = candidates[0]
    mac = clean(read(f"/sys/class/net/{iface}/address").strip().lower(), 20)
    return {
        "iface": clean(iface, 32),
        "is_wireless": is_wireless,
        "cidr": clean(cidr, 32),
        "ip": cidr.split("/")[0],
        "prefix": int(cidr.split("/")[1]) if "/" in cidr else 24,
        "gateway": clean(gateway, 32) if gateway else None,
        "mac": mac,
    }


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


def traffic_stats(iface):
    """Compute live RX/TX bytes per second and total bytes for `iface`."""
    now = time.monotonic()
    rx_bytes = tx_bytes = 0
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        if name.strip() == iface:
            fields = rest.split()
            if len(fields) >= 9:
                rx_bytes = int(fields[0])
                tx_bytes = int(fields[8])
            break
    prev = _last_net.get(iface)
    rx_rate = tx_rate = None
    if prev and now > prev[0]:
        dt = now - prev[0]
        rx_rate = max(0.0, (rx_bytes - prev[1]) / dt)
        tx_rate = max(0.0, (tx_bytes - prev[2]) / dt)
    _last_net[iface] = (now, rx_bytes, tx_bytes)
    return {
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_rate": round(rx_rate, 1) if rx_rate is not None else None,
        "tx_rate": round(tx_rate, 1) if tx_rate is not None else None,
    }


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


def select_best_hostname(raw_names):
    """Choose the cleanest short hostname from a list of PTR FQDNs."""
    best = ""
    fallback = ""
    for fqdn in raw_names:
        short = re.sub(r"\.(fritz\.box|local|lan|home|arpa)\.?$", "", fqdn, flags=re.I)
        if short.lower() == "fritz.box" or fqdn.lower() == "fritz.box":
            best = "fritz.box"
            break
        if UUID_RE.match(short) or IP_DASH_RE.match(short):
            continue
        if BARE_MAC_RE.match(short):
            fallback = fallback or short
            continue
        if not best or (len(short) < len(best) and not short.startswith(best)):
            best = short
    return clean(best or fallback, 64)


_dns_cache = {}  # ip -> (monotonic_time, hostname)


def sweep_subnet(hosts, gateway, extra_ips=()):
    """Paced ICMP neighbor probe + router reverse-DNS PTR sweep across the subnet."""
    targets = list(dict.fromkeys(list(hosts) + list(extra_ips)))
    if not targets:
        return {}

    now = time.monotonic()
    icmp_sock = None
    try:
        icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
        icmp_payload = struct.pack("!BBHHH", 8, 0, 0, 0, 1) + b"wlanmon"
        icmp_port = 0
    except OSError:
        try:
            icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            icmp_payload = b""
            icmp_port = 33434
        except OSError:
            icmp_sock = None

    dns_sock = None
    dns_server = gateway or "127.0.0.53"
    qid_to_ip = {}
    ptr_found = {}
    try:
        dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_sock.setblocking(False)
    except OSError:
        dns_sock = None

    def drain_dns():
        if not dns_sock:
            return
        while True:
            try:
                data, _ = dns_sock.recvfrom(512)
                qid, names = parse_dns_ptr_packet(data)
                ip = qid_to_ip.get(qid)
                if ip and names:
                    hostname = select_best_hostname(names)
                    if hostname:
                        ptr_found[ip] = hostname
                        _dns_cache[ip] = (now, hostname)
            except BlockingIOError:
                break
            except OSError:
                break

    try:
        if icmp_sock:
            icmp_sock.setblocking(False)
        for idx, ip in enumerate(targets, start=1):
            if icmp_sock:
                try:
                    icmp_sock.sendto(icmp_payload, (ip, icmp_port))
                except OSError:
                    pass
            if dns_sock:
                qid = idx & 0xFFFF
                qid_to_ip[qid] = ip
                try:
                    dns_sock.sendto(build_dns_ptr_packet(qid, ip), (dns_server, 53))
                except OSError:
                    pass
            if idx % 6 == 0:
                time.sleep(0.007)
                drain_dns()
        time.sleep(0.22)
        drain_dns()
    finally:
        if icmp_sock:
            icmp_sock.close()
        if dns_sock:
            dns_sock.close()

    return ptr_found


def best_dns_hostname(ip, gateway):
    """Resolve IP to its cleanest reverse-DNS hostname, using cache or single UDP PTR."""
    now = time.monotonic()
    cached = _dns_cache.get(ip)
    if cached and (now - cached[0]) < 60.0:
        return cached[1]
    for server in (gateway, "127.0.0.53"):
        if not server:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.1)
                sock.sendto(build_dns_ptr_packet(1, ip), (server, 53))
                data, _ = sock.recvfrom(512)
                _, names = parse_dns_ptr_packet(data)
                if names:
                    host = select_best_hostname(names)
                    _dns_cache[ip] = (now, host)
                    return host
        except OSError:
            continue
    _dns_cache[ip] = (now, "")
    return ""


def read_neighbors(iface):
    """Parse `ip -4 neigh show dev <iface>` for resolved MAC addresses and states."""
    out = run_cmd(["ip", "-4", "neigh", "show", "dev", iface])
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
        mac = ""
        if "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                mac = parts[idx + 1].lower()
        state = parts[-1].upper() if parts else ""
        if mac:
            neighbors[ip] = {"mac": clean(mac, 20), "state": clean(state, 20)}
    return neighbors


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


_mdns_cache = {"time": 0.0, "hosts": {}}


def query_mdns(iface, subnet_net, force=False):
    """Collect mDNS hostnames, friendly names, models and MAC hints via avahi-browse."""
    now = time.monotonic()
    if not force and _mdns_cache["hosts"] and (now - _mdns_cache["time"]) < 15.0:
        return _mdns_cache["hosts"]
    if not shutil.which("avahi-browse"):
        return _mdns_cache["hosts"]

    hosts = {}
    master = slave = None
    proc = None
    lines = []
    try:
        master, slave = pty.openpty()
        proc = subprocess.Popen(
            ["avahi-browse", "-a", "-r", "-p"],
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
        if slave is not None:
            try:
                os.close(slave)
            except OSError:
                pass
        if master is not None:
            try:
                os.close(master)
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

    for line in lines:
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 9:
            continue
        _, line_iface, proto, raw_service, stype, _domain, raw_host, address, _port = parts[:9]
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
            {"names": [], "host": "", "model": "", "mac": "", "services": []},
        )
        host_clean = clean(raw_host.removesuffix(".local"), 64)
        if host_clean and not UUID_RE.match(host_clean) and not IP_DASH_RE.match(host_clean):
            if not entry["host"] or BARE_MAC_RE.match(entry["host"]):
                entry["host"] = host_clean

        svc_label = friendly_mdns_label(raw_service)
        if svc_label and svc_label not in entry["names"]:
            entry["names"].append(svc_label)

        txt_field = ";".join(parts[9:])
        for key, val in re.findall(r'"([^"=]+)=([^"]*)"', txt_field):
            k = key.strip().lower()
            v = unescape_avahi(val)
            if not v:
                continue
            if k in ("fn", "name") and not UUID_RE.match(v):
                if v not in entry["names"]:
                    entry["names"].insert(0, v)
            elif k in ("md", "model", "am", "modelid", "device type") and not entry["model"]:
                entry["model"] = clean(v, 48)
            elif k in ("deviceid", "bs") and not entry["mac"]:
                if re.fullmatch(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", v):
                    entry["mac"] = v.lower()

        stype_clean = clean(stype, 32)
        if stype_clean and stype_clean not in entry["services"]:
            entry["services"].append(stype_clean)

    _mdns_cache["time"] = now
    _mdns_cache["hosts"] = hosts
    return hosts


# --- Device Discovery & Merging -----------------------------------------------

_tick = 0
_known_devices = {}  # ip -> device dict with last_seen timestamp
_ptr_leases = {}     # ip -> hostname discovered from router DNS PTR sweep


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


def snapshot(force_scan=False):
    global _tick, _ptr_leases
    _tick += 1
    now = time.monotonic()

    net = detect_interface()
    if not net:
        return {
            "time": int(time.time()),
            "active": False,
            "scanning": False,
            "link": None,
            "traffic": None,
            "devices": [],
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

    do_scan = force_scan or (_tick == 1) or (_tick % SCAN_EVERY == 0)
    mdns_map = query_mdns(iface, subnet_net, force=do_scan)
    if do_scan:
        hosts = subnet_hosts(local_ip, net["prefix"])
        swept = sweep_subnet(hosts, gateway_ip, extra_ips=mdns_map.keys())
        if swept:
            _ptr_leases = swept

    neighbors = read_neighbors(iface)
    wlan = wireless_details(iface) if net["is_wireless"] else {}
    traffic = traffic_stats(iface)

    # Candidate IPs: self, gateway, ARP neighbors, mDNS services, and router DHCP DNS leases
    all_ips = set(neighbors.keys()) | set(mdns_map.keys()) | set(_ptr_leases.keys())
    if local_ip:
        all_ips.add(local_ip)
    if gateway_ip:
        all_ips.add(gateway_ip)

    devices = []
    for ip in all_ips:
        is_self = ip == local_ip
        is_gateway = ip == gateway_ip
        neigh = neighbors.get(ip, {})
        mdns = mdns_map.get(ip, {})
        prev = _known_devices.get(ip, {})

        mac = (
            (net["mac"] if is_self else "")
            or neigh.get("mac")
            or mdns.get("mac")
            or prev.get("mac")
            or ""
        )
        vendor = lookup_vendor(mac) or prev.get("vendor") or ""
        dns_name = (
            clean(socket.gethostname(), 48)
            if is_self
            else _ptr_leases.get(ip) or best_dns_hostname(ip, gateway_ip) or prev.get("hostname") or ""
        )
        model = mdns.get("model") or prev.get("model") or ""
        if is_gateway and wlan.get("ssid") and not model:
            model = wlan["ssid"]

        online = bool(is_self or is_gateway or neigh.get("mac"))
        if online:
            last_seen = now
            state = "this PC" if is_self else ("router" if is_gateway else "online")
        else:
            last_seen = prev.get("last_seen", now)
            state = "sleeping"

        name = choose_device_name(ip, is_self, is_gateway, dns_name, mdns, vendor)
        if not vendor and re.match(r"^(iPhone|iPad|MacBook|iMac|Mac|Apple|HomePod|AirPort)", name, re.I):
            vendor = "Apple"
        if model and model.lower() == name.lower():
            model = ""

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
            "last_seen": last_seen,
        }
        _known_devices[ip] = dev
        devices.append(dev)

    # Keep recently-seen devices (within 10 minutes) in the list marked as sleeping
    for ip, prev in list(_known_devices.items()):
        if ip not in all_ips:
            if (now - prev.get("last_seen", 0)) <= 600:
                sleeping_copy = dict(prev, online=False, state="sleeping")
                devices.append(sleeping_copy)
            else:
                del _known_devices[ip]

    def sort_key(dev):
        try:
            ip_num = int(ipaddress.IPv4Address(dev["ip"]))
        except ValueError:
            ip_num = 0
        rank = 0 if dev["is_gateway"] else (1 if dev["is_self"] else (2 if dev["online"] else 3))
        return (rank, ip_num)

    devices.sort(key=sort_key)
    online_count = sum(1 for d in devices if d["online"])

    return {
        "time": int(time.time()),
        "active": True,
        "scanning": do_scan,
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
        },
        "traffic": traffic,
        "devices": devices,
        "online_count": online_count,
        "total_count": len(devices),
    }


def main():
    once = "--once" in sys.argv
    net = detect_interface()
    if net:
        traffic_stats(net["iface"])
    if once:
        time.sleep(0.25)
        print(json.dumps(snapshot(force_scan=True)), flush=True)
        return 0

    while True:
        try:
            print(json.dumps(snapshot()), flush=True)
        except BrokenPipeError:
            return 0
        except Exception as exc:
            print(json.dumps({"error": clean(str(exc), 200)}), flush=True)
        time.sleep(INTERVAL)


if __name__ == "__main__":
    sys.exit(main())
