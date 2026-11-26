#!/usr/bin/env python3
"""Live Network Monitor telemetry for Maprisma WLAN Monitor (Python 3 stdlib only, zero root).

Collects active TCP/UDP connections, listening ports, per-process traffic and connection
counts, per-interface statistics, DNS servers, and a rolling 30-sample throughput history.
Primary socket source is `ss -tunapi`, with a pure `/proc/net/*` + `/proc/<pid>/fd` fallback.
"""

from collections import deque
import ipaddress
import os
import re
import select
import shutil
import socket
import struct
import subprocess
import threading
import time


SS_TIMEOUT = 1.5
SS_MAX_BYTES = 512 * 1024  # 512 KiB
IP_TIMEOUT = 1.5
IP_MAX_BYTES = 128 * 1024
HISTORY_MAX = 30
RDNS_CACHE_MAX = 512
RDNS_TTL = 600.0
RDNS_NEGATIVE_TTL = 120.0
RDNS_QUEUE_MAX = 64
MAX_CONNECTIONS = 500   # rows sent per snapshot (the summary still counts all)
MAX_PROCESSES = 128

WELL_KNOWN_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    548: "AFP",
    587: "SMTP",
    631: "IPP",
    636: "LDAPS",
    853: "DoT",
    993: "IMAPS",
    995: "POP3S",
    1194: "OpenVPN",
    1433: "MSSQL",
    1883: "MQTT",
    1900: "SSDP",
    2049: "NFS",
    3000: "HTTP-Dev",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP",
    5353: "mDNS",
    5355: "LLMNR",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    6379: "Redis",
    6443: "K8s-API",
    8000: "HTTP-Alt",
    8008: "Cast",
    8009: "Cast",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8883: "MQTTS",
    9000: "HTTP-Alt",
    9090: "Prometheus",
    9200: "Elasticsearch",
    27017: "MongoDB",
    51820: "WireGuard",
}

STATE_MAP = {
    "ESTAB": "ESTABLISHED",
    "ESTABLISHED": "ESTABLISHED",
    "LISTEN": "LISTEN",
    "TIME-WAIT": "TIME_WAIT",
    "TIME_WAIT": "TIME_WAIT",
    "CLOSE-WAIT": "CLOSE_WAIT",
    "CLOSE_WAIT": "CLOSE_WAIT",
    "FIN-WAIT-1": "FIN_WAIT_1",
    "FIN_WAIT_1": "FIN_WAIT_1",
    "FIN-WAIT-2": "FIN_WAIT_2",
    "FIN_WAIT_2": "FIN_WAIT_2",
    "SYN-SENT": "SYN_SENT",
    "SYN_SENT": "SYN_SENT",
    "SYN-RECV": "SYN_RECV",
    "SYN_RECV": "SYN_RECV",
    "LAST-ACK": "LAST_ACK",
    "LAST_ACK": "LAST_ACK",
    "CLOSING": "CLOSING",
    "CLOSE": "CLOSE",
    "UNCONN": "UNCONN",
}

PROC_TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT_1",
    "05": "FIN_WAIT_2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

VPN_PREFIXES = (
    "nordlynx",
    "nordtun",
    "tailscale",
    "proton",
    "pvpn",
    "wg",
    "mullvad",
    "zt",
    "tun",
    "tap",
    "ppp",
    "ipsec",
    "vti",
)
VPN_LINK_TYPES = {"65534", "512"}

_USER_RE = re.compile(r'\("([^"]*)",pid=(\d+),fd=\d+\)')
_RTT_RE = re.compile(r"\brtt:(\d+(?:\.\d+)?)/")
_BYTES_SENT_RE = re.compile(r"\bbytes_sent:(\d+)")
_BYTES_ACKED_RE = re.compile(r"\bbytes_acked:(\d+)")
_BYTES_RECV_RE = re.compile(r"\bbytes_received:(\d+)")
_SOCKET_INODE_RE = re.compile(r"^socket:\[(\d+)\]$")


def clean(text, limit=120):
    """Sanitize strings so UI/JSON consumers never see markup or control chars."""
    text = "".join(ch for ch in str(text or "") if ch.isprintable() and ch not in "<>&")
    return text.strip()[:limit]


def _read_text(path, default="", max_bytes=131072):
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(max_bytes)
    except OSError:
        return default


def run_cmd(argv, timeout=SS_TIMEOUT, max_bytes=SS_MAX_BYTES):
    """Run an external command (argv list, no shell) with bounded time and output."""
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
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


def normalize_state(state):
    raw = str(state or "").strip().upper()
    if raw in STATE_MAP:
        return STATE_MAP[raw]
    return clean(raw.replace("-", "_"), 24)


def identify_service(port, protocol="tcp"):
    """Return well-known service name for a port/protocol, or ''."""
    if not port:
        return ""
    if port == 443 and str(protocol or "").startswith("udp"):
        return "QUIC"
    return WELL_KNOWN_SERVICES.get(int(port), "")


def classify_scope(ip_str):
    """Classify an IP address into 'loopback', 'lan', or 'external'."""
    raw = str(ip_str or "").strip()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    if "%" in raw:
        raw = raw.split("%", 1)[0]
    if not raw or raw in ("*", "0.0.0.0", "::"):
        return "loopback"
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return "loopback"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if addr.is_loopback or addr.is_unspecified:
        return "loopback"
    if addr.is_private or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return "lan"
    return "external"


def parse_addr_port(token):
    """Parse an `ss` address:port token into (ip, port_int, is_ipv6).

    Handles IPv4, bracketed IPv6 `[::1]:443`, interface scopes `192.168.1.2%wlan0:68`
    or `[fe80::1%wlan0]:5353`, wildcards `*:*` / `0.0.0.0:*` / `[::]:*`, and unbracketed IPv6.
    """
    raw = str(token or "").strip()
    if not raw:
        return "", 0, False

    ip_part = ""
    port_part = ""
    is_v6 = False

    if raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            ip_part = raw[1:end]
            rest = raw[end + 1 :]
            if "%" in rest and ":" in rest:
                # e.g. [::1]%lo:53
                rest = rest[rest.rfind(":") :]
            if rest.startswith(":"):
                port_part = rest[1:]
            is_v6 = True
        else:
            ip_part = raw
    else:
        idx = raw.rfind(":")
        if idx != -1:
            ip_part = raw[:idx]
            port_part = raw[idx + 1 :]
        else:
            ip_part = raw

    if "%" in ip_part:
        ip_part = ip_part.split("%", 1)[0]

    if ip_part in ("*", ""):
        ip_clean = "*" if ip_part == "*" else ""
    else:
        if ":" in ip_part:
            is_v6 = True
        # Normalize valid IPs (and unwrap IPv4-mapped IPv6? Keep canonical representation)
        try:
            addr = ipaddress.ip_address(ip_part)
            ip_clean = str(addr)
            is_v6 = isinstance(addr, ipaddress.IPv6Address)
        except ValueError:
            ip_clean = clean(ip_part, 64)

    port = 0
    if port_part and port_part != "*":
        try:
            p = int(port_part)
            if 0 <= p <= 65535:
                port = p
        except ValueError:
            port = 0

    return ip_clean, port, is_v6


def own_process(pid, proc_root="/proc"):
    """True only for a process of this user (another account's command line is never shown)."""
    try:
        return os.stat(os.path.join(proc_root, str(pid))).st_uid == os.getuid()
    except OSError:
        return False


def read_cmdline(pid, proc_root="/proc"):
    """Read and sanitize /proc/<pid>/cmdline of one of this user's processes, truncated to 160
    chars. The owner is checked before and after the read, so a PID reused meanwhile by another
    account's process is never read."""
    if not isinstance(pid, int) or pid <= 0:
        return ""
    if not own_process(pid, proc_root):
        return ""
    try:
        with open(os.path.join(proc_root, str(pid), "cmdline"), "rb") as handle:
            raw = handle.read(4096)
    except OSError:
        return ""
    if not own_process(pid, proc_root):
        return ""
    if not raw:
        return ""
    text = raw.replace(b"\x00", b" ").decode("utf-8", "replace")
    return clean(" ".join(text.split()), 160)


def parse_ss_output(text, cmdline_reader=read_cmdline):
    """Parse `ss -tunapi` stdout into a list of raw connection dicts."""
    connections = []
    cmdline_cache = {}

    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if line.startswith("Netid"):
            continue
        if line[0] in (" ", "\t"):
            # Extended TCP info line attached to previous socket
            if not connections:
                continue
            conn = connections[-1]
            m_rtt = _RTT_RE.search(line)
            if m_rtt:
                try:
                    conn["rtt_ms"] = round(float(m_rtt.group(1)), 2)
                except ValueError:
                    pass
            sent = 0
            acked = 0
            m_sent = _BYTES_SENT_RE.search(line)
            if m_sent:
                sent = int(m_sent.group(1))
            m_acked = _BYTES_ACKED_RE.search(line)
            if m_acked:
                acked = int(m_acked.group(1))
            if sent or acked:
                conn["tx_bytes"] = max(sent, acked)
            m_recv = _BYTES_RECV_RE.search(line)
            if m_recv:
                conn["rx_bytes"] = int(m_recv.group(1))
            continue

        parts = line.split(None, 6)
        if len(parts) < 6:
            continue
        netid = parts[0].lower()
        if netid not in ("tcp", "udp"):
            continue
        state = normalize_state(parts[1])
        local_ip, local_port, local_v6 = parse_addr_port(parts[4])
        remote_ip, remote_port, remote_v6 = parse_addr_port(parts[5])
        is_v6 = local_v6 or remote_v6
        proto = ("tcp6" if is_v6 else "tcp") if netid == "tcp" else ("udp6" if is_v6 else "udp")

        process = ""
        pid = None
        cmdline = ""
        if len(parts) >= 7:
            m_user = _USER_RE.search(parts[6])
            if m_user:
                process = clean(m_user.group(1), 64)
                try:
                    pid = int(m_user.group(2))
                except ValueError:
                    pid = None
                if pid is not None and cmdline_reader is not None:
                    if pid not in cmdline_cache:
                        cmdline_cache[pid] = cmdline_reader(pid)
                    cmdline = cmdline_cache[pid]

        is_listening = state in ("LISTEN", "UNCONN") and (not remote_port or remote_ip in ("", "*", "0.0.0.0", "::"))
        service_port = local_port if is_listening else (remote_port or local_port)
        scope_ip = local_ip if (is_listening and local_ip not in ("", "*", "0.0.0.0", "::")) else remote_ip

        connections.append(
            {
                "id": f"{proto}:{local_ip}:{local_port}->{remote_ip}:{remote_port}",
                "proto": proto,
                "protocol": proto,
                "state": state,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "remote_host": "",
                "scope": classify_scope(scope_ip),
                "service": identify_service(service_port, proto),
                "process": process,
                "pid": pid,
                "cmdline": cmdline,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_rate": 0.0,
                "tx_rate": 0.0,
                "rtt_ms": None,
            }
        )
    return connections


def _decode_proc_ip(hex_ip, is_v6):
    try:
        if not is_v6:
            if len(hex_ip) != 8:
                return ""
            packed = struct.pack("<I", int(hex_ip, 16))
            return socket.inet_ntop(socket.AF_INET, packed)
        if len(hex_ip) != 32:
            return ""
        packed = b"".join(struct.pack("<I", int(hex_ip[i : i + 8], 16)) for i in range(0, 32, 8))
        return socket.inet_ntop(socket.AF_INET6, packed)
    except (ValueError, OSError):
        return ""


def build_inode_pid_map(proc_root="/proc"):
    """Map socket inode (str) -> (process_name, pid) by scanning /proc/<pid>/fd."""
    mapping = {}
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return mapping
    for entry in entries:
        if not entry.isdigit():
            continue
        pid = int(entry)
        if not own_process(pid, proc_root):
            continue
        fd_dir = os.path.join(proc_root, entry, "fd")
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        comm = None
        for fd_name in fds:
            try:
                target = os.readlink(os.path.join(fd_dir, fd_name))
            except OSError:
                continue
            m = _SOCKET_INODE_RE.match(target)
            if not m:
                continue
            inode = m.group(1)
            if comm is None:
                comm = clean(_read_text(os.path.join(proc_root, entry, "comm"), "", 128), 64)
            mapping[inode] = (comm, pid)
    return mapping


def parse_proc_net(text, proto, inode_map=None, cmdline_reader=read_cmdline, proc_root="/proc"):
    """Parse one /proc/net/{tcp,tcp6,udp,udp6} file into connection dicts."""
    is_v6 = proto.endswith("6")
    is_udp = proto.startswith("udp")
    inode_map = inode_map or {}
    cmdline_cache = {}
    connections = []

    for line in (text or "").splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        local_hex, _, local_port_hex = fields[1].partition(":")
        remote_hex, _, remote_port_hex = fields[2].partition(":")
        state_hex = fields[3].upper()
        inode = fields[9]

        local_ip = _decode_proc_ip(local_hex, is_v6)
        remote_ip = _decode_proc_ip(remote_hex, is_v6)
        try:
            local_port = int(local_port_hex, 16)
            remote_port = int(remote_port_hex, 16)
        except ValueError:
            continue

        if is_udp:
            state = "ESTABLISHED" if state_hex == "01" else "UNCONN"
        else:
            state = PROC_TCP_STATES.get(state_hex, "CLOSE")

        process = ""
        pid = None
        cmdline = ""
        if inode in inode_map:
            process, pid = inode_map[inode]
            if pid is not None and cmdline_reader is not None:
                if pid not in cmdline_cache:
                    cmdline_cache[pid] = cmdline_reader(pid, proc_root) if cmdline_reader is read_cmdline else cmdline_reader(pid)
                cmdline = cmdline_cache[pid]

        is_listening = state in ("LISTEN", "UNCONN") and (not remote_port or remote_ip in ("", "0.0.0.0", "::"))
        service_port = local_port if is_listening else (remote_port or local_port)
        scope_ip = local_ip if (is_listening and local_ip not in ("", "0.0.0.0", "::")) else remote_ip

        connections.append(
            {
                "id": f"{proto}:{local_ip}:{local_port}->{remote_ip}:{remote_port}",
                "proto": proto,
                "protocol": proto,
                "state": state,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "remote_host": "",
                "scope": classify_scope(scope_ip),
                "service": identify_service(service_port, proto),
                "process": clean(process, 64),
                "pid": pid,
                "cmdline": cmdline,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_rate": 0.0,
                "tx_rate": 0.0,
                "rtt_ms": None,
            }
        )
    return connections


def collect_proc_connections(proc_root="/proc", cmdline_reader=read_cmdline):
    """Fallback connection collector using /proc/net/{tcp,tcp6,udp,udp6} + /proc/<pid>/fd."""
    inode_map = build_inode_pid_map(proc_root)
    out = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        text = _read_text(os.path.join(proc_root, "net", proto), "", 512 * 1024)
        if text:
            out.extend(parse_proc_net(text, proto, inode_map, cmdline_reader=cmdline_reader, proc_root=proc_root))
    return out


def parse_proc_net_dev(text):
    """Parse /proc/net/dev into {iface: {rx_bytes, rx_errors, rx_dropped, tx_bytes, tx_errors, tx_dropped}}."""
    stats = {}
    for line in (text or "").splitlines()[2:]:
        name, sep, rest = line.partition(":")
        if not sep:
            continue
        iface = clean(name.strip(), 32)
        if not iface:
            continue
        fields = rest.split()
        if len(fields) < 12:
            continue
        try:
            stats[iface] = {
                "rx_bytes": int(fields[0]),
                "rx_errors": int(fields[2]),
                "rx_dropped": int(fields[3]),
                "tx_bytes": int(fields[8]),
                "tx_errors": int(fields[10]),
                "tx_dropped": int(fields[11]),
            }
        except ValueError:
            continue
    return stats


def parse_ip_addr_output(text):
    """Parse `ip -o addr show` into {iface: {'ip': ipv4, 'ipv6': ipv6}}."""
    addrs = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        iface = clean(parts[1], 32)
        family = parts[2]
        if family not in ("inet", "inet6"):
            continue
        cidr = parts[3]
        ip_str = cidr.split("/", 1)[0]
        entry = addrs.setdefault(iface, {"ip": "", "ipv6": ""})
        if family == "inet":
            if not entry["ip"]:
                entry["ip"] = clean(ip_str, 48)
        else:
            # Prefer non-link-local IPv6 over fe80::
            try:
                v6 = ipaddress.IPv6Address(ip_str)
                is_ll = v6.is_link_local
            except ValueError:
                is_ll = ip_str.lower().startswith("fe80:")
            if not entry["ipv6"] or (entry["ipv6"].lower().startswith("fe80:") and not is_ll):
                entry["ipv6"] = clean(ip_str, 64)
    return addrs


def classify_interface_kind(name, sys_net="/sys/class/net"):
    """Classify an interface as 'wifi', 'ethernet', 'vpn', 'loopback', or 'other'."""
    if name == "lo":
        return "loopback"
    base = os.path.join(sys_net, name)
    link_type = _read_text(os.path.join(base, "type"), "", 32).strip()
    if link_type == "772":
        return "loopback"
    if os.path.isdir(os.path.join(base, "wireless")) or os.path.isdir(os.path.join(base, "phy80211")):
        return "wifi"
    if name.startswith("wl"):
        return "wifi"
    if link_type in VPN_LINK_TYPES or any(name.startswith(p) for p in VPN_PREFIXES):
        return "vpn"
    if name.startswith(("docker", "br-", "virbr", "veth", "cni", "flannel", "podman")):
        return "other"
    if link_type == "1" and (name.startswith(("en", "eth")) or os.path.exists(os.path.join(base, "device"))):
        return "ethernet"
    return "other"


def read_dns_servers(path="/etc/resolv.conf"):
    """Read deduplicated nameserver IPs from /etc/resolv.conf."""
    servers = []
    for line in _read_text(path, "", 32768).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            cand = parts[1].split("%", 1)[0]
            try:
                ip_norm = str(ipaddress.ip_address(cand))
            except ValueError:
                continue
            if ip_norm not in servers:
                servers.append(ip_norm)
    return servers


def filter_connections(
    connections,
    protocol=None,
    state=None,
    scope=None,
    process=None,
    port=None,
    search=None,
    sort_by=None,
):
    """Filter and sort connection dicts (shared by NetMonitor and MCP server)."""
    out = list(connections or [])

    if protocol:
        p = str(protocol).strip().lower()
        if p not in ("", "all"):
            if p == "tcp":
                out = [c for c in out if c.get("protocol") in ("tcp", "tcp6")]
            elif p == "udp":
                out = [c for c in out if c.get("protocol") in ("udp", "udp6")]
            else:
                out = [c for c in out if c.get("protocol") == p]

    if state:
        s = normalize_state(state)
        if s and s != "ALL":
            out = [c for c in out if c.get("state") == s]

    if scope:
        sc = str(scope).strip().lower()
        if sc not in ("", "all"):
            out = [c for c in out if c.get("scope") == sc]

    if process:
        proc_q = str(process).strip().lower()
        if proc_q:
            out = [
                c
                for c in out
                if proc_q in (c.get("process") or "").lower()
                or proc_q in (c.get("cmdline") or "").lower()
            ]

    if port is not None and port != "":
        try:
            pnum = int(port)
        except (TypeError, ValueError):
            pnum = None
        if pnum is not None:
            out = [c for c in out if c.get("local_port") == pnum or c.get("remote_port") == pnum]

    if search:
        q = str(search).strip().lower()
        if q:
            filtered = []
            for c in out:
                haystack = " ".join(
                    (
                        str(c.get("process") or ""),
                        str(c.get("cmdline") or ""),
                        str(c.get("local_ip") or ""),
                        str(c.get("remote_ip") or ""),
                        str(c.get("remote_host") or ""),
                        str(c.get("service") or ""),
                        str(c.get("state") or ""),
                        str(c.get("protocol") or ""),
                        str(c.get("local_port") or ""),
                        str(c.get("remote_port") or ""),
                    )
                ).lower()
                if q in haystack:
                    filtered.append(c)
            out = filtered

    mode = str(sort_by or "rate").strip().lower()
    if mode == "bytes":
        out.sort(
            key=lambda c: (
                -(int(c.get("rx_bytes") or 0) + int(c.get("tx_bytes") or 0)),
                -(float(c.get("rx_rate") or 0.0) + float(c.get("tx_rate") or 0.0)),
                (c.get("process") or "").lower(),
            )
        )
    elif mode == "process":
        out.sort(
            key=lambda c: (
                (c.get("process") or "zzz").lower(),
                -(float(c.get("rx_rate") or 0.0) + float(c.get("tx_rate") or 0.0)),
                c.get("remote_ip") or "",
            )
        )
    elif mode == "remote":
        out.sort(key=lambda c: (c.get("remote_ip") or "", int(c.get("remote_port") or 0)))
    elif mode == "state":
        out.sort(key=lambda c: (c.get("state") or "", (c.get("process") or "").lower()))
    elif mode == "port":
        out.sort(key=lambda c: (int(c.get("remote_port") or c.get("local_port") or 0), c.get("protocol") or ""))
    elif mode == "rtt":
        out.sort(key=lambda c: (c.get("rtt_ms") is None, -(float(c.get("rtt_ms") or 0.0))))
    else:  # "rate" (default)
        out.sort(
            key=lambda c: (
                -(float(c.get("rx_rate") or 0.0) + float(c.get("tx_rate") or 0.0)),
                -(int(c.get("rx_bytes") or 0) + int(c.get("tx_bytes") or 0)),
                0 if c.get("state") == "ESTABLISHED" else 1,
                (c.get("process") or "zzz").lower(),
            )
        )
    return out


class NetMonitor:
    """Stateful network telemetry collector with delta rates, history, and async reverse-DNS."""

    def __init__(self, proc_root="/proc", sys_net="/sys/class/net", resolv_path="/etc/resolv.conf"):
        self.proc_root = proc_root
        self.sys_net = sys_net
        self.resolv_path = resolv_path
        self._prev_sock_bytes = {}  # key -> (rx_bytes, tx_bytes)
        self._prev_sock_time = None
        self._prev_iface_bytes = {}  # iface -> (rx_bytes, tx_bytes)
        self._prev_iface_time = None
        self.history = deque(maxlen=HISTORY_MAX)
        self._rdns_lock = threading.Lock()
        self._rdns_cache = {}  # ip -> (expires_monotonic, hostname)
        self._rdns_pending = set()

    # -- bounded non-blocking reverse DNS

    def _lookup_rdns_cached(self, ip_str, now):
        try:
            ip_str = str(ipaddress.ip_address(ip_str))  # only real IP literals are looked up
        except ValueError:
            return ""
        if ip_str in ("0.0.0.0", "::") or classify_scope(ip_str) == "loopback":
            return ""
        with self._rdns_lock:
            entry = self._rdns_cache.get(ip_str)
            if entry is not None and entry[0] > now:
                return entry[1]
            if ip_str in self._rdns_pending or len(self._rdns_pending) >= RDNS_QUEUE_MAX:
                return entry[1] if entry is not None else ""
            self._rdns_pending.add(ip_str)

        try:
            threading.Thread(target=self._rdns_worker, args=(ip_str,), daemon=True).start()
        except RuntimeError:  # no thread available: the slot is freed, nothing is looked up
            with self._rdns_lock:
                self._rdns_pending.discard(ip_str)
        return ""

    def _rdns_worker(self, ip_str):
        host = ""
        try:
            name, _, _ = socket.gethostbyaddr(ip_str)
            host = clean(name, 80)
        except Exception:  # any failure is a negative answer; the slot is always freed below
            host = ""
        now = time.monotonic()
        ttl = RDNS_TTL if host else RDNS_NEGATIVE_TTL
        with self._rdns_lock:
            self._rdns_pending.discard(ip_str)
            if len(self._rdns_cache) >= RDNS_CACHE_MAX:
                # Evict expired entries first, then oldest
                expired = [k for k, v in self._rdns_cache.items() if v[0] <= now]
                for k in expired:
                    self._rdns_cache.pop(k, None)
                if len(self._rdns_cache) >= RDNS_CACHE_MAX:
                    oldest = min(self._rdns_cache, key=lambda k: self._rdns_cache[k][0])
                    self._rdns_cache.pop(oldest, None)
            self._rdns_cache[ip_str] = (now + ttl, host)

    # -- socket & interface collection

    def _collect_raw_connections(self):
        if shutil.which("ss"):
            out = run_cmd(["ss", "-tunapi"], timeout=SS_TIMEOUT, max_bytes=SS_MAX_BYTES)
            if out and ("Netid" in out or "tcp" in out or "udp" in out):
                return parse_ss_output(out)
        return collect_proc_connections(self.proc_root)

    def collect_interfaces(self, now=None):
        now = time.monotonic() if now is None else now
        dev_text = _read_text(os.path.join(self.proc_root, "net", "dev"), "", 131072)
        dev_stats = parse_proc_net_dev(dev_text)
        ip_out = run_cmd(["ip", "-o", "addr", "show"], timeout=IP_TIMEOUT, max_bytes=IP_MAX_BYTES) if shutil.which("ip") else ""
        addr_map = parse_ip_addr_output(ip_out)

        dt = (now - self._prev_iface_time) if (self._prev_iface_time is not None and now > self._prev_iface_time) else None
        new_prev = {}
        interfaces = []

        for name in sorted(dev_stats):
            st = dev_stats[name]
            base = os.path.join(self.sys_net, name)
            kind = classify_interface_kind(name, self.sys_net)
            oper = _read_text(os.path.join(base, "operstate"), "", 32).strip().lower()
            try:
                flags = int(_read_text(os.path.join(base, "flags"), "0", 32).strip() or "0", 16)
            except ValueError:
                flags = 0
            mac = clean(_read_text(os.path.join(base, "address"), "", 32).strip().lower(), 20)
            if mac == "00:00:00:00:00:00":
                mac = ""
            addr_info = addr_map.get(name, {"ip": "", "ipv6": ""})
            is_up = oper == "up" or (oper in ("unknown", "") and bool(flags & 0x1) and (name == "lo" or kind == "vpn" or bool(addr_info["ip"] or addr_info["ipv6"])))

            rx_bytes = st["rx_bytes"]
            tx_bytes = st["tx_bytes"]
            rx_rate = 0.0
            tx_rate = 0.0
            if dt and name in self._prev_iface_bytes:
                prx, ptx = self._prev_iface_bytes[name]
                rx_rate = round(max(0.0, (rx_bytes - prx) / dt), 1)
                tx_rate = round(max(0.0, (tx_bytes - ptx) / dt), 1)
            new_prev[name] = (rx_bytes, tx_bytes)

            interfaces.append(
                {
                    "name": name,
                    "kind": kind,
                    "state": "up" if is_up else "down",
                    "ip": addr_info["ip"],
                    "ipv6": addr_info["ipv6"],
                    "mac": mac,
                    "rx_bytes": rx_bytes,
                    "tx_bytes": tx_bytes,
                    "rx_rate": rx_rate,
                    "tx_rate": tx_rate,
                    "rx_errors": st["rx_errors"],
                    "tx_errors": st["tx_errors"],
                    "rx_dropped": st["rx_dropped"],
                    "tx_dropped": st["tx_dropped"],
                }
            )

        self._prev_iface_bytes = new_prev
        self._prev_iface_time = now
        # Sort: up non-loopback first (wifi/ethernet/vpn/other), then down, then loopback
        kind_rank = {"wifi": 0, "ethernet": 1, "vpn": 2, "other": 3, "loopback": 4}
        interfaces.sort(key=lambda i: (0 if i["state"] == "up" else 1, kind_rank.get(i["kind"], 5), i["name"]))
        return interfaces

    def collect(self, resolve=False):
        """Collect a complete live Network Monitor telemetry snapshot."""
        now = time.monotonic()
        connections = self._collect_raw_connections()
        dt = (now - self._prev_sock_time) if (self._prev_sock_time is not None and now > self._prev_sock_time) else None

        new_sock_bytes = {}
        for conn in connections:
            key = (
                conn["protocol"],
                conn["local_ip"],
                conn["local_port"],
                conn["remote_ip"],
                conn["remote_port"],
                conn["pid"],
            )
            rx_b = conn["rx_bytes"]
            tx_b = conn["tx_bytes"]
            if dt and key in self._prev_sock_bytes:
                prx, ptx = self._prev_sock_bytes[key]
                conn["rx_rate"] = round(max(0.0, (rx_b - prx) / dt), 1)
                conn["tx_rate"] = round(max(0.0, (tx_b - ptx) / dt), 1)
            new_sock_bytes[key] = (rx_b, tx_b)

            if resolve and conn["remote_ip"] and conn["scope"] != "loopback":
                conn["remote_host"] = self._lookup_rdns_cached(conn["remote_ip"], now)

        self._prev_sock_bytes = new_sock_bytes
        self._prev_sock_time = now

        # Sort connections by active throughput, then total bytes
        connections = filter_connections(connections, sort_by="rate")

        # Per-process aggregation
        proc_map = {}
        for conn in connections:
            pname = conn["process"] or "system"
            rec = proc_map.get(pname)
            if rec is None:
                rec = {
                    "name": pname,
                    "pids": [],
                    "connections": 0,
                    "external": 0,
                    "lan": 0,
                    "listening": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0,
                    "rx_rate": 0.0,
                    "tx_rate": 0.0,
                }
                proc_map[pname] = rec
            if conn["pid"] is not None and conn["pid"] not in rec["pids"]:
                rec["pids"].append(conn["pid"])
            rec["connections"] += 1
            if conn["scope"] == "external":
                rec["external"] += 1
            elif conn["scope"] == "lan":
                rec["lan"] += 1
            if conn["state"] == "LISTEN":
                rec["listening"] += 1
            rec["rx_bytes"] += conn["rx_bytes"]
            rec["tx_bytes"] += conn["tx_bytes"]
            rec["rx_rate"] = round(rec["rx_rate"] + conn["rx_rate"], 1)
            rec["tx_rate"] = round(rec["tx_rate"] + conn["tx_rate"], 1)

        processes = sorted(
            proc_map.values(),
            key=lambda p: (-(p["rx_rate"] + p["tx_rate"]), -p["connections"], p["name"].lower()),
        )
        for p in processes:
            p["pids"].sort()

        interfaces = self.collect_interfaces(now=now)
        non_lo = [i for i in interfaces if i["kind"] != "loopback"]
        total_rx_rate = round(sum(i["rx_rate"] for i in non_lo), 1)
        total_tx_rate = round(sum(i["tx_rate"] for i in non_lo), 1)
        total_rx_bytes = sum(i["rx_bytes"] for i in non_lo)
        total_tx_bytes = sum(i["tx_bytes"] for i in non_lo)

        self.history.append({"rx_rate": total_rx_rate, "tx_rate": total_tx_rate})

        summary = {
            "total": len(connections),
            "established": sum(1 for c in connections if c["state"] == "ESTABLISHED"),
            "listening": sum(1 for c in connections if c["state"] == "LISTEN"),
            "tcp": sum(1 for c in connections if c["protocol"].startswith("tcp")),
            "udp": sum(1 for c in connections if c["protocol"].startswith("udp")),
            "external": sum(1 for c in connections if c["scope"] == "external"),
            "lan": sum(1 for c in connections if c["scope"] == "lan"),
            "loopback": sum(1 for c in connections if c["scope"] == "loopback"),
            "processes": len(processes),
            "rx_rate": total_rx_rate,
            "tx_rate": total_tx_rate,
            "rx_bytes": total_rx_bytes,
            "tx_bytes": total_tx_bytes,
        }

        summary["shown"] = min(len(connections), MAX_CONNECTIONS)
        return {
            "time": int(time.time()),
            "summary": summary,
            "connections": connections[:MAX_CONNECTIONS],
            "processes": processes[:MAX_PROCESSES],
            "interfaces": interfaces,
            "dns": read_dns_servers(self.resolv_path),
            "history": list(self.history),
        }
