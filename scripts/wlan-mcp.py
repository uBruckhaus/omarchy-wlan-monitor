#!/usr/bin/env python3
"""MCP (Model Context Protocol) JSON-RPC 2.0 stdio server for WLAN Monitor.

Reuses scripts/wlan-monitor.py, scripts/net_monitor.py, and scripts/wifi_setup.py directly
(zero external dependencies, Python 3 stdlib only, works with `python3 -I`).
FRITZ!Box passwords and Wi-Fi passphrases are never read, echoed, or exposed: the server is
never the FRITZ!Box collector (Monitor(can_lead=False)), so it never opens the saved login.

Read-only by default. Tools that change anything (device names/flags, trust, alerts, Wi-Fi
radio, connect, disconnect, forget) and active network scans are listed and callable only when
the server is started with --allow-changes, and each such call must pass "confirm": true.
"""

import difflib
import importlib.util
import json
from pathlib import Path
import signal
import sys
import time


SERVER_NAME = "omarchy-wlan-monitor"
SERVER_VERSION = "0.11.1"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26")
STATE_RESOURCE_URI = "wlan://state"
CONNECTIONS_RESOURCE_URI = "wlan://connections"
WIFI_RESOURCE_URI = "wlan://wifi"
MAX_LINE_BYTES = 512 * 1024  # 512 KiB per JSON-RPC message line
DEFAULT_STALE_SECONDS = 2.0
MAX_JSON_DEPTH = 32

_MODULES = {}


def _load_sibling(mod_name, filename, script_path=None):
    """Load a sibling module via importlib (works with `python3 -I`)."""
    if script_path is None and mod_name in _MODULES:
        return _MODULES[mod_name]
    path = Path(script_path) if script_path is not None else (Path(__file__).resolve().parent / filename)
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError("Unable to load %s from %s" % (filename, path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if script_path is None:
        _MODULES[mod_name] = mod
    return mod


def load_wlan_module(script_path=None):
    return _load_sibling("wlan_monitor", "wlan-monitor.py", script_path)


def load_net_monitor_module(script_path=None, wlan_module=None):
    if script_path is None:
        wmod = wlan_module if wlan_module is not None else load_wlan_module()
        sibling = getattr(wmod, "net_monitor_mod", None)
        if sibling is not None:
            return sibling
    return _load_sibling("net_monitor", "net_monitor.py", script_path)


def load_wifi_setup_module(script_path=None, wlan_module=None):
    if script_path is None:
        wmod = wlan_module if wlan_module is not None else load_wlan_module()
        sibling = getattr(wmod, "wifi_setup_mod", None)
        if sibling is not None:
            return sibling
    return _load_sibling("wifi_setup", "wifi_setup.py", script_path)


def _json_depth_ok(text, max_depth=MAX_JSON_DEPTH):
    """Verify JSON nesting depth stays within `max_depth` before calling json.loads."""
    depth = 0
    in_str = False
    escaped = False
    for ch in text:
        if in_str:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            depth += 1
            if depth > max_depth:
                return False
        elif ch in "}]":
            depth -= 1
    return True


def _clean(text, limit=200):
    raw = "".join(ch for ch in str(text or "") if ch.isprintable() and ch not in "<>&")
    return raw.strip()[:limit]


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


class ToolError(Exception):
    """Expected user/validation/resolution/network error returned as MCP tool isError=True."""

    def __init__(self, message, extra=None):
        super().__init__(message)
        self.extra = dict(extra) if isinstance(extra, dict) else None


class RpcError(Exception):
    """JSON-RPC 2.0 protocol error."""

    def __init__(self, code, message, data=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _format_device_candidate(dev):
    name = dev.get("name") or dev.get("ip") or ""
    ip = dev.get("ip") or ""
    mac = dev.get("mac") or ""
    parts = [p for p in (ip, mac) if p]
    if parts:
        return "%s (%s)" % (name, ", ".join(parts))
    return name


def _resolve_device(query, devices):
    """Resolve a device by exact IP, exact MAC (case-insensitive), or case-insensitive name/hostname."""
    if not isinstance(query, str) or not query.strip():
        raise ToolError("Invalid target: must be a non-empty IP address, MAC address, or device name.")
    q = query.strip()
    q_low = q.lower()

    # 1. Exact IP match
    for dev in devices:
        if (dev.get("ip") or "").strip().lower() == q_low:
            return dev

    # 2. Exact MAC match
    for dev in devices:
        mac = (dev.get("mac") or "").strip().lower()
        if mac and mac == q_low:
            return dev

    # 3. Exact case-insensitive name or auto_name or hostname match
    exact = []
    for dev in devices:
        names = {
            (dev.get("name") or "").strip().lower(),
            (dev.get("auto_name") or "").strip().lower(),
            (dev.get("hostname") or "").strip().lower(),
        }
        names.discard("")
        if q_low in names:
            exact.append(dev)
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        opts = ", ".join(_format_device_candidate(d) for d in exact[:8])
        raise ToolError("Ambiguous device '%s'. Matches: %s. Specify IP or MAC to disambiguate." % (q, opts))

    if not devices:
        raise ToolError("Device '%s' not found (no devices currently discovered)." % q)

    # 4. Fuzzy suggestions
    scored = []
    seen = set()
    for dev in devices:
        key = dev.get("ip") or dev.get("mac") or dev.get("name")
        hay = " ".join(
            (
                str(dev.get("name") or ""),
                str(dev.get("auto_name") or ""),
                str(dev.get("hostname") or ""),
                str(dev.get("vendor") or ""),
            )
        ).lower()
        if q_low in hay and key not in seen:
            seen.add(key)
            scored.append(dev)

    name_map = {}
    for dev in devices:
        for field in ("name", "auto_name", "hostname"):
            val = str(dev.get(field) or "").strip().lower()
            if val:
                name_map.setdefault(val, []).append(dev)
    for close in difflib.get_close_matches(q_low, list(name_map.keys()), n=5, cutoff=0.45):
        for dev in name_map[close]:
            key = dev.get("ip") or dev.get("mac") or dev.get("name")
            if key not in seen:
                seen.add(key)
                scored.append(dev)

    if scored:
        suggestions = ", ".join(_format_device_candidate(d) for d in scored[:6])
        raise ToolError("Device '%s' not found. Did you mean: %s?" % (q, suggestions))

    avail = ", ".join(_format_device_candidate(d) for d in devices[:8])
    suffix = " (and %d more)" % (len(devices) - 8) if len(devices) > 8 else ""
    raise ToolError("Device '%s' not found. Available devices: %s%s." % (q, avail, suffix))


# ---------------------------------------------------------------------------
# Tool definitions (JSON Schemas)

TOOLS = [
    {
        "name": "wlan_status",
        "description": "Get current Wi-Fi or wired network link status, signal quality, band, channel, IP, gateway, VPN state, traffic rates, online/total device counts, trusted status, and Wi-Fi radio state.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "refresh": {"type": "boolean", "description": "Force a fresh snapshot read."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_list_devices",
        "description": "List devices discovered on the local network with optional filtering by online state, device kind, group, search query, hidden visibility, or a fresh rescan.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "online_only": {"type": "boolean", "description": "When true, return only currently online devices."},
                "kind": {"type": "string", "description": "Filter by device kind (e.g. 'router', 'computer', 'laptop', 'phone', 'tablet', 'tv', 'speaker', 'printer', 'smarthome', 'light', 'nas')."},
                "group": {"type": "string", "description": "Filter by device group (e.g. 'apple', 'android', 'media', 'network', 'smarthome', 'office', 'other')."},
                "search": {"type": "string", "description": "Case-insensitive substring search across name, hostname, IP, MAC, vendor, and model."},
                "include_hidden": {"type": "boolean", "description": "When true, include devices the user marked as hidden (default false)."},
                "rescan": {"type": "boolean", "description": "Run an active subnet/mDNS scan before listing (needs --allow-changes)."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_get_device",
        "description": "Get full details for a single local network device by IP address, MAC address, or case-insensitive name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Device IP address, MAC address, or case-insensitive name."},
                "rescan": {"type": "boolean", "description": "Run an active scan before resolving (needs --allow-changes)."},
            },
            "required": ["target"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_network_monitor",
        "description": "Inspect live active TCP/UDP connections, listening ports, per-process traffic aggregation, interface stats, and DNS servers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "protocol": {
                    "type": "string",
                    "enum": ["all", "tcp", "tcp6", "udp", "udp6"],
                    "description": "Filter by transport protocol.",
                },
                "state": {
                    "type": "string",
                    "description": "Filter by socket state (e.g. 'ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT', 'UNCONN').",
                },
                "scope": {
                    "type": "string",
                    "enum": ["all", "external", "lan", "loopback"],
                    "description": "Filter by address scope.",
                },
                "process": {"type": "string", "description": "Case-insensitive filter by process name or command line."},
                "port": {"type": "integer", "minimum": 1, "maximum": 65535, "description": "Filter by local or remote port number."},
                "search": {"type": "string", "description": "Case-insensitive search across process, IPs, hostnames, service, and ports."},
                "group_by_process": {"type": "boolean", "description": "When true, emphasize per-process aggregation and omit individual connection rows."},
                "resolve_hosts": {"type": "boolean", "description": "When true, enable cached non-blocking reverse-DNS lookups for remote IPs."},
                "sort_by": {
                    "type": "string",
                    "enum": ["rate", "bytes", "process", "remote", "state", "port", "rtt"],
                    "description": "Sort order for connections (default 'rate').",
                },
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "description": "Maximum number of connection rows to return (default 100)."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_list_interfaces",
        "description": "List all local network interfaces with IPv4/IPv6 addresses, MAC, kind, link state, RX/TX byte counters and rates, errors/drops, and configured DNS servers.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_wifi_list",
        "description": "List Wi-Fi radio state, saved Wi-Fi profiles, visible scanned Wi-Fi networks, wired Ethernet devices/profiles, VPN profiles, and DNS servers via NetworkManager.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rescan": {"type": "boolean", "description": "When true, request a fresh Wi-Fi scan before listing."},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_rescan",
        "description": "Run an ACTIVE local network scan now (ping and reverse-DNS sweep of the subnet, mDNS, neighbour table), even on a network that is not trusted, and return the updated summary and devices. Needs --allow-changes and confirm: true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "confirm": {"type": "boolean", "description": "Must be true: the user asked for an active scan."},
            },
            "required": ["confirm"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_set_device",
        "description": "Update a local network device's custom name, pinned status, hidden status, or mark it as known/acknowledged.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Device MAC address, IP address, or case-insensitive name."},
                "name": {"type": "string", "description": "New custom display name (empty string clears custom name)."},
                "pinned": {"type": "boolean", "description": "Pin or unpin the device in the list."},
                "hidden": {"type": "boolean", "description": "Hide or unhide the device."},
                "known": {"type": "boolean", "description": "Mark the device as known (true clears 'new' badge, false marks as new)."},
                "confirm": {"type": "boolean", "description": "Must be true: the user asked for exactly this change."},
            },
            "required": ["target", "confirm"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_set_trust",
        "description": "Trust or untrust the current network for active scanning/device tracking, and/or toggle new-device desktop alerts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "trusted": {"type": "boolean", "description": "Trust (true) or untrust (false) the current network."},
                "alerts": {"type": "boolean", "description": "Enable (true) or disable (false) new-device notifications."},
                "confirm": {"type": "boolean", "description": "Must be true: the user asked for exactly this change."},
            },
            "required": ["confirm"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_wifi_radio",
        "description": "Turn the Wi-Fi radio on or off via NetworkManager.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "on": {"type": "boolean", "description": "Enable (true) or disable (false) Wi-Fi radio."},
                "confirm": {"type": "boolean", "description": "Must be true: the user asked for exactly this change."},
            },
            "required": ["on", "confirm"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_wifi_connect",
        "description": "Connect to a saved Wi-Fi profile by UUID or an open Wi-Fi network by SSID. Wi-Fi passwords are not accepted over MCP and must be entered directly in the WLAN Monitor Setup UI.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ssid": {"type": "string", "description": "Open or already-saved Wi-Fi network SSID to connect to."},
                "uuid": {"type": "string", "description": "Saved NetworkManager Wi-Fi connection UUID."},
                "confirm": {"type": "boolean", "description": "Must be true: the user asked for exactly this change."},
            },
            "required": ["confirm"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_wifi_disconnect",
        "description": "Disconnect an active Wi-Fi connection by UUID (Wi-Fi only; Ethernet and VPN are never touched).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uuid": {"type": "string", "description": "Active NetworkManager Wi-Fi connection UUID."},
                "confirm": {"type": "boolean", "description": "Must be true: the user asked for exactly this change."},
            },
            "required": ["uuid", "confirm"],
            "additionalProperties": False,
        },
    },
    {
        "name": "wlan_wifi_forget",
        "description": "Delete (forget) a saved Wi-Fi connection profile by UUID.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "uuid": {"type": "string", "description": "Saved NetworkManager Wi-Fi profile UUID."},
                "ssid": {"type": "string", "description": "The profile's network name, repeated as a check (must match)."},
                "confirm": {"type": "boolean", "description": "Must be true: the user asked for exactly this change."},
            },
            "required": ["uuid", "ssid", "confirm"],
            "additionalProperties": False,
        },
    },
]

# Tools that change something, or scan actively: only with --allow-changes and confirm: true.
WRITE_TOOLS = frozenset({
    "wlan_rescan", "wlan_set_device", "wlan_set_trust", "wlan_wifi_radio",
    "wlan_wifi_connect", "wlan_wifi_disconnect", "wlan_wifi_forget",
})
DESTRUCTIVE_TOOLS = frozenset({"wlan_wifi_radio", "wlan_wifi_disconnect", "wlan_wifi_forget", "wlan_set_trust"})
OPEN_WORLD_TOOLS = frozenset({"wlan_rescan", "wlan_wifi_connect", "wlan_wifi_list"})
for _tool in TOOLS:
    _name = _tool["name"]
    _tool["annotations"] = {
        "readOnlyHint": _name not in WRITE_TOOLS,
        "destructiveHint": _name in DESTRUCTIVE_TOOLS,
        "openWorldHint": _name in OPEN_WORLD_TOOLS,
    }

TOOL_NAMES = frozenset(t["name"] for t in TOOLS)
TOOL_PROPERTIES = {t["name"]: frozenset(t["inputSchema"].get("properties", {})) for t in TOOLS}

RESOURCES = [
    {
        "uri": STATE_RESOURCE_URI,
        "name": "WLAN Monitor State",
        "description": "Sanitized WLAN Monitor snapshot (link status, traffic, discovered devices, FRITZ!Box mesh status — no credentials)",
        "mimeType": "application/json",
    },
    {
        "uri": CONNECTIONS_RESOURCE_URI,
        "name": "Live Network Connections",
        "description": "Live Network Monitor telemetry (active TCP/UDP connections, listening ports, per-process summary, interfaces, DNS)",
        "mimeType": "application/json",
    },
    {
        "uri": WIFI_RESOURCE_URI,
        "name": "Wi-Fi and Network Profiles",
        "description": "NetworkManager Wi-Fi radio state, known profiles, visible networks, wired interfaces, and VPN profiles",
        "mimeType": "application/json",
    },
]


# ---------------------------------------------------------------------------
# MCP Server

class WlanMCPServer:
    """MCP JSON-RPC 2.0 server backed by wlan_monitor.Monitor, net_monitor.NetMonitor, and wifi_setup."""

    def __init__(
        self,
        monitor=None,
        net_monitor=None,
        wlan_module=None,
        net_monitor_module=None,
        wifi_setup_module=None,
        stale_seconds=DEFAULT_STALE_SECONDS,
        allow_changes=False,
    ):
        self.allow_changes = bool(allow_changes)
        self.wlan_mod = wlan_module if wlan_module is not None else load_wlan_module()
        self.net_mod = (
            net_monitor_module
            if net_monitor_module is not None
            else load_net_monitor_module(wlan_module=self.wlan_mod)
        )
        self.wifi_mod = (
            wifi_setup_module
            if wifi_setup_module is not None
            else load_wifi_setup_module(wlan_module=self.wlan_mod)
        )
        # Never the FRITZ!Box collector: no leader lock, no saved login, no request socket.
        self.monitor = monitor if monitor is not None else self.wlan_mod.Monitor(can_lead=False)
        self.net_monitor = net_monitor if net_monitor is not None else self.net_mod.NetMonitor()
        self.stale_seconds = float(stale_seconds)
        self._last_snapshot = None
        self._last_snapshot_at = 0.0

    # -- security / redaction

    def redact(self, text, extra_secrets=()):
        raw = str(text or "")
        for secret in extra_secrets or ():
            if isinstance(secret, str) and len(secret) >= 2:
                raw = raw.replace(secret, "***")
        return raw

    def _safe_error(self, exc, extra_secrets=()):
        return _clean(self.redact(str(exc), extra_secrets), 200) or "Operation failed"

    @classmethod
    def _strip_sensitive_keys(cls, obj):
        """Recursively drop any credential/password keys defensively before emitting state."""
        if isinstance(obj, dict):
            return {
                k: cls._strip_sensitive_keys(v)
                for k, v in obj.items()
                if str(k).lower() not in ("password", "psk", "secret", "passphrase", "secrets")
            }
        if isinstance(obj, list):
            return [cls._strip_sensitive_keys(v) for v in obj]
        return obj

    def _ensure_snapshot(self, force=False, force_scan=False):
        now = time.monotonic()
        if (
            force
            or force_scan
            or self._last_snapshot is None
            or (now - self._last_snapshot_at) > self.stale_seconds
        ):
            snap = self.monitor.snapshot(force_scan=force_scan)
            self._last_snapshot = self._strip_sensitive_keys(snap)
            self._last_snapshot_at = time.monotonic()
        return self._last_snapshot

    # -- read tools

    def _tool_wlan_status(self, args):
        refresh = args.get("refresh", False)
        if not isinstance(refresh, bool):
            raise ToolError("refresh must be a boolean.")
        snap = self._ensure_snapshot(force=refresh)
        return {
            "time": snap.get("time"),
            "active": bool(snap.get("active", False)),
            "link": snap.get("link"),
            "traffic": snap.get("traffic"),
            "online_count": int(snap.get("online_count", 0)),
            "idle_count": int(snap.get("idle_count", 0)),
            "total_count": int(snap.get("total_count", 0)),
            "hidden_count": int(snap.get("hidden_count", 0)),
            "new_count": int(snap.get("new_count", 0)),
            "named_count": int(snap.get("named_count", 0)),
            "tracking": bool(snap.get("tracking", False)),
            "alerts": bool(snap.get("alerts", True)),
            "mesh_active": bool(snap.get("mesh_active", False)),
            "nm_available": bool(snap.get("nm_available", False)),
            "wifi_device": bool(snap.get("wifi_device", False)),
            "wifi_on": bool(snap.get("wifi_on", False)),
        }

    def _tool_wlan_list_devices(self, args):
        online_only = args.get("online_only", False)
        include_hidden = args.get("include_hidden", False)
        rescan = args.get("rescan", False)
        if not all(isinstance(v, bool) for v in (online_only, include_hidden, rescan)):
            raise ToolError("online_only, include_hidden, and rescan must be booleans.")

        kind_filter = args.get("kind")
        group_filter = args.get("group")
        search = args.get("search")
        for fname, fval in (("kind", kind_filter), ("group", group_filter), ("search", search)):
            if fval is not None and not isinstance(fval, str):
                raise ToolError("%s must be a string." % fname)

        snap = self._ensure_snapshot(force=rescan, force_scan=rescan)
        devices = list(snap.get("devices") or [])

        if not include_hidden:
            devices = [d for d in devices if not d.get("hidden")]
        if online_only:
            devices = [d for d in devices if d.get("online")]
        if kind_filter and kind_filter.strip():
            kf = kind_filter.strip().lower()
            devices = [d for d in devices if (d.get("kind") or "").lower() == kf]
        if group_filter and group_filter.strip():
            gf = group_filter.strip().lower()
            devices = [d for d in devices if (d.get("group") or "").lower() == gf]
        if search and search.strip():
            q = search.strip().lower()
            devices = [
                d
                for d in devices
                if q in " ".join(
                    (
                        str(d.get("name") or ""),
                        str(d.get("auto_name") or ""),
                        str(d.get("hostname") or ""),
                        str(d.get("ip") or ""),
                        str(d.get("mac") or ""),
                        str(d.get("vendor") or ""),
                        str(d.get("model") or ""),
                    )
                ).lower()
            ]

        return {
            "active": bool(snap.get("active", False)),
            "online_count": sum(1 for d in devices if d.get("online")),
            "total_count": len(devices),
            "devices": devices,
        }

    def _tool_wlan_get_device(self, args):
        rescan = args.get("rescan", False)
        if not isinstance(rescan, bool):
            raise ToolError("rescan must be a boolean.")
        snap = self._ensure_snapshot(force=rescan, force_scan=rescan)
        dev = _resolve_device(args.get("target"), list(snap.get("devices") or []))
        return {"device": dev}

    def _tool_wlan_network_monitor(self, args):
        protocol = args.get("protocol")
        state = args.get("state")
        scope = args.get("scope")
        process = args.get("process")
        port = args.get("port")
        search = args.get("search")
        group_by_process = args.get("group_by_process", False)
        resolve_hosts = args.get("resolve_hosts", False)
        sort_by = args.get("sort_by", "rate")
        limit = args.get("limit", 100)

        if not isinstance(group_by_process, bool) or not isinstance(resolve_hosts, bool):
            raise ToolError("group_by_process and resolve_hosts must be booleans.")
        if protocol is not None and protocol not in ("all", "tcp", "tcp6", "udp", "udp6"):
            raise ToolError("protocol must be one of: all, tcp, tcp6, udp, udp6.")
        if scope is not None and scope not in ("all", "external", "lan", "loopback"):
            raise ToolError("scope must be one of: all, external, lan, loopback.")
        if sort_by is not None and sort_by not in ("rate", "bytes", "process", "remote", "state", "port", "rtt"):
            raise ToolError("sort_by must be one of: rate, bytes, process, remote, state, port, rtt.")
        if port is not None:
            if not _is_int(port) or not (1 <= port <= 65535):
                raise ToolError("port must be an integer between 1 and 65535.")
        if not _is_int(limit) or not (1 <= limit <= 500):
            raise ToolError("limit must be an integer between 1 and 500.")
        for fname, fval in (("state", state), ("process", process), ("search", search)):
            if fval is not None and not isinstance(fval, str):
                raise ToolError("%s must be a string." % fname)

        data = self.net_monitor.collect(resolve=resolve_hosts)
        filtered = self.net_mod.filter_connections(
            data["connections"],
            protocol=protocol,
            state=state,
            scope=scope,
            process=process,
            port=port,
            search=search,
            sort_by=sort_by,
        )

        # Recompute per-process summary if filters were applied
        any_filter = any(
            [
                protocol and protocol != "all",
                state,
                scope and scope != "all",
                process,
                port is not None,
                search,
            ]
        )
        if any_filter:
            proc_map = {}
            for conn in filtered:
                pname = conn["process"] or "system"
                rec = proc_map.setdefault(
                    pname,
                    {
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
                    },
                )
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
        else:
            processes = data["processes"]

        result = {
            "time": data["time"],
            "summary": data["summary"],
            "matched_count": len(filtered),
            "processes": processes,
            "interfaces": data["interfaces"],
            "dns": data["dns"],
        }
        if not group_by_process:
            result["connections"] = filtered[:limit]
            result["truncated"] = len(filtered) > limit
        return result

    def _tool_wlan_list_interfaces(self, _args):
        interfaces = self.net_monitor.collect_interfaces()
        dns = self.net_mod.read_dns_servers(self.net_monitor.resolv_path)
        return {"interfaces": interfaces, "dns": dns}

    def _tool_wlan_wifi_list(self, args):
        rescan = args.get("rescan", False)
        if not isinstance(rescan, bool):
            raise ToolError("rescan must be a boolean.")
        return self.wifi_mod.get_wifi_state(rescan=rescan)

    def _tool_wlan_rescan(self, _args):
        snap = self._ensure_snapshot(force=True, force_scan=True)
        return {
            "ok": True,
            "active": bool(snap.get("active", False)),
            "link": snap.get("link"),
            "online_count": int(snap.get("online_count", 0)),
            "idle_count": int(snap.get("idle_count", 0)),
            "total_count": int(snap.get("total_count", 0)),
            "new_count": int(snap.get("new_count", 0)),
            "devices": list(snap.get("devices") or []),
        }

    # -- mutation tools

    def _tool_wlan_set_device(self, args):
        target = args.get("target")
        has_name = "name" in args and args["name"] is not None
        has_pinned = "pinned" in args and args["pinned"] is not None
        has_hidden = "hidden" in args and args["hidden"] is not None
        has_known = "known" in args and args["known"] is not None
        if not (has_name or has_pinned or has_hidden or has_known):
            raise ToolError("Specify at least one of: name, pinned, hidden, known.")
        if has_name and not isinstance(args["name"], str):
            raise ToolError("name must be a string.")
        for field in ("pinned", "hidden", "known"):
            if field in args and args[field] is not None and not isinstance(args[field], bool):
                raise ToolError("%s must be a boolean." % field)
        if has_pinned and has_hidden and args["pinned"] and args["hidden"]:
            raise ToolError("A device cannot be both pinned and hidden at the same time.")

        snap = self._ensure_snapshot()
        dev = _resolve_device(target, list(snap.get("devices") or []))
        mac = (dev.get("mac") or "").lower()
        if not mac or not self.wlan_mod.MAC_RE.match(mac):
            raise ToolError("Device '%s' has no known MAC address and cannot be edited." % dev.get("name", target))

        applied = []
        if has_name:
            clean_nm = self.wlan_mod.clean_name(args["name"])
            if not self.monitor.handle({"cmd": "rename", "mac": mac, "name": clean_nm}):
                raise ToolError("Unable to rename device '%s' on the current network." % dev.get("name", mac))
            applied.append("rename")
        if has_pinned:
            if not self.monitor.handle({"cmd": "pin", "mac": mac, "on": args["pinned"]}):
                raise ToolError("Unable to update pin state for '%s'." % dev.get("name", mac))
            applied.append("pin")
        if has_hidden:
            if not self.monitor.handle({"cmd": "hide", "mac": mac, "on": args["hidden"]}):
                raise ToolError("Unable to update hidden state for '%s'." % dev.get("name", mac))
            applied.append("hide")
        if has_known:
            if not self.monitor.handle({"cmd": "known", "mac": mac, "on": args["known"]}):
                raise ToolError("Unable to update known state for '%s'." % dev.get("name", mac))
            applied.append("known")

        updated_snap = self._ensure_snapshot(force=True)
        updated_dev = next(
            (d for d in (updated_snap.get("devices") or []) if (d.get("mac") or "").lower() == mac),
            dev,
        )
        return {"ok": True, "applied": applied, "device": updated_dev}

    def _tool_wlan_set_trust(self, args):
        has_trusted = "trusted" in args and args["trusted"] is not None
        has_alerts = "alerts" in args and args["alerts"] is not None
        if not has_trusted and not has_alerts:
            raise ToolError("Specify at least one of: trusted, alerts.")
        if has_trusted and not isinstance(args["trusted"], bool):
            raise ToolError("trusted must be a boolean.")
        if has_alerts and not isinstance(args["alerts"], bool):
            raise ToolError("alerts must be a boolean.")

        self._ensure_snapshot(force=True)
        if has_trusted:
            if not self.monitor.trust_identity.get("gateway_mac"):
                raise ToolError("No active network gateway MAC detected; cannot change trust state.")
            cmd = "trust" if args["trusted"] else "untrust"
            if not self.monitor.handle(cmd):
                raise ToolError("Unable to %s the current network." % cmd)
        if has_alerts:
            self.monitor.handle({"cmd": "alerts", "on": args["alerts"]})

        snap = self._ensure_snapshot(force=True)
        link = snap.get("link") or {}
        return {
            "ok": True,
            "trusted": bool(link.get("trusted", False)),
            "alerts": bool(snap.get("alerts", True)),
            "ssid": link.get("ssid", ""),
            "gateway_mac": link.get("gateway_mac", ""),
        }

    def _tool_wlan_wifi_radio(self, args):
        on = args.get("on")
        if not isinstance(on, bool):
            raise ToolError("on must be a boolean.")
        res = self.wifi_mod.set_wifi_radio(on)
        self._last_snapshot = None
        if not res.get("ok"):
            raise ToolError(res.get("message") or "Failed to toggle Wi-Fi radio.")
        return res

    def _tool_wlan_wifi_connect(self, args):
        if "password" in args and args["password"] is not None:
            raise ToolError(
                "Wi-Fi passwords cannot be submitted over MCP. Enter the password directly in the WLAN Monitor Setup UI."
            )
        ssid = args.get("ssid", "")
        uuid = args.get("uuid")

        if ssid is not None and not isinstance(ssid, str):
            raise ToolError("ssid must be a string.")
        if uuid is not None and not isinstance(uuid, str):
            raise ToolError("uuid must be a string.")
        ssid = ssid or ""
        if not ssid.strip() and not (uuid and uuid.strip()):
            raise ToolError("Specify either ssid or uuid to connect.")

        res = self.wifi_mod.wifi_connect(ssid=ssid, password=None, uuid=uuid)
        self._last_snapshot = None
        if not res.get("ok"):
            msg = self.redact(res.get("message") or "Wi-Fi connection failed.")
            raise ToolError(
                msg,
                extra={
                    "ok": False,
                    "auth_failed": bool(res.get("auth_failed", False)),
                    "ssid": res.get("ssid", ""),
                    "uuid": res.get("uuid", ""),
                },
            )
        return res

    def _tool_wlan_wifi_disconnect(self, args):
        uuid = args.get("uuid")
        if not isinstance(uuid, str) or not uuid.strip():
            raise ToolError("uuid must be a non-empty NetworkManager connection UUID.")
        res = self.wifi_mod.wifi_disconnect(uuid.strip())
        self._last_snapshot = None
        if not res.get("ok"):
            raise ToolError(res.get("message") or "Failed to disconnect connection.")
        return res

    def _tool_wlan_wifi_forget(self, args):
        uuid = args.get("uuid")
        if not isinstance(uuid, str) or not uuid.strip():
            raise ToolError("uuid must be a non-empty NetworkManager Wi-Fi connection UUID.")
        ssid = args.get("ssid")
        if not isinstance(ssid, str) or not ssid:
            raise ToolError("ssid must name the saved network to forget.")
        known = self.wifi_mod.get_wifi_state(rescan=False).get("known") or []
        match = next((k for k in known if k.get("uuid") == uuid.strip()), None)
        if match is None or ssid not in (match.get("ssid"), match.get("name")):
            raise ToolError("No saved Wi-Fi profile with this uuid and ssid.")
        res = self.wifi_mod.wifi_forget(uuid.strip())
        self._last_snapshot = None
        if not res.get("ok"):
            raise ToolError(res.get("message") or "Failed to forget Wi-Fi network.")
        return res

    # -- MCP method dispatch

    def call_tool(self, name, arguments=None):
        if name not in TOOL_NAMES:
            raise RpcError(-32602, "Unknown tool: %s" % name)
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            raise RpcError(-32602, "Tool arguments must be a JSON object.")

        handler = getattr(self, "_tool_" + name, None)
        if handler is None:
            raise RpcError(-32602, "Unknown tool: %s" % name)
        unknown = sorted(k for k in arguments if k not in TOOL_PROPERTIES[name])
        if unknown:
            # Only the key names are reported (cut short), never a value that might be a secret.
            names = ", ".join(_clean(str(k), 40) for k in unknown[:5])
            return {"content": [{"type": "text", "text": json.dumps({"error": "Unknown argument(s): " + names})}],
                    "isError": True}
        if name in WRITE_TOOLS or (name in ("wlan_list_devices", "wlan_get_device") and arguments.get("rescan") is True):
            if not self.allow_changes:
                return {"content": [{"type": "text", "text": json.dumps(
                    {"error": "This server is read-only. Start it with --allow-changes to allow changes and active scans."})}],
                    "isError": True}
            if name in WRITE_TOOLS and arguments.get("confirm") is not True:
                return {"content": [{"type": "text", "text": json.dumps(
                    {"error": "Pass confirm: true once the user has asked for exactly this change."})}],
                    "isError": True}

        extra_secrets = ()
        if isinstance(arguments.get("password"), str) and arguments["password"]:
            extra_secrets = (arguments["password"],)

        try:
            payload = handler(arguments)
            text = json.dumps(self._strip_sensitive_keys(payload), allow_nan=False)
            text = self.redact(text, extra_secrets)
            return {
                "content": [{"type": "text", "text": text}],
                "isError": False,
            }
        except ToolError as exc:
            err_body = {"error": self.redact(str(exc), extra_secrets)}
            if exc.extra:
                err_body.update(self._strip_sensitive_keys(exc.extra))
            err_text = self.redact(json.dumps(err_body, allow_nan=False), extra_secrets)
            return {
                "content": [{"type": "text", "text": err_text}],
                "isError": True,
            }
        except Exception as exc:
            err_text = json.dumps({"error": self._safe_error(exc, extra_secrets)}, allow_nan=False)
            return {
                "content": [{"type": "text", "text": err_text}],
                "isError": True,
            }

    def handle_message(self, msg):
        """Process one parsed JSON-RPC 2.0 message dict. Returns response dict or None for notifications."""
        if not isinstance(msg, dict):
            return self._error_response(None, -32600, "Invalid Request: expected JSON object.")

        has_id = "id" in msg
        req_id = msg.get("id")
        if has_id and req_id is not None and (isinstance(req_id, bool) or not isinstance(req_id, (str, int))):
            return self._error_response(None, -32600, "Invalid Request: id must be string, integer, or null.")

        method = msg.get("method")
        if not isinstance(method, str) or not method:
            return self._error_response(req_id if has_id else None, -32600, "Invalid Request: missing method.")

        params = msg.get("params")
        if params is not None and not isinstance(params, dict):
            if not has_id:
                return None
            return self._error_response(req_id, -32602, "Invalid params: expected object.")
        params = params or {}

        # Notifications (no id) never get a JSON-RPC response
        if not has_id:
            return None

        try:
            if method == "initialize":
                client_ver = params.get("protocolVersion")
                proto = client_ver if client_ver in SUPPORTED_PROTOCOL_VERSIONS else DEFAULT_PROTOCOL_VERSION
                result = {
                    "protocolVersion": proto,
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                }
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": [t for t in TOOLS if self.allow_changes or t["name"] not in WRITE_TOOLS]}
            elif method == "tools/call":
                tname = params.get("name")
                if not isinstance(tname, str) or not tname:
                    raise RpcError(-32602, "Invalid params: missing tool name.")
                result = self.call_tool(tname, params.get("arguments"))
            elif method == "resources/list":
                result = {"resources": RESOURCES}
            elif method == "resources/read":
                uri = params.get("uri")
                if not isinstance(uri, str) or not uri:
                    raise RpcError(-32602, "Invalid params: missing resource uri.")
                if uri == STATE_RESOURCE_URI:
                    payload = self._ensure_snapshot()
                elif uri == CONNECTIONS_RESOURCE_URI:
                    payload = self.net_monitor.collect(resolve=False)
                elif uri == WIFI_RESOURCE_URI:
                    payload = self.wifi_mod.get_wifi_state(rescan=False)
                else:
                    raise RpcError(-32002, "Resource not found: %s" % uri)
                text = self.redact(json.dumps(self._strip_sensitive_keys(payload), allow_nan=False))
                result = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": text,
                        }
                    ]
                }
            else:
                raise RpcError(-32601, "Method not found: %s" % method)

            return {"jsonrpc": "2.0", "id": req_id, "result": result}
        except RpcError as exc:
            return self._error_response(req_id, exc.code, self.redact(exc.message), exc.data)
        except Exception as exc:
            return self._error_response(req_id, -32603, "Internal error: %s" % self._safe_error(exc))

    def _error_response(self, req_id, code, message, data=None):
        err = {"code": int(code), "message": str(message)}
        if data is not None:
            err["data"] = data
        return {"jsonrpc": "2.0", "id": req_id, "error": err}

    # -- stdio transport

    def serve_stdio(self, stdin=None, stdout=None):
        """Read newline-delimited JSON-RPC 2.0 requests from stdin and write responses to stdout."""
        in_stream = stdin if stdin is not None else sys.stdin.buffer
        out_stream = stdout if stdout is not None else sys.stdout.buffer

        def write_response(resp):
            line = json.dumps(resp, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
            out_stream.write(line)
            out_stream.flush()

        while True:
            raw_line = in_stream.readline(MAX_LINE_BYTES + 1)
            if not raw_line:
                return
            if len(raw_line) > MAX_LINE_BYTES:
                while not raw_line.endswith(b"\n"):
                    raw_line = in_stream.readline(MAX_LINE_BYTES + 1)
                    if not raw_line:
                        break
                write_response(self._error_response(None, -32600, "Request line exceeds maximum size."))
                continue
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                text = stripped.decode("utf-8")
            except UnicodeDecodeError:
                write_response(self._error_response(None, -32700, "Parse error: invalid UTF-8."))
                continue
            if not _json_depth_ok(text):
                write_response(self._error_response(None, -32700, "Parse error: JSON nesting too deep."))
                continue
            try:
                msg = json.loads(text)
            except (ValueError, TypeError, RecursionError):
                write_response(self._error_response(None, -32700, "Parse error: malformed JSON."))
                continue
            resp = self.handle_message(msg)
            if resp is not None:
                write_response(resp)


def _terminate(signum, _frame):
    sys.exit(128 + signum)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    unknown = [a for a in argv if a != "--allow-changes"]
    if unknown:
        sys.stderr.write("usage: wlan-mcp.py [--allow-changes]\n")
        return 2
    signal.signal(signal.SIGTERM, _terminate)
    server = WlanMCPServer(allow_changes="--allow-changes" in argv)
    try:
        server.serve_stdio()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
    finally:
        server.monitor.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
