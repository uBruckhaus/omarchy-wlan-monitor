import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts")
MCP_PATH = os.path.join(SCRIPTS_DIR, "wlan-mcp.py")

os.environ.setdefault("XDG_RUNTIME_DIR", tempfile.mkdtemp(prefix="wlan-mcp-test-"))
spec = importlib.util.spec_from_file_location("wlan_mcp", MCP_PATH)
wlan_mcp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wlan_mcp)


UUID_WIFI = "f4aff26e-1193-43cc-8418-9e72a62e952e"


def make_fake_snapshot(trusted=True, alerts=True, devices=None):
    if devices is None:
        devices = [
            {
                "ip": "192.168.178.1",
                "name": "Router (FRITZ!Box 7690)",
                "auto_name": "Router (FRITZ!Box 7690)",
                "hostname": "fritz.box",
                "mac": "1c:11:22:33:44:6c",
                "vendor": "AVM FRITZ!",
                "model": "FRITZ!Box 7690",
                "online": True,
                "state": "router",
                "is_self": False,
                "is_gateway": True,
                "web_url": "http://192.168.178.1/",
                "kind": "router",
                "group": "network",
                "mesh": None,
                "seen_min": None,
                "custom_name": False,
                "pinned": False,
                "hidden": False,
                "new": False,
                "can_edit": True,
            },
            {
                "ip": "192.168.178.25",
                "name": "Living Room TV",
                "auto_name": "LGwebOSTV",
                "hostname": "LGwebOSTV",
                "mac": "aa:bb:cc:dd:ee:11",
                "vendor": "LG Electronics",
                "model": "OLED65",
                "online": True,
                "state": "online",
                "is_self": False,
                "is_gateway": False,
                "web_url": "",
                "kind": "tv",
                "group": "media",
                "mesh": None,
                "seen_min": None,
                "custom_name": True,
                "pinned": True,
                "hidden": False,
                "new": False,
                "can_edit": True,
            },
            {
                "ip": "192.168.178.40",
                "name": "Hidden Printer",
                "auto_name": "Brother HL",
                "hostname": "brother",
                "mac": "aa:bb:cc:dd:ee:22",
                "vendor": "Brother",
                "model": "HL-L2350DW",
                "online": False,
                "state": "sleeping",
                "is_self": False,
                "is_gateway": False,
                "web_url": "",
                "kind": "printer",
                "group": "office",
                "mesh": None,
                "seen_min": 5,
                "custom_name": True,
                "pinned": False,
                "hidden": True,
                "new": True,
                "can_edit": True,
            },
        ]
    return {
        "time": 1700000000,
        "active": True,
        "scanning": False,
        "link": {
            "iface": "wlan0",
            "is_wireless": True,
            "ip": "192.168.178.22",
            "prefix": 24,
            "cidr": "192.168.178.22/24",
            "gateway": "192.168.178.1",
            "gateway_mac": "1c:11:22:33:44:6c",
            "net_id": "abcdef123456-1",
            "mac": "de:ad:be:ef:00:01",
            "ssid": "FRITZ!Box 7690",
            "bssid": "2e:11:22:33:44:6c",
            "signal_dbm": -55,
            "quality": 90,
            "freq_mhz": 6135.0,
            "band": "6 GHz",
            "channel": 37,
            "width_mhz": 160,
            "tx_mbps": 2400,
            "rx_mbps": 2400,
            "domain": "fritz.box",
            "trusted": trusted,
            "can_trust": True,
            "scan_mode": "active" if trusted else "passive",
            "via": "Router",
            "vpn": None,
            "via_band": "6 GHz",
        },
        "traffic": {"rx_bytes": 1000000, "tx_bytes": 500000, "rx_rate": 12000.0, "tx_rate": 3000.0},
        "devices": devices,
        "devices_rev": "rev1",
        "online_count": sum(1 for d in devices if d["online"]),
        "idle_count": 0,
        "total_count": len(devices),
        "hidden_count": sum(1 for d in devices if d["hidden"]),
        "new_count": sum(1 for d in devices if d["new"] and not d["hidden"]),
        "named_count": sum(1 for d in devices if d["custom_name"]),
        "tracking": trusted,
        "alerts": alerts,
        "view": {"mode": "list", "collapsed": []},
        "fritz": {"state": "connected", "user": "admin", "model": "FRITZ!Box 7690", "aps": []},
        "mesh_active": True,
        "nm_available": True,
        "wifi_device": True,
        "wifi_on": True,
    }


def make_fake_netmon():
    return {
        "time": 1700000000,
        "summary": {
            "total": 2,
            "established": 1,
            "listening": 1,
            "tcp": 2,
            "udp": 0,
            "external": 1,
            "lan": 0,
            "loopback": 1,
            "processes": 2,
            "rx_rate": 5000.0,
            "tx_rate": 1000.0,
            "rx_bytes": 500000,
            "tx_bytes": 100000,
        },
        "connections": [
            {
                "protocol": "tcp",
                "state": "ESTABLISHED",
                "local_ip": "192.168.178.22",
                "local_port": 44000,
                "remote_ip": "194.25.134.50",
                "remote_port": 993,
                "remote_host": "mail.example.net",
                "scope": "external",
                "service": "IMAPS",
                "process": "omamail",
                "pid": 3527,
                "cmdline": "omamail",
                "rx_bytes": 500000,
                "tx_bytes": 30000,
                "rx_rate": 5000.0,
                "tx_rate": 1000.0,
                "rtt_ms": 14.2,
            },
            {
                "protocol": "tcp",
                "state": "LISTEN",
                "local_ip": "127.0.0.1",
                "local_port": 8080,
                "remote_ip": "0.0.0.0",
                "remote_port": 0,
                "remote_host": "",
                "scope": "loopback",
                "service": "HTTP-Alt",
                "process": "python3",
                "pid": 1001,
                "cmdline": "python3 server.py",
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_rate": 0.0,
                "tx_rate": 0.0,
                "rtt_ms": None,
            },
        ],
        "processes": [
            {
                "name": "omamail",
                "pids": [3527],
                "connections": 1,
                "external": 1,
                "lan": 0,
                "listening": 0,
                "rx_bytes": 500000,
                "tx_bytes": 30000,
                "rx_rate": 5000.0,
                "tx_rate": 1000.0,
            },
            {
                "name": "python3",
                "pids": [1001],
                "connections": 1,
                "external": 0,
                "lan": 0,
                "listening": 1,
                "rx_bytes": 0,
                "tx_bytes": 0,
                "rx_rate": 0.0,
                "tx_rate": 0.0,
            },
        ],
        "interfaces": [
            {
                "name": "wlan0",
                "kind": "wifi",
                "state": "up",
                "ip": "192.168.178.22",
                "ipv6": "2003::22",
                "mac": "de:ad:be:ef:00:01",
                "rx_bytes": 500000,
                "tx_bytes": 100000,
                "rx_rate": 5000.0,
                "tx_rate": 1000.0,
                "rx_errors": 0,
                "tx_errors": 0,
                "rx_dropped": 0,
                "tx_dropped": 0,
            }
        ],
        "dns": ["192.168.178.1"],
        "history": [{"rx_rate": 5000.0, "tx_rate": 1000.0}],
    }


class FakeMonitor:
    def __init__(self):
        self.snap = make_fake_snapshot()
        self.trust_identity = {"ssid": "FRITZ!Box 7690", "gateway_mac": "1c:11:22:33:44:6c"}
        self.handled = []
        self.force_scans = 0

    def snapshot(self, force_scan=False):
        if force_scan:
            self.force_scans += 1
        return json.loads(json.dumps(self.snap))

    def handle(self, cmd):
        self.handled.append(cmd)
        if cmd == "trust":
            self.snap["link"]["trusted"] = True
            return True
        if cmd == "untrust":
            self.snap["link"]["trusted"] = False
            return True
        if isinstance(cmd, dict):
            c = cmd["cmd"]
            if c == "alerts":
                self.snap["alerts"] = cmd["on"]
                return True
            mac = cmd.get("mac")
            for d in self.snap["devices"]:
                if d["mac"] == mac:
                    if c == "rename":
                        d["name"] = cmd["name"] or d["auto_name"]
                        d["custom_name"] = bool(cmd["name"])
                    elif c == "pin":
                        d["pinned"] = cmd["on"]
                        if cmd["on"]:
                            d["hidden"] = False
                    elif c == "hide":
                        d["hidden"] = cmd["on"]
                        if cmd["on"]:
                            d["pinned"] = False
                    elif c == "known":
                        d["new"] = not cmd["on"]
                    return True
        return False


class FakeNetMonitor:
    resolv_path = "/etc/resolv.conf"

    def __init__(self):
        self.data = make_fake_netmon()
        self.last_resolve = None

    def collect(self, resolve=False):
        self.last_resolve = resolve
        return json.loads(json.dumps(self.data))

    def collect_interfaces(self):
        return json.loads(json.dumps(self.data["interfaces"]))


class McpProtocolTests(unittest.TestCase):
    def setUp(self):
        self.mon = FakeMonitor()
        self.net = FakeNetMonitor()
        self.wifi = mock.MagicMock()
        self.wifi.get_wifi_state.return_value = {
            "nm_available": True,
            "wifi_device": True,
            "wifi_on": True,
            "active_ssid": "FRITZ!Box 7690",
            "dns": ["192.168.178.1"],
            "known": [{"name": "FRITZ!Box 7690", "uuid": UUID_WIFI, "active": True, "device": "wlan0", "autoconnect": True}],
            "visible": [],
            "wired": [],
            "wired_devices": [],
            "vpn": [],
            "error": "",
        }
        self.server = wlan_mcp.WlanMCPServer(
            monitor=self.mon,
            net_monitor=self.net,
            wifi_setup_module=self.wifi,
            allow_changes=True,
        )

    def _call_tool(self, name, arguments=None):
        resp = self.server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments or {}}}
        )
        self.assertIn("result", resp)
        res = resp["result"]
        return res["isError"], json.loads(res["content"][0]["text"])

    def test_initialize_ping_notifications_and_errors(self):
        init = self.server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}
        )
        self.assertEqual(init["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(init["result"]["serverInfo"]["name"], "omarchy-wlan-monitor")
        self.assertEqual(init["result"]["serverInfo"]["version"], wlan_mcp.SERVER_VERSION)

        # Unknown protocol falls back to default
        init2 = self.server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}
        )
        self.assertEqual(init2["result"]["protocolVersion"], "2024-11-05")

        # Ping
        self.assertEqual(self.server.handle_message({"jsonrpc": "2.0", "id": 3, "method": "ping"})["result"], {})

        # Notification produces None
        self.assertIsNone(self.server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}))

        # Unknown method & unknown tool
        bad_m = self.server.handle_message({"jsonrpc": "2.0", "id": 4, "method": "nope"})
        self.assertEqual(bad_m["error"]["code"], -32601)
        bad_t = self.server.handle_message({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "bogus"}})
        self.assertEqual(bad_t["error"]["code"], -32602)

    def test_tools_list_and_resources(self):
        tools_resp = self.server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in tools_resp["result"]["tools"]}
        expected = {
            "wlan_status",
            "wlan_list_devices",
            "wlan_get_device",
            "wlan_network_monitor",
            "wlan_list_interfaces",
            "wlan_wifi_list",
            "wlan_rescan",
            "wlan_set_device",
            "wlan_set_trust",
            "wlan_wifi_radio",
            "wlan_wifi_connect",
            "wlan_wifi_disconnect",
            "wlan_wifi_forget",
        }
        self.assertEqual(names, expected)

        res_list = self.server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "resources/list"})
        uris = {r["uri"] for r in res_list["result"]["resources"]}
        self.assertEqual(uris, {"wlan://state", "wlan://connections", "wlan://wifi"})

        # Inject a stray password key to verify defensive stripping on resources/read
        self.mon.snap["fritz"]["password"] = "LEAKED_FRITZ_PW"
        for uri in ("wlan://state", "wlan://connections", "wlan://wifi"):
            r = self.server.handle_message({"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": uri}})
            text = r["result"]["contents"][0]["text"]
            self.assertNotIn("LEAKED_FRITZ_PW", text)
            json.loads(text)

        missing = self.server.handle_message({"jsonrpc": "2.0", "id": 4, "method": "resources/read", "params": {"uri": "wlan://nope"}})
        self.assertEqual(missing["error"]["code"], -32002)

    def test_read_tools(self):
        err, st = self._call_tool("wlan_status")
        self.assertFalse(err)
        self.assertTrue(st["active"])
        self.assertEqual(st["online_count"], 2)
        self.assertTrue(st["wifi_on"])

        # Default excludes hidden devices
        err, devs = self._call_tool("wlan_list_devices")
        self.assertFalse(err)
        self.assertEqual(devs["total_count"], 2)

        err, devs_all = self._call_tool("wlan_list_devices", {"include_hidden": True})
        self.assertEqual(devs_all["total_count"], 3)

        err, tv = self._call_tool("wlan_list_devices", {"kind": "tv", "online_only": True, "search": "oled"})
        self.assertEqual([d["ip"] for d in tv["devices"]], ["192.168.178.25"])

        # Get device by IP, MAC, Name, and fuzzy error
        err, d1 = self._call_tool("wlan_get_device", {"target": "192.168.178.25"})
        self.assertFalse(err)
        self.assertEqual(d1["device"]["name"], "Living Room TV")
        err, d2 = self._call_tool("wlan_get_device", {"target": "AA:BB:CC:DD:EE:11"})
        self.assertFalse(err)
        self.assertEqual(d2["device"]["ip"], "192.168.178.25")
        err, d3 = self._call_tool("wlan_get_device", {"target": "living room tv"})
        self.assertFalse(err)
        self.assertEqual(d3["device"]["mac"], "aa:bb:cc:dd:ee:11")
        err, nf = self._call_tool("wlan_get_device", {"target": "Living Room"})
        self.assertTrue(err)
        self.assertIn("Living Room TV", nf["error"])

        # Network monitor & interfaces & wifi list & rescan
        err, nm = self._call_tool("wlan_network_monitor", {"scope": "external", "port": 993, "resolve_hosts": True})
        self.assertFalse(err)
        self.assertTrue(self.net.last_resolve)
        self.assertEqual(nm["matched_count"], 1)
        self.assertEqual(nm["connections"][0]["process"], "omamail")

        err, nm_grp = self._call_tool("wlan_network_monitor", {"group_by_process": True})
        self.assertFalse(err)
        self.assertNotIn("connections", nm_grp)
        self.assertEqual(len(nm_grp["processes"]), 2)

        with mock.patch.object(self.server.net_mod, "read_dns_servers", return_value=["192.168.178.1"]):
            err, ifaces = self._call_tool("wlan_list_interfaces")
            self.assertFalse(err)
            self.assertEqual(ifaces["interfaces"][0]["name"], "wlan0")
            self.assertEqual(ifaces["dns"], ["192.168.178.1"])

        err, wlist = self._call_tool("wlan_wifi_list", {"rescan": True})
        self.assertFalse(err)
        self.wifi.get_wifi_state.assert_called_with(rescan=True)
        self.assertEqual(wlist["active_ssid"], "FRITZ!Box 7690")

        err, resc = self._call_tool("wlan_rescan", {"confirm": True})
        self.assertFalse(err)
        self.assertEqual(self.mon.force_scans, 1)

    def test_reuses_sibling_modules_from_wlan_monitor(self):
        srv = wlan_mcp.WlanMCPServer(monitor=self.mon, net_monitor=self.net)
        self.assertIs(srv.net_mod, srv.wlan_mod.net_monitor_mod)
        self.assertIs(srv.wifi_mod, srv.wlan_mod.wifi_setup_mod)

    def test_mutation_tools_and_password_policy(self):
        # wlan_set_device
        err, upd = self._call_tool("wlan_set_device", {"target": "Living Room TV", "name": "OLED TV", "pinned": False, "known": True, "confirm": True})
        self.assertFalse(err)
        self.assertEqual(upd["device"]["name"], "OLED TV")
        self.assertFalse(upd["device"]["pinned"])

        # Conflict pinned + hidden
        err, bad = self._call_tool("wlan_set_device", {"target": "OLED TV", "pinned": True, "hidden": True, "confirm": True})
        self.assertTrue(err)

        # wlan_set_trust
        err, tr = self._call_tool("wlan_set_trust", {"trusted": False, "alerts": False, "confirm": True})
        self.assertFalse(err)
        self.assertFalse(tr["trusted"])
        self.assertFalse(tr["alerts"])

        # wlan_wifi_radio
        self.wifi.set_wifi_radio.return_value = {"ok": True, "action": "radio", "wifi_on": False, "message": "Wi-Fi disabled."}
        err, rad = self._call_tool("wlan_wifi_radio", {"on": False, "confirm": True})
        self.assertFalse(err)
        self.assertFalse(rad["wifi_on"])

        # wlan_wifi_connect refuses password over MCP (must enter in Setup UI) and redacts secret
        secret = "UltraSecretPass99!"
        err, rejected = self._call_tool("wlan_wifi_connect", {"ssid": "Office", "password": secret, "confirm": True})
        self.assertTrue(err)
        self.assertIn("password", rejected["error"])
        self.assertNotIn(secret, json.dumps(rejected))
        self.wifi.wifi_connect.assert_not_called()

        # wlan_wifi_connect schema does not expose a password parameter
        connect_schema = next(t["inputSchema"] for t in wlan_mcp.TOOLS if t["name"] == "wlan_wifi_connect")
        self.assertNotIn("password", connect_schema["properties"])

        # wlan_wifi_connect works for saved UUID and reports auth_failed on missing secrets
        self.wifi.wifi_connect.return_value = {
            "ok": False,
            "auth_failed": True,
            "action": "connect",
            "ssid": "Office",
            "uuid": UUID_WIFI,
            "message": "Secrets were required",
        }
        err, conn = self._call_tool("wlan_wifi_connect", {"uuid": UUID_WIFI, "confirm": True})
        self.assertTrue(err)
        self.assertTrue(conn["auth_failed"])
        self.wifi.wifi_connect.assert_called_with(ssid="", password=None, uuid=UUID_WIFI)

        self.wifi.wifi_connect.return_value = {
            "ok": True,
            "auth_failed": False,
            "action": "connect",
            "ssid": "OpenCafe",
            "uuid": "",
            "message": "Connected to OpenCafe.",
        }
        err, conn_ok = self._call_tool("wlan_wifi_connect", {"ssid": "OpenCafe", "confirm": True})
        self.assertFalse(err)
        self.assertTrue(conn_ok["ok"])

        # wlan_wifi_disconnect & forget
        self.wifi.wifi_disconnect.return_value = {"ok": True, "action": "disconnect", "uuid": UUID_WIFI, "message": "Disconnected"}
        err, disc = self._call_tool("wlan_wifi_disconnect", {"uuid": UUID_WIFI, "confirm": True})
        self.assertFalse(err)
        self.assertTrue(disc["ok"])
        self.wifi.connection_down.assert_not_called()  # Wi-Fi only: Ethernet/VPN never touched

        self.wifi.wifi_forget.return_value = {"ok": True, "action": "forget", "uuid": UUID_WIFI, "message": "Forgot"}
        err, wrong = self._call_tool("wlan_wifi_forget", {"uuid": UUID_WIFI, "ssid": "Other", "confirm": True})
        self.assertTrue(err)
        self.wifi.wifi_forget.assert_not_called()
        err, forg = self._call_tool("wlan_wifi_forget", {"uuid": UUID_WIFI, "ssid": "FRITZ!Box 7690", "confirm": True})
        self.assertFalse(err)
        self.assertTrue(forg["ok"])

    def test_writes_need_confirm(self):
        err, out = self._call_tool("wlan_wifi_radio", {"on": False})
        self.assertTrue(err)
        self.assertIn("confirm", out["error"])
        self.wifi.set_wifi_radio.assert_not_called()

    def test_unknown_argument_keys_rejected_without_values(self):
        err, out = self._call_tool("wlan_status", {"psk": "TopSecret123", "refresh": True})
        self.assertTrue(err)
        self.assertIn("psk", out["error"])
        self.assertNotIn("TopSecret123", json.dumps(out))

    def test_read_only_by_default(self):
        srv = wlan_mcp.WlanMCPServer(monitor=self.mon, net_monitor=self.net, wifi_setup_module=self.wifi)
        resp = srv.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertFalse(names & wlan_mcp.WRITE_TOOLS)
        for name, args in (("wlan_wifi_forget", {"uuid": UUID_WIFI, "ssid": "FRITZ!Box 7690", "confirm": True}),
                           ("wlan_rescan", {"confirm": True}),
                           ("wlan_list_devices", {"rescan": True})):  # no such argument any more
            resp = srv.handle_message({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                                       "params": {"name": name, "arguments": args}})
            self.assertTrue(resp["result"]["isError"], name)
        self.wifi.wifi_forget.assert_not_called()
        self.assertEqual(self.mon.force_scans, 0)

    def test_server_is_never_the_fritz_leader(self):
        wmod = wlan_mcp.load_wlan_module()
        with mock.patch.object(wmod, "Monitor") as monitor_cls:
            wlan_mcp.WlanMCPServer(wlan_module=wmod, net_monitor=self.net, wifi_setup_module=self.wifi)
        monitor_cls.assert_called_once_with(can_lead=False)
        bare = wmod.Monitor.__new__(wmod.Monitor)
        bare.can_lead, bare.fritz = False, None
        with mock.patch.object(wmod, "take_leader_lock") as take:
            self.assertFalse(bare.lead())
        take.assert_not_called()

    def test_tools_carry_annotations(self):
        for tool in wlan_mcp.TOOLS:
            ann = tool["annotations"]
            self.assertEqual(ann["readOnlyHint"], tool["name"] not in wlan_mcp.WRITE_TOOLS)

    def test_stdio_transport_framing_and_safety(self):
        lines = [
            b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n',
            b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
            b"{bad json\n",
            b"\xff\xfe\n",
            b"[" * 40 + b"]" * 40 + b"\n",
            b"x" * (wlan_mcp.MAX_LINE_BYTES + 10) + b"\n",
        ]
        stdin = io.BytesIO(b"".join(lines))
        stdout = io.BytesIO()
        self.server.serve_stdio(stdin=stdin, stdout=stdout)
        out_lines = [json.loads(l) for l in stdout.getvalue().splitlines()]
        self.assertEqual(len(out_lines), 5)  # notification produced no response
        self.assertEqual(out_lines[0]["id"], 1)
        self.assertEqual(out_lines[1]["error"]["code"], -32700)
        self.assertEqual(out_lines[2]["error"]["code"], -32700)
        self.assertEqual(out_lines[3]["error"]["code"], -32700)
        self.assertEqual(out_lines[4]["error"]["code"], -32600)

    def test_isolated_python_dash_I_smoke(self):
        req = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}}) + "\n"
        proc = subprocess.run(
            [sys.executable, "-I", MCP_PATH],
            input=req,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        resp = json.loads(proc.stdout.strip())
        self.assertEqual(resp["id"], 9)
        self.assertEqual(resp["result"]["serverInfo"]["name"], "omarchy-wlan-monitor")


if __name__ == "__main__":
    unittest.main()
