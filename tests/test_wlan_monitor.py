import importlib.util
import ipaddress
import math
import os
import struct
import tempfile
import unittest
from unittest import mock

SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "wlan-monitor.py")
spec = importlib.util.spec_from_file_location("wlan_monitor", SCRIPT_PATH)
wlan_monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wlan_monitor)


class WlanMonitorTests(unittest.TestCase):
    def test_clean_strips_markup_and_control_characters(self):
        hostile = '<img src="https://evil.example/x">My\x00\n\rTV & Soundbar'
        cleaned = wlan_monitor.clean(hostile)
        self.assertNotIn("<", cleaned)
        self.assertNotIn(">", cleaned)
        self.assertNotIn("&", cleaned)
        self.assertNotIn("\n", cleaned)
        self.assertIn("MyTV  Soundbar", cleaned)

    def test_unescape_avahi_and_friendly_label(self):
        raw = r"\091LG\093\032webOS\032TV\032OLED65G49LS"
        self.assertEqual(wlan_monitor.friendly_mdns_label(raw), "[LG] webOS TV OLED65G49LS")
        airtunes = r"80C3BA8409C2@AMBEO\032Soundbar\032Plus"
        self.assertEqual(wlan_monitor.friendly_mdns_label(airtunes), "AMBEO Soundbar Plus")
        uuid_only = "e705a57f-b02e-25eb-38bb-ba291629c280"
        self.assertEqual(wlan_monitor.friendly_mdns_label(uuid_only), "")

    def test_select_best_hostname_filters_uuids_and_macs(self):
        names = [
            "c769b9d1-8cac-4af4-8a22-dcab8d244a01.fritz.box",
            "LGwebOSTV-PzEp-1.fritz.box",
            "LGwebOSTV.fritz.box",
        ]
        self.assertEqual(wlan_monitor.select_best_hostname(names), "LGwebOSTV")
        mac_only = ["C42996C9B46D.fritz.box"]
        self.assertEqual(wlan_monitor.select_best_hostname(mac_only), "C42996C9B46D")

    def test_freq_to_band_channel_and_quality(self):
        self.assertEqual(wlan_monitor.freq_to_band_channel(2437.0), ("2.4 GHz", 6))
        self.assertEqual(wlan_monitor.freq_to_band_channel(5180.0), ("5 GHz", 36))
        self.assertEqual(wlan_monitor.freq_to_band_channel(6135.0), ("6 GHz", 37))
        self.assertEqual(wlan_monitor.dbm_to_quality(-50), 100)
        self.assertEqual(wlan_monitor.dbm_to_quality(-70), 60)
        self.assertEqual(wlan_monitor.dbm_to_quality(-100), 0)

    def test_dns_ptr_packet_roundtrip_and_malformed_safety(self):
        pkt = wlan_monitor.build_dns_ptr_packet(42, "192.168.178.1")
        self.assertTrue(len(pkt) > 12)
        # Truncated/malformed packets must not raise
        self.assertEqual(wlan_monitor.parse_dns_ptr_packet(b""), (None, []))
        self.assertEqual(wlan_monitor.parse_dns_ptr_packet(b"\x00" * 12), (0, []))
        # Compression pointer loop protection
        loop_pkt = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + b"\xc0\x0c" * 8
        qid, names = wlan_monitor.parse_dns_ptr_packet(loop_pkt)
        self.assertEqual(qid, 7)
        self.assertEqual(names, [])

    def test_shorten_vendor(self):
        self.assertEqual(wlan_monitor.shorten_vendor("Sonova Consumer Hearing GmbH"), "Sennheiser (Sonova)")
        self.assertEqual(wlan_monitor.shorten_vendor("CLOUD NETWORK TECHNOLOGY SINGAPORE PTE."), "Foxconn / MediaTek")
        self.assertEqual(wlan_monitor.shorten_vendor("Espressif Inc."), "Espressif")


SUBNET = ipaddress.IPv4Network("192.168.178.0/24")


class NetworkStateTests(unittest.TestCase):
    def test_same_network_detects_changes(self):
        base = ("wlan0", "192.168.178.1", "192.168.178.0/24")
        home = {"base": base, "ssid": "Home", "gateway_mac": "aa:bb:cc:dd:ee:ff"}
        self.assertFalse(wlan_monitor.same_network(None, home))
        self.assertTrue(wlan_monitor.same_network(home, dict(home)))
        # Unknown values (not yet learned) do not count as a change
        self.assertTrue(wlan_monitor.same_network(home, dict(home, ssid="", gateway_mac="")))
        self.assertFalse(wlan_monitor.same_network(home, dict(home, ssid="Cafe")))
        self.assertFalse(wlan_monitor.same_network(home, dict(home, gateway_mac="11:22:33:44:55:66")))
        self.assertFalse(wlan_monitor.same_network(home, dict(home, base=("wlan0", "10.0.0.1", "10.0.0.0/24"))))

    def test_reset_network_forgets_devices(self):
        with mock.patch.object(wlan_monitor, "load_trusted", return_value=[]):
            mon = wlan_monitor.Monitor()
        mon.known["192.168.178.5"] = {"ip": "192.168.178.5", "last_seen": 1.0}
        mon.ptr_names["192.168.178.5"] = ["phone.fritz.box"]
        mon.domain = "fritz.box"
        mon.gateway_web = "http"
        mon.reset_network({"base": ("wlan0", "10.0.0.1", "10.0.0.0/24"), "ssid": "Cafe", "gateway_mac": ""})
        self.assertEqual(mon.known, {})
        self.assertEqual(mon.ptr_names, {})
        self.assertEqual(mon.domain, "")
        self.assertIsNone(mon.gateway_web)
        self.assertEqual(mon.last_full_scan, -math.inf)

    def test_neighbor_states(self):
        out = (
            "192.168.178.1 lladdr 1c:23:a2:92:2a:6c REACHABLE\n"
            "192.168.178.25 lladdr d4:00:00:00:00:01 STALE\n"
            "192.168.178.30 lladdr d4:00:00:00:00:02 FAILED\n"
            "192.168.178.31 INCOMPLETE\n"
            "192.168.178.32 lladdr $(id) STALE\n"
            "garbage line\n"
        )
        neigh = wlan_monitor.parse_neighbors(out)
        self.assertEqual(set(neigh), {"192.168.178.1", "192.168.178.25"})
        now = 1000.0
        self.assertTrue(wlan_monitor.neighbor_online("192.168.178.1", "REACHABLE", now, {}))
        self.assertFalse(wlan_monitor.neighbor_online("192.168.178.25", "STALE", now, {}))
        self.assertTrue(wlan_monitor.neighbor_online("192.168.178.25", "STALE", now, {"192.168.178.25": now - 10}))
        self.assertFalse(wlan_monitor.neighbor_online("192.168.178.25", "STALE", now, {"192.168.178.25": now - 300}))

    def test_default_routes_from_proc(self):
        text = (
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
            "enp1s0\t00000000\t0100A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
            "wlp2s0\t00000000\t01B2A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
            "wlp2s0\t00B2A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n"
        )
        routes, primary = wlan_monitor.parse_default_routes(text)
        self.assertEqual(routes, {"enp1s0": "192.168.0.1", "wlp2s0": "192.168.178.1"})
        self.assertEqual(primary, "enp1s0")

    def test_proc_wireless_signal(self):
        text = (
            "Inter-| sta-|   Quality        |   Discarded packets\n"
            " face | tus | link level noise |  nwid  crypt   frag\n"
            "wlp15s0: 0000   58.  -52.  -256        0      0      0\n"
        )
        self.assertEqual(wlan_monitor.proc_wireless_signal("wlp15s0", text), -52)
        self.assertIsNone(wlan_monitor.proc_wireless_signal("wlan9", text))

    def test_devices_revision_ignores_order_of_keys_only(self):
        dev = {"ip": "192.168.178.2", "name": "A", "online": True}
        self.assertEqual(wlan_monitor.devices_revision([dev]), wlan_monitor.devices_revision([dict(dev)]))
        self.assertNotEqual(
            wlan_monitor.devices_revision([dev]), wlan_monitor.devices_revision([dict(dev, online=False)])
        )


class DnsTests(unittest.TestCase):
    def test_reply_must_come_from_server_with_outstanding_id(self):
        reply = struct.pack("!HHHHHH", 77, 0x8180, 0, 0, 0, 0)
        pending = {77: "192.168.178.5"}
        self.assertEqual(wlan_monitor.match_dns_reply(reply, ("192.168.178.66", 53), "192.168.178.1", pending)[0], None)
        self.assertEqual(wlan_monitor.match_dns_reply(reply, ("192.168.178.1", 5353), "192.168.178.1", pending)[0], None)
        self.assertIn(77, pending)
        self.assertEqual(wlan_monitor.match_dns_reply(reply, ("192.168.178.1", 53), "192.168.178.1", pending)[0], "192.168.178.5")
        # Each ID is accepted only once
        self.assertEqual(wlan_monitor.match_dns_reply(reply, ("192.168.178.1", 53), "192.168.178.1", pending)[0], None)

    def test_domain_learning_and_stripping(self):
        names = ["phone.example.lan", "tv.example.lan", "example.lan"]
        self.assertEqual(wlan_monitor.learn_domain(names), "example.lan")
        self.assertEqual(wlan_monitor.learn_domain(["one.host.x"]), "")
        domains = list(wlan_monitor.DEFAULT_DOMAINS) + ["example.lan"]
        self.assertEqual(wlan_monitor.select_best_hostname(["phone.example.lan"], domains), "phone")
        self.assertEqual(wlan_monitor.select_best_hostname(["printer.speedport.ip"]), "printer")
        self.assertEqual(wlan_monitor.select_best_hostname(["nas.home.arpa"]), "nas")
        self.assertEqual(wlan_monitor.resolv_search_domains("search . corp.example\ndomain $(id)\n"), ["corp.example"])


class WebUrlTests(unittest.TestCase):
    def test_make_web_url_accepts_only_local_literals(self):
        self.assertEqual(wlan_monitor.make_web_url("http", "192.168.178.1", subnet=SUBNET), "http://192.168.178.1/")
        self.assertEqual(
            wlan_monitor.make_web_url("https", "192.168.178.9", "8443", "/admin/index.html", SUBNET),
            "https://192.168.178.9:8443/admin/index.html",
        )
        self.assertEqual(wlan_monitor.make_web_url("http", "192.168.178.9", 80, "/", SUBNET), "http://192.168.178.9/")
        self.assertEqual(wlan_monitor.make_web_url("http", "8.8.8.8"), "")
        self.assertEqual(wlan_monitor.make_web_url("http", "127.0.0.1"), "")
        self.assertEqual(wlan_monitor.make_web_url("http", "10.0.0.5", subnet=SUBNET), "")
        self.assertEqual(wlan_monitor.make_web_url("file", "192.168.178.9", subnet=SUBNET), "")
        self.assertEqual(wlan_monitor.make_web_url("javascript", "192.168.178.9"), "")
        self.assertEqual(wlan_monitor.make_web_url("http", "evil.example"), "")
        self.assertEqual(wlan_monitor.make_web_url("http", "192.168.178.9", "99999"), "")
        self.assertEqual(wlan_monitor.make_web_url("http", "192.168.178.9", "80; rm"), "")

    def test_make_web_url_neutralizes_hostile_paths(self):
        for path in ("/../../etc", "/a b", "/$(id)", "/x\n", "//evil.example/", "/<img src=x>"):
            url = wlan_monitor.make_web_url("http", "192.168.178.9", None, path, SUBNET)
            self.assertRegex(url, r"^http://192\.168\.178\.9/[A-Za-z0-9._~/-]*$")
            self.assertNotIn("..", url)
        self.assertEqual(
            wlan_monitor.make_web_url("http", "192.168.178.9", None, "/ui?x=1#y", SUBNET), "http://192.168.178.9/ui"
        )

    def test_admin_url_must_point_at_the_device(self):
        self.assertEqual(
            wlan_monitor.parse_admin_url("http://192.168.178.40:631/printers/x", "192.168.178.40", "printer"),
            ("http", 631, "/printers/x"),
        )
        self.assertEqual(
            wlan_monitor.parse_admin_url("https://printer.local./", "192.168.178.40", "printer"), ("https", None, "/")
        )
        self.assertIsNone(wlan_monitor.parse_admin_url("http://evil.example/", "192.168.178.40", "printer"))
        self.assertIsNone(wlan_monitor.parse_admin_url("http://192.168.178.41/", "192.168.178.40", "printer"))
        self.assertIsNone(wlan_monitor.parse_admin_url("file:///etc/passwd", "192.168.178.40", "printer"))
        self.assertIsNone(wlan_monitor.parse_admin_url("http://192.168.178.40:bad/", "192.168.178.40", "printer"))

    def test_mdns_lines_give_web_urls(self):
        lines = [
            '=;wlan0;IPv4;Coffee;_http._tcp;local;coffee.local;192.168.178.100;8080;"path=/status"',
            '=;wlan0;IPv4;Printer;_ipp._tcp;local;printer.local;192.168.178.40;631;"adminurl=http://printer.local:631/admin" "ty=Laser"',
            '=;wlan0;IPv4;Fake;_http._tcp;local;fake.local;8.8.8.8;80;',
            '=;wlan0;IPv4;Evil;_ipp._tcp;local;evil.local;192.168.178.41;631;"adminurl=http://evil.example/"',
            '=;wlan0;IPv4;TV;_googlecast._tcp;local;tv.local;192.168.178.25;8009;"md=Chromecast"',
        ]
        hosts = wlan_monitor.parse_mdns_lines(lines, "wlan0", SUBNET)
        self.assertEqual(hosts["192.168.178.100"]["web"], ["http://192.168.178.100:8080/status"])
        self.assertEqual(hosts["192.168.178.40"]["web"], ["http://192.168.178.40:631/admin"])
        self.assertNotIn("8.8.8.8", hosts)
        self.assertEqual(hosts["192.168.178.41"]["web"], [])
        self.assertEqual(hosts["192.168.178.25"]["web"], [])
        self.assertEqual(hosts["192.168.178.25"]["model"], "Chromecast")


class TrustTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_roundtrip_and_private_permissions(self):
        nets = [{"ssid": "Home", "gateway_mac": "aa:bb:cc:dd:ee:ff"}]
        self.assertTrue(wlan_monitor.save_trusted(nets))
        self.assertEqual(wlan_monitor.load_trusted(), nets)
        directory = wlan_monitor.config_dir()
        self.assertEqual(os.stat(directory).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(os.path.join(directory, wlan_monitor.TRUST_FILE)).st_mode & 0o777, 0o600)
        self.assertTrue(wlan_monitor.is_trusted({"ssid": "Home", "gateway_mac": "aa:bb:cc:dd:ee:ff"}, nets))
        self.assertFalse(wlan_monitor.is_trusted({"ssid": "Home", "gateway_mac": "11:22:33:44:55:66"}, nets))
        self.assertFalse(wlan_monitor.is_trusted({"ssid": "Home", "gateway_mac": ""}, nets))

    def test_refuses_symlinked_file_and_dir(self):
        target = os.path.join(self.tmp.name, "elsewhere.json")
        with open(target, "w") as handle:
            handle.write('{"networks": [{"ssid": "X", "gateway_mac": "aa:bb:cc:dd:ee:ff"}]}')
        os.makedirs(wlan_monitor.config_dir())
        os.symlink(target, os.path.join(wlan_monitor.config_dir(), wlan_monitor.TRUST_FILE))
        self.assertEqual(wlan_monitor.load_trusted(), [])

        other = os.path.join(self.tmp.name, "other")
        os.makedirs(other)
        os.unlink(os.path.join(wlan_monitor.config_dir(), wlan_monitor.TRUST_FILE))
        os.rmdir(wlan_monitor.config_dir())
        os.symlink(other, wlan_monitor.config_dir())
        self.assertFalse(wlan_monitor.save_trusted([{"ssid": "", "gateway_mac": "aa:bb:cc:dd:ee:ff"}]))
        self.assertEqual(os.listdir(other), [])

    def test_ignores_malformed_entries(self):
        os.makedirs(wlan_monitor.config_dir())
        with open(os.path.join(wlan_monitor.config_dir(), wlan_monitor.TRUST_FILE), "w") as handle:
            handle.write('{"networks": [{"gateway_mac": "$(id)"}, {"ssid": 5, "gateway_mac": "aa:bb:cc:dd:ee:ff"},'
                         ' "x", {"ssid": "<b>Home</b>", "gateway_mac": "AA:BB:CC:DD:EE:01"}]}')
        self.assertEqual(wlan_monitor.load_trusted(), [{"ssid": "bHome/b", "gateway_mac": "aa:bb:cc:dd:ee:01"}])

    def test_commands(self):
        self.assertEqual(wlan_monitor.parse_command(" Rescan\r\n"), "rescan")
        self.assertEqual(wlan_monitor.parse_command("rm -rf /"), "")
        mon = wlan_monitor.Monitor()
        self.assertFalse(mon.handle("trust"))  # gateway MAC not known yet
        mon.trust_identity = {"ssid": "Home", "gateway_mac": "aa:bb:cc:dd:ee:ff"}
        self.assertTrue(mon.handle("trust"))
        self.assertEqual(wlan_monitor.load_trusted(), [mon.trust_identity])
        self.assertTrue(mon.handle("trust"))  # no duplicates
        self.assertEqual(len(mon.trusted), 1)
        self.assertTrue(mon.handle("untrust"))
        self.assertEqual(wlan_monitor.load_trusted(), [])
        self.assertTrue(mon.handle("open"))
        self.assertTrue(mon.panel_open)
        self.assertFalse(mon.handle("closed"))
        self.assertTrue(mon.handle("rescan"))
        self.assertTrue(mon.force_next)


class FloodSocket:
    """Fake datagram socket whose peers never stop answering (spoofed and real sources)."""

    reads = 0

    def __init__(self, *args):
        self.n = 0

    def setblocking(self, flag):
        pass

    def connect(self, addr):
        pass

    def sendto(self, data, addr):
        pass

    def send(self, data):
        pass

    def recvfrom(self, size):
        FloodSocket.reads += 1
        self.n += 1
        src = "192.168.178.%d" % (self.n % 3 + 1) if self.n % 2 else "10.66.%d.%d" % (self.n // 250 % 250, self.n % 250)
        return b"\x00" + b"x" * 15, (src, 0)

    def close(self):
        pass


class SweepBudgetTests(unittest.TestCase):
    def test_flood_is_bounded_and_spoofed_sources_ignored(self):
        targets = ["192.168.178.%d" % i for i in range(1, 11)]
        FloodSocket.reads = 0
        with mock.patch.object(wlan_monitor.socket, "socket", FloodSocket), \
                mock.patch.object(wlan_monitor.time, "sleep", lambda s: None):
            start = wlan_monitor.time.monotonic()
            _, responders = wlan_monitor.sweep(targets, dns_server="192.168.178.1", settle=0.05)
            elapsed = wlan_monitor.time.monotonic() - start
        self.assertLess(elapsed, wlan_monitor.SWEEP_MAX_SECONDS + 1)
        budget = wlan_monitor.SWEEP_MAX_REPLIES * len(targets) + 16
        self.assertLessEqual(FloodSocket.reads, 2 * budget)
        self.assertTrue(responders)
        self.assertTrue(responders <= set(targets))

    def test_sweep_deadline_stops_slow_flood(self):
        targets = ["192.168.178.%d" % i for i in range(1, 255)]
        clock = {"t": 0.0}

        def fake_monotonic():
            clock["t"] += 0.05
            return clock["t"]
        with mock.patch.object(wlan_monitor.socket, "socket", FloodSocket), \
                mock.patch.object(wlan_monitor.time, "sleep", lambda s: None), \
                mock.patch.object(wlan_monitor.time, "monotonic", fake_monotonic):
            wlan_monitor.sweep(targets, settle=100)
        self.assertLess(clock["t"], wlan_monitor.SWEEP_MAX_SECONDS + 1)

    def test_prune_reachable(self):
        net = ipaddress.IPv4Network("192.168.178.0/24")
        keep = lambda ip: ipaddress.IPv4Address(ip) in net
        state = {"192.168.178.5": 100.0, "192.168.178.6": 10.0, "10.66.1.1": 100.0}
        self.assertEqual(wlan_monitor.prune_reachable(state, 120.0, keep), {"192.168.178.5": 100.0})


if __name__ == "__main__":
    unittest.main()
