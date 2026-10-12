import importlib.util
import ipaddress
import math
import os
import struct
import tempfile
import time
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


class WebCacheBoundTests(unittest.TestCase):
    NET = ipaddress.IPv4Network("192.168.178.0/24")

    def advert(self, path, ip="192.168.178.50", n=0):
        return ('=;wlan0;IPv4;Dev%d;_http._tcp;local;dev.local;%s;8080;"path=/%s"' % (n, ip, path))

    def test_fresh_paths_are_capped_per_host(self):
        lines = [self.advert("p%d" % i, n=i) for i in range(500)]
        hosts = wlan_monitor.parse_mdns_lines(lines, "wlan0", self.NET)
        entry = hosts["192.168.178.50"]
        self.assertEqual(len(entry["web"]), wlan_monitor.MDNS_MAX_WEB)
        self.assertLessEqual(len(entry["names"]), wlan_monitor.MDNS_MAX_NAMES)
        self.assertLessEqual(len(entry["services"]), wlan_monitor.MDNS_MAX_SERVICES)

    def test_rotating_adverts_do_not_grow_cache(self):
        cache = {}
        now = 1000.0
        for round_no in range(200):
            lines = [self.advert("r%d-%d" % (round_no, i)) for i in range(wlan_monitor.MDNS_MAX_WEB)]
            hosts = wlan_monitor.parse_mdns_lines(lines, "wlan0", self.NET)
            for url in hosts["192.168.178.50"]["web"]:
                cache[url] = (now + wlan_monitor.WEB_FAIL_TTL, False)  # closed port
            cache = wlan_monitor.prune_web_cache(cache, hosts, now)
            now += 15
        self.assertLessEqual(len(cache), wlan_monitor.MDNS_MAX_WEB)

    def test_expired_and_overflow_entries_dropped(self):
        hosts = {"192.168.178.%d" % i: {"web": ["http://192.168.178.%d:80/" % i]} for i in range(1, 200)}
        cache = {"http://192.168.178.%d:80/" % i: (100.0 + i, False) for i in range(1, 200)}
        pruned = wlan_monitor.prune_web_cache(cache, hosts, 150.0, limit=20)
        self.assertEqual(len(pruned), 20)
        self.assertTrue(all(v[0] > 150.0 for v in pruned.values()))


if __name__ == "__main__":
    unittest.main()


class NamingTests(unittest.TestCase):
    def test_tidy_name(self):
        tidy = wlan_monitor.tidy_name
        self.assertEqual(tidy("PHILIPS_EP8757_20_392985"), "Philips EP8757")
        self.assertEqual(tidy("MacBook-Pro-von-Uwe-2"), "MacBook Pro von Uwe 2")
        self.assertEqual(tidy("Hue Bridge - C9B46D"), "Hue Bridge")
        self.assertEqual(tidy("AMBEO Soundbar Plus"), "AMBEO Soundbar Plus")
        self.assertEqual(tidy("LGwebOSTV"), "LGwebOSTV")
        self.assertEqual(tidy("192-168-178-5"), "192-168-178-5")
        self.assertEqual(tidy("123_456"), "123_456")
        self.assertEqual(tidy("SwitchBot-HubMiniMatter-47DBEC"), "SwitchBot HubMiniMatter")
        self.assertEqual(tidy("Office-2"), "Office 2")

    def test_device_kind(self):
        kind = wlan_monitor.device_kind
        self.assertEqual(kind("iPhone 17 pro max", "", "", "Private MAC", []), "phone")
        self.assertEqual(kind("iPad Pro", "", "", "", []), "tablet")
        self.assertEqual(kind("MacBook Pro", "", "", "Apple", ["_airplay._tcp"]), "laptop")
        self.assertEqual(kind("[LG] webOS TV OLED65", "LGwebOSTV", "", "LG Electronics", []), "tv")
        self.assertEqual(kind("Brother HL-L2350DW", "", "", "", []), "printer")
        self.assertEqual(kind("Office", "", "", "", ["_ipp._tcp"]), "printer")
        self.assertEqual(kind("", "", "", "Espressif", []), "smarthome")
        self.assertEqual(kind("Philips EP8757", "", "", "Philips (Versuni)", []), "appliance")
        self.assertEqual(kind("Hue Bridge", "", "", "Philips Hue (Signify)", []), "light")
        self.assertEqual(kind("x", "", "", "", [], is_gateway=True), "router")
        self.assertEqual(kind("something", "", "", "Apple", []), "unknown")

    def test_vendor_only_names_say_what_the_device_is(self):
        choose = wlan_monitor.choose_device_name
        self.assertEqual(choose("10.0.0.5", False, False, "", {}, "Espressif"), "Smart-home device (Espressif)")
        self.assertEqual(choose("10.0.0.5", False, False, "", {}, "Apple"), "Apple device")
        self.assertEqual(choose("10.0.0.5", False, False, "", {}, "Private MAC"), "10.0.0.5")
        self.assertEqual(choose("10.0.0.1", False, True, "fritz.box", {}, "AVM"), "Router")
        self.assertEqual(choose("10.0.0.7", False, False, "PHILIPS_EP8757_20_392985", {}, ""), "Philips EP8757")


class DeviceCommandTests(unittest.TestCase):
    def test_json_commands_are_validated(self):
        parse = wlan_monitor.parse_command
        self.assertEqual(parse('{"cmd":"rename","mac":"AA:BB:CC:DD:EE:FF","name":"  <b>Pellet\\n stove</b>  "}'),
                         {"cmd": "rename", "mac": "aa:bb:cc:dd:ee:ff", "name": "bPellet stove/b"})
        self.assertEqual(parse('{"cmd":"rename","mac":"aa:bb:cc:dd:ee:ff","name":"' + "x" * 80 + '"}')["name"], "x" * 40)
        self.assertEqual(parse('{"cmd":"pin","mac":"aa:bb:cc:dd:ee:ff","on":"yes"}')["on"], False)
        self.assertEqual(parse('{"cmd":"alerts","on":true}'), {"cmd": "alerts", "on": True})
        self.assertEqual(parse('{"cmd":"rename","mac":"$(id)","name":"x"}'), "")
        self.assertEqual(parse('{"cmd":"rename","mac":["aa"],"name":"x"}'), "")
        self.assertEqual(parse('{"cmd":"rename","mac":"aa:bb:cc:dd:ee:ff","name":5}')["name"], "")
        self.assertEqual(parse('{"cmd":"shell","mac":"aa:bb:cc:dd:ee:ff"}'), "")
        self.assertEqual(parse('{"cmd":"pin"'), "")
        self.assertEqual(parse("[1]"), "")
        self.assertEqual(parse('{"cmd":"pin","mac":"aa:bb:cc:dd:ee:ff","pad":"' + "x" * 1100 + '"}'), "")
        self.assertEqual(parse("known_all"), "known_all")


class StoreTests(unittest.TestCase):
    HOME = {"ssid": "Home", "gateway_mac": "aa:bb:cc:dd:ee:01"}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()
        self.notify = mock.patch.object(wlan_monitor, "notify_new_devices")
        self.notified = self.notify.start()

    def tearDown(self):
        self.notify.stop()
        self.env.stop()
        self.tmp.cleanup()

    def device(self, mac, name="Thing", **extra):
        return dict({"ip": "10.0.0.9", "name": name, "mac": mac, "is_self": False, "is_gateway": False}, **extra)

    def monitor(self):
        mon = wlan_monitor.Monitor()
        mon.trust_identity = dict(self.HOME)
        return mon

    def test_store_roundtrip_permissions_and_malformed_entries(self):
        store = {"alerts": False, "view": {"mode": "platform", "collapsed": ["apple"]}, "networks": {"aa:bb:cc:dd:ee:01|Home": {"since": 5, "devices": {
            "aa:bb:cc:dd:ee:02": {"name": "Stove", "pinned": True, "hidden": False, "new": False, "first": 5}}}}}
        self.assertTrue(wlan_monitor.save_store(store))
        self.assertEqual(wlan_monitor.load_store(), store)
        path = os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_FILE)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        with open(path, "w") as handle:
            handle.write('{"networks": {"nomac": {}, "aa:bb:cc:dd:ee:01|<x>": {}, "aa:bb:cc:dd:ee:01|Home": '
                         '{"since": true, "devices": {"$(id)": {}, "aa:bb:cc:dd:ee:03": {"name": "<i>TV</i>", "pinned": 1}}}}}')
        loaded = wlan_monitor.load_store()
        self.assertTrue(loaded["alerts"])
        self.assertEqual(list(loaded["networks"]), ["aa:bb:cc:dd:ee:01|Home"])
        net = loaded["networks"]["aa:bb:cc:dd:ee:01|Home"]
        self.assertIsNone(net["since"])
        self.assertEqual(net["devices"], {"aa:bb:cc:dd:ee:03": {"name": "iTV/i", "pinned": False, "hidden": False, "new": False, "first": 0}})

    def test_store_refuses_symlink(self):
        target = os.path.join(self.tmp.name, "elsewhere.json")
        with open(target, "w") as handle:
            handle.write('{"alerts": false}')
        os.makedirs(wlan_monitor.config_dir())
        os.symlink(target, os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_FILE))
        self.assertTrue(wlan_monitor.load_store()["alerts"])

    def test_store_device_is_bounded(self):
        net = {"since": 0, "devices": {}}
        with mock.patch.object(wlan_monitor, "MAX_STORE_DEVICES", 3):
            wlan_monitor.store_device(net, "aa:bb:cc:dd:ee:01", 1)["name"] = "Keep"
            for i in range(2, 9):
                wlan_monitor.store_device(net, f"aa:bb:cc:dd:ee:0{i}", i)
        self.assertEqual(len(net["devices"]), 3)
        self.assertIn("aa:bb:cc:dd:ee:01", net["devices"])

    def test_baseline_then_new_devices_alert(self):
        mon = self.monitor()
        with mock.patch.object(wlan_monitor.time, "time", return_value=1000.0):
            first = [self.device("aa:bb:cc:dd:ee:02")]
            self.assertTrue(mon.apply_store(first, True, "Home"))
        self.assertFalse(first[0]["new"])
        self.notified.assert_not_called()
        with mock.patch.object(wlan_monitor.time, "time", return_value=1000.0 + wlan_monitor.BASELINE_SECONDS + 1):
            later = [self.device("aa:bb:cc:dd:ee:02"), self.device("aa:bb:cc:dd:ee:03", "Stranger")]
            mon.apply_store(later, True, "Home")
        self.assertEqual([d["new"] for d in later], [False, True])
        self.notified.assert_called_once_with("Home", ["Stranger"])
        # Persisted: a fresh monitor still knows the device is new, and alerts only once.
        mon2 = self.monitor()
        again = [self.device("aa:bb:cc:dd:ee:03", "Stranger")]
        mon2.apply_store(again, True, "Home")
        self.assertTrue(again[0]["new"])
        self.assertEqual(self.notified.call_count, 1)

    def test_untrusted_networks_are_not_tracked(self):
        mon = self.monitor()
        devices = [self.device("aa:bb:cc:dd:ee:02")]
        self.assertFalse(mon.apply_store(devices, False, "Cafe"))
        self.assertFalse(os.path.exists(os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_FILE)))
        self.assertTrue(devices[0]["can_edit"])

    def test_rename_pin_hide_known(self):
        mon = self.monitor()
        mac = "aa:bb:cc:dd:ee:02"
        self.assertFalse(mon.handle({"cmd": "rename", "mac": mac, "name": "Stove"}))  # not on this network
        mon.known = {"10.0.0.9": {"mac": mac}}
        self.assertTrue(mon.handle({"cmd": "rename", "mac": mac, "name": "Stove"}))
        self.assertTrue(mon.handle({"cmd": "pin", "mac": mac, "on": True}))
        devices = [self.device(mac, "Smart-home device (Microchip)")]
        mon.apply_store(devices, False, "Home")
        self.assertEqual(devices[0]["name"], "Stove")
        self.assertEqual(devices[0]["auto_name"], "Smart-home device (Microchip)")
        self.assertTrue(devices[0]["custom_name"] and devices[0]["pinned"])
        self.assertTrue(mon.handle({"cmd": "hide", "mac": mac, "on": True}))
        rec = wlan_monitor.load_store()["networks"]["aa:bb:cc:dd:ee:01|Home"]["devices"][mac]
        self.assertTrue(rec["hidden"])
        self.assertFalse(rec["pinned"])
        mon.handle({"cmd": "rename", "mac": mac, "name": ""})
        devices = [self.device(mac, "Auto")]
        mon.apply_store(devices, False, "Home")
        self.assertEqual(devices[0]["name"], "Auto")
        self.assertFalse(devices[0]["custom_name"])
        rec["new"] = True
        mon.store["networks"]["aa:bb:cc:dd:ee:01|Home"]["devices"][mac]["new"] = True
        self.assertTrue(mon.handle("known_all"))
        self.assertFalse(wlan_monitor.load_store()["networks"]["aa:bb:cc:dd:ee:01|Home"]["devices"][mac]["new"])
        self.assertTrue(mon.handle({"cmd": "alerts", "on": False}))
        self.assertFalse(wlan_monitor.load_store()["alerts"])


class MdnsModelTests(unittest.TestCase):
    def test_flag_values_are_not_models(self):
        net = ipaddress.IPv4Network("10.0.0.0/24")
        lines = [
            '=;wlan0;IPv4;Mac;_companion-link._tcp;local;mac.local;10.0.0.5;7000;"model=0,1,2"',
            '=;wlan0;IPv4;Printer;_ipp._tcp;local;prn.local;10.0.0.6;631;"ty=Brother HL-L2350DW" "md=HL-L2350DW"',
        ]
        hosts = wlan_monitor.parse_mdns_lines(lines, "wlan0", net)
        self.assertEqual(hosts["10.0.0.5"]["model"], "")
        self.assertEqual(hosts["10.0.0.6"]["model"], "HL-L2350DW")


class NotifyTests(unittest.TestCase):
    def test_notification_text_is_plain_and_bounded(self):
        with mock.patch.object(wlan_monitor.shutil, "which", return_value="/usr/bin/notify-send"), \
                mock.patch.object(wlan_monitor, "run_cmd") as run:
            wlan_monitor.notify_new_devices('<img src="http://x/y.png">Home\r\n', ["<b>A</b>", "B & C", "D", "E"])
        argv = run.call_args[0][0]
        self.assertEqual(argv[:6], ["notify-send", "-a", "WLAN Monitor", "-i", "network-wireless", "--"])
        for text in argv[6:]:
            self.assertFalse(set(text) & set("<>&\r\n"))
        self.assertTrue(argv[6].startswith("4 new devices on "))
        self.assertIn("and 1 more", argv[7])


class GroupTests(unittest.TestCase):
    def test_device_group(self):
        group = wlan_monitor.device_group
        self.assertEqual(group("phone", "Private MAC", "iPhone 17 pro max", "", []), "apple")
        self.assertEqual(group("unknown", "Private MAC", "Thing", "", ["_companion-link._tcp"]), "apple")
        self.assertEqual(group("phone", "Private MAC", "Galaxy S24", "", []), "android")
        self.assertEqual(group("unknown", "Samsung Electronics", "x", "", []), "android")
        self.assertEqual(group("tv", "Samsung Electronics", "Samsung TV", "", []), "media")
        self.assertEqual(group("tv", "LG Electronics", "[LG] webOS TV", "", ["_airplay._tcp"]), "media")
        self.assertEqual(group("router", "Apple", "AirPort", "", []), "network")
        self.assertEqual(group("light", "", "Hue Bridge", "", []), "smarthome")
        self.assertEqual(group("printer", "", "HL", "", []), "office")
        self.assertEqual(group("unknown", "", "x", "", []), "other")

    def test_bssid_owner_matches_middle_bytes(self):
        devices = [
            {"mac": "1c:23:a2:92:2a:6c", "is_gateway": True, "kind": "router", "name": "Router"},
            {"mac": "2e:23:a2:11:22:33", "is_gateway": False, "kind": "phone", "name": "Phone"},
        ]
        self.assertEqual(wlan_monitor.bssid_owner("2e:23:a2:92:2a:80", devices)["name"], "Router")
        self.assertIsNone(wlan_monitor.bssid_owner("2e:23:a2:11:22:99", devices))  # a phone is no access point
        self.assertIsNone(wlan_monitor.bssid_owner("nonsense", devices))

    def test_view_command(self):
        parse = wlan_monitor.parse_command
        self.assertEqual(parse('{"cmd":"view","mode":"type","collapsed":["apple","apple","aa:bb:cc:dd:ee:ff","$(x)",5]}'),
                         {"cmd": "view", "mode": "type", "collapsed": ["apple", "aa:bb:cc:dd:ee:ff"]})
        self.assertEqual(parse('{"cmd":"view","mode":"tree","collapsed":[]}'), "")


class FritzTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_digest_rfc2617_vector(self):
        challenge = {"realm": "testrealm@host.com", "nonce": "dcd98b7102dd2f0e8b11d0f600bfb0c093", "qop": "auth",
                     "opaque": "5ccc069c403ebaf9f0171e9517f40e41"}
        header = wlan_monitor.digest_authorization("Mufasa", "Circle Of Life", "GET", "/dir/index.html",
                                                   challenge, "0a4f113b")
        self.assertIn('response="6629fae49393a05397450978507c4ef1"', header)
        parsed = wlan_monitor.parse_digest_challenge('Digest realm="F!Box SOAP-Auth", nonce="ABC123", algorithm=MD5, qop="auth"')
        self.assertEqual((parsed["realm"], parsed["nonce"], parsed["qop"]), ("F!Box SOAP-Auth", "ABC123", "auth"))
        self.assertIsNone(wlan_monitor.parse_digest_challenge("Basic realm=x"))

    def test_login_command_validation(self):
        parse = wlan_monitor.parse_command
        self.assertEqual(parse('{"cmd":"fritz_login","user":"fritz1234","password":"p\\"w d"}'),
                         {"cmd": "fritz_login", "user": "fritz1234", "password": 'p"w d'})
        self.assertEqual(parse('{"cmd":"fritz_login","user":"a\\" b","password":"x"}'), "")  # quotes would break the header
        self.assertEqual(parse('{"cmd":"fritz_login","user":"u","password":""}'), "")
        self.assertEqual(parse('{"cmd":"fritz_login","user":"u","password":"a\\nb"}'), "")
        self.assertEqual(parse('{"cmd":"fritz_login","user":"u","password":"' + "x" * 129 + '"}'), "")

    MESH = {"nodes": [
        {"uid": "n-1", "device_name": "fritz.box", "device_model": "FRITZ!Box 5690 Pro", "device_mac_address": "1C:23:A2:92:2A:6C",
         "mesh_role": "master", "node_interfaces": [
             {"uid": "ni-ap5", "name": "AP:5G:0", "type": "WLAN", "node_links": []},
             {"uid": "ni-lan", "name": "LAN:1", "type": "LAN", "node_links": []}]},
        {"uid": "n-2", "device_name": "Repeater Kitchen", "device_model": "FRITZ!Repeater 3000", "device_mac_address": "aa:aa:aa:00:00:02",
         "mesh_role": "slave", "node_interfaces": [
             {"uid": "ni-r-up", "name": "UPLINK:5G:0", "type": "WLAN", "node_links": [
                 {"state": "CONNECTED", "node_1_uid": "n-1", "node_2_uid": "n-2", "node_interface_1_uid": "ni-ap5",
                  "node_interface_2_uid": "ni-r-up", "cur_data_rate_rx": 1201000}]},
             {"uid": "ni-r-ap2", "name": "AP:2G:0", "type": "WLAN", "node_links": []}]},
        {"uid": "n-3", "device_name": "Pellet-Ofen", "device_mac_address": "60:8a:10:cf:a6:2e", "mesh_role": "unknown",
         "node_interfaces": [{"uid": "ni-c", "name": "", "type": "WLAN", "node_links": [
             {"state": "CONNECTED", "node_1_uid": "n-2", "node_2_uid": "n-3", "node_interface_1_uid": "ni-r-ap2",
              "node_interface_2_uid": "ni-c", "cur_data_rate_rx": 65000, "rx_rcpi": 120}]}]},
        {"uid": "n-4", "device_name": "<b>Old phone</b>", "device_mac_address": "aa:aa:aa:00:00:04", "mesh_role": "unknown",
         "node_interfaces": [{"uid": "ni-o", "type": "WLAN", "node_links": [
             {"state": "DISCONNECTED", "node_1_uid": "n-1", "node_2_uid": "n-4"}]}]},
        "junk", {"uid": 5}, {"uid": "n-6", "device_mac_address": "$(id)"},
    ]}

    def test_parse_mesh(self):
        info, aps = wlan_monitor.parse_mesh(self.MESH)
        self.assertEqual(set(info), {"1c:23:a2:92:2a:6c", "aa:aa:aa:00:00:02", "60:8a:10:cf:a6:2e"})
        stove = info["60:8a:10:cf:a6:2e"]
        self.assertEqual((stove["via"], stove["band"], stove["rate_mbps"], stove["signal_dbm"], stove["box_name"]),
                         ("Repeater Kitchen", "2.4 GHz", 65, -50, "Pellet-Ofen"))
        repeater = info["aa:aa:aa:00:00:02"]
        self.assertEqual((repeater["role"], repeater["via"], repeater["band"], repeater["rate_mbps"]), ("slave", "fritz.box", "5 GHz", 1201))
        self.assertEqual([(ap["name"], ap["clients"]) for ap in aps], [("fritz.box", 0), ("Repeater Kitchen", 1)])
        self.assertEqual(wlan_monitor.rcpi_dbm(-61), -61)   # FRITZ!OS 8: already dBm
        self.assertEqual(wlan_monitor.rcpi_dbm(120), -50)   # older: RCPI scale
        self.assertIsNone(wlan_monitor.rcpi_dbm(255))       # unknown
        self.assertIsNone(wlan_monitor.rcpi_dbm(True))
        self.assertEqual(wlan_monitor.parse_mesh({"nodes": "x"}), ({}, []))
        self.assertEqual(wlan_monitor.parse_mesh([]), ({}, []))

    def test_fritz_model_from_description(self):
        body = b"<root><device><modelName>FRITZ!Box 5690 Pro</modelName></device></root>"
        with mock.patch.object(wlan_monitor, "bounded_http", return_value=(200, {}, body, "")):
            self.assertEqual(wlan_monitor.fritz_model("192.168.178.1"), "FRITZ!Box 5690 Pro")
        with mock.patch.object(wlan_monitor, "bounded_http", return_value=(200, {}, b"<modelName>Speedport</modelName>", "")):
            self.assertEqual(wlan_monitor.fritz_model("192.168.178.1"), "")
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=OSError):
            self.assertEqual(wlan_monitor.fritz_model("192.168.178.1"), "")

    def test_login_flow_pins_certificate_and_never_exposes_password(self):
        soap_ok = ("<s:Envelope><NewX_AVM-DE_MeshListPath>/meshlist.lua?sid=0123456789abcdef"
                   "</NewX_AVM-DE_MeshListPath></s:Envelope>")
        mesh_json = __import__("json").dumps(self.MESH).encode()
        calls = []

        def fake_http(ip, port, method, path, body=None, headers=None, tls=False, pin=None, **kw):
            calls.append((port, method, path, pin, (headers or {}).get("Authorization", "")))
            if method == "POST" and "Authorization" not in (headers or {}):
                return 401, {"www-authenticate": 'Digest realm="F!Box SOAP-Auth", nonce="N1", qop="auth"'}, b"", "c" * 64
            if method == "POST":
                return 200, {}, soap_ok.encode(), "c" * 64
            return 200, {}, mesh_json, "c" * 64

        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("192.168.178.1", "1c:23:a2:92:2a:6c", True, True)
        fritz.model_for = ("192.168.178.1", "1c:23:a2:92:2a:6c")
        fritz.login("fritz1234", "s3cret pass")
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=fake_http):
            fritz.step()
        info, clients = fritz.snapshot()
        self.assertEqual(info["state"], "connected")
        self.assertEqual(info["user"], "fritz1234")
        self.assertNotIn("s3cret", __import__("json").dumps(info))
        self.assertIn("60:8a:10:cf:a6:2e", clients)
        self.assertTrue(all(port == wlan_monitor.FRITZ_TLS_PORT for port, *_ in calls))
        self.assertIn('username="fritz1234"', calls[1][4])
        self.assertNotIn("s3cret", "".join(c[4] for c in calls))
        self.assertEqual(calls[-1][3], "c" * 64)  # the mesh list is fetched with the pinned certificate
        saved = wlan_monitor.load_fritz()
        self.assertEqual((saved["user"], saved["pin"], saved["gateway_mac"]), ("fritz1234", "c" * 64, "1c:23:a2:92:2a:6c"))
        path = os.path.join(wlan_monitor.config_dir(), wlan_monitor.FRITZ_FILE)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        # Another router (different MAC) never gets the credentials.
        fritz.set_network("192.168.1.1", "11:22:33:44:55:66", True, True)
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect")), \
                mock.patch.object(wlan_monitor, "fritz_model", return_value=""):
            fritz.step()
        self.assertEqual(fritz.snapshot()[0]["state"], "off")
        fritz.logout()
        self.assertFalse(os.path.exists(path))

    def test_wrong_password_and_changed_certificate(self):
        def unauthorized(ip, port, method, path, body=None, headers=None, tls=False, pin=None, **kw):
            return 401, {"www-authenticate": 'Digest realm="r", nonce="n", qop="auth"'}, b"", "c" * 64
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("192.168.178.1", "1c:23:a2:92:2a:6c", True, True)
        fritz.model_for = ("192.168.178.1", "1c:23:a2:92:2a:6c")
        fritz.login("u", "bad")
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=unauthorized):
            fritz.step()
        self.assertEqual(fritz.snapshot()[0]["state"], "error")
        self.assertIn("Wrong user name or password", fritz.snapshot()[0]["message"])
        self.assertIsNone(wlan_monitor.load_fritz())
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=PermissionError):
            with self.assertRaises(wlan_monitor.FritzError) as ctx:
                wlan_monitor.fritz_soap("192.168.178.1", "u", "p", "d" * 64, "urn:x", "/c", "A")
        self.assertIn("certificate changed", str(ctx.exception))

    def test_load_fritz_rejects_malformed(self):
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": "x", "user": "u", "password": "p", "pin": "0" * 64})
        self.assertIsNone(wlan_monitor.load_fritz())
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": "AA:BB:CC:DD:EE:FF", "user": "u", "password": "p", "pin": "0" * 64})
        self.assertEqual(wlan_monitor.load_fritz()["gateway_mac"], "aa:bb:cc:dd:ee:ff")


class BoundedHttpTests(unittest.TestCase):
    """A router-side responder must not stall or exhaust the collector (review finding class 7b)."""

    def serve(self, handler):
        import socket as s_, threading as t_
        srv = s_.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def run():
            try:
                conn, _ = srv.accept()
                conn.recv(4096)
                handler(conn)
                conn.close()
            except OSError:
                pass
            finally:
                srv.close()
        t_.Thread(target=run, daemon=True).start()
        return srv.getsockname()[1]

    def test_drip_status_line_hits_deadline(self):
        def drip(conn):
            for ch in b"HTTP/1.1 200 OK\r\n":
                try:
                    conn.send(bytes([ch]))
                except OSError:
                    return
                time.sleep(0.2)
        port = self.serve(drip)
        start = time.monotonic()
        with self.assertRaises((OSError, wlan_monitor.http.client.HTTPException)):
            wlan_monitor.bounded_http("127.0.0.1", port, "GET", "/", timeout=1.0)
        self.assertLess(time.monotonic() - start, 2.5)

    def test_endless_body_is_capped(self):
        def flood(conn):
            try:
                conn.send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                while True:
                    conn.send(b"4000\r\n" + b"x" * 0x4000 + b"\r\n")
            except OSError:
                pass
        port = self.serve(flood)
        with self.assertRaises(OSError):
            wlan_monitor.bounded_http("127.0.0.1", port, "GET", "/", max_body=65536, timeout=3.0)

    def test_huge_content_length_refused(self):
        port = self.serve(lambda conn: conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\nabc"))
        with self.assertRaises(OSError):
            wlan_monitor.bounded_http("127.0.0.1", port, "GET", "/", max_body=65536)

    def test_public_gateway_is_never_contacted(self):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("8.8.8.8", "1c:23:a2:92:2a:6c", True, True)
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect")):
            self.assertEqual(fritz.step(), 5.0)


class PrivateWriteTests(unittest.TestCase):
    def test_permissive_existing_file_ends_private_and_no_temp_left(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": tmp}):
            os.makedirs(wlan_monitor.config_dir(), mode=0o700)
            path = os.path.join(wlan_monitor.config_dir(), wlan_monitor.FRITZ_FILE)
            with open(path, "w") as handle:
                handle.write("{}")
            os.chmod(path, 0o644)
            self.assertTrue(wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"a": 1}))
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(sorted(os.listdir(wlan_monitor.config_dir())), [wlan_monitor.FRITZ_FILE])
