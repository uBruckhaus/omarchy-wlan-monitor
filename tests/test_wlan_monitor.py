import contextlib
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

    def test_refuses_files_others_may_change_and_a_symlinked_dir_for_reading(self):
        nets = [{"ssid": "Home", "gateway_mac": "aa:bb:cc:dd:ee:ff"}]
        self.assertTrue(wlan_monitor.save_trusted(nets))
        directory = wlan_monitor.config_dir()
        path = os.path.join(directory, wlan_monitor.TRUST_FILE)
        os.chmod(path, 0o666)
        self.assertEqual(wlan_monitor.load_trusted(), [])  # anyone could have added a network
        os.chmod(path, 0o644)
        self.assertEqual(wlan_monitor.load_trusted(), nets)  # readable by others is fine for this one
        os.chmod(directory, 0o777)
        self.assertEqual(wlan_monitor.load_trusted(), [])  # a directory others may change: nothing read
        os.chmod(directory, 0o700)
        # The FRITZ!Box login holds the password: any group or other access refuses it.
        login = {"gateway_mac": "aa:bb:cc:dd:ee:ff", "user": "u", "password": "p", "pin": "c" * 64}
        self.assertTrue(wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, login))
        self.assertEqual(wlan_monitor.load_fritz()["user"], "u")
        os.chmod(os.path.join(directory, wlan_monitor.FRITZ_FILE), 0o640)
        self.assertIsNone(wlan_monitor.load_fritz())
        # A symlinked config directory is never read through, nor written.
        os.rename(directory, directory + ".real")
        os.symlink(directory + ".real", directory)
        os.chmod(os.path.join(directory + ".real", wlan_monitor.FRITZ_FILE), 0o600)
        self.assertEqual(wlan_monitor.load_trusted(), [])
        self.assertIsNone(wlan_monitor.load_fritz())
        self.assertIsNone(wlan_monitor.store_stamp())
        self.assertIsNone(wlan_monitor.fritz_revision())  # unusable, never "no Disconnect yet"
        self.assertFalse(wlan_monitor.remove_fritz())
        with wlan_monitor.fritz_file_lock() as held:
            self.assertFalse(held)
        self.assertFalse(os.path.exists(os.path.join(directory + ".real", wlan_monitor.FRITZ_LOCK_FILE)))

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
        self.assertEqual(kind("Mac", "", "", "Private MAC", []), "computer")

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
        self.assertEqual(parse('{"cmd":"pin","mac":"aa:bb:cc:dd:ee:ff","on":"yes"}'), "")  # not a boolean: refused
        self.assertEqual(parse('{"cmd":"alerts","on":true}'), {"cmd": "alerts", "on": True})
        self.assertEqual(parse('{"cmd":"rename","mac":"$(id)","name":"x"}'), "")
        self.assertEqual(parse('{"cmd":"rename","mac":["aa"],"name":"x"}'), "")
        self.assertEqual(parse('{"cmd":"rename","mac":"aa:bb:cc:dd:ee:ff","name":5}'), "")  # not text: refused
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
        self.notified.assert_called_once_with("Home", ["Stranger"], "en")
        # Persisted: a fresh monitor still knows the device is new, and alerts only once.
        mon2 = self.monitor()
        again = [self.device("aa:bb:cc:dd:ee:03", "Stranger")]
        mon2.apply_store(again, True, "Home")
        self.assertTrue(again[0]["new"])
        self.assertEqual(self.notified.call_count, 1)

    def test_two_collectors_keep_each_others_changes(self):
        """One collector per screen: a rename on A and a pin on B (and alerts, view and a newly
        seen device) all survive, and each collector shows the other's changes."""
        a, b = self.monitor(), self.monitor()
        one, two = "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"
        for mon in (a, b):
            mon.known = {"10.0.0.9": {"mac": one}, "10.0.0.10": {"mac": two}}
        self.assertTrue(a.handle({"cmd": "rename", "mac": one, "name": "Stove"}))
        self.assertTrue(b.handle({"cmd": "pin", "mac": two, "on": True}))
        self.assertTrue(a.handle({"cmd": "alerts", "on": False}))
        self.assertTrue(b.handle({"cmd": "view", "mode": "type", "collapsed": ["apple"]}))
        self.assertTrue(b.handle({"cmd": "pin", "mac": one, "on": True}))
        # B scans a trusted network and remembers a new device: nothing of A's is lost.
        b.apply_store([self.device("aa:bb:cc:dd:ee:04")], True, "Home")
        saved = wlan_monitor.load_store()
        devices = saved["networks"]["aa:bb:cc:dd:ee:01|Home"]["devices"]
        self.assertEqual((devices[one]["name"], devices[one]["pinned"]), ("Stove", True))
        self.assertTrue(devices[two]["pinned"])
        self.assertIn("aa:bb:cc:dd:ee:04", devices)
        self.assertFalse(saved["alerts"])
        self.assertEqual(saved["view"], {"mode": "type", "collapsed": ["apple"]})
        shown = [self.device(one), self.device(two)]
        a.apply_store(shown, True, "Home")
        self.assertEqual((shown[0]["name"], shown[0]["pinned"], shown[1]["pinned"]), ("Stove", True, True))
        self.assertFalse(a.store["alerts"])
        self.assertEqual(a.store["view"]["mode"], "type")

    def test_a_new_device_is_announced_by_one_screen_only(self):
        a, b = self.monitor(), self.monitor()
        with mock.patch.object(wlan_monitor.time, "time", return_value=1000.0):
            a.apply_store([self.device("aa:bb:cc:dd:ee:02")], True, "Home")
        later = 1000.0 + wlan_monitor.BASELINE_SECONDS + 1
        with mock.patch.object(wlan_monitor.time, "time", return_value=later):
            seen_a = [self.device("aa:bb:cc:dd:ee:03", "Stranger")]
            seen_b = [self.device("aa:bb:cc:dd:ee:03", "Stranger")]
            b.reload_store()
            a.apply_store(seen_a, True, "Home")
            with mock.patch.object(b, "reload_store"):  # B scanned before it saw A's write
                b.apply_store(seen_b, True, "Home")
        self.assertTrue(seen_a[0]["new"] and seen_b[0]["new"])
        self.notified.assert_called_once_with("Home", ["Stranger"], "en")

    def test_store_change_without_the_lock_writes_nothing(self):
        mon = self.monitor()
        mac = "aa:bb:cc:dd:ee:02"
        mon.known = {"10.0.0.9": {"mac": mac}}
        fcntl = __import__("fcntl")
        os.makedirs(wlan_monitor.config_dir(), mode=0o700)
        held = os.open(os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(held, fcntl.LOCK_EX)
            with mock.patch.object(wlan_monitor, "FRITZ_LOCK_WAIT", 0.05):
                self.assertTrue(mon.handle({"cmd": "rename", "mac": mac, "name": "Stove"}))
        finally:
            os.close(held)
        self.assertFalse(os.path.exists(os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_FILE)))
        shown = [self.device(mac)]
        mon.apply_store(shown, False, "Home")
        self.assertEqual(shown[0]["name"], "Stove")  # kept here until the file changes

    def test_out_of_range_times_are_dropped(self):
        os.makedirs(wlan_monitor.config_dir(), mode=0o700)
        path = os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_FILE)
        with open(path, "w") as handle:
            handle.write('{"networks": {"aa:bb:cc:dd:ee:01|Home": {"since": 1' + "0" * 400 + ', "devices": {'
                         '"aa:bb:cc:dd:ee:02": {"first": 1e999}, "aa:bb:cc:dd:ee:03": {"first": -5},'
                         '"aa:bb:cc:dd:ee:04": {"first": NaN}, "aa:bb:cc:dd:ee:05": {"first": 1700000000.5}}}}}')
        os.chmod(path, 0o600)
        net = wlan_monitor.load_store()["networks"]["aa:bb:cc:dd:ee:01|Home"]
        self.assertIsNone(net["since"])
        self.assertEqual([r["first"] for r in net["devices"].values()], [0, 0, 0, 1700000000.5])
        mon = self.monitor()
        devices = [self.device("aa:bb:cc:dd:ee:06")]
        self.assertTrue(mon.apply_store(devices, True, "Home"))  # no OverflowError, ever
        self.assertIsNotNone(wlan_monitor.load_store()["networks"]["aa:bb:cc:dd:ee:01|Home"]["since"])

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
        self.assertEqual(parse('{"cmd":"view","mode":"type","collapsed":["apple",5]}'), "")  # a wrong type: all refused
        self.assertEqual(parse('{"cmd":"view","mode":"type","collapsed":["apple","apple","aa:bb:cc:dd:ee:ff","$(x)"]}'),
                         {"cmd": "view", "mode": "type", "collapsed": ["apple", "aa:bb:cc:dd:ee:ff"]})
        self.assertEqual(parse('{"cmd":"view","mode":"tree","collapsed":[]}'), "")
        self.assertEqual(parse('{"cmd":"view","mode":"band","collapsed":["gsix"]}'), {"cmd": "view", "mode": "band", "collapsed": ["gsix"]})


class FritzTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()
        # The kernel's neighbour table as the tests want it (never this machine's real one).
        self.neighbors = {"192.168.178.1": "1c:23:a2:92:2a:6c"}
        self.neigh = mock.patch.object(wlan_monitor, "neighbor_mac", side_effect=lambda ip, iface: self.neighbors.get(ip, "") if iface == "wlan0" else "")
        self.neigh.start()

    def tearDown(self):
        self.neigh.stop()
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
        self.assertEqual(parse('{"cmd":"fritz_login","user":"fritz1234","password":"p\\"w d","net":"0a1b2c3d4e5f-3"}'),
                         {"cmd": "fritz_login", "user": "fritz1234", "password": 'p"w d', "net": "0a1b2c3d4e5f-3"})
        # Without the network the form was opened for, the login is refused later (net "").
        self.assertEqual(parse('{"cmd":"fritz_login","user":"u","password":"x"}')["net"], "")
        for net in ('1', '[]', '{}', 'null', '"' + "a" * 65 + '"', '"a b"'):
            self.assertEqual(parse('{"cmd":"fritz_login","user":"u","password":"x","net":' + net + '}'), "", net)
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
        fritz.set_network("192.168.178.1", "1c:23:a2:92:2a:6c", True, True, "wlan0")
        fritz.model_for = ("192.168.178.1", "1c:23:a2:92:2a:6c")
        fritz.login("fritz1234", "s3cret pass", fritz.net_id)
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
        fritz.set_network("192.168.1.1", "11:22:33:44:55:66", True, True, "wlan0")
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect")), \
                mock.patch.object(wlan_monitor, "fritz_model", return_value=""):
            fritz.step()
        self.assertEqual(fritz.snapshot()[0]["state"], "off")
        fritz.logout()
        self.assertFalse(os.path.exists(path))

    def test_a_queued_login_never_goes_to_another_gateway(self):
        """Typed for router A, the network changes to router B (even at the same address) before
        the login is sent: nothing is sent to B, nothing is saved, the user is told."""
        never = mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect"))
        no_model = mock.patch.object(wlan_monitor, "fritz_model", return_value="")
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("192.168.178.1", "1c:23:a2:92:2a:6c", True, True, "wlan0")
        fritz.login("fritz1234", "s3cret pass", fritz.net_id)
        self.assertEqual(fritz.pending_login[2:4], ("192.168.178.1", "1c:23:a2:92:2a:6c"))
        fritz.set_network("192.168.178.1", "66:66:66:66:66:66", True, True, "wlan0")     # router B, same address
        self.assertIsNone(fritz.pending_login)
        with never, no_model:
            fritz.step()
        info = fritz.snapshot()[0]
        self.assertEqual((info["state"], info["message_code"]), ("error", "fzNetworkChanged"))
        self.assertIsNone(wlan_monitor.load_fritz())
        # A login still queued for A when step() already sees B (the change not reported yet): not sent.
        fritz.pending_login = ("fritz1234", "s3cret pass", "192.168.178.1", "1c:23:a2:92:2a:6c", 1, "")
        with never, no_model:
            fritz.step()
        self.assertEqual(fritz.snapshot()[0]["message_code"], "fzNetworkChanged")
        self.assertIsNone(fritz.pending_login)
        # No gateway known: a login is refused at once, nothing is queued.
        fritz.set_network(None, "", False, True, "wlan0")
        fritz.login("fritz1234", "s3cret pass", fritz.net_id)
        self.assertIsNone(fritz.pending_login)
        self.assertEqual(fritz.snapshot()[0]["state"], "error")

    def challenge_http(self, calls, on_challenge=None):
        soap_ok = ("<s:Envelope><NewX_AVM-DE_MeshListPath>/meshlist.lua?sid=0123456789abcdef"
                   "</NewX_AVM-DE_MeshListPath></s:Envelope>")
        mesh_json = __import__("json").dumps(self.MESH).encode()

        def fake_http(ip, port, method, path, body=None, headers=None, tls=False, pin=None, **kw):
            calls.append((method, (headers or {}).get("Authorization", "")))
            if method == "POST" and "Authorization" not in (headers or {}):
                if on_challenge:
                    on_challenge()
                return 401, {"www-authenticate": 'Digest realm="F!Box SOAP-Auth", nonce="N1", qop="auth"'}, b"", "c" * 64
            if method == "POST":
                return 200, {}, soap_ok.encode(), "c" * 64
            return 200, {}, mesh_json, "c" * 64
        return fake_http

    def login_pair(self):
        """Two collectors (two screens) on the same FRITZ!Box; the first has a login queued."""
        ip, mac = "192.168.178.1", "1c:23:a2:92:2a:6c"
        first, second = wlan_monitor.FritzMesh(), wlan_monitor.FritzMesh()
        for fritz in (first, second):
            fritz.set_network(ip, mac, True, True, "wlan0")
            fritz.model_for = (ip, mac)
        first.login("fritz1234", "s3cret pass", first.net_id)
        return first, second

    def test_disconnect_elsewhere_during_a_login_is_not_undone(self):
        """Screen A logs in, screen B presses Disconnect while A's login is still in flight: A
        saves nothing, and neither collector uses a login afterwards."""
        first, second = self.login_pair()
        calls = []
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http(calls, second.logout)), \
                mock.patch.object(wlan_monitor, "neighbor_mac", return_value="1c:23:a2:92:2a:6c"):
            first.step()
        self.assertTrue(calls)  # the login really was in flight
        self.assertIsNone(wlan_monitor.load_fritz())
        self.assertIsNone(first.creds)
        self.assertEqual(first.snapshot()[0]["state"], "off")
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect")):
            first.step()
            second.step()
        self.assertIsNone(wlan_monitor.load_fritz())
        self.assertEqual((first.snapshot()[0]["user"], second.snapshot()[0]["user"]), ("", ""))
        # A login typed after that Disconnect is saved and followed by the other screen.
        first.login("fritz1234", "s3cret pass", first.net_id)
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http([])), \
                mock.patch.object(wlan_monitor, "neighbor_mac", return_value="1c:23:a2:92:2a:6c"):
            first.step()
        self.assertEqual(first.snapshot()[0]["state"], "connected")
        self.assertEqual(wlan_monitor.load_fritz()["user"], "fritz1234")
        with mock.patch.object(second, "refresh", side_effect=wlan_monitor.FritzError("fzNoMesh", "x")):
            second.step()
        self.assertEqual(second.snapshot()[0]["user"], "fritz1234")

    def test_login_while_another_collector_holds_the_lock_saves_nothing(self):
        """The lock is held by another process (a separate open file) for longer than the wait:
        the login fails closed instead of saving without it."""
        first, _second = self.login_pair()
        directory = wlan_monitor.private_config_dir()
        other = os.open(os.path.join(directory, wlan_monitor.FRITZ_LOCK_FILE), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            __import__("fcntl").flock(other, __import__("fcntl").LOCK_EX)
            with mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http([])), \
                    mock.patch.object(wlan_monitor, "neighbor_mac", return_value="1c:23:a2:92:2a:6c"), \
                    mock.patch.object(wlan_monitor, "FRITZ_LOCK_WAIT", 0.1):
                first.step()
        finally:
            os.close(other)
        self.assertIsNone(wlan_monitor.load_fritz())
        self.assertNotEqual(first.snapshot()[0]["state"], "connected")
        lock = os.path.join(directory, wlan_monitor.FRITZ_LOCK_FILE)
        self.assertEqual(os.stat(lock).st_mode & 0o777, 0o600)

    def test_disconnect_elsewhere_stops_a_refresh_before_the_password_response(self):
        A, ip = "1c:23:a2:92:2a:6c", "192.168.178.1"
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "u", "password": "p",
                                                                 "pin": "c" * 64})
        first, second = wlan_monitor.FritzMesh(), wlan_monitor.FritzMesh()
        for fritz in (first, second):
            fritz.set_network(ip, A, True, True, "wlan0")
            fritz.model_for = (ip, A)
        calls = []
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http(calls, second.logout)):
            first.step()
        self.assertEqual([c for c in calls if c[1]], [])  # no password-derived response went out
        self.assertNotEqual(first.snapshot()[0]["state"], "connected")
        self.assertIsNone(wlan_monitor.load_fritz())

    def test_disconnect_racing_the_save_wins(self):
        """A Disconnect that could not wait for the lock renews the revision right after another
        collector saved its login: that collector deletes what it saved."""
        first, _second = self.login_pair()
        real_save = wlan_monitor.save_private_json

        def save_then_disconnect(name, data, *a, **kw):
            done = real_save(name, data, *a, **kw)
            if name == wlan_monitor.FRITZ_FILE:
                wlan_monitor.fritz_new_revision()
            return done
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http([])), \
                mock.patch.object(wlan_monitor, "neighbor_mac", return_value="1c:23:a2:92:2a:6c"), \
                mock.patch.object(wlan_monitor, "save_private_json", side_effect=save_then_disconnect):
            first.step()
        self.assertIsNone(wlan_monitor.load_fritz())
        self.assertIsNone(first.creds)
        self.assertEqual(first.snapshot()[0]["state"], "off")

    def test_a_disconnect_that_cannot_delete_is_retried_and_nothing_is_used(self):
        A, ip = "1c:23:a2:92:2a:6c", "192.168.178.1"
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "u", "password": "p",
                                                                 "pin": "c" * 64})
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(ip, A, True, True, "wlan0")
        fritz.model_for = (ip, A)
        never = mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect"))
        with mock.patch.object(wlan_monitor, "fritz_new_revision", return_value=None), never:
            fritz.logout()
            self.assertEqual(fritz.snapshot()[0]["message_code"], "fzNotDeleted")
            self.assertEqual(fritz.step(), wlan_monitor.FRITZ_REVOKE_RETRY)
            fritz.login("u", "p", fritz.net_id)
            self.assertIsNone(fritz.pending_login)  # no new login before the Disconnect is done
        self.assertIsNotNone(wlan_monitor.load_fritz())
        self.assertIsNone(fritz.creds)
        with never:
            fritz.step()
        self.assertIsNone(wlan_monitor.load_fritz())
        self.assertFalse(fritz.revoke_pending)
        self.assertEqual(fritz.snapshot()[0]["state"], "off")

    def test_a_failed_disconnect_during_a_step_uses_nothing(self):
        """The worker passed its revoke check when a Disconnect whose revision cannot be written
        starts: it neither adopts the old login from disk nor sends anything with it."""
        A, ip = "1c:23:a2:92:2a:6c", "192.168.178.1"
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "u", "password": "p",
                                                                 "pin": "c" * 64})
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(ip, A, True, True, "wlan0")
        fritz.model_for = (ip, A)
        never = mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect"))
        real_load = wlan_monitor.load_fritz
        calls = []

        def load_then_disconnect():
            if not calls:
                calls.append(1)
                fritz.logout()  # between the step's checks, and its revision cannot be written
            return real_load()
        with mock.patch.object(wlan_monitor, "fritz_new_revision", return_value=None), never, \
                mock.patch.object(wlan_monitor, "load_fritz", side_effect=load_then_disconnect):
            fritz.creds = None
            fritz.step()
            self.assertIsNone(fritz.creds)
            self.assertFalse(fritz.current(ip, A, fritz.generation))
            self.assertEqual(fritz.step(), wlan_monitor.FRITZ_REVOKE_RETRY)
        self.assertTrue(fritz.revoke_pending)

    def test_a_login_file_that_cannot_be_deleted_is_used_nowhere(self):
        A, ip = "1c:23:a2:92:2a:6c", "192.168.178.1"
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "u", "password": "p",
                                                                 "pin": "c" * 64})
        first, second = wlan_monitor.FritzMesh(), wlan_monitor.FritzMesh()
        self.assertEqual(second.creds["user"], "u")  # saved by 0.8.0 (no revision): still used
        for fritz in (first, second):
            fritz.set_network(ip, A, True, True, "wlan0")
            fritz.model_for = (ip, A)
        with mock.patch.object(wlan_monitor, "remove_fritz", return_value=False):
            first.logout()
        self.assertTrue(os.path.exists(os.path.join(wlan_monitor.config_dir(), wlan_monitor.FRITZ_FILE)))
        self.assertFalse(first.revoke_pending)  # the new revision is what counts
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect")):
            second.step()
        self.assertIsNone(second.creds)
        self.assertIsNone(wlan_monitor.FritzMesh().creds)  # nor by a collector started later
        # A later Disconnect that can delete it removes the stale file.
        first.logout()
        self.assertFalse(os.path.exists(os.path.join(wlan_monitor.config_dir(), wlan_monitor.FRITZ_FILE)))

    def test_unreadable_revision_is_repaired_only_under_the_lock(self):
        first, _second = self.login_pair()
        self.assertIsNotNone(first.pending_login)
        first.pending_login = None
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_REV_FILE, {"rev": 1})
        # A Disconnect elsewhere writes a valid revision while this login waits for the lock.
        written = "d" * 32
        with mock.patch.object(wlan_monitor, "fritz_revision", side_effect=[None, written]), \
                mock.patch.object(wlan_monitor, "fritz_new_revision", side_effect=AssertionError("never replaced")):
            first.login("fritz1234", "s3cret pass", first.net_id)
        self.assertIsNone(first.pending_login)
        self.assertEqual(first.snapshot()[0]["state"], "off")
        # Without the lock it is not repaired at all.
        with mock.patch.object(wlan_monitor, "fritz_file_lock", return_value=contextlib.nullcontext(False)), \
                mock.patch.object(wlan_monitor, "fritz_new_revision", side_effect=AssertionError("never replaced")):
            first.login("fritz1234", "s3cret pass", first.net_id)
        self.assertIsNone(first.pending_login)
        self.assertEqual(first.snapshot()[0]["message_code"], "fzNotStored")
        # Still unreadable under the lock: repaired, and the login is queued with the new revision.
        first.login("fritz1234", "s3cret pass", first.net_id)
        self.assertRegex(first.pending_login[5], r"^[0-9a-f]{32}$")
        self.assertEqual(first.pending_login[5], wlan_monitor.fritz_revision())

    def test_revision_repair_and_disconnect_never_overwrite_each_other(self):
        """Screen A repairs an unreadable revision under the lock while screen B presses Disconnect:
        B writes nothing without the lock, retries, and A's login is then not saved."""
        first, second = self.login_pair()
        first.pending_login = None
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_REV_FILE, {"rev": 1})
        real_new = wlan_monitor.fritz_new_revision

        def repair_while_b_disconnects():
            with mock.patch.object(wlan_monitor, "FRITZ_LOCK_WAIT", 0.05):
                second.logout()  # A holds the lock: B's Disconnect writes nothing yet
            self.assertTrue(second.revoke_pending)
            self.assertEqual(wlan_monitor.load_private_json(wlan_monitor.FRITZ_REV_FILE, 256), {"rev": 1})
            return real_new()
        with mock.patch.object(wlan_monitor, "fritz_new_revision", side_effect=repair_while_b_disconnects):
            first.login("fritz1234", "s3cret pass", first.net_id)
        repaired = first.pending_login[5]
        self.assertEqual(wlan_monitor.fritz_revision(), repaired)
        second.step()  # B's retry, now with the lock: a new revision
        self.assertFalse(second.revoke_pending)
        self.assertNotEqual(wlan_monitor.fritz_revision(), repaired)
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http([])), \
                mock.patch.object(wlan_monitor, "neighbor_mac", return_value="1c:23:a2:92:2a:6c"):
            first.step()
        self.assertIsNone(wlan_monitor.load_fritz())
        self.assertNotEqual(first.snapshot()[0]["state"], "connected")

    def test_lock_file_is_never_a_symlink_or_fifo(self):
        directory = wlan_monitor.private_config_dir()
        lock = os.path.join(directory, wlan_monitor.FRITZ_LOCK_FILE)
        target = os.path.join(self.tmp.name, "elsewhere")
        os.symlink(target, lock)
        with wlan_monitor.fritz_file_lock() as held:
            self.assertFalse(held)
        self.assertFalse(os.path.exists(target))
        os.unlink(lock)
        os.mkfifo(lock, 0o600)
        with wlan_monitor.fritz_file_lock() as held:
            self.assertFalse(held)
        os.unlink(lock)
        with wlan_monitor.fritz_file_lock() as held:
            self.assertTrue(held)
        # A Disconnect replaces the revision even while its value on disk is nonsense.
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_REV_FILE, {"rev": [1]})
        self.assertIsNone(wlan_monitor.fritz_revision())  # never taken for any revision
        wlan_monitor.FritzMesh().logout()
        self.assertRegex(wlan_monitor.fritz_revision(), r"^[0-9a-f]{32}$")

    def test_a_gateway_change_during_login_work_sends_no_password_response(self):
        """The gateway changes (router B at the same address) while a login is in flight: during
        the model probe, between the challenge and the response, or seen only by the kernel. No
        Digest response is sent, nothing is saved, nothing of the old login is kept."""
        A, B = "1c:23:a2:92:2a:6c", "66:66:66:66:66:66"
        ip = "192.168.178.1"

        def run(probe=None, on_challenge=None):
            fritz = wlan_monitor.FritzMesh()
            fritz.set_network(ip, A, True, True, "wlan0")
            fritz.login("fritz1234", "s3cret pass", fritz.net_id)
            calls = []
            model = (lambda _ip, _iface=None: probe(fritz) or "") if probe else (lambda _ip, _iface=None: "")
            hook = (lambda: on_challenge(fritz)) if on_challenge else None
            with mock.patch.object(wlan_monitor, "fritz_model", side_effect=model), \
                    mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http(calls, hook)):
                fritz.step()
            return fritz, calls

        # 1. B takes over the address during the model probe (set_network reports it).
        fritz, calls = run(probe=lambda f: f.set_network(ip, B, True, True, "wlan0"))
        self.assertEqual(calls, [])
        self.assertEqual(fritz.snapshot()[0]["message_code"], "fzNetworkChanged")
        # 2. B answers the challenge: the change arrives after it, before the response.
        fritz, calls = run(on_challenge=lambda f: f.set_network(ip, B, True, True, "wlan0"))
        self.assertEqual([auth for _m, auth in calls], [""])
        # 3. Not reported yet, but the kernel already has B's MAC at this address.
        self.neighbors[ip] = B
        fritz, calls = run(on_challenge=lambda f: None)
        self.assertEqual(calls, [])
        self.neighbors[ip] = A
        # 4. A logout while the login is in flight.
        fritz, calls = run(on_challenge=lambda f: f.logout())
        self.assertEqual([auth for _m, auth in calls], [""])
        self.assertIsNone(fritz.creds)
        self.assertIsNone(wlan_monitor.load_fritz())
        # 5. The change comes after the response, before the result is kept: nothing kept or saved.
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(ip, A, True, True, "wlan0")
        fritz.login("fritz1234", "s3cret pass", fritz.net_id)
        calls = []
        real = self.challenge_http(calls)

        def late(*args, **kw):
            result = real(*args, **kw)
            if args[2] == "GET":
                fritz.set_network(ip, B, True, True, "wlan0")
            return result
        with mock.patch.object(wlan_monitor, "fritz_model", return_value=""), \
                mock.patch.object(wlan_monitor, "bounded_http", side_effect=late):
            fritz.step()
        info, clients = fritz.snapshot()
        self.assertEqual((info["message_code"], clients), ("fzNetworkChanged", {}))
        self.assertIsNone(fritz.creds)
        self.assertIsNone(wlan_monitor.load_fritz())
        # Unchanged gateway: the login still works.
        fritz, calls = run()
        self.assertEqual(fritz.snapshot()[0]["state"], "connected")
        self.assertIn('username="fritz1234"', calls[1][1])

    def test_saved_login_refresh_stops_on_gateway_change(self):
        A, ip = "1c:23:a2:92:2a:6c", "192.168.178.1"
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "u", "password": "p",
                                                                 "pin": "c" * 64})
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(ip, A, True, True, "wlan0")
        fritz.model_for = (ip, A)
        calls = []
        hook = lambda: fritz.set_network(ip, "66:66:66:66:66:66", True, True, "wlan0")
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=self.challenge_http(calls, hook)):
            fritz.step()
        self.assertEqual([auth for _m, auth in calls], [""])
        self.assertEqual(fritz.snapshot()[1], {})

    def test_wrong_password_and_changed_certificate(self):
        def unauthorized(ip, port, method, path, body=None, headers=None, tls=False, pin=None, **kw):
            return 401, {"www-authenticate": 'Digest realm="r", nonce="n", qop="auth"'}, b"", "c" * 64
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("192.168.178.1", "1c:23:a2:92:2a:6c", True, True, "wlan0")
        fritz.model_for = ("192.168.178.1", "1c:23:a2:92:2a:6c")
        fritz.login("u", "bad", fritz.net_id)
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

    def test_drip_body_after_connection_close_hits_deadline(self):
        def drip(conn):
            try:
                conn.send(b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n")
                for _ in range(100):
                    conn.send(b"x")
                    time.sleep(0.1)
            except OSError:
                pass
        port = self.serve(drip)
        start = time.monotonic()
        with self.assertRaises((OSError, wlan_monitor.http.client.HTTPException)):
            wlan_monitor.bounded_http("127.0.0.1", port, "GET", "/", timeout=1.0)
        self.assertLess(time.monotonic() - start, 2.5)

    def test_endless_trailers_hit_deadline(self):
        def trailers(conn):
            try:
                conn.send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n")
                end = time.monotonic() + 10
                while time.monotonic() < end:
                    conn.send(b"X-Pad: y\r\n")
                    time.sleep(0.01)
            except OSError:
                pass
        port = self.serve(trailers)
        start = time.monotonic()
        with self.assertRaises((OSError, wlan_monitor.http.client.HTTPException)):
            wlan_monitor.bounded_http("127.0.0.1", port, "GET", "/", timeout=1.0)
        self.assertLess(time.monotonic() - start, 2.5)

    def test_huge_content_length_refused(self):
        port = self.serve(lambda conn: conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\nabc"))
        with self.assertRaises(OSError):
            wlan_monitor.bounded_http("127.0.0.1", port, "GET", "/", max_body=65536)

    def test_public_gateway_is_never_contacted(self):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("8.8.8.8", "1c:23:a2:92:2a:6c", True, True, "wlan0")
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


class VpnTests(unittest.TestCase):
    def make_iface(self, base, name, flags="0x1003", typ="1"):
        os.makedirs(os.path.join(base, name))
        with open(os.path.join(base, name, "flags"), "w") as handle:
            handle.write(flags + "\n")
        with open(os.path.join(base, name, "type"), "w") as handle:
            handle.write(typ + "\n")

    def test_detect_vpn(self):
        with tempfile.TemporaryDirectory() as base:
            self.make_iface(base, "lo", typ="772")
            self.make_iface(base, "wlp15s0")
            self.make_iface(base, "docker0")
            self.assertIsNone(wlan_monitor.detect_vpn("wlp15s0", base))
            self.make_iface(base, "nordlynx", flags="0x91", typ="65534")
            vpn = wlan_monitor.detect_vpn("wlp15s0", base)
            self.assertEqual((vpn["iface"], vpn["name"]), ("nordlynx", "NordVPN"))
            self.assertIn("nordvpn set lan-discovery enable", vpn["hint"])
        with tempfile.TemporaryDirectory() as base:
            self.make_iface(base, "wlp15s0")
            self.make_iface(base, "wg0", flags="0x90", typ="65534")  # down: ignored
            self.assertIsNone(wlan_monitor.detect_vpn("wlp15s0", base))
            self.make_iface(base, "corpvpn", flags="0x91", typ="65534")  # unknown name, tunnel type
            self.assertEqual(wlan_monitor.detect_vpn("wlp15s0", base)["name"], "VPN")

    def test_gateway_reachable(self):
        with mock.patch.object(wlan_monitor.socket, "create_connection", side_effect=ConnectionRefusedError):
            self.assertTrue(wlan_monitor.gateway_reachable("192.168.1.1"))
        with mock.patch.object(wlan_monitor.socket, "create_connection", side_effect=wlan_monitor.socket.timeout):
            self.assertFalse(wlan_monitor.gateway_reachable("192.168.1.1"))
        with mock.patch.object(wlan_monitor.socket, "create_connection", side_effect=AssertionError("must not connect")):
            self.assertTrue(wlan_monitor.gateway_reachable("8.8.8.8"))

class LanguageTests(unittest.TestCase):
    """Interface language: the lang command, coded FRITZ!Box errors, translated notifications."""

    def test_lang_command_is_validated(self):
        self.assertEqual(wlan_monitor.parse_command('{"cmd": "lang", "lang": "de"}'), {"cmd": "lang", "lang": "de"})
        self.assertEqual(wlan_monitor.parse_command('{"cmd": "lang", "lang": "../x"}'), {"cmd": "lang", "lang": "en"})

    def test_fritz_error_keeps_code_args_and_english_text(self):
        exc = wlan_monitor.FritzError("fzRefused", "The FRITZ!Box refused the request (error %s).", 606)
        self.assertEqual((exc.code, exc.args_, str(exc)), ("fzRefused", ["606"], "The FRITZ!Box refused the request (error 606)."))

    def test_notification_in_german(self):
        with mock.patch.object(wlan_monitor.shutil, "which", return_value="/usr/bin/notify-send"), \
             mock.patch.object(wlan_monitor, "run_cmd") as run:
            wlan_monitor.notify_new_devices("Home", ["Phone", "Tablet"], "de")
        argv = run.call_args[0][0]
        self.assertEqual(argv[-2:], ["2 neue Geräte in Home", "Phone, Tablet"])



class HostileCommandTests(unittest.TestCase):
    """Panel commands are untrusted JSON: wrong types are refused and never end the collector."""

    def test_wrong_types_are_refused(self):
        parse = wlan_monitor.parse_command
        for line in ('{"cmd":[]}', '{"cmd":{}}', '{"cmd":1}', '{"cmd":null}', '{"cmd":true}', '[]', '"rescan"',
                     '{"cmd":"rename","mac":[],"name":"x"}', '{"cmd":"rename","mac":"aa:bb:cc:dd:ee:ff","name":{}}',
                     '{"cmd":"view","mode":[],"collapsed":[]}', '{"cmd":"view","mode":"list","collapsed":{}}',
                     '{"cmd":"lang","lang":[]}', '{"cmd":"alerts","on":[]}', '{"cmd":"fritz_login","user":[],"password":"x"}',
                     '{"cmd":"fritz_login","user":"u","password":{}}', '{"cmd":"pin","mac":"aa:bb:cc:dd:ee:ff","on":{}}',
                     '{"cmd":"rename"}', '{', '{"cmd":"x' + "y" * 2000 + '"}'):
            self.assertEqual(parse(line), "", line)  # refused, never coerced into a change
        self.assertEqual(parse('{"cmd":[]}'), "")
        self.assertEqual(parse('{"cmd":{}}'), "")
        # A wrong type inside a list refuses the whole command; valid commands still work.
        for line in ('{"cmd":"view","mode":"list","collapsed":["type",[],{}]}',
                     '{"cmd":"view","mode":"list","collapsed":[123,"type"]}',
                     '{"cmd":"view","mode":"list","collapsed":["type",null]}'):
            self.assertEqual(parse(line), "", line)
        self.assertEqual(parse('{"cmd":"view","mode":"list","collapsed":["type","$(x)"]}'),
                         {"cmd": "view", "mode": "list", "collapsed": ["type"]})
        self.assertEqual(parse('{"cmd":"alerts","on":false}'), {"cmd": "alerts", "on": False})
        self.assertEqual(parse('{"cmd":"pin","mac":"AA:BB:CC:DD:EE:FF","on":true}'),
                         {"cmd": "pin", "mac": "aa:bb:cc:dd:ee:ff", "on": True})
        self.assertEqual(parse('{"cmd":"rename","mac":"aa:bb:cc:dd:ee:ff","name":""}'),
                         {"cmd": "rename", "mac": "aa:bb:cc:dd:ee:ff", "name": ""})

    def test_a_failing_command_never_ends_the_collector(self):
        monitor = mock.Mock()
        monitor.handle.side_effect = TypeError("boom")
        self.assertFalse(wlan_monitor.handle_line(monitor, '{"cmd":"rescan"}'))
        monitor.handle.side_effect = None
        monitor.handle.return_value = True
        self.assertTrue(wlan_monitor.handle_line(monitor, "rescan"))
        with mock.patch.object(wlan_monitor, "parse_command", side_effect=ValueError("bad")):
            self.assertFalse(wlan_monitor.handle_line(monitor, "rescan"))
        # Interrupts and exits are not swallowed.
        monitor.handle.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            wlan_monitor.handle_line(monitor, "rescan")
        monitor.handle.side_effect = SystemExit(0)
        with self.assertRaises(SystemExit):
            wlan_monitor.handle_line(monitor, "rescan")


class LoginNetworkTests(unittest.TestCase):
    """A login names the network its form was opened for; the collector refuses it on any other."""
    A = "1c:23:a2:92:2a:6c"
    B = "66:66:66:66:66:66"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_network_id_follows_the_gateway(self):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("192.168.178.1", self.A, True, True, "wlan0")
        first = fritz.net_id
        self.assertRegex(first, wlan_monitor.NET_ID_RE)
        fritz.set_network("192.168.178.1", self.A, True, False, "wlan0")
        self.assertEqual(fritz.net_id, first)                     # same router: same id
        fritz.set_network("192.168.178.1", self.B, True, True, "wlan0")
        self.assertNotEqual(fritz.net_id, first)                  # same address, other router
        fritz.set_network("192.168.178.1", self.A, True, True, "wlan0")
        self.assertNotEqual(fritz.net_id, first)                  # back again: still a new id
        # Another collector process never reuses an id.
        other = wlan_monitor.FritzMesh()
        other.set_network("192.168.178.1", self.A, True, True, "wlan0")
        self.assertNotEqual(other.net_id, first)

    def test_login_for_another_network_is_refused(self):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("192.168.178.1", self.A, True, True, "wlan0")
        opened_for = fritz.net_id
        # The panel still shows router A (devices frozen while renaming), the collector already sees B.
        fritz.set_network("192.168.178.1", self.B, True, True, "wlan0")
        fritz.login("fritz1234", "s3cret pass", opened_for)
        self.assertIsNone(fritz.pending_login)
        info = fritz.snapshot()[0]
        self.assertEqual((info["state"], info["message_code"]), ("error", "fzNetworkChanged"))
        for missing in ("", None, "0a1b2c3d4e5f-1"):
            fritz.login("fritz1234", "s3cret pass", missing)
            self.assertIsNone(fritz.pending_login)
        fritz.login("fritz1234", "s3cret pass", fritz.net_id)
        self.assertEqual(fritz.pending_login[:4], ("fritz1234", "s3cret pass", "192.168.178.1", self.B))

    def test_monitor_passes_the_network_id(self):
        monitor = wlan_monitor.Monitor()
        monitor.fritz.set_network("192.168.178.1", self.A, True, True, "wlan0")
        monitor.handle(wlan_monitor.parse_command('{"cmd":"fritz_login","user":"u","password":"x"}'))
        self.assertIsNone(monitor.fritz.pending_login)
        line = '{"cmd":"fritz_login","user":"u","password":"x","net":"%s"}' % monitor.fritz.net_id
        monitor.handle(wlan_monitor.parse_command(line))
        self.assertIsNotNone(monitor.fritz.pending_login)

    def test_link_reports_gateway_mac_and_network_id(self):
        net = {"iface": "wlan0", "ip": "192.168.178.20", "gateway": "192.168.178.1", "prefix": 24,
               "cidr": "192.168.178.20/24", "mac": "02:00:00:00:00:01", "is_wireless": True}
        neighbors = {"192.168.178.1": {"mac": self.A, "state": "REACHABLE"}}
        wlan = {"ssid": "Home", "bssid": self.A}
        with mock.patch.object(wlan_monitor, "detect_interface", return_value=net), \
                mock.patch.object(wlan_monitor, "read_neighbors", side_effect=lambda iface: dict(neighbors)), \
                mock.patch.object(wlan_monitor.Monitor, "wireless", return_value=wlan), \
                mock.patch.object(wlan_monitor, "detect_vpn", return_value=None), \
                mock.patch.object(wlan_monitor, "read_traffic", return_value=(0, 0)), \
                mock.patch.object(wlan_monitor, "lookup_ptr", return_value=[]), \
                mock.patch.object(wlan_monitor, "run_cmd", return_value=""):
            monitor = wlan_monitor.Monitor()
            link = monitor.snapshot()["link"]
            self.assertEqual(link["gateway_mac"], self.A)
            self.assertEqual(link["net_id"], monitor.fritz.net_id)
            first = link["net_id"]
            neighbors["192.168.178.1"] = {"mac": self.B, "state": "REACHABLE"}  # other router, same SSID + address
            link = monitor.snapshot()["link"]
            self.assertEqual(link["gateway_mac"], self.B)
            self.assertNotEqual(link["net_id"], first)
            self.assertEqual(link["net_id"], monitor.fritz.net_id)


class InterfaceBindingTests(unittest.TestCase):
    """FRITZ!Box traffic goes only out of the monitored interface, to the router seen there."""
    A = "1c:23:a2:92:2a:6c"
    IP = "192.168.178.1"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_interface_change_is_a_network_change(self):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(self.IP, self.A, True, True, "wlan0")
        first = fritz.net_id
        fritz.login("u", "p", first)
        fritz.set_network(self.IP, self.A, True, True, "eth0")   # same address and MAC, other interface
        self.assertNotEqual(fritz.net_id, first)
        self.assertIsNone(fritz.pending_login)
        # An interface name that is not a plain kernel name: nothing is ever contacted.
        fritz.set_network(self.IP, self.A, True, True, "-x;")
        self.assertIsNone(fritz.network[0])

    def test_login_traffic_is_scoped_to_the_interface(self):
        seen, neigh = [], []

        def fake_http(ip, port, method, path, body=None, headers=None, tls=False, pin=None, iface=None, **kw):
            seen.append(iface)
            if method == "POST" and "Authorization" not in (headers or {}):
                return 401, {"www-authenticate": 'Digest realm="r", nonce="n", qop="auth"'}, b"", "c" * 64
            return 401, {}, b"", "c" * 64

        def fake_neigh(ip, iface):
            neigh.append(iface)
            return self.A
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(self.IP, self.A, True, True, "wlan0")
        fritz.login("u", "p", fritz.net_id)
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=fake_http), \
                mock.patch.object(wlan_monitor, "neighbor_mac", side_effect=fake_neigh):
            fritz.step()
        self.assertTrue(seen)
        self.assertEqual(set(seen), {"wlan0"})          # model probe and both login requests
        self.assertEqual(set(neigh), {"wlan0"})

    def test_neighbor_lookup_names_the_interface(self):
        with mock.patch.object(wlan_monitor, "run_cmd", return_value="192.168.178.1 dev wlan0 lladdr 1c:23:a2:92:2a:6c REACHABLE\n") as run:
            self.assertEqual(wlan_monitor.neighbor_mac(self.IP, "wlan0"), self.A)
        self.assertEqual(run.call_args[0][0], ["ip", "-4", "neigh", "show", "to", self.IP, "dev", "wlan0"])

    def test_connection_is_bound_to_the_device(self):
        sock = mock.Mock()
        with mock.patch.object(wlan_monitor.socket, "socket", return_value=sock):
            wlan_monitor.connect_bound(("192.168.178.1", 49443), 4.0, None, "wlan0")
        names = [c[0] for c in sock.method_calls]
        self.assertLess(names.index("setsockopt"), names.index("connect"))
        sock.setsockopt.assert_any_call(wlan_monitor.socket.SOL_SOCKET, wlan_monitor.SO_BINDTODEVICE, b"wlan0")
        # Binding refused (old kernel): nothing is connected.
        sock = mock.Mock()
        sock.setsockopt.side_effect = PermissionError
        with mock.patch.object(wlan_monitor.socket, "socket", return_value=sock):
            with self.assertRaises(OSError):
                wlan_monitor.connect_bound(("192.168.178.1", 49443), 4.0, None, "wlan0")
        sock.connect.assert_not_called()
        sock.close.assert_called()


class StoreLimitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_the_largest_valid_store_reads_back(self):
        store = {"alerts": False, "view": {"mode": "type", "collapsed": ["type"]}, "networks": {}}
        name = "\U0001F600" * wlan_monitor.NAME_MAX
        for n in range(wlan_monitor.MAX_STORE_NETWORKS):
            devices = {}
            for d in range(wlan_monitor.MAX_STORE_DEVICES):
                mac = "02:%02x:%02x:%02x:00:01" % (n, d >> 8, d & 255)
                devices[mac] = {"name": name, "pinned": True, "hidden": False, "new": True, "first": 1761480000.123456}
            key = "aa:bb:cc:dd:%02x:01|" % n + "\U0001F600" * 64
            store["networks"][key] = {"since": 1761480000.123456, "devices": devices}
        self.assertTrue(wlan_monitor.save_store(store))
        self.assertEqual(wlan_monitor.load_store(), store)

    def test_a_fifo_does_not_block_reading(self):
        import threading
        os.makedirs(wlan_monitor.config_dir(), mode=0o700, exist_ok=True)
        os.mkfifo(os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_FILE), 0o600)
        result = []
        worker = threading.Thread(target=lambda: result.append(wlan_monitor.load_private_json(wlan_monitor.DEVICES_FILE)),
                                  daemon=True)
        worker.start()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [None])


class MalformedReplyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_malformed_mesh_fields_do_not_raise(self):
        A = "1c:23:a2:92:2a:6c"
        for nodes in (
            [{"uid": "a", "device_mac_address": A, "mesh_role": "master", "node_interfaces": 1}],
            [{"uid": "a", "device_mac_address": A, "node_interfaces": [{"uid": "i", "node_links": 5}]}],
            [{"uid": "a", "device_mac_address": A, "node_interfaces": [{"uid": "i", "node_links": [
                {"state": "CONNECTED", "node_1_uid": "a", "node_2_uid": [], "node_interface_2_uid": {}}]}]}],
            [{"uid": "a", "device_mac_address": A, "node_interfaces": [{"uid": "i", "name": [], "node_links": [
                {"state": "CONNECTED", "node_1_uid": "a", "node_2_uid": "b", "node_interface_2_uid": "j"}]}]},
             {"uid": "b", "device_mac_address": "aa:aa:aa:00:00:02", "mesh_role": "master", "device_name": 7,
              "node_interfaces": [{"uid": "j", "name": {}, "type": []}]}],
        ):
            clients, aps = wlan_monitor.parse_mesh({"nodes": nodes})
            self.assertIsInstance(clients, dict)
            self.assertIsInstance(aps, list)

    def test_unexpected_error_during_login_never_leaves_it_connecting(self):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network("192.168.178.1", "1c:23:a2:92:2a:6c", True, True, "wlan0")
        fritz.model_for = ("192.168.178.1", "1c:23:a2:92:2a:6c")
        fritz.login("u", "p", fritz.net_id)
        with mock.patch.object(wlan_monitor, "neighbor_mac", return_value="1c:23:a2:92:2a:6c"), \
                mock.patch.object(wlan_monitor, "fritz_soap", side_effect=TypeError("odd reply")):
            fritz.step()
        info = fritz.snapshot()[0]
        self.assertEqual(info["state"], "error")
        self.assertIsNone(fritz.pending_login)
        self.assertIsNone(wlan_monitor.load_fritz())

    def test_deeply_nested_config_is_refused(self):
        os.makedirs(wlan_monitor.config_dir(), mode=0o700, exist_ok=True)
        path = os.path.join(wlan_monitor.config_dir(), wlan_monitor.DEVICES_FILE)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.write(fd, b"[" * 200000)
        os.close(fd)
        self.assertIsNone(wlan_monitor.load_private_json(wlan_monitor.DEVICES_FILE, wlan_monitor.MAX_STORE_BYTES))
        self.assertEqual(wlan_monitor.load_store()["networks"], {})

    def test_refresh_error_carries_its_own_code(self):
        A, ip = "1c:23:a2:92:2a:6c", "192.168.178.1"
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "u", "password": "p",
                                                                 "pin": "c" * 64})
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(ip, A, True, True, "wlan0")
        fritz.model_for = (ip, A)
        fritz.message_code = "fzConnecting"  # left over from the login
        with mock.patch.object(fritz, "refresh", side_effect=wlan_monitor.FritzError("fzCert", "changed")):
            fritz.step()
        info = fritz.snapshot()[0]
        self.assertEqual((info["state"], info["message_code"]), ("error", "fzCert"))

    def test_disconnect_in_another_collector_stops_this_one(self):
        """One collector per screen: Disconnect on one screen deletes the shared login, and the
        other collectors stop using it (and pick up a login saved by another one)."""
        A, ip = "1c:23:a2:92:2a:6c", "192.168.178.1"
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "u", "password": "p",
                                                                 "pin": "c" * 64})
        first, second = wlan_monitor.FritzMesh(), wlan_monitor.FritzMesh()
        for fritz in (first, second):
            fritz.set_network(ip, A, True, True, "wlan0")
            fritz.model_for = (ip, A)
        first.logout()
        with mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect")):
            second.step()
        self.assertIsNone(second.creds)
        self.assertEqual(second.snapshot()[0]["user"], "")
        wlan_monitor.save_private_json(wlan_monitor.FRITZ_FILE, {"gateway_mac": A, "user": "v", "password": "q",
                                                                 "pin": "c" * 64, "rev": wlan_monitor.fritz_revision()})
        with mock.patch.object(second, "refresh", side_effect=wlan_monitor.FritzError("fzNoMesh", "x")):
            second.step()
        self.assertEqual(second.snapshot()[0]["user"], "v")


class StaleNetworkTests(unittest.TestCase):
    """What was learned about one network never carries over to the next one."""
    A = "1c:23:a2:92:2a:6c"
    B = "66:66:66:66:66:66"
    IP = "192.168.178.1"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_a_previous_fritzbox_model_does_not_offer_login_elsewhere(self):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(self.IP, self.A, True, True, "wlan0")
        fritz.model, fritz.model_for = "FRITZ!Box 7590", (self.IP, self.A)
        self.assertTrue(fritz.snapshot()[0]["available"])
        fritz.set_network(self.IP, self.B, False, True, "wlan0")       # another, non-FRITZ router
        self.assertFalse(fritz.snapshot()[0]["available"])
        fritz.login("u", "p", fritz.net_id)
        self.assertIsNone(fritz.pending_login)
        # A model probe that finishes after the network changed is not kept for the new one.
        fritz.set_network(self.IP, self.A, True, True, "wlan0")
        fritz.model, fritz.model_for = "", None   # not probed yet on this gateway
        def probe(ip, iface=None):
            fritz.set_network(self.IP, self.B, False, True, "wlan0")
            return "FRITZ!Box 7590"
        with mock.patch.object(wlan_monitor, "fritz_model", side_effect=probe), \
                mock.patch.object(wlan_monitor, "bounded_http", side_effect=AssertionError("must not connect")):
            fritz.step()
        self.assertFalse(fritz.snapshot()[0]["available"])
        self.assertNotEqual(fritz.model_for, (self.IP, self.B))

    def run_snapshots(self, steps):
        net = {"iface": "wlan0", "ip": "192.168.178.20", "gateway": self.IP, "prefix": 24,
               "cidr": "192.168.178.20/24", "mac": "02:00:00:00:00:01", "is_wireless": True}
        state = {"net": net, "neighbors": {self.IP: {"mac": self.A, "state": "REACHABLE"}}}
        with mock.patch.object(wlan_monitor, "detect_interface", side_effect=lambda cache: state["net"]), \
                mock.patch.object(wlan_monitor, "read_neighbors", side_effect=lambda iface: dict(state["neighbors"])), \
                mock.patch.object(wlan_monitor.Monitor, "wireless", return_value={"ssid": "Home", "bssid": self.A}), \
                mock.patch.object(wlan_monitor, "detect_vpn", return_value=None), \
                mock.patch.object(wlan_monitor, "read_traffic", return_value=(0, 0)), \
                mock.patch.object(wlan_monitor, "lookup_ptr", return_value=[]), \
                mock.patch.object(wlan_monitor, "sweep", return_value=({}, set())) as sweep, \
                mock.patch.object(wlan_monitor, "run_cmd", return_value=""):
            monitor = wlan_monitor.Monitor()
            steps(monitor, state, sweep)

    def test_trust_needs_the_router_seen_now(self):
        def steps(monitor, state, sweep):
            monitor.snapshot()
            monitor.handle("trust")
            self.assertTrue(monitor.snapshot()["link"]["trusted"])
            # Same address and subnet, the router not in the neighbour table yet: no inherited trust.
            state["neighbors"] = {}
            monitor.last_full_scan = -math.inf
            sweep.reset_mock()
            snap = monitor.snapshot()
            self.assertFalse(snap["link"]["trusted"])
            sweep.assert_not_called()
        self.run_snapshots(steps)

    def test_untrust_on_one_screen_stops_the_other_collector(self):
        def steps(monitor, state, sweep):
            monitor.snapshot()
            monitor.handle("trust")
            other = wlan_monitor.Monitor()
            self.assertTrue(other.snapshot()["link"]["trusted"])
            monitor.handle("untrust")
            other.last_full_scan = -math.inf
            sweep.reset_mock()
            self.assertFalse(other.snapshot()["link"]["trusted"])
            sweep.assert_not_called()
            # Trust on the other screen applies here too.
            other.handle("trust")
            self.assertTrue(monitor.snapshot()["link"]["trusted"])
            # Untrust while another process holds the lock: nothing is written without it, this
            # screen stops at once, and the shared list follows once the lock is free.
            fcntl = __import__("fcntl")
            held = os.open(os.path.join(wlan_monitor.config_dir(), wlan_monitor.TRUST_LOCK_FILE), os.O_RDWR)
            try:
                fcntl.flock(held, fcntl.LOCK_EX)
                with mock.patch.object(wlan_monitor, "FRITZ_LOCK_WAIT", 0.05):
                    monitor.handle("untrust")
                    self.assertFalse(monitor.snapshot()["link"]["trusted"])
                self.assertTrue(wlan_monitor.load_trusted())
            finally:
                os.close(held)
            monitor.snapshot()
            self.assertEqual(wlan_monitor.load_trusted(), [])
            self.assertFalse(other.snapshot()["link"]["trusted"])
        self.run_snapshots(steps)

    def test_disconnect_forgets_the_network(self):
        def steps(monitor, state, sweep):
            first = monitor.snapshot()["link"]["net_id"]
            state["net"] = None
            self.assertIsNone(monitor.snapshot()["link"])
            self.assertIsNone(monitor.identity)
            self.assertIsNone(monitor.fritz.network[0])
            state["net"] = dict(state.get("last") or {}, **{"iface": "wlan0", "ip": "192.168.178.20", "gateway": self.IP,
                                "prefix": 24, "cidr": "192.168.178.20/24", "mac": "02:00:00:00:00:01", "is_wireless": True})
            self.assertNotEqual(monitor.snapshot()["link"]["net_id"], first)
        self.run_snapshots(steps)


class UnknownMakerAndGatewayRefreshTests(unittest.TestCase):
    """0.8.2: a FRITZ!Box whose MAC prefix the database lacks still gets its login (asked once, on a
    trusted network only), and trust does not lapse because the router's ARP entry aged out."""

    GW, MAC = "192.168.178.1", "aa:bb:cc:11:22:33"

    def test_fritz_maker(self):
        self.assertIs(wlan_monitor.fritz_maker("FRITZ! Technology GmbH", False), True)
        self.assertIs(wlan_monitor.fritz_maker("", True), None)
        self.assertIs(wlan_monitor.fritz_maker("Private MAC", True), None)
        self.assertIs(wlan_monitor.fritz_maker("", False), False)          # untrusted: never asked
        self.assertIs(wlan_monitor.fritz_maker("TP-Link", True), False)    # a known other maker

    def probe(self, maker, model_reply):
        fritz = wlan_monitor.FritzMesh()
        fritz.set_network(self.GW, self.MAC, maker, True, "wlan0")
        with mock.patch.object(wlan_monitor, "fritz_model", return_value=model_reply) as asked:
            fritz.step()
            fritz.step()
        return fritz, asked

    def test_unknown_maker_is_asked_once_and_shows_the_login(self):
        fritz, asked = self.probe(None, "FRITZ!Box 5690 Pro")
        self.assertEqual(asked.call_count, 1)
        info, _ = fritz.snapshot()
        self.assertTrue(info["available"])
        self.assertEqual(info["model"], "FRITZ!Box 5690 Pro")

    def test_unknown_maker_that_is_no_fritzbox_stays_hidden(self):
        fritz, asked = self.probe(None, "")
        self.assertEqual(asked.call_count, 1)
        self.assertFalse(fritz.snapshot()[0]["available"])

    def test_known_other_maker_is_never_asked(self):
        fritz, asked = self.probe(False, "FRITZ!Box 5690 Pro")
        asked.assert_not_called()
        self.assertFalse(fritz.snapshot()[0]["available"])

    def test_poke_neighbor_refuses_public_addresses_and_bad_interfaces(self):
        with mock.patch.object(wlan_monitor.socket, "socket") as sock:
            self.assertFalse(wlan_monitor.poke_neighbor("8.8.8.8", "wlan0"))
            self.assertFalse(wlan_monitor.poke_neighbor("192.168.178.1", "wlan0;rm"))
            self.assertFalse(wlan_monitor.poke_neighbor("not-an-ip", "wlan0"))
            sock.assert_not_called()

    def test_poke_neighbor_errors_never_escape(self):
        failing = mock.MagicMock()
        failing.sendto.side_effect = PermissionError("blocked by a VPN")
        with mock.patch.object(wlan_monitor.socket, "socket", return_value=failing):
            self.assertFalse(wlan_monitor.poke_neighbor(self.GW, "wlan0"))
        failing.close.assert_called_once()

    def test_missing_gateway_entry_is_renewed_and_read_again(self):
        mon = wlan_monitor.Monitor()
        neighbors = {}
        with mock.patch.object(wlan_monitor, "poke_neighbor", return_value=True) as poke, \
                mock.patch.object(wlan_monitor, "neighbor_mac", side_effect=["", self.MAC]), \
                mock.patch.object(wlan_monitor.time, "sleep"):
            mon.refresh_gateway(neighbors, self.GW, "wlan0", 100.0)
            poke.assert_called_once_with(self.GW, "wlan0")
        self.assertEqual(neighbors[self.GW]["mac"], self.MAC)
        # Rate-limited: a second missing entry within GATEWAY_POKE_EVERY sends nothing.
        with mock.patch.object(wlan_monitor, "poke_neighbor", return_value=True) as poke:
            mon.refresh_gateway({}, self.GW, "wlan0", 100.0 + wlan_monitor.GATEWAY_POKE_EVERY / 2)
            poke.assert_not_called()

    def test_fresh_gateway_entry_is_left_alone_and_stale_one_renewed_without_waiting(self):
        mon = wlan_monitor.Monitor()
        with mock.patch.object(wlan_monitor, "poke_neighbor", return_value=True) as poke:
            mon.refresh_gateway({self.GW: {"mac": self.MAC, "state": "REACHABLE"}}, self.GW, "wlan0", 50.0)
            poke.assert_not_called()
        with mock.patch.object(wlan_monitor, "poke_neighbor", return_value=True) as poke, \
                mock.patch.object(wlan_monitor, "neighbor_mac") as reread:
            mon.refresh_gateway({self.GW: {"mac": self.MAC, "state": "STALE"}}, self.GW, "wlan0", 50.0)
            poke.assert_called_once()
            reread.assert_not_called()

    def test_router_mac_not_seen_now_hides_the_login_and_drops_a_queued_one(self):
        fritz, _ = self.probe(None, "FRITZ!Box 5690 Pro")
        old_id = fritz.net_id
        fritz.login("fritz1234", "pw", old_id)
        fritz.set_network(self.GW, "", None, True, "wlan0")     # same address, router MAC unknown now
        info, _ = fritz.snapshot()
        self.assertFalse(info["available"])
        self.assertIsNone(fritz.pending_login)
        self.assertNotEqual(fritz.net_id, old_id)
