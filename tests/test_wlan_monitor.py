import importlib.util
import os
import struct
import unittest

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


if __name__ == "__main__":
    unittest.main()
