import importlib.util
import os
import stat
import tempfile
import threading
import unittest
from unittest import mock


SCRIPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts")
WIFI_PATH = os.path.join(SCRIPTS_DIR, "wifi_setup.py")
WLAN_PATH = os.path.join(SCRIPTS_DIR, "wlan-monitor.py")

spec_w = importlib.util.spec_from_file_location("wifi_setup", WIFI_PATH)
wifi_setup = importlib.util.module_from_spec(spec_w)
spec_w.loader.exec_module(wifi_setup)

os.environ.setdefault("XDG_RUNTIME_DIR", tempfile.mkdtemp(prefix="wlan-setup-test-"))
spec_m = importlib.util.spec_from_file_location("wlan_monitor_integ", WLAN_PATH)
wlan_monitor = importlib.util.module_from_spec(spec_m)
spec_m.loader.exec_module(wlan_monitor)


UUID_WIFI = "f4aff26e-1193-43cc-8418-9e72a62e952e"
UUID_NEW = "11111111-2222-3333-4444-555555555555"
UUID_ETH = "ea447854-8010-35ca-af1b-1051ffa77142"
UUID_VPN = "99999999-8888-7777-6666-555555555555"


class WifiSetupParserAndValidationTests(unittest.TestCase):
    def test_nm_terse_split_handles_escaped_colons_and_backslashes(self):
        line = r"*:My\:Home\\Net:1C\:23\:A2\:92\:2A\:80:77:WPA2:11:2462 MHz:1170 Mbit/s"
        self.assertEqual(
            wifi_setup.nm_terse_split(line),
            ["*", r"My:Home\Net", "1C:23:A2:92:2A:80", "77", "WPA2", "11", "2462 MHz", "1170 Mbit/s"],
        )
        self.assertEqual(wifi_setup.nm_terse_split("a::b:"), ["a", "", "b", ""])

    def test_validators_utf8_bytes_and_att_ssid(self):
        self.assertEqual(wifi_setup.validate_ssid("FRITZ!Box 7690 ML"), "FRITZ!Box 7690 ML")
        self.assertEqual(wifi_setup.validate_ssid("AT&T Wifi"), "AT&T Wifi")
        self.assertEqual(wifi_setup.clean_ssid("AT&T Wifi"), "AT&T Wifi")
        self.assertEqual(wifi_setup.validate_ssid("ä" * 16), "ä" * 16)  # 32 UTF-8 bytes
        self.assertIsNone(wifi_setup.validate_ssid("ä" * 17))  # 34 UTF-8 bytes > 32
        self.assertIsNone(wifi_setup.validate_ssid(""))
        self.assertIsNone(wifi_setup.validate_ssid("   "))
        self.assertIsNone(wifi_setup.validate_ssid("-evil"))
        self.assertIsNone(wifi_setup.validate_ssid("a" * 33))
        self.assertIsNone(wifi_setup.validate_ssid("line\nbreak"))

        self.assertEqual(wifi_setup.validate_uuid(UUID_WIFI), UUID_WIFI)
        self.assertIsNone(wifi_setup.validate_uuid("short"))
        self.assertIsNone(wifi_setup.validate_uuid("not_a_uuid!"))
        self.assertIsNone(wifi_setup.validate_uuid("$(id)-1234"))

        self.assertEqual(wifi_setup.validate_password("correcthorse"), "correcthorse")
        self.assertEqual(wifi_setup.validate_password("12345678"), "12345678")
        self.assertEqual(wifi_setup.validate_password("a" * 63), "a" * 63)
        # UTF-8 multibyte passphrase bounds (bytes, not code points)
        self.assertEqual(wifi_setup.validate_password("ü" * 4), "ü" * 4)  # 8 UTF-8 bytes
        self.assertEqual(wifi_setup.validate_password("ü" * 31), "ü" * 31)  # 62 UTF-8 bytes
        self.assertIsNone(wifi_setup.validate_password("ü" * 32))  # 64 UTF-8 bytes (not hex)
        # 64 hex chars raw PSK is valid; 64 non-hex chars is not
        self.assertEqual(wifi_setup.validate_password("a0" * 32), "a0" * 32)
        self.assertIsNone(wifi_setup.validate_password("z" * 64))
        self.assertIsNone(wifi_setup.validate_password("short7!"))
        self.assertIsNone(wifi_setup.validate_password(" leading8"))
        self.assertIsNone(wifi_setup.validate_password("trailing8 "))
        self.assertIsNone(wifi_setup.validate_password("bad\npass12"))

    def test_freq_to_band_and_narrowed_auth_failure(self):
        self.assertEqual(wifi_setup.freq_to_band("2462 MHz"), "2.4 GHz")
        self.assertEqual(wifi_setup.freq_to_band("5180 MHz"), "5 GHz")
        self.assertEqual(wifi_setup.freq_to_band("6135 MHz"), "6 GHz")
        self.assertEqual(wifi_setup.freq_to_band("unknown"), "")

        self.assertTrue(wifi_setup.is_auth_failure("Error: Secrets were required, but not provided."))
        self.assertTrue(wifi_setup.is_auth_failure("No agents were available for this request."))
        self.assertTrue(wifi_setup.is_auth_failure("Reason: no-secrets"))
        self.assertTrue(wifi_setup.is_auth_failure("4-way handshake timeout"))
        self.assertTrue(wifi_setup.is_auth_failure("Invalid key length"))
        self.assertTrue(wifi_setup.is_auth_failure("Wrong password"))
        # Broad words that should NOT be misclassified as wrong password
        self.assertFalse(wifi_setup.is_auth_failure("802-11-wireless-security property unknown"))
        self.assertFalse(wifi_setup.is_auth_failure("wpa_supplicant service not running"))
        self.assertFalse(wifi_setup.is_auth_failure("Device wlan0 not found"))


class PasswdFileSecurityTests(unittest.TestCase):
    def test_passwd_file_permissions_content_backslash_and_cleanup(self):
        with tempfile.TemporaryDirectory() as xdg:
            os.chmod(xdg, 0o700)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": xdg}):
                secret_path = None
                secret_dir = None
                pw = r"Super\Secret\99!"
                self.assertEqual(wifi_setup.validate_password(pw), pw)
                with wifi_setup._write_passwd_file(pw) as pfile:
                    secret_path = pfile
                    secret_dir = os.path.dirname(pfile)
                    self.assertTrue(secret_dir.startswith(xdg))
                    self.assertEqual(stat.S_IMODE(os.stat(secret_dir).st_mode), 0o700)
                    self.assertEqual(stat.S_IMODE(os.stat(pfile).st_mode), 0o600)
                    with open(pfile, "r", encoding="utf-8") as fh:
                        self.assertEqual(fh.read(), f"802-11-wireless-security.psk:{pw}\n")
                self.assertFalse(os.path.exists(secret_path))
                self.assertFalse(os.path.exists(secret_dir))

    def test_passwd_file_cleaned_up_on_exception_and_refuses_symlink_xdg(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_dir = os.path.join(tmp, "real")
            os.makedirs(real_dir, mode=0o700)
            link_dir = os.path.join(tmp, "link")
            os.symlink(real_dir, link_dir)
            with mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": link_dir}):
                seen_path = None
                try:
                    with wifi_setup._write_passwd_file("SecretPass123") as pfile:
                        seen_path = pfile
                        self.assertFalse(pfile.startswith(link_dir))
                        raise RuntimeError("boom")
                except RuntimeError:
                    pass
                self.assertFalse(os.path.exists(seen_path))
                self.assertFalse(os.path.exists(os.path.dirname(seen_path)))


class WifiStateAndActionsTests(unittest.TestCase):
    def test_get_wifi_state_preserves_att_ssid_and_matches_by_profile_ssid(self):
        with tempfile.TemporaryDirectory() as tmp:
            resolv = os.path.join(tmp, "resolv.conf")
            with open(resolv, "w") as f:
                f.write("nameserver 192.168.178.1\n")

            def fake_nmcli(args, timeout=15.0):
                if args == ["-t", "radio", "wifi"]:
                    return 0, "enabled\n", ""
                if args[:3] == ["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION"]:
                    return 0, (
                        "wlan0:wifi:connected:Work Profile 1\n"
                        "enp16s0:ethernet:unavailable:\n"
                        "lo:loopback:connected (externally):lo\n"
                    ), ""
                if args[:3] == ["-t", "-f", "NAME,UUID,TYPE,DEVICE,AUTOCONNECT"]:
                    return 0, (
                        f"Work Profile 1:{UUID_WIFI}:802-11-wireless:wlan0:yes\n"
                        f"Wired 1:{UUID_ETH}:802-3-ethernet::yes\n"
                        f"HomeVPN:{UUID_VPN}:wireguard:wg0:no\n"
                    ), ""
                if args[:2] == ["-g", "802-11-wireless.ssid"]:
                    return 0, "AT&T Wifi\n", ""
                if "wifi" in args and "list" in args:
                    return 0, (
                        r" :AT&T Wifi:1C\:23\:A2\:92\:2A\:80:88:WPA2:11:2462 MHz:1170 Mbit/s" + "\n"
                        r"*:AT&T Wifi:2E\:23\:A2\:92\:2A\:80:65:WPA3:37:6135 MHz:2400 Mbit/s" + "\n"
                        r" ::AA\:BB\:CC\:DD\:EE\:FF:99:WPA2:1:2412 MHz:54 Mbit/s" + "\n"
                        r" :CafeGuest:11\:22\:33\:44\:55\:66:72:WPA2:36:5180 MHz:866 Mbit/s" + "\n"
                        r" :CafeGuest:11\:22\:33\:44\:55\:77:40:WPA2:6:2437 MHz:144 Mbit/s" + "\n"
                    ), ""
                return 1, "", "unexpected"

            with mock.patch.object(wifi_setup, "nm_available", return_value=True), \
                    mock.patch.object(wifi_setup, "_run_nmcli", side_effect=fake_nmcli):
                st = wifi_setup.get_wifi_state(rescan=True, resolv_path=resolv, sys_net=tmp)

            self.assertTrue(st["nm_available"])
            self.assertTrue(st["wifi_device"])
            self.assertTrue(st["wifi_on"])
            self.assertEqual(st["active_ssid"], "AT&T Wifi")
            self.assertEqual(st["dns"], ["192.168.178.1"])
            self.assertEqual(len(st["known"]), 1)
            self.assertEqual(st["known"][0]["ssid"], "AT&T Wifi")
            self.assertTrue(st["known"][0]["autoconnect"])
            self.assertEqual(len(st["wired"]), 1)
            self.assertEqual(len(st["wired_devices"]), 1)
            self.assertEqual(len(st["vpn"]), 1)
            self.assertTrue(st["vpn"][0]["active"])

            # Hidden SSID skipped, duplicates collapsed, in-use AP kept first, AT&T preserved & marked known
            self.assertEqual([v["ssid"] for v in st["visible"]], ["AT&T Wifi", "CafeGuest"])
            self.assertTrue(st["visible"][0]["in_use"])
            self.assertTrue(st["visible"][0]["known"])
            self.assertEqual(st["visible"][0]["band"], "6 GHz")
            self.assertEqual(st["visible"][0]["channel"], 37)
            self.assertEqual(st["visible"][0]["rate_mbps"], 2400)
            self.assertEqual(st["visible"][1]["signal"], 72)
            self.assertEqual(st["visible"][1]["band"], "5 GHz")
            self.assertFalse(st["visible"][1]["known"])

    def test_wifi_connect_new_wpa3_ssid_uses_sae_wait20_and_cleans_up_on_failure(self):
        calls = []
        pw = "MySecretWifiPass1!"

        def fake_nmcli(args, timeout=15.0):
            calls.append(list(args))
            self.assertNotIn(pw, " ".join(args))
            if args[:3] == ["-t", "-f", "NAME,UUID,TYPE"]:
                return 0, "", ""
            if args[:3] == ["-t", "-f", "SSID,SECURITY"]:
                return 0, "CoffeeShop:WPA3\n", ""
            if "add" in args:
                self.assertIn("sae", args)
                return 0, f"connection.uuid:{UUID_NEW}\n", ""
            if "up" in args:
                self.assertEqual(args[:2], ["--wait", "20"])
                self.assertIn("passwd-file", args)
                pfile = args[args.index("passwd-file") + 1]
                self.assertTrue(os.path.isfile(pfile))
                return 4, "", f"Error: Secrets were required for {pw}"
            if "delete" in args:
                return 0, "", ""
            return 1, "", ""

        with mock.patch.object(wifi_setup, "nm_available", return_value=True), \
                mock.patch.object(wifi_setup, "_run_nmcli", side_effect=fake_nmcli):
            res = wifi_setup.wifi_connect(ssid="CoffeeShop", password=pw)

        self.assertFalse(res["ok"])
        self.assertTrue(res["auth_failed"])
        self.assertNotIn(pw, res["message"])
        self.assertTrue(any(c[:3] == ["connection", "delete", "uuid"] and c[3] == UUID_NEW for c in calls))

    def test_wifi_connect_saved_uuid_preserves_wpa3_sae_and_never_uses_remove(self):
        calls = []
        pw = "FreshPassphrase2026"

        def fake_nmcli(args, timeout=15.0):
            calls.append(list(args))
            self.assertNotIn(pw, " ".join(args))
            self.assertNotIn("remove", args)
            if args[:3] == ["-t", "-f", "connection.id,connection.type"]:
                return 0, "connection.id:HomeNet\nconnection.type:802-11-wireless\n", ""
            if args[:2] == ["-g", "802-11-wireless.ssid"]:
                return 0, "HomeNet\n", ""
            if args[:2] == ["-g", "802-11-wireless-security.key-mgmt,802-11-wireless-security.psk-flags"]:
                return 0, "sae\n1\n", ""
            if "modify" in args:
                self.assertIn("sae", args)
                self.assertNotIn("wpa-psk", args)
                self.assertIn("wifi-sec.psk", args)
                # Existing psk-flags=1 should be preserved (not overwritten to 0)
                self.assertNotIn("wifi-sec.psk-flags", args)
                return 0, "", ""
            if "up" in args:
                self.assertEqual(args[:2], ["--wait", "20"])
                self.assertIn("passwd-file", args)
                return 0, "Connection successfully activated\n", ""
            return 0, "", ""

        with mock.patch.object(wifi_setup, "nm_available", return_value=True), \
                mock.patch.object(wifi_setup, "_run_nmcli", side_effect=fake_nmcli):
            res = wifi_setup.wifi_connect(uuid=UUID_WIFI, password=pw)

        self.assertTrue(res["ok"])
        self.assertFalse(res["auth_failed"])
        self.assertEqual(res["ssid"], "HomeNet")

    def test_wifi_connect_refuses_enterprise_8021x_saved_and_visible(self):
        def fake_nmcli_saved(args, timeout=15.0):
            if args[:3] == ["-t", "-f", "connection.id,connection.type"]:
                return 0, "connection.id:CorpWiFi\nconnection.type:802-11-wireless\n", ""
            if args[:2] == ["-g", "802-11-wireless.ssid"]:
                return 0, "CorpWiFi\n", ""
            if args[:2] == ["-g", "802-11-wireless-security.key-mgmt,802-11-wireless-security.psk-flags"]:
                return 0, "wpa-eap\n0\n", ""
            return 0, "", ""

        with mock.patch.object(wifi_setup, "nm_available", return_value=True), \
                mock.patch.object(wifi_setup, "_run_nmcli", side_effect=fake_nmcli_saved):
            res = wifi_setup.wifi_connect(uuid=UUID_WIFI, password="ValidPassword123")
        self.assertFalse(res["ok"])
        self.assertFalse(res["auth_failed"])
        self.assertIn("802.1X", res["message"])

        def fake_nmcli_visible(args, timeout=15.0):
            if args[:3] == ["-t", "-f", "NAME,UUID,TYPE"]:
                return 0, "", ""
            if args[:3] == ["-t", "-f", "SSID,SECURITY"]:
                return 0, "Eduroam:WPA2 802.1X\n", ""
            return 0, "", ""

        with mock.patch.object(wifi_setup, "nm_available", return_value=True), \
                mock.patch.object(wifi_setup, "_run_nmcli", side_effect=fake_nmcli_visible):
            res2 = wifi_setup.wifi_connect(ssid="Eduroam", password="ValidPassword123")
        self.assertFalse(res2["ok"])
        self.assertIn("802.1X", res2["message"])

    def test_wifi_connect_reuses_existing_saved_profile_for_ssid(self):
        calls = []

        def fake_nmcli(args, timeout=15.0):
            calls.append(list(args))
            if args[:3] == ["-t", "-f", "NAME,UUID,TYPE"]:
                return 0, f"Custom Name:{UUID_WIFI}:802-11-wireless\n", ""
            if args[:2] == ["-g", "802-11-wireless.ssid"]:
                return 0, "AT&T Wifi\n", ""
            if args[:3] == ["-t", "-f", "connection.id,connection.type"]:
                return 0, "connection.id:Custom Name\nconnection.type:802-11-wireless\n", ""
            if "up" in args:
                self.assertEqual(args, ["--wait", "20", "connection", "up", "uuid", UUID_WIFI])
                return 0, "ok\n", ""
            return 0, "", ""

        with mock.patch.object(wifi_setup, "nm_available", return_value=True), \
                mock.patch.object(wifi_setup, "_run_nmcli", side_effect=fake_nmcli):
            res = wifi_setup.wifi_connect(ssid="AT&T Wifi")

        self.assertTrue(res["ok"])
        self.assertEqual(res["uuid"], UUID_WIFI)
        self.assertEqual(res["ssid"], "AT&T Wifi")
        self.assertFalse(any("add" in c for c in calls))

    def test_forget_and_connection_type_validation(self):
        def fake_nmcli(args, timeout=15.0):
            if "show" in args and UUID_ETH in args:
                return 0, "connection.id:Wired 1\nconnection.type:802-3-ethernet\n", ""
            if "show" in args and UUID_WIFI in args:
                return 0, "connection.id:Home\nconnection.type:802-11-wireless\n", ""
            return 0, "", ""

        with mock.patch.object(wifi_setup, "nm_available", return_value=True), \
                mock.patch.object(wifi_setup, "_run_nmcli", side_effect=fake_nmcli):
            bad = wifi_setup.wifi_forget(UUID_ETH)
            self.assertFalse(bad["ok"])
            ok_eth = wifi_setup.connection_up(UUID_ETH)
            self.assertTrue(ok_eth["ok"])
            ok_wifi = wifi_setup.wifi_forget(UUID_WIFI)
            self.assertTrue(ok_wifi["ok"])


class WlanMonitorIntegrationTests(unittest.TestCase):
    def test_parse_new_json_commands(self):
        parse = wlan_monitor.parse_command
        self.assertEqual(parse('{"cmd":"netmon","on":true,"resolve":true}'), {"cmd": "netmon", "on": True, "resolve": True})
        self.assertEqual(parse('{"cmd":"netmon","on":"yes"}'), "")
        self.assertEqual(parse('{"cmd":"wifi_scan","rescan":true}'), {"cmd": "wifi_scan", "rescan": True})
        self.assertEqual(parse('{"cmd":"wifi_radio","on":false}'), {"cmd": "wifi_radio", "on": False})
        self.assertEqual(
            parse(f'{{"cmd":"wifi_connect","ssid":"AT&T Wifi","password":"secret123","uuid":"{UUID_WIFI}"}}'),
            {"cmd": "wifi_connect", "ssid": "AT&T Wifi", "uuid": UUID_WIFI, "password": "secret123"},
        )
        self.assertEqual(parse('{"cmd":"wifi_connect","ssid":"-bad"}'), "")
        self.assertEqual(parse('{"cmd":"wifi_connect"}'), "")
        for cmd in ("wifi_disconnect", "wifi_forget", "conn_up", "conn_down"):
            self.assertEqual(parse(f'{{"cmd":"{cmd}","uuid":"{UUID_WIFI}"}}'), {"cmd": cmd, "uuid": UUID_WIFI})
            self.assertEqual(parse(f'{{"cmd":"{cmd}","uuid":"$(id)"}}'), "")

    def test_snapshot_includes_wifi_status_and_optional_netmon(self):
        with tempfile.TemporaryDirectory() as cfg:
            with mock.patch.dict(os.environ, {"XDG_CONFIG_HOME": cfg}):
                mon = wlan_monitor.Monitor()
                try:
                    with mock.patch.object(wlan_monitor, "detect_interface", return_value=None), \
                            mock.patch.object(wlan_monitor.wifi_setup_mod, "nm_available", return_value=True), \
                            mock.patch.object(wlan_monitor.wifi_setup_mod, "has_wifi_device", return_value=True), \
                            mock.patch.object(wlan_monitor.wifi_setup_mod, "get_wifi_radio", return_value=False):
                        snap = mon.snapshot()
                        self.assertFalse(snap["active"])
                        self.assertTrue(snap["nm_available"])
                        self.assertTrue(snap["wifi_device"])
                        self.assertFalse(snap["wifi_on"])
                        self.assertNotIn("netmon", snap)

                        self.assertTrue(mon.handle({"cmd": "netmon", "on": True, "resolve": False}))
                        with mock.patch.object(mon.net_monitor, "collect", return_value={"summary": {"total": 3}}) as col:
                            snap2 = mon.snapshot()
                            col.assert_called_once_with(resolve=False)
                            self.assertEqual(snap2["netmon"], {"summary": {"total": 3}})
                finally:
                    mon.close()

    def test_wifi_command_worker_emits_result_and_state_and_dedups_scans(self):
        emitted = []
        mon = wlan_monitor.Monitor()
        mon._emit_fn = emitted.append
        fake_state = {
            "nm_available": True,
            "wifi_device": True,
            "wifi_on": True,
            "active_ssid": "Home",
            "dns": [],
            "known": [],
            "visible": [],
            "wired": [],
            "wired_devices": [],
            "vpn": [],
            "error": "",
        }
        with mock.patch.object(wlan_monitor.wifi_setup_mod, "set_wifi_radio", return_value={"ok": True, "action": "radio", "message": "Wi-Fi enabled."}), \
                mock.patch.object(wlan_monitor.wifi_setup_mod, "get_wifi_state", return_value=fake_state):
            mon._run_wifi_command({"cmd": "wifi_radio", "on": True})
        self.assertEqual([e["event"] for e in emitted], ["wifi_result", "wifi_state"])
        self.assertTrue(emitted[0]["ok"])
        self.assertEqual(emitted[1]["active_ssid"], "Home")

        # Duplicate concurrent wifi_scan should be skipped while one is in flight
        entered = threading.Event()
        release = threading.Event()

        def slow_scan(rescan=False):
            entered.set()
            release.wait(timeout=2.0)
            return fake_state

        with mock.patch.object(wlan_monitor.wifi_setup_mod, "get_wifi_state", side_effect=slow_scan):
            t1 = mon._spawn_wifi_command({"cmd": "wifi_scan", "rescan": True})
            self.assertIsNotNone(t1)
            self.assertTrue(entered.wait(timeout=2.0))
            t2 = mon._spawn_wifi_command({"cmd": "wifi_scan", "rescan": True})
            self.assertIsNone(t2)
            release.set()
            t1.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
