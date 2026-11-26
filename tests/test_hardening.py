"""Regression tests for the 0.11.1 review findings (hostile input: beacon floods, BiDi SSIDs,
hyphen UUIDs, killed collectors, other users' processes, broken rDNS input)."""

import importlib.util
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


wifi = load("nm_wifi_hardening", "nm_wifi.py")
netmon = load("net_monitor_hardening", "net_monitor.py")


class WifiSetupHardening(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.chmod(self.tmp.name, 0o700)
        self.env = mock.patch.dict(os.environ, {"XDG_RUNTIME_DIR": self.tmp.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tmp.cleanup()

    def test_clean_ssid_drops_bidi_and_c1_and_caps_bytes(self):
        self.assertEqual(wifi.clean_ssid("Caf‮e\x85⁦X"), "CafeX")
        self.assertEqual(wifi.clean_ssid("a<b>&c"), "a<b>&c")
        long = wifi.clean_ssid("é" * 40)
        self.assertLessEqual(len(long.encode("utf-8")), 32)

    def test_uuid_must_be_canonical(self):
        for bad in ("--------", "-a000000", "-f000000", "--ffffff", "abcdefgh", "8b1c2d3e00004000800000000000000"):
            self.assertIsNone(wifi.validate_uuid(bad), bad)
        self.assertTrue(wifi.validate_uuid("f4aff26e-1193-43cc-8418-9e72a62e952e"))

    def test_runner_caps_output_and_kills(self):
        real = wifi.subprocess.Popen

        def fake(argv, **kw):  # `yes` floods stdout forever: must stop at the cap
            return real(["yes", "flood"], **kw)
        with mock.patch.object(wifi.subprocess, "Popen", side_effect=fake):
            rc, out, err = wifi._run_nmcli(["x"], timeout=5.0, max_out=4096)
        self.assertEqual(rc, 125)
        self.assertEqual(out, "")
        self.assertEqual(wifi._ACTIVE_PROCS, ())

    def test_runner_deadline(self):
        real = wifi.subprocess.Popen

        def fake(argv, **kw):
            return real(["sleep", "10"], **kw)
        with mock.patch.object(wifi.subprocess, "Popen", side_effect=fake):
            started = time.monotonic()
            rc, _, err = wifi._run_nmcli(["x"], timeout=0.3)
        self.assertEqual(rc, 124)
        self.assertLess(time.monotonic() - started, 4)

    def test_visible_networks_capped_for_beacon_flood(self):
        lines = ["*:Home:aa\\:bb\\:cc\\:dd\\:ee\\:ff:90:WPA2:36:5180 MHz:866 Mbit/s"]
        lines += [" :Fake%04d:aa\\:bb\\:cc\\:00\\:%02x\\:%02x:%d:WPA2:1:2412 MHz:54 Mbit/s" % (i, i // 256 % 256, i % 256, i % 100)
                  for i in range(3000)]

        def run(args, timeout=None, **_kw):
            if args[:2] == ["-t", "radio"]:
                return 0, "enabled\n", ""
            if "device" in args and "status" in args:
                return 0, "wlan0:wifi:connected:Home\n", ""
            if "connection" in args and "show" in args:
                return 0, "", ""
            if "list" in args:
                return 0, "\n".join(lines), ""
            return 1, "", ""
        with mock.patch.object(wifi, "_run_nmcli", side_effect=run), \
                mock.patch.object(wifi, "nm_available", return_value=True):
            state = wifi.get_wifi_state(sys_net=self.tmp.name)
        self.assertLessEqual(len(state["visible"]), wifi.MAX_VISIBLE)
        self.assertTrue(any(v["in_use"] for v in state["visible"]))

    def test_secret_dir_private_and_symlink_refused(self):
        folder = wifi.secret_dir()
        self.assertTrue(folder.startswith(self.tmp.name))
        self.assertEqual(stat.S_IMODE(os.lstat(folder).st_mode), 0o700)
        os.rmdir(folder)
        os.symlink("/tmp", folder)
        self.assertIsNone(wifi.secret_dir())
        with self.assertRaises(OSError):
            with wifi._write_passwd_file("password123"):
                pass

    def test_passwd_file_removed_and_tracked(self):
        with wifi._write_passwd_file("password123") as path:
            self.assertIn(path, wifi._ACTIVE_SECRETS)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertFalse(os.path.exists(path))
        self.assertNotIn(path, wifi._ACTIVE_SECRETS)

    def test_cleanup_active_removes_file_in_flight(self):
        ctx = wifi._write_passwd_file("password123")
        path = ctx.__enter__()
        wifi.cleanup_active()  # what the collector's SIGTERM handler does
        self.assertFalse(os.path.exists(path))
        ctx.__exit__(None, None, None)

    def test_sweep_removes_only_old_leftovers(self):
        folder = wifi.secret_dir()
        old = os.path.join(folder, wifi.SECRET_PREFIX + "1-aaaa")
        new = os.path.join(folder, wifi.SECRET_PREFIX + "2-bbbb")
        for d in (old, new):
            os.mkdir(d, 0o700)
            with open(os.path.join(d, "secrets"), "w") as fh:
                fh.write("x")
        past = time.time() - 3600
        os.utime(old, (past, past))
        self.assertEqual(wifi.sweep_stale_secrets(), 1)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(new))

    def test_new_profile_deleted_when_password_file_fails(self):
        calls = []

        def run(args, timeout=None, **_kw):
            calls.append(args)
            if "add" in args:
                return 0, "f4aff26e-1193-43cc-8418-9e72a62e952e\n", ""
            return 0, "", ""
        with mock.patch.object(wifi, "_run_nmcli", side_effect=run), \
                mock.patch.object(wifi, "nm_available", return_value=True), \
                mock.patch.object(wifi, "_find_saved_wifi_uuid", return_value=None), \
                mock.patch.object(wifi, "_detect_visible_security", return_value="wpa-psk"), \
                mock.patch.object(wifi, "_write_passwd_file", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                wifi.wifi_connect(ssid="Cafe", password="password123")
        self.assertIn(["connection", "delete", "uuid", "f4aff26e-1193-43cc-8418-9e72a62e952e"], calls)

    def test_no_private_folder_changes_nothing(self):
        with mock.patch.object(wifi, "nm_available", return_value=True), \
                mock.patch.object(wifi, "_find_saved_wifi_uuid", return_value=None), \
                mock.patch.object(wifi, "_detect_visible_security", return_value="wpa-psk"), \
                mock.patch.object(wifi, "secret_dir", return_value=None), \
                mock.patch.object(wifi, "_run_nmcli") as run:
            res = wifi.wifi_connect(ssid="Cafe", password="password123")
        self.assertFalse(res["ok"])
        run.assert_not_called()  # no profile added
        with mock.patch.object(wifi, "nm_available", return_value=True), \
                mock.patch.object(wifi, "_get_connection_meta", return_value=("Cafe", "802-11-wireless")), \
                mock.patch.object(wifi, "_get_wifi_profile_ssid", return_value="Cafe"), \
                mock.patch.object(wifi, "_get_wifi_security_props", return_value=("wpa-psk", "")), \
                mock.patch.object(wifi, "secret_dir", return_value=None), \
                mock.patch.object(wifi, "_run_nmcli") as run:
            res = wifi.wifi_connect(uuid="f4aff26e-1193-43cc-8418-9e72a62e952e", password="password123")
        self.assertFalse(res["ok"])
        run.assert_not_called()  # the saved password is not cleared

    def test_cleanup_reads_without_lock(self):
        with wifi._ACTIVE_LOCK:  # the signal handler may interrupt the thread holding it
            done = []
            t = threading.Thread(target=lambda: (wifi.cleanup_active(), done.append(1)))
            t.start()
            t.join(2.0)
        self.assertEqual(done, [1])

    def test_password_change_refused_on_open_profile(self):
        with mock.patch.object(wifi, "nm_available", return_value=True), \
                mock.patch.object(wifi, "_get_connection_meta", return_value=("Cafe", "802-11-wireless")), \
                mock.patch.object(wifi, "_get_wifi_profile_ssid", return_value="Cafe"), \
                mock.patch.object(wifi, "_get_wifi_security_props", return_value=("owe", "")), \
                mock.patch.object(wifi, "_run_nmcli") as run:
            res = wifi.wifi_connect(uuid="f4aff26e-1193-43cc-8418-9e72a62e952e", password="password123")
        self.assertFalse(res["ok"])
        run.assert_not_called()


class NetMonitorHardening(unittest.TestCase):
    def test_cmdline_of_other_user_not_read(self):
        with mock.patch.object(netmon, "own_process", return_value=False), \
                mock.patch("builtins.open") as opened:
            self.assertEqual(netmon.read_cmdline(1), "")
        opened.assert_not_called()

    def test_rdns_only_for_ip_literals_and_slot_freed(self):
        mon = netmon.NetMonitor()
        self.assertEqual(mon._lookup_rdns_cached("evil.example\x00", time.monotonic()), "")
        self.assertFalse(mon._rdns_pending)
        with mock.patch.object(netmon.socket, "gethostbyaddr", side_effect=UnicodeError("bad")):
            mon._rdns_worker("8.8.8.8")
        self.assertNotIn("8.8.8.8", mon._rdns_pending)

    def test_connections_and_processes_capped(self):
        mon = netmon.NetMonitor()
        rows = [{"protocol": "tcp", "local_ip": "10.0.0.2", "local_port": 40000 + (i % 20000),
                 "remote_ip": "1.1.1.%d" % (i % 250), "remote_port": 443, "pid": i, "process": "p%d" % i,
                 "rx_bytes": 0, "tx_bytes": 0, "rx_rate": 0.0, "tx_rate": 0.0, "scope": "external",
                 "state": "ESTABLISHED", "cmdline": "", "service": "https", "rtt_ms": None,
                 "remote_host": ""} for i in range(2000)]
        with mock.patch.object(mon, "_collect_raw_connections", return_value=rows), \
                mock.patch.object(mon, "collect_interfaces", return_value=[]):
            snap = mon.collect()
        self.assertLessEqual(len(snap["connections"]), netmon.MAX_CONNECTIONS)
        self.assertLessEqual(len(snap["processes"]), netmon.MAX_PROCESSES)
        self.assertEqual(snap["summary"]["total"], 2000)


class CollectorHardening(unittest.TestCase):
    def setUp(self):
        self.wm = load("wlan_monitor_hardening", "wlan-monitor.py")

    def test_saved_profile_ssid_is_only_a_label(self):
        uuid = "f4aff26e-1193-43cc-8418-9e72a62e952e"
        cmd = self.wm.parse_command('{"cmd": "wifi_connect", "ssid": "-dash net", "uuid": "%s"}' % uuid)
        self.assertEqual((cmd["uuid"], cmd["ssid"]), (uuid, "-dash net"))
        self.assertEqual(self.wm.parse_command('{"cmd": "wifi_connect", "ssid": "-dash net"}'), "")

    def test_thread_start_failure_frees_busy(self):
        mon = self.wm.Monitor.__new__(self.wm.Monitor)
        mon._wifi_scan_lock = threading.Lock()
        mon._wifi_scan_running = False
        mon._wifi_busy = False
        out = []
        mon._emit_fn = out.append
        with mock.patch.object(self.wm.threading.Thread, "start", side_effect=RuntimeError("no threads")):
            self.assertIsNone(mon._spawn_wifi_command({"cmd": "wifi_radio", "on": True}))
        self.assertFalse(mon._wifi_busy)
        self.assertFalse(out[0]["ok"])

    def test_second_network_change_refused_while_one_runs(self):
        mon = self.wm.Monitor.__new__(self.wm.Monitor)
        mon._wifi_scan_lock = threading.Lock()
        mon._wifi_worker_lock = threading.Lock()
        mon._wifi_scan_running = False
        mon._wifi_busy = True
        out = []
        mon._emit_fn = out.append
        self.assertIsNone(mon._spawn_wifi_command({"cmd": "wifi_forget", "uuid": "f4aff26e-1193-43cc-8418-9e72a62e952e"}))
        self.assertEqual(out[0]["event"], "wifi_result")
        self.assertFalse(out[0]["ok"])

    def test_worker_exception_reports_failure_and_frees_busy(self):
        mon = self.wm.Monitor.__new__(self.wm.Monitor)
        mon._wifi_scan_lock = threading.Lock()
        mon._wifi_worker_lock = threading.Lock()
        mon._wifi_busy = True
        out = []
        mon._emit_fn = out.append
        fake = mock.MagicMock()
        fake.wifi_connect.side_effect = OSError("secret password123 leaked?")
        with mock.patch.object(self.wm, "wifi_setup_mod", fake):
            mon._run_wifi_command({"cmd": "wifi_connect", "ssid": "Cafe", "password": "password123"})
        self.assertFalse(mon._wifi_busy)
        self.assertEqual(out[-1]["event"], "wifi_result")
        self.assertNotIn("password123", str(out))

    def test_wifi_uuid_regex_canonical(self):
        self.assertIsNone(self.wm.WIFI_UUID_RE.match("--------"))
        self.assertTrue(self.wm.WIFI_UUID_RE.match("f4aff26e-1193-43cc-8418-9e72a62e952e"))

    def test_passive_monitor_overlays_but_never_records_or_notifies(self):
        mon = self.wm.Monitor.__new__(self.wm.Monitor)
        mon.passive = True
        mon.trust_identity = {"ssid": "Home", "gateway_mac": "aa:bb:cc:dd:ee:01"}
        mon.lang = "en"
        key = self.wm.network_key(mon.trust_identity)
        mon.store = {"alerts": True, "view": {}, "networks": {key: {"since": 1.0, "devices": {
            "aa:bb:cc:dd:ee:10": {"name": "Saved TV", "pinned": True, "hidden": False, "new": False, "first": 1.0}}}}}
        devices = [{"mac": "aa:bb:cc:dd:ee:10", "name": "lgtv", "is_self": False},
                   {"mac": "aa:bb:cc:dd:ee:99", "name": "stranger", "is_self": False}]
        with mock.patch.object(mon, "reload_store"), \
                mock.patch.object(mon, "update_store") as update, \
                mock.patch.object(self.wm, "notify_new_devices") as notify:
            mon.apply_store(devices, True, "Home")
        update.assert_not_called()
        notify.assert_not_called()
        self.assertEqual(devices[0]["name"], "Saved TV")
        self.assertFalse(devices[1]["new"])
        self.assertNotIn("aa:bb:cc:dd:ee:99", mon.store["networks"][key]["devices"])

    def test_cleanup_skips_reaped_child(self):
        proc = mock.MagicMock()
        proc.returncode = 0
        proc.pid = 999999
        with mock.patch.object(wifi, "_ACTIVE_PROCS", (proc,)), \
                mock.patch.object(wifi.os, "killpg") as killpg:
            wifi.cleanup_active()
        killpg.assert_not_called()

    def test_netmon_failure_does_not_drop_snapshot(self):
        mon = self.wm.Monitor.__new__(self.wm.Monitor)
        mon.net_monitor = mock.MagicMock()
        mon.net_monitor.collect.side_effect = RuntimeError("boom")
        mon.netmon_resolve = False
        self.assertFalse(mon.collect_netmon()["ok"])


if __name__ == "__main__":
    unittest.main()
