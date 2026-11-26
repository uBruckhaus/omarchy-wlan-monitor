import importlib.util
import os
import tempfile
import time
import unittest
from unittest import mock


SCRIPT_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "scripts", "net_monitor.py")
spec = importlib.util.spec_from_file_location("net_monitor", SCRIPT_PATH)
net_monitor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(net_monitor)


SAMPLE_SS = """\
Netid State      Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   ESTAB      0      0      192.168.178.22:48346 194.25.134.50:993 users:(("omamail",pid=3527,fd=18))
\t cubic rto:215 rtt:14.201/0.578 bytes_sent:31441 bytes_acked:31442 bytes_received:504216
tcp   ESTAB      0      0      [2003:d5:2f0d:2300::1]:33320 [2001:4860:4842:400::]:443 users:(("Web Content",pid=16223,fd=57))
\t cubic rto:226 rtt:25.011/0.515 bytes_sent:1997730 bytes_acked:1997731 bytes_received:73602
tcp   LISTEN     0      4096   127.0.0.1:36027 0.0.0.0:* users:(("<b>agy</b>",pid=16223,fd=12))
\t cubic cwnd:10
tcp   TIME-WAIT  0      0      192.168.178.22:55120 192.168.178.87:8009
udp   UNCONN     0      0      127.0.0.53%lo:53 0.0.0.0:*
udp   ESTAB      0      0      192.168.178.22%wlan0:68 192.168.178.1:67
udp   ESTAB      0      0      [2003:d5:2f0d:2300::1]:44389 [2a00:1450:4016:3::1]:443 users:(("chrome",pid=20261,fd=49))
"""

SAMPLE_SS_T2 = """\
Netid State      Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp   ESTAB      0      0      192.168.178.22:48346 194.25.134.50:993 users:(("omamail",pid=3527,fd=18))
\t cubic rto:215 rtt:14.500/0.500 bytes_sent:33441 bytes_acked:33442 bytes_received:514216
tcp   ESTAB      0      0      [2003:d5:2f0d:2300::1]:33320 [2001:4860:4842:400::]:443 users:(("Web Content",pid=16223,fd=57))
\t cubic rto:226 rtt:25.000/0.500 bytes_sent:2007730 bytes_acked:2007731 bytes_received:93602
"""

SAMPLE_PROC_DEV_1 = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 10000 100 0 0 0 0 0 0 10000 100 0 0 0 0 0 0
 wlan0: 500000 400 1 2 0 0 0 0 200000 300 3 4 0 0 0 0
  enp1: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
   wg0: 50000 50 0 0 0 0 0 0 40000 40 0 0 0 0 0 0
"""

SAMPLE_PROC_DEV_2 = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 99999 200 0 0 0 0 0 0 99999 200 0 0 0 0 0 0
 wlan0: 520000 420 1 2 0 0 0 0 210000 310 3 4 0 0 0 0
  enp1: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
   wg0: 54000 55 0 0 0 0 0 0 42000 42 0 0 0 0 0 0
"""

SAMPLE_IP_ADDR = """\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever
1: lo    inet6 ::1/128 scope host noprefixroute
3: wlan0    inet 192.168.178.22/24 brd 192.168.178.255 scope global wlan0
3: wlan0    inet6 fe80::1/64 scope link
3: wlan0    inet6 2003:d5:2f0d:2300::22/64 scope global dynamic
4: wg0    inet 10.66.0.2/32 scope global wg0
"""


class AddressAndServiceTests(unittest.TestCase):
    def test_parse_addr_port_variants(self):
        self.assertEqual(net_monitor.parse_addr_port("192.168.178.22:443"), ("192.168.178.22", 443, False))
        self.assertEqual(net_monitor.parse_addr_port("192.168.178.22%wlan0:68"), ("192.168.178.22", 68, False))
        self.assertEqual(net_monitor.parse_addr_port("0.0.0.0:*"), ("0.0.0.0", 0, False))
        self.assertEqual(net_monitor.parse_addr_port("*:*"), ("*", 0, False))
        self.assertEqual(net_monitor.parse_addr_port("[::1]:8080"), ("::1", 8080, True))
        self.assertEqual(net_monitor.parse_addr_port("[fe80::1%wlan0]:5353"), ("fe80::1", 5353, True))
        self.assertEqual(net_monitor.parse_addr_port("[::]:*"), ("::", 0, True))
        self.assertEqual(net_monitor.parse_addr_port("[::1]%lo:53"), ("::1", 53, True))

    def test_classify_scope(self):
        for ip in ("127.0.0.1", "127.0.0.53", "::1", "0.0.0.0", "::", "*", "", "::ffff:127.0.0.1"):
            self.assertEqual(net_monitor.classify_scope(ip), "loopback", ip)
        for ip in ("192.168.178.1", "10.0.0.5", "172.16.1.1", "fd27::1", "fe80::1%wlan0", "224.0.0.251", "::ffff:192.168.1.5"):
            self.assertEqual(net_monitor.classify_scope(ip), "lan", ip)
        for ip in ("8.8.8.8", "194.25.134.50", "2a00:1450:4016:3::1", "::ffff:8.8.8.8"):
            self.assertEqual(net_monitor.classify_scope(ip), "external", ip)

    def test_identify_service(self):
        self.assertEqual(net_monitor.identify_service(443, "tcp"), "HTTPS")
        self.assertEqual(net_monitor.identify_service(443, "udp6"), "QUIC")
        self.assertEqual(net_monitor.identify_service(22, "tcp"), "SSH")
        self.assertEqual(net_monitor.identify_service(53, "udp"), "DNS")
        self.assertEqual(net_monitor.identify_service(993, "tcp"), "IMAPS")
        self.assertEqual(net_monitor.identify_service(51820, "udp"), "WireGuard")
        self.assertEqual(net_monitor.identify_service(54321, "tcp"), "")


class SsAndProcParserTests(unittest.TestCase):
    def test_parse_ss_output(self):
        conns = net_monitor.parse_ss_output(SAMPLE_SS, cmdline_reader=lambda pid: f"/usr/bin/app --pid={pid} <tag>")
        self.assertEqual(len(conns), 7)

        imap = conns[0]
        self.assertEqual(imap["protocol"], "tcp")
        self.assertEqual(imap["proto"], "tcp")
        self.assertEqual(imap["id"], "tcp:192.168.178.22:48346->194.25.134.50:993")
        self.assertEqual(imap["state"], "ESTABLISHED")
        self.assertEqual(imap["remote_ip"], "194.25.134.50")
        self.assertEqual(imap["remote_port"], 993)
        self.assertEqual(imap["scope"], "external")
        self.assertEqual(imap["service"], "IMAPS")
        self.assertEqual(imap["process"], "omamail")
        self.assertEqual(imap["pid"], 3527)
        self.assertEqual(imap["rtt_ms"], 14.2)
        self.assertEqual(imap["tx_bytes"], 31442)
        self.assertEqual(imap["rx_bytes"], 504216)

        v6_https = conns[1]
        self.assertEqual(v6_https["protocol"], "tcp6")
        self.assertEqual(v6_https["process"], "Web Content")
        self.assertEqual(v6_https["service"], "HTTPS")
        self.assertEqual(v6_https["scope"], "external")

        listen = conns[2]
        self.assertEqual(listen["state"], "LISTEN")
        self.assertEqual(listen["scope"], "loopback")
        self.assertNotIn("<", listen["process"])
        self.assertEqual(listen["process"], "bagy/b")

        tw = conns[3]
        self.assertEqual(tw["state"], "TIME_WAIT")
        self.assertEqual(tw["scope"], "lan")
        self.assertEqual(tw["service"], "Cast")

        dns_unconn = conns[4]
        self.assertEqual(dns_unconn["protocol"], "udp")
        self.assertEqual(dns_unconn["state"], "UNCONN")
        self.assertEqual(dns_unconn["service"], "DNS")
        self.assertEqual(dns_unconn["scope"], "loopback")

        quic = conns[6]
        self.assertEqual(quic["protocol"], "udp6")
        self.assertEqual(quic["state"], "ESTABLISHED")
        self.assertEqual(quic["service"], "QUIC")
        self.assertEqual(quic["scope"], "external")

    def test_proc_net_fallback_and_inode_mapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "net"))
            # 127.0.0.1:0035 (53) -> 0.0.0.0:0000 LISTEN (0A), inode 12345
            # 192.168.178.22 (16B2A8C0):C000 -> 8.8.8.8 (08080808):01BB (443) ESTAB (01), inode 67890
            with open(os.path.join(tmp, "net", "tcp"), "w") as f:
                f.write(
                    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                    "   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345\n"
                    "   1: 16B2A8C0:C000 08080808:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 67890\n"
                )
            # ::1 (00000000000000000000000001000000):0016 (22) LISTEN
            with open(os.path.join(tmp, "net", "tcp6"), "w") as f:
                f.write(
                    "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                    "   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999\n"
                )
            with open(os.path.join(tmp, "net", "udp"), "w") as f:
                f.write(
                    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
                    "   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 55555\n"
                )
            # Fake /proc/4242/fd/7 -> socket:[67890]
            fd_dir = os.path.join(tmp, "4242", "fd")
            os.makedirs(fd_dir)
            os.symlink("socket:[67890]", os.path.join(fd_dir, "7"))
            with open(os.path.join(tmp, "4242", "comm"), "w") as f:
                f.write("curl\n")
            with open(os.path.join(tmp, "4242", "cmdline"), "wb") as f:
                f.write(b"curl\x00https://example.com\x00")

            conns = net_monitor.collect_proc_connections(proc_root=tmp)
            self.assertEqual(len(conns), 4)
            est = next(c for c in conns if c["state"] == "ESTABLISHED")
            self.assertEqual(est["proto"], "tcp")
            self.assertEqual(est["protocol"], "tcp")
            self.assertEqual(est["id"], "tcp:192.168.178.22:49152->8.8.8.8:443")
            self.assertEqual(est["local_ip"], "192.168.178.22")
            self.assertEqual(est["remote_ip"], "8.8.8.8")
            self.assertEqual(est["remote_port"], 443)
            self.assertEqual(est["process"], "curl")
            self.assertEqual(est["pid"], 4242)
            self.assertEqual(est["cmdline"], "curl https://example.com")
            self.assertEqual(est["scope"], "external")
            self.assertEqual(est["service"], "HTTPS")

            v6 = next(c for c in conns if c["protocol"] == "tcp6")
            self.assertEqual(v6["local_ip"], "::1")
            self.assertEqual(v6["local_port"], 22)
            self.assertEqual(v6["service"], "SSH")

            udp = next(c for c in conns if c["protocol"] == "udp")
            self.assertEqual(udp["state"], "UNCONN")
            self.assertEqual(udp["local_port"], 5353)
            self.assertEqual(udp["service"], "mDNS")


class NetMonitorCollectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proc = os.path.join(self.tmp.name, "proc")
        self.sys_net = os.path.join(self.tmp.name, "sys_net")
        self.resolv = os.path.join(self.tmp.name, "resolv.conf")
        os.makedirs(os.path.join(self.proc, "net"))
        for name, oper, flags, ltype, mac, extra_dir in (
            ("lo", "unknown", "0x9", "772", "00:00:00:00:00:00", None),
            ("wlan0", "up", "0x1003", "1", "aa:bb:cc:dd:ee:01", "wireless"),
            ("enp1", "down", "0x1002", "1", "aa:bb:cc:dd:ee:02", "device"),
            ("wg0", "unknown", "0x10d1", "65534", "", None),
        ):
            d = os.path.join(self.sys_net, name)
            os.makedirs(d)
            with open(os.path.join(d, "operstate"), "w") as f:
                f.write(oper + "\n")
            with open(os.path.join(d, "flags"), "w") as f:
                f.write(flags + "\n")
            with open(os.path.join(d, "type"), "w") as f:
                f.write(ltype + "\n")
            if mac:
                with open(os.path.join(d, "address"), "w") as f:
                    f.write(mac + "\n")
            if extra_dir:
                os.makedirs(os.path.join(d, extra_dir))
        with open(self.resolv, "w") as f:
            f.write("# comment\nnameserver 192.168.178.1\nnameserver 1.1.1.1\nnameserver 1.1.1.1\nnameserver bogus\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_collect_rates_processes_interfaces_and_history_cap(self):
        mon = net_monitor.NetMonitor(proc_root=self.proc, sys_net=self.sys_net, resolv_path=self.resolv)
        dev_path = os.path.join(self.proc, "net", "dev")
        with open(dev_path, "w") as f:
            f.write(SAMPLE_PROC_DEV_1)

        def fake_cmd(argv, **_kw):
            if argv[0] == "ss":
                return state["ss"]
            if argv[0] == "ip":
                return SAMPLE_IP_ADDR
            return ""

        state = {"ss": SAMPLE_SS, "t": 100.0}
        with mock.patch.object(net_monitor.shutil, "which", return_value="/usr/bin/mock"), \
                mock.patch.object(net_monitor, "run_cmd", side_effect=fake_cmd), \
                mock.patch.object(net_monitor.time, "monotonic", side_effect=lambda: state["t"]):
            snap1 = mon.collect(resolve=False)
            self.assertEqual(snap1["dns"], ["192.168.178.1", "1.1.1.1"])
            self.assertEqual(snap1["summary"]["total"], 7)
            self.assertEqual(snap1["summary"]["established"], 4)
            self.assertEqual(snap1["summary"]["listening"], 1)
            self.assertEqual(len(snap1["history"]), 1)

            # Second tick 2.0 seconds later with byte increases
            state["t"] = 102.0
            state["ss"] = SAMPLE_SS_T2
            with open(dev_path, "w") as f:
                f.write(SAMPLE_PROC_DEV_2)
            snap2 = mon.collect(resolve=False)

            # Socket rates: omamail rx +10000 / 2s = 5000.0, tx +2000 / 2s = 1000.0
            oma = next(c for c in snap2["connections"] if c["process"] == "omamail")
            self.assertEqual(oma["rx_rate"], 5000.0)
            self.assertEqual(oma["tx_rate"], 1000.0)
            # Web Content rx +20000 / 2s = 10000.0, tx +10000 / 2s = 5000.0 -> sorted first!
            self.assertEqual(snap2["connections"][0]["process"], "Web Content")
            self.assertEqual(snap2["processes"][0]["name"], "Web Content")

            # Interface stats & rates (non-loopback: wlan0 +20000/+10000, wg0 +4000/+2000 over 2s -> 12000 / 6000)
            wlan = next(i for i in snap2["interfaces"] if i["name"] == "wlan0")
            self.assertEqual(wlan["kind"], "wifi")
            self.assertEqual(wlan["state"], "up")
            self.assertEqual(wlan["ip"], "192.168.178.22")
            self.assertEqual(wlan["ipv6"], "2003:d5:2f0d:2300::22")  # global preferred over fe80
            self.assertEqual(wlan["rx_rate"], 10000.0)
            self.assertEqual(wlan["tx_rate"], 5000.0)
            self.assertEqual(wlan["rx_errors"], 1)
            self.assertEqual(wlan["tx_dropped"], 4)
            self.assertEqual(snap2["summary"]["rx_rate"], 12000.0)
            self.assertEqual(snap2["summary"]["tx_rate"], 6000.0)

            # History capped at 30
            for _ in range(35):
                state["t"] += 1.0
                snap_n = mon.collect(resolve=False)
            self.assertEqual(len(snap_n["history"]), 30)

    def test_rdns_nonblocking_cache(self):
        mon = net_monitor.NetMonitor(proc_root=self.proc, sys_net=self.sys_net, resolv_path=self.resolv)
        with mock.patch.object(net_monitor.socket, "gethostbyaddr", return_value=("mail.t-online.de", [], ["194.25.134.50"])):
            # Trigger worker directly
            mon._rdns_worker("194.25.134.50")
            self.assertEqual(mon._lookup_rdns_cached("194.25.134.50", time.monotonic()), "mail.t-online.de")
            # Loopback is never resolved
            self.assertEqual(mon._lookup_rdns_cached("127.0.0.1", time.monotonic()), "")

    def test_filter_connections(self):
        conns = net_monitor.parse_ss_output(SAMPLE_SS, cmdline_reader=lambda pid: f"cmd-{pid}")
        self.assertEqual(len(net_monitor.filter_connections(conns, protocol="tcp")), 4)
        self.assertEqual(len(net_monitor.filter_connections(conns, protocol="tcp6")), 1)
        self.assertEqual(len(net_monitor.filter_connections(conns, protocol="udp")), 3)
        self.assertEqual(len(net_monitor.filter_connections(conns, state="ESTAB")), 4)
        self.assertEqual(len(net_monitor.filter_connections(conns, state="listen")), 1)
        self.assertEqual(len(net_monitor.filter_connections(conns, scope="external")), 3)
        self.assertEqual(len(net_monitor.filter_connections(conns, scope="lan")), 2)
        self.assertEqual(len(net_monitor.filter_connections(conns, process="oma")), 1)
        self.assertEqual(len(net_monitor.filter_connections(conns, port=443)), 2)
        self.assertEqual(len(net_monitor.filter_connections(conns, search="quic")), 1)
        by_bytes = net_monitor.filter_connections(conns, sort_by="bytes")
        self.assertEqual(by_bytes[0]["process"], "Web Content")
        by_rtt = net_monitor.filter_connections(conns, sort_by="rtt")
        self.assertEqual(by_rtt[0]["rtt_ms"], 25.01)


if __name__ == "__main__":
    unittest.main()
