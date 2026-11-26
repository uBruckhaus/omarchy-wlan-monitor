#!/usr/bin/env python3
"""Safe NetworkManager (`nmcli`) Wi-Fi & Network setup backend (Python 3 stdlib only).

All external calls use fixed argv lists (never a shell). Wi-Fi passwords are never passed
on the command line or echoed in errors; they are written exclusively to an owner-only
0600 file inside a private 0700 runtime directory and deleted immediately after use.
"""

import contextlib
import ipaddress
import os
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import threading
import time


NMCLI_TIMEOUT = 15.0
CONNECT_TIMEOUT = 25.0
NMCLI_WAIT_SECONDS = "20"
RADIO_TIMEOUT = 0.8
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
UUID_FIND_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
PSK_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
ALLOWED_CONN_TYPES = frozenset({"802-11-wireless", "802-3-ethernet", "vpn", "wireguard", "tun"})
ENTERPRISE_KEY_MGMTS = frozenset({"wpa-eap", "wpa-eap-suite-b-192", "ieee8021x"})
OPEN_KEY_MGMTS = frozenset({"", "none", "owe"})

# nmcli output is read with hard caps (a beacon flood can list thousands of networks).
NMCLI_MAX_STDOUT = 512 * 1024
NMCLI_MAX_STDERR = 64 * 1024
MAX_VISIBLE = 128
MAX_KNOWN = 64        # saved Wi-Fi profiles listed (each costs one `nmcli connection show`)
MAX_WIRED = 32
MAX_VPN = 64
SSID_MAX_BYTES = 32
SECRET_DIR_NAME = "ubruckhaus-wlan-monitor-secrets"
STALE_SECRET_AGE = 120.0

# Running nmcli children and passwd-files in flight, so a SIGTERM can end and remove them.
_ACTIVE_LOCK = threading.Lock()
_ACTIVE_PROCS = set()
_ACTIVE_SECRETS = set()

AUTH_FAILURE_MARKERS = (
    "secrets were required",
    "no agents were available",
    "no secrets",
    "no-secrets",
    "4-way handshake",
    "pre-shared key",
    "invalid key",
    "wrong password",
)


def clean(text, limit=120):
    """Sanitize general text so UI/JSON consumers never see markup or control chars."""
    text = "".join(ch for ch in str(text or "") if ch.isprintable() and ch not in "<>&")
    return text.strip()[:limit]


def clean_ssid(text, limit=64):
    """Sanitize an SSID for display: keeps '&', '<', '>' and spaces (every consumer renders plain
    text), drops all control, format (BiDi) and separator characters except the space, and cuts
    the result to 32 UTF-8 bytes (the 802.11 maximum)."""
    raw = "".join(ch for ch in str(text or "") if ch == " " or ch.isprintable())
    raw = raw[:limit]
    while len(raw.encode("utf-8")) > SSID_MAX_BYTES:
        raw = raw[:-1]
    return raw


def nm_terse_split(line):
    """Split an `nmcli -t` colon-delimited line, properly unescaping `\\:` and `\\\\`."""
    fields = []
    buf = []
    escaped = False
    for ch in str(line or ""):
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if escaped:
        buf.append("\\")
    fields.append("".join(buf))
    return fields


def validate_ssid(ssid):
    """Validate a Wi-Fi SSID: 1..32 UTF-8 bytes, printable, no control chars, not starting with '-'."""
    if not isinstance(ssid, str):
        return None
    if not ssid.strip():
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in ssid):
        return None
    if not all(ch.isprintable() for ch in ssid):
        return None
    if ssid.startswith("-"):
        return None
    byte_len = len(ssid.encode("utf-8"))
    if not (1 <= byte_len <= 32):
        return None
    return ssid


def validate_uuid(uuid):
    """Validate a NetworkManager connection UUID (canonical 8-4-4-4-12 hex form only)."""
    if not isinstance(uuid, str):
        return None
    u = uuid.strip()
    if not UUID_RE.match(u):
        return None
    return u


def validate_password(password):
    """Validate a WPA-PSK/SAE passphrase: 8..63 UTF-8 bytes or 64 hex chars, printable, no outer spaces."""
    if not isinstance(password, str):
        return None
    if "\n" in password or "\r" in password or "\x00" in password:
        return None
    if password != password.strip():
        return None
    if not all(ch.isprintable() for ch in password):
        return None
    byte_len = len(password.encode("utf-8"))
    if 8 <= byte_len <= 63:
        return password
    if PSK_HEX_RE.match(password):
        return password
    return None


def is_auth_failure(stderr):
    """Return True if an `nmcli` error indicates missing/wrong Wi-Fi secrets or 4-way handshake failure."""
    low = str(stderr or "").lower()
    return any(marker in low for marker in AUTH_FAILURE_MARKERS)


def freq_to_band(freq_str):
    """Convert an `nmcli` FREQ string (e.g. '2462 MHz', '5180 MHz', '6135 MHz') to band label."""
    m = re.search(r"(\d{4})", str(freq_str or ""))
    if not m:
        return ""
    mhz = int(m.group(1))
    if 2400 <= mhz <= 2500:
        return "2.4 GHz"
    if 5000 <= mhz <= 5900:
        return "5 GHz"
    if 5925 <= mhz <= 7125:
        return "6 GHz"
    return ""


def _parse_int_prefix(text):
    m = re.search(r"(\d+)", str(text or ""))
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _redact(text, secret=None):
    raw = str(text or "")
    if isinstance(secret, str) and secret:
        raw = raw.replace(secret, "***")
    return clean(raw, 200)


def _owned_private_dir(path, create=False):
    """True if `path` is (or was just created as) a real directory owned by this user with no
    group/other bits; never follows a symlink."""
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        except OSError:
            return False
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        return stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not (info.st_mode & 0o077)
    except OSError:
        return False
    finally:
        os.close(fd)


def secret_dir():
    """The private folder for nmcli passwd-files: <runtime dir>/ubruckhaus-wlan-monitor-secrets, or
    /tmp/ubruckhaus-wlan-monitor-secrets-<uid> without a usable runtime dir. None (and no Wi-Fi
    password is ever written) unless it is a real 0700 directory owned by this user."""
    parent = _private_runtime_parent()
    path = (os.path.join(parent, SECRET_DIR_NAME) if parent
            else "/tmp/%s-%d" % (SECRET_DIR_NAME, os.getuid()))
    return path if _owned_private_dir(path, create=True) else None


def sweep_stale_secrets(now=None, max_age=STALE_SECRET_AGE):
    """Remove passwd-file folders left behind by a collector that was killed (older than
    `max_age`, so another screen's connect in flight is never touched)."""
    folder = secret_dir()
    if not folder:
        return 0
    now = time.time() if now is None else now
    removed = 0
    try:
        names = os.listdir(folder)
    except OSError:
        return 0
    for name in names:
        if not name.startswith("wlan-wifi-"):
            continue
        sub = os.path.join(folder, name)
        try:
            info = os.lstat(sub)
        except OSError:
            continue
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or now - info.st_mtime < max_age:
            continue
        try:
            os.unlink(os.path.join(sub, "secrets"))
        except OSError:
            pass
        try:
            os.rmdir(sub)
            removed += 1
        except OSError:
            pass
    return removed


def cleanup_active():
    """End running nmcli children and delete passwd-files in flight (the collector's SIGTERM)."""
    with _ACTIVE_LOCK:
        procs = list(_ACTIVE_PROCS)
        paths = list(_ACTIVE_SECRETS)
    for proc in procs:
        try:
            proc.kill()
        except OSError:
            pass
    for path in paths:
        try:
            os.unlink(path)
        except OSError:
            pass
        try:
            os.rmdir(os.path.dirname(path))
        except OSError:
            pass


def _private_runtime_parent():
    """Return validated owner-only $XDG_RUNTIME_DIR if safe, else None."""
    xdg = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if not xdg or not os.path.isabs(xdg):
        return None
    try:
        fd = os.open(xdg, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not (info.st_mode & 0o022):
            return xdg
    except OSError:
        pass
    finally:
        os.close(fd)
    return None


@contextlib.contextmanager
def _write_passwd_file(password):
    """Create a private 0700 dir + 0600 `secrets` file for `nmcli passwd-file`, always removed.

    nmcli reads `setting.property:value` literally (without backslash unescaping), so the
    passphrase is written verbatim.
    """
    folder = secret_dir()
    if not folder:
        raise OSError("No private folder for the Wi-Fi password.")
    tmp_dir = os.path.join(folder, "wlan-wifi-%d-%s" % (os.getpid(), secrets.token_hex(8)))
    os.mkdir(tmp_dir, 0o700)
    secret_path = os.path.join(tmp_dir, "secrets")
    with _ACTIVE_LOCK:
        _ACTIVE_SECRETS.add(secret_path)
    try:
        fd = os.open(
            secret_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            os.fchmod(fd, 0o600)
            payload = ("802-11-wireless-security.psk:%s\n" % password).encode("utf-8")
            while payload:
                written = os.write(fd, payload)
                payload = payload[written:]
        finally:
            os.close(fd)
        yield secret_path
    finally:
        try:
            os.unlink(secret_path)
        except OSError:
            pass
        try:
            os.rmdir(tmp_dir)
        except OSError:
            pass
        with _ACTIVE_LOCK:
            _ACTIVE_SECRETS.discard(secret_path)


def _run_nmcli(args, timeout=NMCLI_TIMEOUT, max_out=NMCLI_MAX_STDOUT, max_err=NMCLI_MAX_STDERR):
    """Run `nmcli` with fixed argv (no shell) and C locale. Returns (rc, stdout, stderr).

    Output is read with byte caps and one overall deadline; on overflow or timeout the child is
    killed (124 = timed out, 125 = output too large)."""
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    try:
        proc = subprocess.Popen(
            ["nmcli", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            start_new_session=True,
        )
    except FileNotFoundError:
        return 127, "", "nmcli not found"
    except OSError as exc:
        return 1, "", str(exc)
    with _ACTIVE_LOCK:
        _ACTIVE_PROCS.add(proc)
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    bufs = {out_fd: bytearray(), err_fd: bytearray()}
    caps = {out_fd: max_out, err_fd: max_err}
    open_fds = set(bufs)
    deadline = time.monotonic() + timeout
    failure = None
    try:
        while open_fds:
            left = deadline - time.monotonic()
            if left <= 0:
                failure = (124, "nmcli timed out")
                break
            ready, _, _ = select.select(list(open_fds), [], [], left)
            for fd in ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    open_fds.discard(fd)
                    continue
                bufs[fd].extend(chunk)
                if len(bufs[fd]) > caps[fd]:
                    failure = (125, "nmcli output too large")
                    break
            if failure:
                break
        if failure:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            rc = proc.wait(timeout=max(0.1, deadline - time.monotonic()) if not failure else 2.0)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            proc.wait()
            failure = failure or (124, "nmcli timed out")
            rc = 124
    finally:
        proc.stdout.close()
        proc.stderr.close()
        with _ACTIVE_LOCK:
            _ACTIVE_PROCS.discard(proc)
    if failure:
        return failure[0], "", failure[1]
    return (rc, bytes(bufs[out_fd]).decode("utf-8", "replace"),
            bytes(bufs[err_fd]).decode("utf-8", "replace"))


def nm_available():
    return shutil.which("nmcli") is not None


def has_wifi_device(sys_net="/sys/class/net"):
    """Fast check for any wireless network interface via /sys/class/net."""
    try:
        names = os.listdir(sys_net)
    except OSError:
        return False
    for name in names:
        base = os.path.join(sys_net, name)
        if os.path.isdir(os.path.join(base, "wireless")) or os.path.isdir(os.path.join(base, "phy80211")):
            return True
    return False


def get_wifi_radio(timeout=RADIO_TIMEOUT):
    """Return True if Wi-Fi radio is enabled, False if disabled, or None on error."""
    if not nm_available():
        return None
    rc, out, _ = _run_nmcli(["-t", "radio", "wifi"], timeout=timeout)
    if rc != 0:
        return None
    val = out.strip().lower()
    if val == "enabled":
        return True
    if val == "disabled":
        return False
    return None


def _read_dns_servers(path="/etc/resolv.conf"):
    servers = []
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read(32768)
    except OSError:
        return servers
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0] == "nameserver":
            cand = parts[1].split("%", 1)[0]
            try:
                norm = str(ipaddress.ip_address(cand))
            except ValueError:
                continue
            if norm not in servers:
                servers.append(norm)
    return servers


def _get_connection_meta(uuid):
    """Return (name, conn_type) for an existing NetworkManager connection UUID, or (None, None)."""
    rc, out, _ = _run_nmcli(
        ["-t", "-f", "connection.id,connection.type", "connection", "show", "uuid", uuid],
        timeout=5.0,
    )
    if rc != 0:
        return None, None
    name = ""
    ctype = ""
    for line in out.splitlines():
        parts = nm_terse_split(line)
        if len(parts) >= 2:
            key = parts[0].strip()
            val = parts[1]
            if key == "connection.id":
                name = clean_ssid(val, 64)
            elif key == "connection.type":
                ctype = clean(val, 40)
    if not ctype:
        return None, None
    return name, ctype


def _get_wifi_profile_ssid(uuid):
    """Return the `802-11-wireless.ssid` property of a saved Wi-Fi connection, or '' if unavailable."""
    rc, out, _ = _run_nmcli(
        ["-g", "802-11-wireless.ssid", "connection", "show", "uuid", uuid],
        timeout=3.0,
    )
    if rc != 0 or not out:
        return ""
    # `-g` prints the raw property value on a single line (preserve spaces, strip only newline/control)
    first = out.splitlines()[0]
    return clean_ssid(first, 64)


def _get_wifi_security_props(uuid):
    """Return (key_mgmt, psk_flags) for a saved Wi-Fi profile via `nmcli -g`."""
    rc, out, _ = _run_nmcli(
        [
            "-g",
            "802-11-wireless-security.key-mgmt,802-11-wireless-security.psk-flags",
            "connection",
            "show",
            "uuid",
            uuid,
        ],
        timeout=5.0,
    )
    if rc != 0:
        return "", ""
    lines = out.splitlines()
    key_mgmt = lines[0].strip().lower() if len(lines) >= 1 else ""
    psk_flags = lines[1].strip() if len(lines) >= 2 else ""
    return key_mgmt, psk_flags


def _find_saved_wifi_uuid(target_ssid):
    """Find an existing saved `802-11-wireless` profile whose SSID equals `target_ssid`, or None."""
    rc, out, _ = _run_nmcli(["-t", "-f", "NAME,UUID,TYPE", "connection", "show"], timeout=5.0)
    if rc != 0:
        return None
    fallback_uuid = None
    looked = 0
    for line in out.splitlines():
        parts = nm_terse_split(line)
        if len(parts) < 3:
            continue
        cname, cuuid, ctype = parts[0], parts[1], parts[2]
        if ctype != "802-11-wireless" or not validate_uuid(cuuid):
            continue
        looked += 1
        if looked > MAX_KNOWN:
            break
        prof_ssid = _get_wifi_profile_ssid(cuuid)
        if prof_ssid:
            if prof_ssid == target_ssid:
                return cuuid
        elif clean_ssid(cname, 64) == target_ssid and fallback_uuid is None:
            fallback_uuid = cuuid
    return fallback_uuid


def _detect_visible_security(target_ssid):
    """Inspect cached visible Wi-Fi scan to choose key-mgmt for `target_ssid`.

    Returns one of: 'enterprise', 'sae', 'owe', 'wpa-psk'.
    """
    rc, out, _ = _run_nmcli(
        ["-t", "-f", "SSID,SECURITY", "device", "wifi", "list", "--rescan", "no"],
        timeout=5.0,
    )
    if rc != 0 or not out:
        return "wpa-psk"
    tokens = set()
    matched = False
    for line in out.splitlines():
        parts = nm_terse_split(line)
        if len(parts) < 2:
            continue
        if clean_ssid(parts[0], 64) != target_ssid:
            continue
        matched = True
        for tok in parts[1].upper().split():
            tokens.add(tok)
    if not matched:
        return "wpa-psk"
    if any("802.1X" in t or "EAP" in t for t in tokens):
        return "enterprise"
    if "WPA3" in tokens and "WPA2" not in tokens and "WPA1" not in tokens:
        return "sae"
    if "OWE" in tokens and "WPA2" not in tokens and "WPA3" not in tokens and "WPA1" not in tokens:
        return "owe"
    return "wpa-psk"


def get_wifi_state(rescan=False, resolv_path="/etc/resolv.conf", sys_net="/sys/class/net"):
    """Collect current Wi-Fi, wired, VPN, and DNS state from NetworkManager."""
    dns = _read_dns_servers(resolv_path)
    state = {
        "nm_available": False,
        "wifi_device": has_wifi_device(sys_net),
        "wifi_on": False,
        "active_ssid": "",
        "dns": dns,
        "known": [],
        "visible": [],
        "wired": [],
        "wired_devices": [],
        "vpn": [],
        "error": "",
    }
    if not nm_available():
        state["error"] = "NetworkManager (nmcli) is not available."
        return state
    state["nm_available"] = True

    rc_r, out_r, err_r = _run_nmcli(["-t", "radio", "wifi"], timeout=5.0)
    if rc_r == 0:
        state["wifi_on"] = out_r.strip().lower() == "enabled"
    else:
        state["error"] = clean(err_r or "Unable to query NetworkManager.", 200)
        return state

    # Devices
    device_active_conn = ""
    rc_d, out_d, _ = _run_nmcli(["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"], timeout=5.0)
    if rc_d == 0:
        for line in out_d.splitlines():
            parts = nm_terse_split(line)
            if len(parts) < 4:
                continue
            dev, dtype, dstate, dconn = parts[0], parts[1], parts[2], parts[3]
            if dtype == "wifi":
                state["wifi_device"] = True
                if dstate == "connected" and dconn and not device_active_conn:
                    device_active_conn = clean_ssid(dconn, 64)
            elif dtype == "ethernet" and len(state["wired_devices"]) < MAX_WIRED:
                state["wired_devices"].append(
                    {
                        "device": clean(dev, 32),
                        "state": clean(dstate, 32),
                        "connection": clean_ssid(dconn, 64),
                    }
                )

    # Saved profiles (Wi-Fi, Wired, VPN)
    known_ssids = set()
    rc_c, out_c, _ = _run_nmcli(
        ["-t", "-f", "NAME,UUID,TYPE,DEVICE,AUTOCONNECT", "connection", "show"],
        timeout=5.0,
    )
    if rc_c == 0:
        for line in out_c.splitlines():
            parts = nm_terse_split(line)
            if len(parts) < 5:
                continue
            cname, cuuid, ctype, cdev, cauto = parts[0], parts[1], parts[2], parts[3], parts[4]
            if not validate_uuid(cuuid):
                continue
            active = bool(cdev and cdev != "--")
            dev_clean = "" if cdev == "--" else clean(cdev, 32)
            name_clean = clean_ssid(cname, 64)
            if ctype == "802-11-wireless":
                if len(state["known"]) >= MAX_KNOWN:
                    continue
                prof_ssid = _get_wifi_profile_ssid(cuuid) or name_clean
                known_ssids.add(prof_ssid)
                if active and not state["active_ssid"]:
                    state["active_ssid"] = prof_ssid
                state["known"].append(
                    {
                        "name": name_clean,
                        "ssid": prof_ssid,
                        "uuid": cuuid,
                        "active": active,
                        "device": dev_clean,
                        "autoconnect": cauto.strip().lower() == "yes",
                    }
                )
            elif ctype == "802-3-ethernet":
                if len(state["wired"]) >= MAX_WIRED:
                    continue
                state["wired"].append(
                    {
                        "name": clean(cname, 64),
                        "uuid": cuuid,
                        "active": active,
                        "device": dev_clean,
                    }
                )
            elif ctype in ("vpn", "wireguard", "tun"):
                if len(state["vpn"]) >= MAX_VPN:
                    continue
                state["vpn"].append(
                    {
                        "name": clean(cname, 64),
                        "uuid": cuuid,
                        "active": active,
                        "device": dev_clean,
                    }
                )

    if not state["active_ssid"] and device_active_conn:
        state["active_ssid"] = device_active_conn

    state["known"].sort(key=lambda item: (not item["active"], item["name"].lower()))
    state["wired"].sort(key=lambda item: (not item["active"], item["name"].lower()))
    state["vpn"].sort(key=lambda item: (not item["active"], item["name"].lower()))

    # Visible Wi-Fi networks
    if state["wifi_device"] and state["wifi_on"]:
        scan_arg = "yes" if rescan else "no"
        rc_w, out_w, err_w = _run_nmcli(
            [
                "-t",
                "-f",
                "IN-USE,SSID,BSSID,SIGNAL,SECURITY,CHAN,FREQ,RATE",
                "device",
                "wifi",
                "list",
                "--rescan",
                scan_arg,
            ],
            timeout=15.0 if rescan else 6.0,
        )
        if rc_w == 0:
            by_ssid = {}
            for line in out_w.splitlines():
                parts = nm_terse_split(line)
                if len(parts) < 8:
                    continue
                in_use_raw, raw_ssid, raw_bssid, raw_sig, raw_sec, raw_chan, raw_freq, raw_rate = parts[:8]
                ssid = clean_ssid(raw_ssid, 64)
                if not ssid or not ssid.strip():
                    continue  # skip hidden empty SSIDs
                in_use = in_use_raw.strip() == "*"
                sig = _parse_int_prefix(raw_sig)
                sig = max(0, min(100, sig)) if sig is not None else 0
                chan = _parse_int_prefix(raw_chan)
                band = freq_to_band(raw_freq)
                rate = _parse_int_prefix(raw_rate)
                sec = clean(raw_sec, 48)
                bssid = clean(raw_bssid.lower(), 20)
                if in_use:
                    state["active_ssid"] = ssid
                entry = {
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal": sig,
                    "security": sec,
                    "band": band,
                    "channel": chan,
                    "rate_mbps": rate,
                    "in_use": in_use,
                    "known": ssid in known_ssids,
                }
                prev = by_ssid.get(ssid)
                if prev is None:
                    if len(by_ssid) >= 4 * MAX_VISIBLE and not in_use:
                        continue  # a beacon flood: the strongest are kept below, the rest ignored
                    by_ssid[ssid] = entry
                else:
                    # Keep in-use AP, otherwise strongest signal
                    if (entry["in_use"], entry["signal"]) > (prev["in_use"], prev["signal"]):
                        by_ssid[ssid] = entry
            visible = list(by_ssid.values())
            visible.sort(key=lambda item: (item["in_use"], item["signal"]), reverse=True)
            state["visible"] = visible[:MAX_VISIBLE]
        elif err_w and not state["error"]:
            state["error"] = clean(err_w, 200)

    return state


def set_wifi_radio(on):
    """Turn Wi-Fi radio on or off via nmcli."""
    if not isinstance(on, bool):
        return {"ok": False, "action": "radio", "message": "Invalid radio state: expected boolean."}
    if not nm_available():
        return {"ok": False, "action": "radio", "message": "NetworkManager (nmcli) is not available."}
    rc, _out, err = _run_nmcli(["radio", "wifi", "on" if on else "off"], timeout=8.0)
    if rc == 0:
        return {
            "ok": True,
            "action": "radio",
            "wifi_on": on,
            "message": "Wi-Fi enabled." if on else "Wi-Fi disabled.",
        }
    return {
        "ok": False,
        "action": "radio",
        "wifi_on": None,
        "message": clean(err or "Failed to toggle Wi-Fi radio.", 200),
    }


def wifi_connect(ssid="", password=None, uuid=None):
    """Connect to a Wi-Fi network by saved UUID or SSID (with optional passphrase via private passwd-file)."""
    if not nm_available():
        return {
            "ok": False,
            "auth_failed": False,
            "action": "connect",
            "ssid": clean_ssid(ssid, 64),
            "uuid": clean(uuid or "", 64),
            "message": "NetworkManager (nmcli) is not available.",
        }

    # Path 1: saved connection UUID
    if uuid is not None and str(uuid).strip() != "":
        valid_uuid = validate_uuid(uuid)
        if not valid_uuid:
            return {
                "ok": False,
                "auth_failed": False,
                "action": "connect",
                "ssid": clean_ssid(ssid, 64),
                "uuid": "",
                "message": "Invalid connection UUID.",
            }
        conn_name, conn_type = _get_connection_meta(valid_uuid)
        if conn_type != "802-11-wireless":
            return {
                "ok": False,
                "auth_failed": False,
                "action": "connect",
                "ssid": clean_ssid(ssid or conn_name or "", 64),
                "uuid": valid_uuid,
                "message": "Saved Wi-Fi connection not found.",
            }
        prof_ssid = _get_wifi_profile_ssid(valid_uuid)
        label = clean_ssid(ssid or prof_ssid or conn_name or valid_uuid, 64)

        if password is None:
            rc, out, err = _run_nmcli(
                ["--wait", NMCLI_WAIT_SECONDS, "connection", "up", "uuid", valid_uuid],
                timeout=CONNECT_TIMEOUT,
            )
            if rc == 0:
                return {
                    "ok": True,
                    "auth_failed": False,
                    "action": "connect",
                    "ssid": label,
                    "uuid": valid_uuid,
                    "message": "Connected to %s." % label,
                }
            raw_err = err or out or "Connection failed."
            return {
                "ok": False,
                "auth_failed": is_auth_failure(raw_err),
                "action": "connect",
                "ssid": label,
                "uuid": valid_uuid,
                "message": clean(raw_err, 200),
            }

        valid_pw = validate_password(password)
        if valid_pw is None:
            return {
                "ok": False,
                "auth_failed": False,
                "action": "connect",
                "ssid": label,
                "uuid": valid_uuid,
                "message": "Wi-Fi password must be 8-63 UTF-8 bytes (or 64 hex chars) without leading or trailing spaces.",
            }

        key_mgmt, psk_flags = _get_wifi_security_props(valid_uuid)
        if key_mgmt in OPEN_KEY_MGMTS:
            return {
                "ok": False,
                "auth_failed": False,
                "action": "connect",
                "ssid": label,
                "uuid": valid_uuid,
                "message": "This saved network has no password (open or OWE); connect without one.",
            }
        if key_mgmt in ENTERPRISE_KEY_MGMTS:
            return {
                "ok": False,
                "auth_failed": False,
                "action": "connect",
                "ssid": label,
                "uuid": valid_uuid,
                "message": "Enterprise (802.1X) Wi-Fi passwords cannot be changed here.",
            }

        # Preserve WPA3 SAE; never downgrade sae -> wpa-psk. Clear only the stale PSK property.
        target_km = "sae" if key_mgmt == "sae" else "wpa-psk"
        mod_args = [
            "connection",
            "modify",
            "uuid",
            valid_uuid,
            "wifi-sec.key-mgmt",
            target_km,
            "wifi-sec.psk",
            "",
        ]
        if not psk_flags:
            mod_args.extend(["wifi-sec.psk-flags", "0"])
        rc_mod, out_mod, err_mod = _run_nmcli(mod_args, timeout=8.0)
        if rc_mod != 0:
            return {
                "ok": False,
                "auth_failed": False,
                "action": "connect",
                "ssid": label,
                "uuid": valid_uuid,
                "message": _redact(err_mod or out_mod or "Failed to update Wi-Fi security settings.", valid_pw),
            }

        with _write_passwd_file(valid_pw) as pfile:
            rc, out, err = _run_nmcli(
                ["--wait", NMCLI_WAIT_SECONDS, "connection", "up", "uuid", valid_uuid, "passwd-file", pfile],
                timeout=CONNECT_TIMEOUT,
            )
        if rc == 0:
            return {
                "ok": True,
                "auth_failed": False,
                "action": "connect",
                "ssid": label,
                "uuid": valid_uuid,
                "message": "Connected to %s." % label,
            }
        raw_err = err or out or "Connection failed."
        return {
            "ok": False,
            "auth_failed": is_auth_failure(raw_err),
            "action": "connect",
            "ssid": label,
            "uuid": valid_uuid,
            "message": _redact(raw_err, valid_pw),
        }

    # Path 2: connect by SSID
    valid_ssid = validate_ssid(ssid)
    if valid_ssid is None:
        return {
            "ok": False,
            "auth_failed": False,
            "action": "connect",
            "ssid": clean_ssid(ssid, 64),
            "uuid": "",
            "message": "Invalid SSID: must be 1-32 UTF-8 bytes, printable, and not start with '-'.",
        }
    label = clean_ssid(valid_ssid, 64)

    # Reuse existing saved Wi-Fi profile for this SSID instead of creating a duplicate
    existing_uuid = _find_saved_wifi_uuid(valid_ssid)
    if existing_uuid:
        return wifi_connect(ssid=valid_ssid, password=password, uuid=existing_uuid)

    detected_sec = _detect_visible_security(valid_ssid)
    if detected_sec == "enterprise":
        return {
            "ok": False,
            "auth_failed": False,
            "action": "connect",
            "ssid": label,
            "uuid": "",
            "message": "Enterprise (802.1X) Wi-Fi networks must be configured in system network settings.",
        }

    if password is None:
        rc, out, err = _run_nmcli(
            ["--wait", NMCLI_WAIT_SECONDS, "device", "wifi", "connect", valid_ssid],
            timeout=CONNECT_TIMEOUT,
        )
        if rc == 0:
            m = UUID_FIND_RE.search(out or "")
            return {
                "ok": True,
                "auth_failed": False,
                "action": "connect",
                "ssid": label,
                "uuid": m.group(0) if m else "",
                "message": "Connected to %s." % label,
            }
        raw_err = err or out or "Connection failed."
        return {
            "ok": False,
            "auth_failed": is_auth_failure(raw_err),
            "action": "connect",
            "ssid": label,
            "uuid": "",
            "message": clean(raw_err, 200),
        }

    valid_pw = validate_password(password)
    if valid_pw is None:
        return {
            "ok": False,
            "auth_failed": False,
            "action": "connect",
            "ssid": label,
            "uuid": "",
            "message": "Wi-Fi password must be 8-63 UTF-8 bytes (or 64 hex chars) without leading or trailing spaces.",
        }

    # Create profile first (without password on argv), bring up with passwd-file, delete on failure
    add_args = [
        "-t",
        "-f",
        "connection.uuid",
        "connection",
        "add",
        "type",
        "wifi",
        "con-name",
        valid_ssid,
        "ssid",
        valid_ssid,
        "wifi-sec.key-mgmt",
        detected_sec,
    ]
    if detected_sec != "owe":
        add_args.extend(["wifi-sec.psk-flags", "0"])

    rc_add, out_add, err_add = _run_nmcli(add_args, timeout=10.0)
    m_uuid = UUID_FIND_RE.search(out_add or "")
    new_uuid = m_uuid.group(0) if m_uuid else ""
    if rc_add != 0 or not new_uuid:
        return {
            "ok": False,
            "auth_failed": False,
            "action": "connect",
            "ssid": label,
            "uuid": "",
            "message": _redact(err_add or out_add or "Failed to create Wi-Fi profile.", valid_pw),
        }

    try:
        if detected_sec == "owe":
            rc_up, out_up, err_up = _run_nmcli(
                ["--wait", NMCLI_WAIT_SECONDS, "connection", "up", "uuid", new_uuid],
                timeout=CONNECT_TIMEOUT,
            )
        else:
            with _write_passwd_file(valid_pw) as pfile:
                rc_up, out_up, err_up = _run_nmcli(
                    ["--wait", NMCLI_WAIT_SECONDS, "connection", "up", "uuid", new_uuid, "passwd-file", pfile],
                    timeout=CONNECT_TIMEOUT,
                )
    except Exception:
        # Never leave a half-configured profile behind (e.g. no private folder for the password).
        _run_nmcli(["connection", "delete", "uuid", new_uuid], timeout=8.0)
        raise
    if rc_up == 0:
        return {
            "ok": True,
            "auth_failed": False,
            "action": "connect",
            "ssid": label,
            "uuid": new_uuid,
            "message": "Connected to %s." % label,
        }

    # Clean up half-configured profile on failure
    _run_nmcli(["connection", "delete", "uuid", new_uuid], timeout=8.0)
    raw_err = err_up or out_up or "Connection failed."
    return {
        "ok": False,
        "auth_failed": is_auth_failure(raw_err),
        "action": "connect",
        "ssid": label,
        "uuid": "",
        "message": _redact(raw_err, valid_pw),
    }


def _connection_action(uuid, action, allowed_types, nmcli_subcmd, verb_ok):
    if not nm_available():
        return {"ok": False, "action": action, "uuid": "", "message": "NetworkManager (nmcli) is not available."}
    valid_uuid = validate_uuid(uuid)
    if not valid_uuid:
        return {"ok": False, "action": action, "uuid": "", "message": "Invalid connection UUID."}
    conn_name, conn_type = _get_connection_meta(valid_uuid)
    if conn_type not in allowed_types:
        return {
            "ok": False,
            "action": action,
            "uuid": valid_uuid,
            "message": "Connection not found or unsupported connection type.",
        }
    cmd = ["connection", nmcli_subcmd, "uuid", valid_uuid]
    if nmcli_subcmd == "up":
        cmd = ["--wait", NMCLI_WAIT_SECONDS, *cmd]
    rc, out, err = _run_nmcli(cmd, timeout=CONNECT_TIMEOUT)
    label = conn_name or valid_uuid
    if rc == 0:
        return {
            "ok": True,
            "action": action,
            "uuid": valid_uuid,
            "name": label,
            "message": "%s %s." % (verb_ok, label),
        }
    return {
        "ok": False,
        "action": action,
        "uuid": valid_uuid,
        "name": label,
        "message": clean(err or out or "Operation failed.", 200),
    }


def wifi_disconnect(uuid):
    """Disconnect an active Wi-Fi connection by UUID."""
    return _connection_action(uuid, "disconnect", frozenset({"802-11-wireless"}), "down", "Disconnected")


def wifi_forget(uuid):
    """Delete (forget) a saved Wi-Fi profile by UUID."""
    return _connection_action(uuid, "forget", frozenset({"802-11-wireless"}), "delete", "Forgot")


def connection_up(uuid):
    """Activate a saved Wi-Fi, Ethernet, or VPN connection by UUID."""
    return _connection_action(uuid, "conn_up", ALLOWED_CONN_TYPES, "up", "Connected")


def connection_down(uuid):
    """Deactivate an active Wi-Fi, Ethernet, or VPN connection by UUID."""
    return _connection_action(uuid, "conn_down", ALLOWED_CONN_TYPES, "down", "Disconnected")
