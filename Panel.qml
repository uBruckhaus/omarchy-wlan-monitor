pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "I18n.js" as I18n
import "corners.js" as Corners

// Detail popup: Wi-Fi link & signal quality in plain words, live throughput, and the
// list of devices on the local WLAN with a type icon. Clicking a device expands its
// details (status explained, maker, model, MAC) with actions: rename, pin, hide, open
// its web page, mark as known. Names, pins and hidden flags are stored per network by
// the collector; on trusted networks it also flags devices that joined recently.
Panel {
  id: root
  moduleName: "ubruckhaus.wlan-monitor"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  readonly property var barIdentity: hostWidget || root
  property var stats: ({})  // pushed by BarWidget on every snapshot
  property var wifiState: ({})  // pushed by BarWidget on wifi_state events
  readonly property var link: stats.link || ({})
  readonly property var traffic: stats.traffic || ({})
  // Only replace the device list when its content changed, so rows are not rebuilt every
  // tick, and never while a name is being edited (a rebuild would drop the text field).
  property var devices: []
  property string devicesRev: ""
  onStatsChanged: {
    refreshDevices()
    dropFormOfOtherNetwork()
    if (!root.netmonPaused && root.stats && root.stats.netmon && typeof root.stats.netmon === "object") {
      root.netmon = root.stats.netmon
    }
  }
  function refreshDevices() {
    if (root.editingKey !== "") return
    var rev = String(stats.devices_rev || "")
    if (rev === "" || rev !== devicesRev) {
      devicesRev = rev
      devices = stats.devices || []
    }
  }
  readonly property var gatewayDevice: {
    for (var i = 0; i < devices.length; i++) if (devices[i].is_gateway) return devices[i]
    return null
  }
  readonly property bool trusted: root.link.trusted === true
  readonly property real maxDeviceListHeight: Style.space(280)
  readonly property int onlineCount: Number(stats.online_count || 0)
  readonly property int totalCount: Number(stats.total_count || 0)
  readonly property int idleCount: Number(stats.idle_count || 0)
  readonly property int hiddenCount: Number(stats.hidden_count || 0)
  readonly property int newCount: Number(stats.new_count || 0)
  readonly property int namedCount: Number(stats.named_count || 0)
  readonly property bool alertsOn: stats.alerts !== false
  // Settings page (gear in the header). Back with the button, Backspace or Esc.
  property bool settingsOpen: false
  property bool infoPageOpen: false
  readonly property string lang: hostWidget ? hostWidget.lang : "en"
  readonly property string languageSetting: hostWidget ? hostWidget.languageSetting : "auto"
  readonly property string systemLang: hostWidget ? hostWidget.systemLang : "en"
  function t(key, args) { return I18n.tr(lang, key, args) }
  function tn(key, n, args) { return I18n.trn(lang, key, n, args) }

  // Corners (radius: cards, popups; control: buttons, drop-downs, fields; small: tracks,
  // swatches; pill: round dots or square ones) and the F12 screenshot key, from the widget's
  // shell.json entry. The panel's frame is the shell's card and keeps Style.cornerRadius.
  readonly property string cornersSetting: hostWidget ? hostWidget.cornersSetting : "windows"
  readonly property var corners: Corners.sizes(cornersSetting, Style.cornerRadius)
  readonly property bool screenshotKey: hostWidget ? hostWidget.screenshotKey : true
  readonly property real settingsLabelWidth: Style.space(150)  // WLAN Monitor's toggle rows
  readonly property var fritz: stats.fritz || ({})
  readonly property var vpn: root.link.vpn || null
  readonly property bool lanBlocked: root.vpn !== null && root.vpn.lan_blocked === true
  // "Allow it with: <command>" hints carry a command the user can copy.
  readonly property string vpnCommand: {
    var hint = root.vpn ? String(root.vpn.hint || "") : ""
    return hint.indexOf("Allow it with: ") === 0 ? hint.slice(15) : ""
  }
  // The VPN hint in the interface language (the collector sends English).
  readonly property string vpnHint: root.vpnCommand ? root.t("allowWith", [root.vpnCommand]) : root.t("vpnHintGeneric")
  property bool vpnCopied: false
  Timer { id: vpnCopiedTimer; interval: 1600; onTriggered: root.vpnCopied = false }
  // Main view pages: "devices", "map", "monitor", "setup".
  property string activePage: "devices"
  readonly property bool mapPage: activePage === "map"
  function setPage(pageName) {
    if (pageName !== "setup" && root.wifiFormOpen) root.closeWifiForm()
    if (root.activePage !== pageName) root.activePage = pageName
    root.syncNetmonMode()
    if (pageName === "setup" && root.hostWidget && typeof root.hostWidget.wifiScan === "function") {
      root.wifiScanning = true
      wifiBusySafetyTimer.restart()
      root.hostWidget.wifiScan(false)
    }
  }
  function showPage(map) { root.setPage(map ? "map" : "devices") }

  // --- Network Monitor state ------------------------------------------------
  property var netmon: ({})
  property string netmonView: "connections"  // "connections", "byapp", "interfaces"
  property string netmonSearchText: ""
  property string netmonProto: "all"         // "all", "tcp", "udp"
  property string netmonScope: "all"         // "all", "active", "listening", "external", "lan", "loopback"
  property string netmonSort: "traffic"      // "traffic", "process", "state", "remote", "port"
  property bool netmonPaused: false
  property bool netmonResolve: false
  property string netmonExpandedKey: ""
  property string netmonCopiedKey: ""
  property bool netmonTableCopied: false
  Timer { id: netmonCopiedTimer; interval: 1500; onTriggered: root.netmonCopiedKey = "" }
  Timer { id: netmonTableCopiedTimer; interval: 1600; onTriggered: root.netmonTableCopied = false }

  function syncNetmonMode() {
    if (!root.hostWidget || typeof root.hostWidget.setNetmonMode !== "function") return
    var on = root.opened && !root.settingsOpen && !root.infoPageOpen && root.activePage === "monitor" && !root.netmonPaused
    root.hostWidget.setNetmonMode(on, on && root.netmonResolve)
  }
  onOpenedChanged: syncNetmonMode()
  onSettingsOpenChanged: syncNetmonMode()
  onInfoPageOpenChanged: syncNetmonMode()
  onActivePageChanged: syncNetmonMode()
  onNetmonPausedChanged: syncNetmonMode()
  onNetmonResolveChanged: syncNetmonMode()

  readonly property bool netmonHasData: root.netmon && typeof root.netmon === "object" && root.netmon.summary !== undefined
  readonly property var netmonSummary: (root.netmon && root.netmon.summary) || ({})
  readonly property bool netmonIsFiltered: root.netmonSearchText.trim() !== "" || root.netmonProto !== "all" || root.netmonScope !== "all"
  function clearNetmonFilters() {
    netmonSearchField.clear()
    root.netmonSearchText = ""
    root.netmonProto = "all"
    root.netmonScope = "all"
  }
  function nextNetmonSort() {
    var order = ["traffic", "process", "state", "remote", "port"]
    var idx = order.indexOf(root.netmonSort)
    root.netmonSort = order[(idx + 1) % order.length]
  }
  function netmonSortLabel(mode) {
    if (mode === "process") return root.t("sortApp")
    if (mode === "state") return root.t("sortState")
    if (mode === "remote") return root.t("sortRemote")
    if (mode === "port") return root.t("sortPort")
    return root.t("sortTraffic")
  }
  function connProto(c) { return String((c && (c.proto || c.protocol)) || "") }
  function connId(c) {
    if (!c) return ""
    if (c.id) return String(c.id)
    return connProto(c) + ":" + String(c.local_ip || "") + ":" + Number(c.local_port || 0)
      + "->" + String(c.remote_ip || "") + ":" + Number(c.remote_port || 0)
  }
  function preferredRemote(c) {
    if (!c) return ""
    var host = String(c.remote_host || "")
    return host !== "" ? host : String(c.remote_ip || "")
  }
  function effectivePort(c) {
    var rp = Number((c && c.remote_port) || 0)
    return rp > 0 ? rp : Number((c && c.local_port) || 0)
  }
  function connStateRank(st) {
    if (st === "ESTABLISHED") return 0
    if (st === "LISTEN") return 1
    if (st === "SYN_SENT" || st === "SYN_RECV") return 2
    if (st === "CLOSE_WAIT") return 3
    if (st === "TIME_WAIT") return 4
    if (st === "UNCONN") return 5
    return 6
  }
  readonly property var filteredConnections: {
    var all = (root.netmon && root.netmon.connections) || []
    var q = root.netmonSearchText.trim().toLowerCase()
    var protoF = root.netmonProto
    var scopeF = root.netmonScope
    var out = all.filter(function(c) {
      var proto = root.connProto(c)
      if (protoF === "tcp" && proto.indexOf("tcp") !== 0) return false
      if (protoF === "udp" && proto.indexOf("udp") !== 0) return false
      var st = String(c.state || "")
      var sc = String(c.scope || "")
      if (scopeF === "active" && st !== "ESTABLISHED" && st !== "SYN_SENT" && st !== "SYN_RECV" && st !== "UNCONN") return false
      if (scopeF === "listening" && st !== "LISTEN") return false
      if (scopeF === "external" && sc !== "external") return false
      if (scopeF === "lan" && sc !== "lan") return false
      if (scopeF === "loopback" && sc !== "loopback") return false
      if (q !== "") {
        var hay = [c.process, c.cmdline, c.remote_ip, c.remote_host, c.remote_port, c.local_ip, c.local_port, c.service, c.pid, st]
          .join(" ").toLowerCase()
        if (hay.indexOf(q) === -1) return false
      }
      return true
    })
    var sortMode = root.netmonSort
    out.sort(function(a, b) {
      if (sortMode === "process") {
        var pa = String(a.process || "").toLowerCase(), pb = String(b.process || "").toLowerCase()
        if (pa !== pb) return pa < pb ? -1 : 1
        return Number(a.remote_port || 0) - Number(b.remote_port || 0)
      }
      if (sortMode === "state") {
        var sa = root.connStateRank(String(a.state || "")), sb = root.connStateRank(String(b.state || ""))
        if (sa !== sb) return sa - sb
        var na = String(a.process || ""), nb = String(b.process || "")
        return na < nb ? -1 : (na > nb ? 1 : 0)
      }
      if (sortMode === "remote") {
        var ha = root.preferredRemote(a).toLowerCase(), hb = root.preferredRemote(b).toLowerCase()
        if (ha !== hb) return ha < hb ? -1 : 1
        return Number(a.remote_port || 0) - Number(b.remote_port || 0)
      }
      if (sortMode === "port") {
        var epa = root.effectivePort(a), epb = root.effectivePort(b)
        if (epa !== epb) return epa - epb
        var qa = String(a.process || ""), qb = String(b.process || "")
        return qa < qb ? -1 : (qa > qb ? 1 : 0)
      }
      var ra = Number(a.rx_rate || 0) + Number(a.tx_rate || 0)
      var rb = Number(b.rx_rate || 0) + Number(b.tx_rate || 0)
      if (rb !== ra) return rb - ra
      var ba = Number(a.rx_bytes || 0) + Number(a.tx_bytes || 0)
      var bb = Number(b.rx_bytes || 0) + Number(b.tx_bytes || 0)
      if (bb !== ba) return bb - ba
      var xa = String(a.process || ""), xb = String(b.process || "")
      return xa < xb ? -1 : (xa > xb ? 1 : 0)
    })
    return out
  }
  readonly property var filteredProcesses: {
    var all = (root.netmon && root.netmon.processes) || []
    var q = root.netmonSearchText.trim().toLowerCase()
    if (q === "") return all
    return all.filter(function(p) { return String(p.name || "").toLowerCase().indexOf(q) !== -1 })
  }
  readonly property var sparklineBars: {
    var hist = (root.netmon && root.netmon.history) || []
    var slice = hist.slice(-30)
    var pts = []
    for (var pad = slice.length; pad < 30; pad++) pts.push({ rx: 0, tx: 0 })
    for (var i = 0; i < slice.length; i++) {
      pts.push({ rx: Number(slice[i].rx_rate || 0), tx: Number(slice[i].tx_rate || 0) })
    }
    var maxRate = 1024
    for (var j = 0; j < pts.length; j++) {
      var tot = pts[j].rx + pts[j].tx
      if (tot > maxRate) maxRate = tot
    }
    return pts.map(function(p) {
      var tot = p.rx + p.tx
      var frac = tot <= 0 ? 0.06 : Math.max(0.10, Math.min(1.0, tot / maxRate))
      return { frac: frac, active: tot > 0, txDominant: p.tx > p.rx }
    })
  }
  function filterByApp(appName) {
    var val = String(appName || "")
    root.netmonView = "connections"
    netmonSearchField.text = val
    root.netmonSearchText = val
  }
  function copyNetmonTable() {
    function cell(v) { return String(v || "").replace(/[|\r\n]/g, " ").trim() }
    var lines = [
      "| Process | Proto | State | Local | Remote | Service | Scope |",
      "| --- | --- | --- | --- | --- | --- | --- |"
    ]
    root.filteredConnections.slice(0, 256).forEach(function(c) {
      var pname = String(c.process || "")
      var local = String(c.local_ip || "") + ":" + Number(c.local_port || 0)
      var rhost = root.preferredRemote(c)
      var rport = Number(c.remote_port || 0)
      var remote = rport > 0 ? (rhost + ":" + rport) : rhost
      lines.push("| " + [pname || "—", root.connProto(c), String(c.state || ""), local, remote, String(c.service || ""), String(c.scope || "")]
        .map(cell).join(" | ") + " |")
    })
    if (!root.copyText(lines.join("\n") + "\n")) return
    root.netmonTableCopied = true
    netmonTableCopiedTimer.restart()
  }
  function copyConnEndpoint(id, ep) {
    if (!root.copyText(ep)) return
    root.netmonCopiedKey = id
    netmonCopiedTimer.restart()
  }

  // --- Network & Wi-Fi Setup state ------------------------------------------
  property bool wifiScanning: false
  property bool wifiBusy: false
  Timer {
    id: wifiBusySafetyTimer
    interval: 35000
    onTriggered: { root.wifiBusy = false; root.wifiScanning = false }
  }
  function onCollectorReset() {
    root.wifiBusy = false
    root.wifiScanning = false
    wifiBusySafetyTimer.stop()
  }
  property bool wifiStatusOk: true
  property string wifiStatusText: ""
  property string wifiSearchText: ""
  property bool wifiFormOpen: false
  property string wifiFormSsid: ""
  property string wifiFormUuid: ""
  property string wifiFormNote: ""
  property bool wifiShowPassword: false

  readonly property bool nmAvailable: root.wifiState.nm_available !== undefined
    ? root.wifiState.nm_available === true
    : (root.stats.nm_available !== false)
  readonly property bool hasWifiDevice: root.wifiState.wifi_device !== undefined
    ? root.wifiState.wifi_device === true
    : (root.stats.wifi_device !== false)
  readonly property bool wifiRadioOn: root.wifiState.wifi_on !== undefined
    ? root.wifiState.wifi_on === true
    : (root.stats.wifi_on !== false)
  readonly property var unseenWifiNetworks: {
    var vis = (root.wifiState && root.wifiState.visible) || []
    return vis.filter(function(v) { return v.known !== true && String(v.ssid || "") !== "" })
  }
  readonly property var filteredVisibleWifi: {
    var q = root.wifiSearchText.trim().toLowerCase()
    return root.unseenWifiNetworks.filter(function(v) {
      return q === "" || String(v.ssid || "").toLowerCase().indexOf(q) !== -1
    })
  }
  readonly property bool allWiredUnplugged: {
    var devs = (root.wifiState && root.wifiState.wired_devices) || []
    return devs.length > 0 && devs.every(function(d) { return String(d.state || "") === "unavailable" })
  }
  function utf8ByteLength(str) {
    var s = String(str || "")
    var bytes = 0
    for (var i = 0; i < s.length; i++) {
      var code = s.charCodeAt(i)
      if (code < 0x80) bytes += 1
      else if (code < 0x800) bytes += 2
      else if (code >= 0xD800 && code <= 0xDBFF) { bytes += 4; i += 1 }
      else bytes += 3
    }
    return bytes
  }
  function wifiPasswordValid(pw) {
    var s = String(pw || "")
    if (s.indexOf("\n") !== -1 || s.indexOf("\r") !== -1) return false
    var blen = root.utf8ByteLength(s)
    if (blen >= 8 && blen <= 63) return true
    return /^[0-9a-fA-F]{64}$/.test(s)
  }
  function openWifiPasswordForm(ssid, uuid, note) {
    root.wifiFormSsid = String(ssid || "")
    root.wifiFormUuid = String(uuid || "")
    root.wifiFormNote = String(note || "")
    root.wifiShowPassword = false
    wifiPasswordField.clear()
    root.wifiFormOpen = true
    Qt.callLater(function() { wifiPasswordField.forceActiveFocus() })
  }
  function closeWifiForm() {
    var wasOpen = root.wifiFormOpen
    var hadFocus = wifiPasswordField.activeFocus
    wifiPasswordField.clear()
    root.wifiFormOpen = false
    root.wifiFormSsid = ""
    root.wifiFormUuid = ""
    root.wifiFormNote = ""
    root.wifiShowPassword = false
    if (wasOpen && hadFocus) keyCatcher.forceActiveFocus()
  }
  function submitWifiPassword() {
    if (!root.hostWidget || root.wifiBusy) return
    var pw = wifiPasswordField.text
    if (!root.wifiPasswordValid(pw)) return
    root.wifiBusy = true
    wifiBusySafetyTimer.restart()
    root.wifiStatusText = ""
    root.hostWidget.wifiConnect(root.wifiFormSsid, pw, root.wifiFormUuid)
  }
  function onWifiState(data) {
    root.wifiScanning = false
    if (!root.wifiBusy) wifiBusySafetyTimer.stop()
  }
  function onWifiResult(data) {
    root.wifiBusy = false
    if (!root.wifiScanning) wifiBusySafetyTimer.stop()
    var ok = data && data.ok === true
    var authFailed = data && data.auth_failed === true
    var ssid = String((data && data.ssid) || "")
    var uuid = String((data && data.uuid) || "")
    var msg = String((data && data.message) || "")
    if (ok) {
      if (root.wifiFormOpen) root.closeWifiForm()
      root.wifiStatusOk = true
      root.wifiStatusText = msg !== "" ? msg : (ssid !== "" ? root.t("connectedToN", [ssid]) : root.t("done"))
    } else if (authFailed && root.opened) {
      if (root.activePage !== "setup") root.setPage("setup")
      root.openWifiPasswordForm(ssid || root.wifiFormSsid, uuid || root.wifiFormUuid, root.t("authFailedHint"))
      root.wifiStatusOk = false
      root.wifiStatusText = msg !== "" ? msg : root.t("authFailedHint")
    } else {
      root.wifiStatusOk = false
      root.wifiStatusText = msg !== "" ? msg : root.t("actionFailed")
    }
  }
  function toggleWifiRadio(on) {
    if (!root.hostWidget || root.wifiBusy) return
    root.wifiBusy = true
    wifiBusySafetyTimer.restart()
    root.wifiStatusText = ""
    root.hostWidget.wifiRadio(on === true)
  }
  function triggerWifiScan(rescan) {
    if (!root.hostWidget || root.wifiScanning || root.wifiBusy) return
    root.wifiScanning = true
    wifiBusySafetyTimer.restart()
    root.hostWidget.wifiScan(rescan === true)
  }
  function connectKnownWifi(uuid, ssid) {
    if (!root.hostWidget || root.wifiBusy) return
    root.wifiBusy = true
    wifiBusySafetyTimer.restart()
    root.wifiStatusText = ""
    root.wifiFormSsid = String(ssid || "")
    root.wifiFormUuid = String(uuid || "")
    root.hostWidget.wifiConnect(ssid, null, uuid)
  }
  function connectVisibleWifi(ssid, secured) {
    if (secured) {
      root.openWifiPasswordForm(ssid, "", "")
      return
    }
    if (!root.hostWidget || root.wifiBusy) return
    root.wifiBusy = true
    wifiBusySafetyTimer.restart()
    root.wifiStatusText = ""
    root.hostWidget.wifiConnect(ssid, null, "")
  }
  function disconnectWifi(uuid) {
    if (!root.hostWidget || root.wifiBusy) return
    root.wifiBusy = true
    wifiBusySafetyTimer.restart()
    root.wifiStatusText = ""
    root.hostWidget.wifiDisconnect(uuid)
  }
  function forgetWifi(uuid) {
    if (!root.hostWidget || root.wifiBusy) return
    root.wifiBusy = true
    wifiBusySafetyTimer.restart()
    root.wifiStatusText = ""
    root.hostWidget.wifiForget(uuid)
  }
  function toggleConn(uuid, up) {
    if (!root.hostWidget || root.wifiBusy) return
    root.wifiBusy = true
    wifiBusySafetyTimer.restart()
    root.wifiStatusText = ""
    root.hostWidget.connToggle(uuid, up === true)
  }
  function openSystemNetSettings() {
    root.close()
    // Third-party plugins may not summon built-in panels directly, so go
    // through the shell CLI (fixed argv, no shell string).
    Quickshell.execDetached(["omarchy-shell", "shell", "summon", "omarchy.network", "{}"])
  }
  // From the map: back to the Devices page, open the device's group, expand and show it.
  function groupIdOf(dev) {
    if (dev.is_gateway || dev.is_self) return ""
    if (root.viewMode === "ap") return dev.mesh && dev.mesh.via_mac ? dev.mesh.via_mac : "none"
    return root.groupOf(dev)
  }
  // The one grouping rule both pages use (list and access-point views have no groups here).
  function bandOf(dev) {
    if (dev.mesh && dev.mesh.band) return dev.mesh.band
    if (dev.is_self && root.link.via_band) return root.link.via_band
    return ""
  }
  function groupOf(dev) {
    if (dev.pinned) return "favourites"
    if (root.viewMode === "platform") return dev.group || "other"
    if (root.viewMode === "type") return root.kindGroups[dev.kind] || "other"
    if (root.viewMode === "band") {
      var band = root.bandOf(dev)
      if (band) return root.bandIds[band] || "gother"
      return dev.online ? "gother" : "gsleep"
    }
    return ""
  }
  function orderFor(mode) {
    return mode === "band" ? root.bandGroupOrder : mode === "type" ? root.typeOrder : root.platformOrder
  }
  function openDevice(dev) {
    root.setPage("devices")
    var drop = ["mappage", groupIdOf(dev)]
    var collapsed = (root.view.collapsed || []).filter(function(id) { return drop.indexOf(id) === -1 })
    root.saveView(root.viewMode, collapsed)
    if (dev.hidden) root.showHidden = true
    root.filterText = ""
    root.expandedKey = root.deviceKey(dev)
    Qt.callLater(function() { Qt.callLater(function() { root.scrollToKey(root.expandedKey) }) })
  }
  function scrollToKey(key) {
    for (var i = 0; i < deviceColumn.children.length; i++) {
      var loader = deviceColumn.children[i]
      if (loader.item && loader.item.dev && root.deviceKey(loader.item.dev) === key) {
        root.ensureVisible(loader)
        return
      }
    }
  }
  readonly property var bandOrder: ["6 GHz", "5 GHz", "2.4 GHz", "LAN"]
  readonly property var bandIds: ({ "6 GHz": "gsix", "5 GHz": "gfive", "2.4 GHz": "gtwo", "LAN": "glan" })
  readonly property var bandGroupOrder: ["favourites", "gsix", "gfive", "gtwo", "glan", "gother", "gsleep"]
  readonly property var typeOrder: ["favourites", "mobile", "computers", "media", "smarthome", "office", "network", "other"]
  function signalQuality(dbm) {
    if (dbm === null || dbm === undefined) return -1
    return Math.max(0, Math.min(100, 2 * (Number(dbm) + 100)))
  }
  // Tree rows for the map: {depth, guides[], last, type, ...}. guides[i] says whether the
  // ancestor at depth i+1 has siblings below, i.e. whether its vertical connector continues.
  readonly property var mapRows: {
    var devs = root.devices.filter(function(d) { return !d.hidden })
    var collapsed = root.view.collapsed || []
    var gateway = null
    devs.forEach(function(d) { if (d.is_gateway) gateway = d })
    var link = root.link
    // Children per access point MAC; devices without mesh data go to fallback buckets.
    var apMacs = {}
    var aps = (root.fritz && root.fritz.aps) || []
    aps.forEach(function(ap) { apMacs[ap.mac] = ap })
    function parentOf(dev) {
      if (dev.mesh && dev.mesh.via_mac && apMacs[dev.mesh.via_mac]) return dev.mesh.via_mac
      return gateway ? gateway.mac : ""
    }
    function isRepeater(d) { return d.kind === "router" && !d.is_gateway && d.mesh && d.mesh.role === "slave" }
    // Under each router / repeater: its devices in the groups chosen on either page,
    // then the repeaters connected to it as their own branches.
    function apNode(mac, dev, title) {
      var node = { type: "ap", id: mac, dev: dev, title: title, children: [] }
      var members = devs.filter(function(d) { return d !== dev && !d.is_gateway && !isRepeater(d) && parentOf(d) === mac })
      if (root.viewMode === "list" || root.viewMode === "ap") {
        members.forEach(function(d) { node.children.push({ type: "device", dev: d }) })
      } else {
        var buckets = {}
        members.forEach(function(d) {
          var id = root.groupOf(d)
          if (!buckets[id]) buckets[id] = []
          buckets[id].push(d)
        })
        root.orderFor(root.viewMode).forEach(function(id) {
          if (!buckets[id]) return
          var info = root.groupInfo[id] || root.groupInfo.other
          node.children.push({ type: "group", id: id, title: info.title, icon: info.icon, devs: buckets[id] })
        })
      }
      devs.forEach(function(d) {
        if (isRepeater(d) && d.mesh.via_mac === mac) node.children.push(apNode(d.mac, d, d.name))
      })
      return node
    }
    var rootNode = { type: "internet", children: [] }
    if (gateway) rootNode.children.push(apNode(gateway.mac, gateway, gateway.name))
    var rows = []
    function walk(node, depth, guides, last) {
      var row = { depth: depth, guides: guides, last: last, type: node.type, node: node }
      if (node.type === "group") {
        row.id = node.id
        row.collapsed = collapsed.indexOf(node.id) !== -1
        row.count = node.devs.length
        row.online = node.devs.filter(function(d) { return d.online }).length
      } else if (node.type === "ap") {
        row.id = node.id
        row.collapsed = node.dev && !node.dev.is_gateway && collapsed.indexOf(node.id) !== -1
      }
      rows.push(row)
      var kids = []
      if (node.type === "group") kids = row.collapsed ? [] : node.devs.map(function(d) { return { type: "device", dev: d } })
      else if (!row.collapsed) kids = node.children || []
      var childGuides = depth > 0 ? guides.concat([!last]) : []
      kids.forEach(function(child, i) {
        if (child.type === "device") {
          rows.push({ depth: depth + 1, guides: childGuides, last: i === kids.length - 1, type: "device", dev: child.dev })
        } else {
          walk(child, depth + 1, childGuides, i === kids.length - 1)
        }
      })
    }
    walk(rootNode, 0, [], true)
    return rows
  }
  readonly property string mapSummary: {
    var n = root.devices.filter(function(d) { return !d.hidden && !d.is_gateway }).length
    return root.tn("devices", n)
  }


  // The network info lines are open while "showinfo" is in the saved view list.
  readonly property bool infoOpen: (root.view.collapsed || []).indexOf("showinfo") !== -1
  property bool fritzFormOpen: false
  property bool fritzHelpOpen: false
  property bool showPassword: false
  // The FRITZ!Box form belongs to the network it was opened on: a login typed there is
  // never sent to another router after the network changed while the form was open. The
  // identity comes from the collector's link (net_id changes with every gateway change; the
  // gateway MAC is the collector's, not the device list's, which is frozen while renaming),
  // and the collector itself refuses a login whose net_id is no longer current.
  property string fritzFormNet: ""
  property string fritzFormNetId: ""
  property string fritzUserNet: ""  // the network the user name in the form was typed on
  function networkId() {
    return JSON.stringify([String(root.link.net_id || ""), root.link.ssid || "", root.link.gateway || "",
      String(root.link.gateway_mac || "")])
  }
  function openFritzForm() {
    // A user name typed for another router (form cancelled there) is not offered on this one.
    if (root.fritzUserNet !== root.networkId()) fritzUser.clear()
    root.fritzUserNet = root.networkId()
    root.fritzFormNet = root.networkId()
    root.fritzFormNetId = String(root.link.net_id || "")
    root.fritzFormOpen = true
  }
  // A saved login that only a new login can fix: shown as a banner at the top, not only in the
  // collapsed network info.
  readonly property bool fritzNeedsLogin: root.fritz.available === true && root.fritz.state === "error"
    && !!root.fritz.user && (root.fritz.message_code === "fzCert" || root.fritz.message_code === "fzWrongLogin")
  function startFritzLogin() {
    root.showPage(false)  // the form lives on the Devices page
    root.openFritzForm()
    if (root.fritz.user && fritzUser.text === "") fritzUser.text = root.fritz.user
    Qt.callLater(function() { (fritzUser.text === "" ? fritzUser : fritzPassword).forceActiveFocus() })
  }
  function closeFritzForm(clearUser) {
    fritzPassword.clear()
    if (clearUser === true) fritzUser.clear()
    root.fritzFormOpen = false
    root.showPassword = false
    root.fritzFormNet = ""
    root.fritzFormNetId = ""
    keyCatcher.forceActiveFocus()
  }
  function dropFormOfOtherNetwork() {
    // A user name typed for another router is not offered on this one either.
    if (root.fritzFormOpen && root.fritzFormNet !== root.networkId()) root.closeFritzForm(true)
  }
  function fritzConnect() {
    if (!root.hostWidget || fritzPassword.text === "") return
    if (root.fritzFormNetId !== "" && root.fritzFormNet === root.networkId())
      root.hostWidget.sendJson({ cmd: "fritz_login", user: fritzUser.text.trim(), password: fritzPassword.text,
        net: root.fritzFormNetId })
    root.closeFritzForm()
  }
  readonly property int sleepingCount: Math.max(0, totalCount - onlineCount - idleCount)
  readonly property bool scanning: root.hostWidget ? root.hostWidget.scanning === true : (stats.scanning === true)
  readonly property color fg: Commons.Color.popups.text
  readonly property color dim: Qt.darker(fg, 1.45)
  readonly property string font: root.bar ? root.bar.fontFamily : Style.font.family

  // Row state, keyed by MAC (or IP when the MAC is unknown) so it survives list updates.
  property string expandedKey: ""
  property string editingKey: ""
  onEditingKeyChanged: if (editingKey === "") refreshDevices()
  property bool showHidden: false
  property string filterText: ""
  readonly property bool showSearch: root.totalCount - root.hiddenCount > 12 || root.filterText !== ""
  readonly property var visibleDevices: {
    var query = root.filterText.trim().toLowerCase()
    return root.devices.filter(function(dev) {
      if (dev.hidden && !root.showHidden) return false
      if (!query) return true
      return [dev.name, dev.auto_name, dev.ip, dev.vendor, dev.model, dev.hostname, root.deviceKindLabel(dev),
        dev.mesh ? dev.mesh.via : ""]
        .join(" ").toLowerCase().indexOf(query) !== -1
    })
  }
  function deviceKey(dev) { return String(dev.mac || dev.ip || "") }

  // List or grouped view. The collector stores the choice; a local copy answers clicks at once.
  property var localView: null
  readonly property var view: localView || stats.view || ({ mode: "list", collapsed: [] })
  readonly property bool meshActive: stats.mesh_active === true
  readonly property string viewMode: (view.mode === "ap" || view.mode === "band") && !meshActive ? "platform" : String(view.mode || "list")
  readonly property var viewModes: meshActive ? ["list", "platform", "type", "band", "ap"] : ["list", "platform", "type"]
  readonly property var viewLabels: ({ list: root.t("viewList"), platform: root.t("viewPlatform"), type: root.t("viewType"),
    band: root.t("viewBand"), ap: root.t("viewAp") })
  function saveView(mode, collapsed) {
    root.localView = { mode: mode, collapsed: collapsed }
    if (root.hostWidget) root.hostWidget.sendJson({ cmd: "view", mode: mode, collapsed: collapsed })
  }
  readonly property var viewOptions: root.viewModes.map(function(m) { return { value: m, label: root.viewShortLabels[m] } })
  readonly property var viewShortLabels: ({ list: root.t("shortList"), platform: root.t("shortPlatform"), type: root.t("shortType"), band: root.t("shortBand"), ap: root.t("shortAp") })
  function setViewMode(mode) {
    if (root.viewModes.indexOf(mode) !== -1 && mode !== root.viewMode) root.saveView(mode, root.view.collapsed || [])
  }
  // Every foldable branch of the map in the current grouping: groups and repeaters.
  readonly property var mapFoldIds: {
    var ids = root.orderFor(root.viewMode).slice()
    var aps = (root.fritz && root.fritz.aps) || []
    aps.forEach(function(ap) { if (ap.role !== "master") ids.push(ap.mac) })
    return ids
  }
  // Groups of the Devices page in the current grouping (access-point mode groups by MAC).
  readonly property var listFoldIds: {
    if (root.viewMode === "ap") {
      var ids = ((root.fritz && root.fritz.aps) || []).map(function(ap) { return ap.mac })
      ids.push("none")
      return ids
    }
    return root.viewMode === "list" ? [] : root.orderFor(root.viewMode).slice()
  }
  function foldAll(fold, ids) {
    ids = ids || root.mapFoldIds
    var collapsed = (root.view.collapsed || []).filter(function(id) { return ids.indexOf(id) === -1 })
    if (fold) collapsed = collapsed.concat(ids)
    root.saveView(root.viewMode, collapsed.slice(0, 32))
  }
  function toggleGroup(id) {
    var collapsed = (root.view.collapsed || []).slice()
    var at = collapsed.indexOf(id)
    if (at === -1) collapsed.push(id)
    else collapsed.splice(at, 1)
    root.saveView(root.viewMode, collapsed.slice(0, 32))
  }

  readonly property var groupInfo: ({
    favourites: { title: root.t("gFavourites"), icon: 0xF04CE },
    apple: { title: "Apple", icon: 0xF0035 },
    android: { title: "Android", icon: 0xF0032 },
    mobile: { title: root.t("gMobile"), icon: 0xF011C },
    computers: { title: root.t("gComputers"), icon: 0xF0379 },
    media: { title: root.t("gMedia"), icon: 0xF07F4 },
    smarthome: { title: root.t("gSmarthome"), icon: 0xF07D0 },
    office: { title: root.t("gOffice"), icon: 0xF042A },
    network: { title: root.t("gNetwork"), icon: 0xF0003 },
    other: { title: root.t("gOther"), icon: 0xF0625 },
    none: { title: root.t("gNone"), icon: 0xF0625 },
    gsix: { title: "6 GHz", icon: 0xF05A9 },
    gfive: { title: "5 GHz", icon: 0xF05A9 },
    gtwo: { title: "2.4 GHz", icon: 0xF05A9 },
    glan: { title: root.t("gLan"), icon: 0xF0200 },
    gother: { title: root.t("gBandUnknown"), icon: 0xF0625 },
    gsleep: { title: root.t("gSleep"), icon: 0xF04B2 }
  })
  readonly property var platformOrder: ["favourites", "apple", "android", "mobile", "computers", "media", "smarthome", "office", "network", "other"]
  readonly property var kindGroups: ({
    router: "network", phone: "mobile", tablet: "mobile", watch: "mobile", computer: "computers", laptop: "computers",
    tv: "media", speaker: "media", console: "media", smarthome: "smarthome", light: "smarthome",
    appliance: "smarthome", camera: "smarthome", printer: "office", nas: "office"
  })
  // Flat list of {type: "header", ...} and {type: "device", dev} entries for the Repeater.
  readonly property var listEntries: {
    var devs = root.visibleDevices
    if (root.viewMode === "list" || root.filterText.trim() !== "")
      return devs.map(function(dev) { return { type: "device", dev: dev } })
    var collapsed = root.view.collapsed || []
    var top = [], buckets = {}, order = []
    var aps = (root.stats.fritz && root.stats.fritz.aps) || []
    if (root.viewMode === "ap") {
      aps.forEach(function(ap) {
        order.push(ap.mac)
        buckets[ap.mac] = { title: ap.name || root.t("accessPoint"), icon: 0xF0003,
          detail: ap.role === "master" ? root.t("mainRouter") : (ap.via ? root.t("viaN", [ap.via + (ap.band ? " " + ap.band : "")]) : root.t("repeater")), devs: [] }
      })
      order.push("none")
    } else {
      order = root.orderFor(root.viewMode)
    }
    devs.forEach(function(dev) {
      if (dev.is_gateway || (dev.is_self && root.viewMode !== "ap")) { top.push(dev); return }
      var id
      if (root.viewMode === "ap") id = dev.mesh && buckets[dev.mesh.via_mac] ? dev.mesh.via_mac : "none"
      else id = root.groupOf(dev)
      if (!buckets[id]) {
        var info = root.groupInfo[id] || root.groupInfo.other
        buckets[id] = { title: info.title, icon: info.icon, detail: "", devs: [] }
      }
      buckets[id].devs.push(dev)
    })
    var out = top.map(function(dev) { return { type: "device", dev: dev } })
    order.forEach(function(id) {
      var bucket = buckets[id]
      if (!bucket || bucket.devs.length === 0) return
      var isCollapsed = collapsed.indexOf(id) !== -1
      var hasNew = bucket.devs.some(function(d) { return d.new === true })
      out.push({
        type: "header", id: id, title: bucket.title, icon: bucket.icon, detail: bucket.detail,
        count: bucket.devs.length, online: bucket.devs.filter(function(d) { return d.online }).length,
        hasNew: hasNew, collapsed: isCollapsed
      })
      // The user's choice always wins; a collapsed group with a new device shows NEW on its header.
      if (!isCollapsed) bucket.devs.forEach(function(dev) { out.push({ type: "device", dev: dev, inGroup: true }) })
    })
    return out
  }

  function glyph(code) { return String.fromCodePoint(code) }
  readonly property var kindIcons: ({
    router: 0xF0469, computer: 0xF0379, laptop: 0xF0322, phone: 0xF011C, tablet: 0xF04F6,
    watch: 0xF0897, tv: 0xF07F4, speaker: 0xF04C3, printer: 0xF042A, console: 0xF0297,
    camera: 0xF07AE, light: 0xF0335, nas: 0xF048B, appliance: 0xF0176, smarthome: 0xF07D0,
    unknown: 0xF0625
  })
  readonly property var kindLabels: ({
    router: root.t("kRouter"), computer: root.t("kComputer"), laptop: root.t("kLaptop"), phone: root.t("kPhone"), tablet: root.t("kTablet"),
    watch: root.t("kWatch"), tv: root.t("kTv"), speaker: root.t("kSpeaker"), printer: root.t("kPrinter"), console: root.t("kConsole"),
    camera: root.t("kCamera"), light: root.t("kLight"), nas: root.t("kNas"), appliance: root.t("kAppliance"),
    smarthome: root.t("kSmarthome"), unknown: root.t("kUnknown")
  })
  function kindIcon(kind) { return glyph(kindIcons[kind] || kindIcons.unknown) }
  function kindLabel(kind) { return kindLabels[kind] || kindLabels.unknown }
  function deviceKindLabel(dev) {
    return dev.kind === "router" && !dev.is_gateway ? root.t("repeaterAp") : kindLabel(dev.kind)
  }
  function meshText(dev) {
    var m = dev.mesh
    if (!m || !m.via) return ""
    // With a single access point "via …" says nothing new; the band is enough.
    if (((root.fritz.aps || []).length) <= 1) return m.band === "LAN" ? root.t("cable") : (m.band || "")
    return root.t("viaN", [m.via]) + (m.band ? " · " + m.band : "")
  }
  function meshDetail(dev) {
    var m = dev.mesh
    if (!m || (!m.band && !m.rate_mbps)) return ""
    var parts = []
    if (m.band) parts.push(m.band === "LAN" ? root.t("cableLan") : m.band)
    if (m.rate_mbps) parts.push(m.rate_mbps + " Mbit/s")
    if (m.signal_dbm !== null && m.signal_dbm !== undefined) {
      var q = Math.max(0, Math.min(100, 2 * (Number(m.signal_dbm) + 100)))
      parts.push(root.t("sigLine", [signalWord(q).toLowerCase(), m.signal_dbm]))
    }
    return parts.join(" · ")
  }

  function signalColor(fraction) {
    return root.hostWidget && root.hostWidget.signalColor ? root.hostWidget.signalColor(fraction) : Commons.Color.accent
  }
  function signalWord(quality) {
    var q = Number(quality || 0)
    return q >= 70 ? root.t("sigExcellent") : q >= 50 ? root.t("sigGood") : q >= 30 ? root.t("sigFair") : root.t("sigWeak")
  }
  function formatBytes(bytes) {
    var b = Number(bytes || 0)
    if (b >= 1073741824) return (b / 1073741824).toFixed(1) + " GiB"
    if (b >= 1048576) return (b / 1048576).toFixed(1) + " MiB"
    if (b >= 1024) return (b / 1024).toFixed(0) + " KiB"
    return b + " B"
  }
  function formatRate(bytesPerSec) {
    if (bytesPerSec === null || bytesPerSec === undefined) return "—"
    var r = Number(bytesPerSec)
    if (r >= 1048576) return (r / 1048576).toFixed(1) + " MB/s"
    if (r >= 1024) return (r / 1024).toFixed(1) + " KB/s"
    return Math.round(r) + " B/s"
  }
  function agoText(minutes) {
    var m = Number(minutes)
    if (minutes === null || minutes === undefined || !isFinite(m)) return ""
    if (m < 1) return root.t("justNow")
    if (m < 60) return root.t("minAgo", [m])
    return root.t("hAgo", [Math.floor(m / 60)])
  }
  function statusWord(dev) {
    if (dev.is_gateway) return root.t("stRouter")
    if (dev.is_self) return root.t("stThisPc")
    if (dev.online) return root.t("stOnline")
    if (dev.state === "idle") return root.t("stIdle")
    var ago = agoText(dev.seen_min)
    return root.t("stSleeping") + (ago ? " · " + ago : "")
  }
  function statusExplain(dev) {
    if (dev.is_gateway) return root.t("exGateway")
    if (dev.is_self) return root.t("exSelf")
    if (dev.online) return root.t("exOnline")
    if (dev.state === "idle")
      return root.t("exIdle")
    var ago = agoText(dev.seen_min)
    return root.t("exSleeping") + " " + (ago ? root.t("lastSeen", [ago]) : root.t("knownFromRouter"))
  }
  function deviceRightLabel(dev) {
    var word = statusWord(dev)
    return (word === root.t("stOnline") || word === root.t("stRouter") ? "" : word + " · ") + dev.ip
  }
  function deviceSubtitle(dev) {
    var label = deviceKindLabel(dev)
    var parts = dev.name.indexOf(label) === 0 ? [] : [label]
    if (dev.is_gateway && dev.model && dev.name.indexOf(dev.model) === -1) parts.push(root.t("modelN", [dev.model]))
    // The band is already the group heading when grouping by band.
    if (meshText(dev) && !(root.viewMode === "band" && !dev.is_self)) parts.push(meshText(dev))
    if (dev.vendor && dev.vendor !== "Private MAC" && dev.name.indexOf(dev.vendor) === -1) parts.push(dev.vendor)
    if (dev.custom_name && dev.auto_name) parts.push(dev.auto_name)
    return parts.join("  ·  ")
  }

  // Open a device's web UI in the default browser (omarchy-launch-browser reads
  // xdg-settings). The collector only builds http(s) URLs for private IPv4 literals;
  // re-check the shape here and pass it as a single argv entry, never through a shell.
  readonly property var webUrlPattern: /^https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d{1,5})?\/[A-Za-z0-9._~\/-]{0,100}$/
  function openWeb(url) {
    var target = String(url || "")
    if (!webUrlPattern.test(target)) return
    root.close()
    Quickshell.execDetached(["omarchy-launch-browser", target])
  }
  // All clipboard writes go to `wl-copy` through stdin, never as an argument: wl-copy stays
  // alive as the clipboard owner, and its command line is readable by other local users
  // in /proc/<pid>/cmdline. Closing stdin (stdinEnabled = false) ends the text.
  property string clipboardQueue: ""
  property bool clipboardQueued: false
  Process {
    id: clipboardWriter
    command: ["wl-copy"]
    stdinEnabled: true
    property string text: ""
    onStarted: {
      clipboardWriter.write(clipboardWriter.text)
      clipboardWriter.text = ""
      clipboardWriter.stdinEnabled = false
    }
    onExited: {
      clipboardWriter.stdinEnabled = true
      if (root.clipboardQueued) {
        root.clipboardQueued = false
        var next = root.clipboardQueue
        root.clipboardQueue = ""
        root.copyText(next)
      }
    }
  }
  function copyText(text) {
    var value = String(text || "").slice(0, 262144)
    if (value === "") return false
    if (clipboardWriter.running) {  // a copy is still being handed over: send this one next
      root.clipboardQueue = value
      root.clipboardQueued = true
      return true
    }
    clipboardWriter.text = value
    clipboardWriter.stdinEnabled = true
    clipboardWriter.running = true
    return true
  }
  // Copy a device IP; only plain IPv4 literals.
  readonly property var ipPattern: /^(\d{1,3}\.){3}\d{1,3}$/
  function copyIp(ip) {
    var text = String(ip || "")
    if (!ipPattern.test(text)) return false
    return root.copyText(text)
  }
  // The device list as a Markdown table on the clipboard (text from the collector is
  // already sanitized; `|` is replaced so cells stay intact). Sent through stdin, see copyText().
  property bool listCopied: false
  Timer { id: listCopiedTimer; interval: 1600; onTriggered: root.listCopied = false }
  function copyList() {
    function cell(value) { return String(value || "").replace(/[|\r\n]/g, " ").trim() }
    var lines = [
      "# Devices on " + cell(root.link.ssid || "the network") + " (" + new Date().toLocaleString(Qt.locale(), Locale.ShortFormat) + ")",
      "",
      "| " + [root.t("colName"), root.t("colType"), root.t("colStatus"), "IP", root.t("colMaker"), root.t("colModel"), "MAC"].join(" | ") + " |",
      "| --- | --- | --- | --- | --- | --- | --- |"
    ]
    root.devices.slice(0, 256).forEach(function(dev) {
      lines.push("| " + [dev.name, root.kindLabel(dev.kind), root.statusWord(dev) + (dev.hidden ? " " + root.t("hiddenMark") : ""),
        dev.ip, dev.vendor, dev.model, dev.mac].map(cell).join(" | ") + " |")
    })
    if (!root.copyText(lines.join("\n") + "\n")) return
    root.listCopied = true
    listCopiedTimer.restart()
  }

  function deviceCommand(cmd, dev, extra) {
    if (!root.hostWidget || !dev || !dev.can_edit) return
    var payload = { cmd: cmd, mac: String(dev.mac || "") }
    for (var key in extra) payload[key] = extra[key]
    root.hostWidget.sendJson(payload)
  }
  function startRename(dev) {
    root.expandedKey = deviceKey(dev)
    root.editingKey = deviceKey(dev)
  }
  function finishRename(dev, name) {
    if (dev && name !== null) deviceCommand("rename", dev, { name: String(name).trim().slice(0, 40) })
    root.editingKey = ""
    keyCatcher.forceActiveFocus()
  }
  function ensureVisible(item) {
    if (!item) return
    var top = item.mapToItem(deviceColumn, 0, 0).y
    var bottom = top + item.height
    if (bottom > deviceScroller.contentY + deviceScroller.height)
      deviceScroller.contentY = Math.min(deviceScroller.contentHeight - deviceScroller.height, bottom - deviceScroller.height)
    if (top < deviceScroller.contentY) deviceScroller.contentY = Math.max(0, top)
  }

  function open() { root.controller.show() }
  function close() {
    root.infoPageOpen = false
    root.settingsOpen = false
    root.editingKey = ""
    if (root.wifiFormOpen) root.closeWifiForm()
    if (root.fritzFormOpen) root.closeFritzForm()
    if (root.hostWidget && typeof root.hostWidget.setNetmonMode === "function") root.hostWidget.setNetmonMode(false, false)
    root.controller.hide()
  }
  function toggle() { if (root.opened) root.close(); else root.open() }

  component Meter: Item {
    id: meter
    property string label: ""
    property string value: ""
    property string tip: ""
    property real fraction: 0
    property color fillColor: Commons.Color.accent
    width: parent ? parent.width : 200
    height: meterLabel.height + Style.space(10)
    Text {
      textFormat: Text.PlainText
      id: meterLabel
      anchors.left: parent.left
      anchors.right: meterValue.left
      anchors.rightMargin: Style.space(8)
      elide: Text.ElideRight
      text: meter.label
      color: root.dim
      font.family: root.font
      font.pixelSize: Style.font.caption
    }
    Text {
      textFormat: Text.PlainText
      id: meterValue
      anchors.right: parent.right
      text: meter.value
      color: root.fg
      font.family: root.font
      font.pixelSize: Style.font.caption
    }
    Rectangle {
      id: track
      anchors.bottom: parent.bottom
      width: parent.width
      height: Style.space(5)
      radius: Math.min(root.corners.small, height / 2)
      color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.12)
      Rectangle {
        width: parent.width * Math.max(0, Math.min(1, meter.fraction))
        height: parent.height
        radius: parent.radius
        color: meter.fillColor
        Behavior on width { NumberAnimation { duration: 400; easing.type: Easing.OutCubic } }
        Behavior on color { ColorAnimation { duration: 400 } }
      }
    }
    MouseArea { id: meterMouse; anchors.fill: parent; hoverEnabled: true; acceptedButtons: Qt.NoButton }
    PanelToolTip { visible: meter.tip !== "" && meterMouse.containsMouse; text: meter.tip; fontFamily: root.font }
  }

  // Small text action used inside expanded device details.
  component LinkAction: Text {
    id: action
    property string icon: ""
    property string label: ""
    property color baseColor: root.fg
    signal activated()
    textFormat: Text.PlainText
    text: (icon ? icon + " " : "") + label
    color: actionMouse.containsMouse ? Commons.Color.accent : baseColor
    font.family: root.font
    font.pixelSize: Style.font.caption
    font.underline: actionMouse.containsMouse
    MouseArea {
      id: actionMouse
      anchors.fill: parent
      anchors.margins: -Style.space(3)
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: action.activated()
    }
  }

  // One device row; click toggles the details.
  component DeviceRow: Item {
    id: block
    property var dev: ({})
    height: rows.implicitHeight + Style.space(6)
    readonly property string key: root.deviceKey(dev)
    readonly property bool online: dev.online === true
    readonly property bool expanded: root.expandedKey === key
    readonly property bool editing: root.editingKey === key && dev.can_edit === true
    readonly property string webUrl: String(dev.web_url || "")
    property bool copied: false
    onEditingChanged: if (editing) Qt.callLater(function() {
      nameField.text = block.dev.name
      nameField.forceActiveFocus()
      nameField.selectAll()
    })

    Timer {
      id: copiedTimer
      interval: 1400
      onTriggered: block.copied = false
    }

    Rectangle {
      anchors.fill: parent
      anchors.margins: -Style.space(3)
      radius: root.corners.control
      color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, block.expanded ? 0.06 : 0.08)
      visible: block.expanded || rowMouse.containsMouse
    }

    Column {
      id: rows
      width: parent.width
      y: Style.space(3)
      spacing: Style.space(2)

      Item {
        width: parent.width
        height: Math.max(deviceName.height, kindIcon.height)
        Text {
          id: kindIcon
          textFormat: Text.PlainText
          anchors.verticalCenter: parent.verticalCenter
          width: Style.space(18)
          horizontalAlignment: Text.AlignHCenter
          text: root.kindIcon(block.dev.kind)
          color: block.online ? Commons.Color.accent : root.dim
          font.family: root.font
          font.pixelSize: Style.font.icon
          MouseArea { id: iconMouse; anchors.fill: parent; hoverEnabled: true; acceptedButtons: Qt.NoButton }
          PanelToolTip {
            visible: iconMouse.containsMouse
            text: root.deviceKindLabel(block.dev) + "\n" + root.statusExplain(block.dev)
            fontFamily: root.font
          }
        }
        Text {
          textFormat: Text.PlainText
          id: deviceName
          visible: !block.editing
          anchors.left: kindIcon.right
          anchors.leftMargin: Style.space(6)
          anchors.right: badges.left
          anchors.rightMargin: Style.space(4)
          anchors.verticalCenter: parent.verticalCenter
          elide: Text.ElideRight
          text: block.dev.name
          color: block.online ? root.fg : root.dim
          font.family: root.font
          font.pixelSize: Style.font.body
          font.bold: block.online
          font.italic: block.dev.hidden === true
        }
        Item {
          visible: block.editing
          anchors.left: kindIcon.right
          anchors.leftMargin: Style.space(6)
          anchors.right: deviceIp.left
          anchors.rightMargin: Style.space(8)
          anchors.verticalCenter: parent.verticalCenter
          height: nameField.implicitHeight
          KeyTextField {
            id: nameField
            radius: root.corners.control
            anchors.fill: parent
            maximumLength: 40
            placeholderText: block.dev.auto_name || root.t("deviceName")
            foreground: root.fg
            verticalPadding: Style.space(2)
            font: Qt.font({ family: root.font, pixelSize: Style.font.body })
            onAccepted: root.finishRename(block.dev, nameField.text)
            Keys.onPressed: function(event) {
              if (event.key === Qt.Key_Escape) {
                root.finishRename(null, null)
                event.accepted = true
              }
            }
          }
        }
        Row {
          id: badges
          visible: !block.editing
          anchors.right: deviceIp.left
          anchors.rightMargin: Style.space(6)
          anchors.verticalCenter: parent.verticalCenter
          spacing: Style.space(4)
          Text {
            visible: block.dev.new === true
            textFormat: Text.PlainText
            text: root.t("newBadge")
            color: Commons.Color.accent
            font.family: root.font
            font.pixelSize: Style.font.caption
            font.bold: true
          }
          Text {
            visible: block.dev.pinned === true
            textFormat: Text.PlainText
            text: root.glyph(0xF0403)
            color: root.dim
            font.family: root.font
            font.pixelSize: Style.font.caption
          }
          Text {
            id: webIcon
            visible: block.webUrl !== ""
            textFormat: Text.PlainText
            text: root.glyph(0xF059F)
            color: webMouse.containsMouse ? Commons.Color.accent : root.fg
            font.family: root.font
            font.pixelSize: Style.font.caption
            MouseArea {
              id: webMouse
              anchors.fill: parent
              anchors.margins: -Style.space(4)
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: root.openWeb(block.webUrl)
            }
            PanelToolTip { visible: webMouse.containsMouse; text: root.t("openUrl", [block.webUrl]); fontFamily: root.font }
          }
        }
        Text {
          textFormat: Text.PlainText
          id: deviceIp
          anchors.right: copyIcon.left
          anchors.rightMargin: Style.space(6)
          anchors.verticalCenter: parent.verticalCenter
          text: block.copied ? root.t("copiedClipboard") : root.deviceRightLabel(block.dev)
          color: (block.dev.is_gateway || block.dev.is_self)
            ? Commons.Color.accent
            : (block.online ? root.fg : root.dim)
          font.family: root.font
          font.pixelSize: Style.font.caption
        }
        Text {
          textFormat: Text.PlainText
          id: copyIcon
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          // No `width` binding: deriving it from visible/implicitWidth loops; empty text keeps it narrow.
          text: String(block.dev.ip || "") === "" ? "" : block.copied ? root.glyph(0xF012C) : root.glyph(0xF018F)
          color: block.copied || copyMouse.containsMouse ? Commons.Color.accent : root.dim
          font.family: root.font
          font.pixelSize: Style.font.caption

          MouseArea {
            id: copyMouse
            anchors.fill: parent
            anchors.margins: -Style.space(4)
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
              if (root.copyIp(block.dev.ip)) {
                block.copied = true
                copiedTimer.restart()
              }
            }
          }
          PanelToolTip { visible: copyMouse.containsMouse && !block.copied; text: root.t("copyIp"); fontFamily: root.font }
        }
      }

      Text {
        textFormat: Text.PlainText
        visible: text !== ""
        width: parent.width
        leftPadding: Style.space(24)
        elide: Text.ElideRight
        text: block.editing ? root.t("editHint") : root.deviceSubtitle(block.dev)
        color: root.dim
        font.family: root.font
        font.pixelSize: Style.font.caption
      }

      // Expanded details: what the device is, in plain words, plus actions.
      Column {
        visible: block.expanded
        width: parent.width
        leftPadding: Style.space(24)
        topPadding: Style.space(4)
        bottomPadding: Style.space(2)
        spacing: Style.space(3)

        Text {
          textFormat: Text.PlainText
          width: parent.width - parent.leftPadding
          wrapMode: Text.WordWrap
          text: root.statusExplain(block.dev)
          color: root.fg
          font.family: root.font
          font.pixelSize: Style.font.caption
        }
        Repeater {
          model: [
            [root.t("dConnectedVia"), block.dev.mesh && block.dev.mesh.via && !block.dev.is_gateway ? block.dev.mesh.via : ""],
            [root.t("dConnection"), root.meshDetail(block.dev)],
            [root.t("dMaker"), block.dev.vendor === "Private MAC"
              ? root.t("dMakerHidden") : block.dev.vendor],
            [root.t("dModel"), block.dev.model],
            [root.t("dAutoName"), block.dev.custom_name ? block.dev.auto_name : ""],
            [root.t("dNetworkName"), block.dev.hostname && block.dev.hostname !== block.dev.name ? block.dev.hostname : ""],
            [root.t("dIp"), block.dev.ip],
            [root.t("dMac"), block.dev.mac]
          ].filter(function(item) { return item[1] })
          delegate: Text {
            required property var modelData
            textFormat: Text.PlainText
            width: parent ? parent.width - Style.space(24) : 0
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            text: modelData[0] + ":  " + modelData[1]
            color: root.dim
            font.family: root.font
            font.pixelSize: Style.font.caption
          }
        }
        Flow {
          width: parent.width - parent.leftPadding
          topPadding: Style.space(3)
          spacing: Style.space(12)
          LinkAction {
            visible: block.dev.can_edit === true && !block.editing
            icon: root.glyph(0xF03EB)
            label: root.t("rename")
            onActivated: root.startRename(block.dev)
          }
          LinkAction {
            visible: block.editing
            icon: root.glyph(0xF012C)
            label: root.t("save")
            onActivated: root.finishRename(block.dev, nameField.text)
          }
          LinkAction {
            visible: block.dev.can_edit === true && !block.dev.is_gateway && !block.dev.is_self && !block.editing
            icon: root.glyph(block.dev.pinned ? 0xF0404 : 0xF0403)
            label: block.dev.pinned ? root.t("unpin") : root.t("pinTop")
            onActivated: root.deviceCommand("pin", block.dev, { on: !block.dev.pinned })
          }
          LinkAction {
            visible: block.dev.can_edit === true && !block.dev.is_gateway && !block.dev.is_self && !block.editing
            icon: root.glyph(block.dev.hidden ? 0xF0208 : 0xF0209)
            label: block.dev.hidden ? root.t("show") : root.t("hide")
            onActivated: {
              root.deviceCommand("hide", block.dev, { on: !block.dev.hidden })
              if (!block.dev.hidden) root.expandedKey = ""
            }
          }
          LinkAction {
            visible: block.webUrl !== "" && !block.editing
            icon: root.glyph(0xF059F)
            label: root.t("openWeb")
            onActivated: root.openWeb(block.webUrl)
          }
          LinkAction {
            visible: block.dev.new === true && !block.editing
            icon: root.glyph(0xF05E0)
            label: root.t("itsMine")
            onActivated: root.deviceCommand("known", block.dev, { on: true })
          }
        }
        Text {
          visible: block.dev.can_edit !== true
          textFormat: Text.PlainText
          width: parent.width - parent.leftPadding
          wrapMode: Text.WordWrap
          text: root.t("noMac")
          color: root.dim
          font.family: root.font
          font.pixelSize: Style.font.caption
        }
      }
    }

    MouseArea {
      id: rowMouse
      // Below the rows so the icons' and actions' own MouseAreas get their clicks.
      z: -1
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: {
        if (block.editing) return
        root.editingKey = ""
        root.expandedKey = block.expanded ? "" : block.key
        if (root.expandedKey !== "") Qt.callLater(function() { root.ensureVisible(block) })
      }
    }
  }

  // Collapsible group header in the grouped view.
  component GroupHeader: Item {
    id: header
    property var group: ({})
    height: headerRow.implicitHeight + Style.space(8)
    Rectangle {
      anchors.fill: parent
      radius: root.corners.control
      color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, headerMouse.containsMouse ? 0.10 : 0.05)
    }
    Item {
      id: headerRow
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(4)
      anchors.rightMargin: Style.space(6)
      implicitHeight: Math.max(groupTitle.implicitHeight, groupIcon.implicitHeight)
      Text {
        id: groupIcon
        textFormat: Text.PlainText
        anchors.verticalCenter: parent.verticalCenter
        width: Style.space(18)
        horizontalAlignment: Text.AlignHCenter
        text: root.glyph(header.group.icon || 0xF0625)
        color: header.group.online > 0 ? Commons.Color.accent : root.dim
        font.family: root.font
        font.pixelSize: Style.font.icon
      }
      Text {
        id: groupTitle
        textFormat: Text.PlainText
        anchors.left: groupIcon.right
        anchors.leftMargin: Style.space(6)
        anchors.right: groupCount.left
        anchors.rightMargin: Style.space(8)
        anchors.verticalCenter: parent.verticalCenter
        elide: Text.ElideRight
        text: (header.group.title || "") + (header.group.detail ? "  ·  " + header.group.detail : "")
        color: root.fg
        font.family: root.font
        font.pixelSize: Style.font.bodySmall
        font.bold: true
      }
      Text {
        id: groupCount
        textFormat: Text.PlainText
        anchors.right: chevron.left
        anchors.rightMargin: Style.space(8)
        anchors.verticalCenter: parent.verticalCenter
        text: (header.group.hasNew ? root.t("newBadge") + "  " : "") + header.group.count + (header.group.online !== header.group.count
          ? " · " + root.t("onlineN", [header.group.online]) : "")
        color: header.group.hasNew ? Commons.Color.accent : root.dim
        font.family: root.font
        font.pixelSize: Style.font.caption
      }
      Text {
        id: chevron
        textFormat: Text.PlainText
        anchors.right: parent.right
        anchors.verticalCenter: parent.verticalCenter
        text: root.glyph(header.group.collapsed ? 0xF0142 : 0xF0140)
        color: root.dim
        font.family: root.font
        font.pixelSize: Style.font.caption
      }
    }
    MouseArea {
      id: headerMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: root.toggleGroup(header.group.id)
    }
  }
  // Four signal bars coloured like the bar widget's signal levels; -1 hides them.
  component SignalBars: Row {
    id: bars
    property real quality: -1
    visible: quality >= 0
    spacing: Style.space(2)
    Repeater {
      model: 4
      delegate: Rectangle {
        required property int index
        y: Style.space(13) - height  // bottom-aligned without anchoring before a parent exists
        width: Style.space(3)
        height: Style.space(4 + index * 3)
        radius: Math.min(root.corners.small, 1)
        readonly property bool lit: bars.quality > [0, 30, 50, 70][index] || (index === 0 && bars.quality >= 0)
        color: lit ? root.signalColor(bars.quality / 100) : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.18)
      }
    }
  }

  // One row of the network map with its tree connectors.
  component MapRow: Item {
    id: mapRow
    property var row: ({})
    readonly property real indent: Style.space(22)
    readonly property int depth: row.depth || 0
    readonly property var dev: row.type === "device" ? row.dev : (row.node && row.node.dev ? row.node.dev : null)
    readonly property bool online: row.type === "device" ? (dev && dev.online === true)
      : row.type === "group" ? row.online > 0 : true
    readonly property color lineColor: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.28)
    height: Style.space(row.type === "group" || row.type === "device" ? 26 : 32)

    // Vertical connectors of the ancestors that still have siblings below.
    Repeater {
      model: mapRow.row.guides || []
      delegate: Rectangle {
        required property var modelData
        required property int index
        visible: modelData === true
        x: index * mapRow.indent + mapRow.indent / 2
        width: 1
        height: mapRow.height
        color: mapRow.lineColor
      }
    }
    // Own elbow: down from the parent, then across to the node.
    Rectangle {
      visible: mapRow.depth > 0
      x: (mapRow.depth - 1) * mapRow.indent + mapRow.indent / 2
      width: 1
      height: mapRow.row.last ? mapRow.height / 2 : mapRow.height
      color: mapRow.lineColor
    }
    Rectangle {
      visible: mapRow.depth > 0
      x: (mapRow.depth - 1) * mapRow.indent + mapRow.indent / 2
      y: mapRow.height / 2
      width: mapRow.indent / 2 + Style.space(2)
      height: 1
      color: mapRow.lineColor
    }

    Rectangle {
      id: nodeHover
      x: mapRow.depth * mapRow.indent
      width: parent.width - x
      height: parent.height
      radius: root.corners.control
      color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.07)
      visible: nodeMouse.containsMouse
    }
    Rectangle {
      id: nodeIcon
      x: mapRow.depth * mapRow.indent + Style.space(2)
      anchors.verticalCenter: parent.verticalCenter
      readonly property bool big: mapRow.row.type === "internet" || mapRow.row.type === "ap"
      width: Style.space(big ? 24 : 20)
      height: width
      radius: Math.min(root.corners.pill, width / 2)
      color: big ? Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.16) : "transparent"
      border.width: 1
      border.color: mapRow.online ? Commons.Color.accent : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.3)
      Text {
        anchors.centerIn: parent
        textFormat: Text.PlainText
        text: {
          var r = mapRow.row
          if (r.type === "internet") return root.glyph(0xF059F)
          if (r.type === "ap") return root.kindIcon("router")
          if (r.type === "group") return root.glyph(r.node.icon || 0xF0625)
          return root.kindIcon(mapRow.dev ? mapRow.dev.kind : "unknown")
        }
        color: mapRow.online ? Commons.Color.accent : root.dim
        font.family: root.font
        font.pixelSize: nodeIcon.big ? Style.font.body : Style.font.caption
      }
    }
    Text {
      id: nodeLabel
      textFormat: Text.PlainText
      anchors.left: nodeIcon.right
      anchors.leftMargin: Style.space(6)
      anchors.right: nodeRight.left
      anchors.rightMargin: Style.space(8)
      anchors.verticalCenter: parent.verticalCenter
      elide: Text.ElideRight
      text: {
        var r = mapRow.row
        if (r.type === "internet") return root.t("internet") + (root.vpn ? "  ·  " + root.t("viaN", [root.vpn.name]) : "")
        if (r.type === "ap") return (r.node.title || root.t("kRouter"))
          + (r.node.dev && r.node.dev.is_gateway && r.node.dev.model ? "  ·  " + r.node.dev.model : "")
        if (r.type === "group") return r.node.title + "  ·  " + root.tn("devices", r.count)
        return mapRow.dev ? mapRow.dev.name : ""
      }
      color: mapRow.online ? root.fg : root.dim
      font.family: root.font
      font.pixelSize: mapRow.row.type === "device" ? Style.font.caption : Style.font.bodySmall
      font.bold: mapRow.row.type !== "device" || (mapRow.dev && mapRow.dev.is_self)
    }
    Row {
      id: nodeRight
      z: 1  // above the row's click area, so the copy icon gets its own clicks
      anchors.right: parent.right
      anchors.rightMargin: Style.space(4)
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(6)
      Text {
        textFormat: Text.PlainText
        anchors.verticalCenter: parent.verticalCenter
        visible: text !== ""
        text: {
          var d = mapRow.dev
          if (mapRow.row.type === "device" && d && d.new) return root.t("newBadge")
          return ""
        }
        color: Commons.Color.accent
        font.family: root.font
        font.pixelSize: Style.font.caption
        font.bold: true
      }
      Text {
        textFormat: Text.PlainText
        anchors.verticalCenter: parent.verticalCenter
        visible: text !== ""
        text: {
          var d = mapRow.dev
          if (mapRow.row.type !== "device" || !d) return ""
          if (d.mesh && d.mesh.rate_mbps) return d.mesh.rate_mbps + " Mbit/s"
          if (!d.online) return root.statusWord(d)
          return ""
        }
        color: root.dim
        font.family: root.font
        font.pixelSize: Style.font.caption
      }
      SignalBars {
        anchors.verticalCenter: parent.verticalCenter
        quality: mapRow.row.type === "device" && mapRow.dev && mapRow.dev.mesh ? root.signalQuality(mapRow.dev.mesh.signal_dbm) : -1
      }
      // Copy the IP address, as on the Devices page (copyIp(): wl-copy through stdin).
      Text {
        id: mapCopy
        textFormat: Text.PlainText
        anchors.verticalCenter: parent.verticalCenter
        visible: mapRow.dev !== null && String(mapRow.dev.ip || "") !== "" && mapRow.row.type !== "group"
        property bool copied: false
        text: root.glyph(copied ? 0xF012C : 0xF018F)
        color: copied || mapCopyMouse.containsMouse ? Commons.Color.accent : root.dim
        font.family: root.font
        font.pixelSize: Style.font.caption
        Timer { id: mapCopyTimer; interval: 1400; onTriggered: mapCopy.copied = false }
        MouseArea {
          id: mapCopyMouse
          anchors.fill: parent
          anchors.margins: -Style.space(4)
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: if (root.copyIp(mapRow.dev.ip)) { mapCopy.copied = true; mapCopyTimer.restart() }
        }
        PanelToolTip {
          visible: mapCopyMouse.containsMouse
          text: mapCopy.copied ? root.t("copied") : root.t("copyIpN", [mapRow.dev ? mapRow.dev.ip : ""])
          fontFamily: root.font
        }
      }
      Text {
        textFormat: Text.PlainText
        anchors.verticalCenter: parent.verticalCenter
        visible: mapRow.row.type === "group" || (mapRow.row.type === "ap" && mapRow.dev && !mapRow.dev.is_gateway)
        text: root.glyph(mapRow.row.collapsed ? 0xF0142 : 0xF0140)
        color: root.dim
        font.family: root.font
        font.pixelSize: Style.font.caption
      }
    }
    MouseArea {
      id: nodeMouse
      anchors.fill: nodeHover
      hoverEnabled: true
      enabled: mapRow.row.type !== "internet"
      cursorShape: Qt.PointingHandCursor
      onClicked: {
        var r = mapRow.row
        if (r.type === "device" && mapRow.dev) root.openDevice(mapRow.dev)
        else if (r.type === "group" || (r.type === "ap" && mapRow.dev && !mapRow.dev.is_gateway)) root.toggleGroup(r.id)
        else if (r.type === "ap" && mapRow.dev) root.openDevice(mapRow.dev)
      }
    }
    PanelToolTip {
      visible: nodeMouse.containsMouse && mapRow.row.type === "device" && mapRow.dev !== null
      fontFamily: root.font
      text: mapRow.dev ? mapRow.dev.name + "\n" + root.deviceKindLabel(mapRow.dev) + "  ·  " + mapRow.dev.ip
        + (root.meshDetail(mapRow.dev) ? "\n" + root.meshDetail(mapRow.dev) : "") + "\n" + root.t("clickDetails") : ""
    }
  }

  // Page switch under the title: Devices | Map | Monitor | Setup.
  component PageTab: Item {
    id: tab
    property string label: ""
    property int icon: 0
    property bool active: false
    signal activated()
    implicitWidth: tabText.implicitWidth + Style.space(10)
    implicitHeight: tabText.implicitHeight + Style.space(10)
    Text {
      id: tabText
      anchors.centerIn: parent
      textFormat: Text.PlainText
      text: root.glyph(tab.icon) + " " + tab.label
      color: tab.active ? Commons.Color.accent : (tabMouse.containsMouse ? root.fg : root.dim)
      font.family: root.font
      font.pixelSize: Style.font.bodySmall
      font.bold: tab.active
    }
    Rectangle {
      anchors.bottom: parent.bottom
      anchors.horizontalCenter: parent.horizontalCenter
      width: parent.width - Style.space(6)
      height: Style.space(2)
      radius: Math.min(root.corners.small, 1)
      color: Commons.Color.accent
      visible: tab.active
    }
    MouseArea {
      id: tabMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: tab.activated()
    }
  }

  // Compact selectable chip for Network Monitor sub-views and filters.
  component FilterChip: Item {
    id: chip
    property string label: ""
    property bool selected: false
    signal activated()
    implicitWidth: chipLabel.implicitWidth + Style.space(14)
    implicitHeight: chipLabel.implicitHeight + Style.space(8)
    Rectangle {
      anchors.fill: parent
      radius: root.corners.control
      color: chip.selected
        ? Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.20)
        : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, chipMouse.containsMouse ? 0.11 : 0.05)
      border.width: 1
      border.color: chip.selected
        ? Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.7)
        : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.14)
    }
    Text {
      id: chipLabel
      anchors.centerIn: parent
      textFormat: Text.PlainText
      text: chip.label
      color: chip.selected ? Commons.Color.accent : root.fg
      font.family: root.font
      font.pixelSize: Style.font.caption
      font.bold: chip.selected
    }
    MouseArea {
      id: chipMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: chip.activated()
    }
  }

  // One live connection row on the Network Monitor page; click expands details.
  component ConnRow: Item {
    id: crow
    property var conn: ({})
    readonly property string cid: root.connId(conn)
    readonly property bool expanded: cid !== "" && root.netmonExpandedKey === cid
    readonly property string proto: root.connProto(conn).toUpperCase()
    readonly property string st: String(conn.state || "")
    readonly property string procName: String(conn.process || "")
    readonly property string appLabel: procName !== "" ? procName : root.t("systemProc")
    readonly property string remoteHostOrIp: root.preferredRemote(conn)
    readonly property int rport: Number(conn.remote_port || 0)
    readonly property int lport: Number(conn.local_port || 0)
    readonly property string endpoint: st === "LISTEN"
      ? (":" + lport)
      : (rport > 0 ? (remoteHostOrIp + ":" + rport) : remoteHostOrIp)
    readonly property real rxRate: Number(conn.rx_rate || 0)
    readonly property real txRate: Number(conn.tx_rate || 0)
    readonly property real totalRate: rxRate + txRate
    readonly property real rxBytes: Number(conn.rx_bytes || 0)
    readonly property real txBytes: Number(conn.tx_bytes || 0)
    readonly property string rightLabel: totalRate > 0
      ? ("↓ " + root.formatRate(rxRate) + " · ↑ " + root.formatRate(txRate))
      : ((rxBytes + txBytes) > 0
        ? (root.formatBytes(rxBytes) + " / " + root.formatBytes(txBytes))
        : st)
    readonly property color dotColor: st === "ESTABLISHED"
      ? root.signalColor(0.85)
      : (st === "LISTEN" ? Commons.Color.accent
        : ((st === "SYN_SENT" || st === "SYN_RECV") ? root.signalColor(0.55) : root.dim))
    readonly property string subtitle: {
      var scopeTag = conn.scope === "external" ? "EXT" : (conn.scope === "lan" ? "LAN" : "LO")
      var parts = [proto, st, scopeTag]
      if (conn.service) parts.push(String(conn.service))
      if (conn.rtt_ms !== null && conn.rtt_ms !== undefined && Number(conn.rtt_ms) > 0)
        parts.push(Number(conn.rtt_ms).toFixed(1) + " ms")
      return parts.join("  ·  ")
    }
    height: connCol.implicitHeight + Style.space(8)

    Rectangle {
      anchors.fill: parent
      radius: root.corners.control
      color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, crow.expanded ? 0.08 : (connMouse.containsMouse ? 0.07 : 0.03))
      border.width: crow.expanded ? 1 : 0
      border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.14)
    }

    Column {
      id: connCol
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.leftMargin: Style.space(6)
      anchors.rightMargin: Style.space(6)
      y: Style.space(4)
      spacing: Style.space(2)

      Item {
        width: parent.width
        height: Math.max(connApp.implicitHeight, connRight.implicitHeight)
        Rectangle {
          id: connDot
          anchors.left: parent.left
          anchors.verticalCenter: parent.verticalCenter
          width: Style.space(7)
          height: width
          radius: Math.min(root.corners.pill, width / 2)
          color: crow.dotColor
        }
        Text {
          id: connApp
          textFormat: Text.PlainText
          anchors.left: connDot.right
          anchors.leftMargin: Style.space(6)
          anchors.verticalCenter: parent.verticalCenter
          text: crow.appLabel
          color: root.fg
          font.family: root.font
          font.pixelSize: Style.font.caption
          font.bold: true
        }
        Text {
          id: connEp
          textFormat: Text.PlainText
          anchors.left: connApp.right
          anchors.leftMargin: Style.space(6)
          anchors.right: connRight.left
          anchors.rightMargin: Style.space(6)
          anchors.verticalCenter: parent.verticalCenter
          elide: Text.ElideRight
          text: crow.endpoint
          color: root.dim
          font.family: root.font
          font.pixelSize: Style.font.caption
        }
        Text {
          id: connRight
          textFormat: Text.PlainText
          anchors.right: parent.right
          anchors.verticalCenter: parent.verticalCenter
          text: crow.rightLabel
          color: crow.totalRate > 0 ? Commons.Color.accent : root.dim
          font.family: root.font
          font.pixelSize: Style.font.caption
        }
      }

      Text {
        textFormat: Text.PlainText
        width: parent.width
        leftPadding: Style.space(13)
        elide: Text.ElideRight
        text: crow.subtitle
        color: root.dim
        font.family: root.font
        font.pixelSize: Style.font.caption
      }

      Column {
        id: connDetails
        visible: crow.expanded
        width: parent.width
        leftPadding: Style.space(13)
        topPadding: Style.space(4)
        bottomPadding: Style.space(2)
        spacing: Style.space(3)

        readonly property string localEp: String(crow.conn.local_ip || "") + ":" + crow.lport
        readonly property string remoteEp: crow.rport > 0
          ? (String(crow.conn.remote_ip || "") + ":" + crow.rport)
          : String(crow.conn.remote_ip || "")

        Repeater {
          model: [
            [root.t("connLocal"), connDetails.localEp],
            [root.t("connRemote"), connDetails.remoteEp],
            [root.t("connHost"), crow.conn.remote_host && crow.conn.remote_host !== crow.conn.remote_ip ? String(crow.conn.remote_host) : ""],
            ["PID", crow.conn.pid && Number(crow.conn.pid) > 0 ? String(crow.conn.pid) : ""],
            [root.t("connCommand"), String(crow.conn.cmdline || "")],
            [root.t("connTraffic"), (crow.rxBytes + crow.txBytes) > 0 ? ("↓ " + root.formatBytes(crow.rxBytes) + " · ↑ " + root.formatBytes(crow.txBytes)) : ""]
          ].filter(function(item) { return item[1] !== "" })
          delegate: Text {
            required property var modelData
            textFormat: Text.PlainText
            width: parent ? parent.width - Style.space(13) : 0
            wrapMode: Text.WrapAtWordBoundaryOrAnywhere
            text: modelData[0] + ":  " + modelData[1]
            color: root.dim
            font.family: root.font
            font.pixelSize: Style.font.caption
          }
        }
        Flow {
          width: parent.width - Style.space(13)
          topPadding: Style.space(2)
          spacing: Style.space(12)
          LinkAction {
            visible: crow.procName !== ""
            icon: root.glyph(0xF0349)
            label: root.t("filterByApp")
            onActivated: root.filterByApp(crow.procName)
          }
          LinkAction {
            readonly property bool copiedNow: root.netmonCopiedKey === crow.cid
            icon: root.glyph(copiedNow ? 0xF012C : 0xF018F)
            label: copiedNow ? root.t("copied") : root.t("copyEndpoint")
            onActivated: root.copyConnEndpoint(crow.cid, crow.st === "LISTEN"
              ? (String(crow.conn.local_ip || "") + ":" + crow.lport)
              : crow.endpoint)
          }
        }
      }
    }

    MouseArea {
      id: connMouse
      z: -1
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: root.netmonExpandedKey = crow.expanded ? "" : crow.cid
    }
  }

  Component { id: groupHeaderComponent; GroupHeader {} }
  Component { id: deviceRowComponent; DeviceRow {} }

  // See-through with the window style (Theme Manager → Settings).
  PopupGlass { inside: shot; active: panel.open }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(430))
    // At least as tall as the screenshot note overlay while it shows.
    contentHeight: panel.fittedContentHeight(Math.max(column.implicitHeight, shot.neededHeight))

    // F12: a screenshot of this panel into ~/Pictures/WLAN Monitor, then an optional note
    // (PanelShot.qml, shared; the keys the catcher leaves alone come up to it).
    PanelShot {
      id: shot
      anchors.fill: parent
      pluginId: "ubruckhaus.wlan-monitor"
      folderName: "WLAN Monitor"
      active: root.screenshotKey
      panelOpen: root.opened
      returnFocus: keyCatcher
      lang: root.lang
      fg: root.fg
      dim: root.dim
      fontFamily: root.font
      corners: root.corners

        PanelKeyCatcher {
        id: keyCatcher
        anchors.fill: parent
        // Text fields need every key while they have focus.
        // Typing in the note overlay must reach its field.
        blocked: shot.overlayOpen || searchField.activeFocus || root.editingKey !== ""
          || fritzUser.activeFocus || fritzPassword.activeFocus
          || netmonSearchField.activeFocus || wifiSearchField.activeFocus || wifiPasswordField.activeFocus
          || devicesViewDrop.popupOpen || mapViewDrop.popupOpen
        onCloseRequested: {
          if (root.infoPageOpen) root.infoPageOpen = false
          else if (root.settingsOpen) root.settingsOpen = false
          else if (root.wifiFormOpen) root.closeWifiForm()
          else if (root.fritzFormOpen) root.closeFritzForm()
          else if (root.activePage === "monitor" && root.netmonIsFiltered) root.clearNetmonFilters()
          else if (root.activePage === "setup" && root.wifiSearchText !== "") wifiSearchField.clear()
          else if (root.activePage === "devices" && root.filterText !== "") searchField.clear()
          else root.close()
        }
        onTabRequested: function(direction) { root.switchPanel(direction) }
        onTextKey: function(t) {
          if (t === "\b" && root.infoPageOpen) { root.infoPageOpen = false; return }
          if (t === "\b" && root.settingsOpen) { root.settingsOpen = false; return }
          if (t === "/" && !root.settingsOpen && !root.infoPageOpen) {
            if (root.activePage === "devices" && root.showSearch) searchField.forceActiveFocus()
            else if (root.activePage === "monitor" && root.netmonView !== "interfaces") netmonSearchField.forceActiveFocus()
            else if (root.activePage === "setup" && wifiSearchField.visible) wifiSearchField.forceActiveFocus()
          }
        }

        Flickable {
          id: scroller
          anchors.fill: parent
          contentWidth: width
          contentHeight: column.implicitHeight
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          interactive: contentHeight > height

          Column {
            id: column
            width: scroller.width
            spacing: Style.space(10)

            PanelHero {
              foreground: root.fg
              fontFamily: root.font
              title: "WLAN Monitor"
              meta: root.stats.active && root.link.ssid
                ? root.link.ssid
                  + (root.link.band ? " · " + root.link.band : "")
                  + (root.link.width_mhz ? " (" + root.link.width_mhz + " MHz)" : "")
                : root.t("notConnected")
              detail: root.stats.active ? root.t("onlineN", [root.onlineCount]) : ""
              trailingControl: Component {
                // As tall as the hero text, with the gear centred on the title
                // row so it lines up with the "N online" pill.
                Item {
                  visible: !root.settingsOpen && !root.infoPageOpen
                  implicitWidth: gearButton.x + gearButton.width
                  implicitHeight: heroTitle.implicitHeight + Style.space(2) + heroMeta.implicitHeight
                  Text { id: heroTitle; visible: false; textFormat: Text.PlainText; text: "W"; font.family: root.font; font.pixelSize: Style.font.title; font.bold: true }
                  Text { id: heroBody; visible: false; textFormat: Text.PlainText; text: "W"; font.family: root.font; font.pixelSize: Style.font.body; font.bold: true }
                  Text { id: heroMeta; visible: false; textFormat: Text.PlainText; text: "W"; font.family: root.font; font.pixelSize: Style.font.caption; font.bold: true }
                  Button {
                    id: infoButton
                    radius: root.corners.control
                    x: 0
                    y: gearButton.y
                    height: gearButton.height
                    width: height
                    iconText: "\u{F02FC}"
                    bordered: true
                    iconSize: Style.font.body
                    horizontalPadding: Style.space(4)
                    verticalPadding: Style.space(1)
                    foreground: root.fg
                    fontFamily: root.font
                    tooltipText: root.t("information")
                    onClicked: root.infoPageOpen = true
                  }
                  Button {
                    id: gearButton
                    radius: root.corners.control
                    x: infoButton.x + infoButton.width + Style.space(6)
                    y: Math.round((heroTitle.implicitHeight - height) / 2)
                    // The pill is its body text plus Style.space(4); a square gear of that height.
                    height: heroBody.implicitHeight + Style.space(4)
                    width: height
                    iconText: "\udb81\udc93"
                    bordered: true
                    // Same size as the "N online" pill next to the title.
                    iconSize: Style.font.body
                    horizontalPadding: Style.space(4)
                    verticalPadding: Style.space(1)
                    foreground: root.fg
                    fontFamily: root.font
                    tooltipText: root.t("settings")
                    onClicked: root.settingsOpen = true
                  }
                }
              }
              iconComponent: Component {
                Text {
                  textFormat: Text.PlainText
                  text: root.glyph(0xF043B)
                  color: root.stats.active ? Commons.Color.accent : root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.display
                }
              }
            }


            // ---------------------------------------------------------------- information
            Column {
              visible: root.infoPageOpen
              width: parent.width
              spacing: Style.space(12)

              PanelSeparator { width: parent.width; foreground: root.fg }

              Row {
                spacing: Style.space(12)
                Button {
                  radius: root.corners.control
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.t("back") + " · \u232b"
                  iconText: "\udb80\udc4d"
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  tooltipText: root.t("backTip")
                  onClicked: root.infoPageOpen = false
                }
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  textFormat: Text.PlainText
                  text: root.t("information").toUpperCase()
                  color: root.fg
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  font.letterSpacing: 1
                }
              }
              PanelSeparator { width: parent.width; foreground: root.fg }

              MorePlugins {
                tileRadius: root.corners.control
                cardRadius: root.corners.radius
                width: parent.width
                separated: false
                ownId: "ubruckhaus.wlan-monitor"
                // The list from the marketplace's catalog when the page shows (plugin_catalog.py).
                catalogScript: decodeURIComponent(Qt.resolvedUrl("plugin_catalog.py").toString().replace(/^file:\/\//, ""))
                lang: root.lang
                fg: root.fg
                dim: root.dim
                fontFamily: root.font
                onOpened: root.close()
              }
            }

            // ---------------------------------------------------------------- settings
            Column {
              visible: root.settingsOpen
              width: parent.width
              spacing: Style.space(12)

              PanelSeparator { width: parent.width; foreground: root.fg }

              Row {
                spacing: Style.space(12)
                Button {
                  radius: root.corners.control
                  anchors.verticalCenter: parent.verticalCenter
                  text: root.t("back") + " · \u232b"
                  iconText: "\udb80\udc4d"
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  tooltipText: root.t("backTip")
                  onClicked: root.settingsOpen = false
                }
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  textFormat: Text.PlainText
                  text: root.t("settings").toUpperCase()
                  color: root.fg
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                  font.bold: true
                  font.letterSpacing: 1
                }
              }
              PanelSeparator { width: parent.width; foreground: root.fg }

              Row {
                spacing: Style.space(10)
                Text {
                  id: languageLabel
                  anchors.verticalCenter: parent.verticalCenter
                  width: root.settingsLabelWidth
                  textFormat: Text.PlainText
                  text: root.t("language")
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }
                CompactDropdown {
                  id: languagePicker
                  popupRadius: root.corners.radius
                  controlRadius: root.corners.control
                  anchors.verticalCenter: parent.verticalCenter
                  // Wide enough for the longest option, plus padding and the chevron.
                  width: fitWidth
                  fontSize: Style.font.caption
                  rowHeight: languageLabel.implicitHeight + Style.space(6)
                  popupRowHeight: languageLabel.implicitHeight + Style.space(8)
                  showLabel: false
                  fontFamily: root.font
                  options: [{ value: "auto", label: root.t("systemLanguage", [I18n.languageName(root.systemLang)]) }]
                    .concat(I18n.LANGUAGES.map(function(l) { return { value: l.code, label: l.name } }))
                  value: root.languageSetting
                  // Picking cuts the value binding inside the dropdown; restore it.
                  onChanged: function(picked) {
                    if (root.hostWidget) root.hostWidget.setLanguage(picked)
                    languagePicker.value = Qt.binding(function() { return root.languageSetting })
                  }
                }
              }

              // Corners of the cards and controls; "Like windows" is Hyprland's rounding.
              Column {
                width: parent.width
                spacing: Style.space(4)
                Row {
                  spacing: Style.space(10)
                  Text {
                    id: cornersLabel
                    anchors.verticalCenter: parent.verticalCenter
                    width: root.settingsLabelWidth
                    textFormat: Text.PlainText
                    text: root.t("corners")
                    wrapMode: Text.WordWrap
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                  CompactDropdown {
                    id: cornersPicker
                    anchors.verticalCenter: parent.verticalCenter
                    width: fitWidth
                    fontSize: Style.font.caption
                    rowHeight: cornersLabel.implicitHeight + Style.space(6)
                    popupRowHeight: cornersLabel.implicitHeight + Style.space(8)
                    controlRadius: root.corners.control
                    popupRadius: root.corners.radius
                    showLabel: false
                    fontFamily: root.font
                    options: Corners.options(root.t, Style.cornerRadius)
                    value: root.cornersSetting
                    onChanged: function(picked) {
                      if (root.hostWidget) root.hostWidget.setCorners(picked)
                      cornersPicker.value = Qt.binding(function() { return root.cornersSetting })
                    }
                  }
                }
                Text {
                  x: root.settingsLabelWidth + Style.space(10)
                  width: parent.width - x
                  textFormat: Text.PlainText
                  text: root.t("cornersHint")
                  wrapMode: Text.WordWrap
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }
              }

              // F12 saves a screenshot of this panel (PanelShot.qml); on by default.
              Column {
                width: parent.width
                spacing: Style.space(4)
                Item {
                  width: parent.width
                  height: Math.max(shotLabel.implicitHeight, shotToggle.implicitHeight)
                  Text {
                    id: shotLabel
                    anchors.verticalCenter: parent.verticalCenter
                    width: root.settingsLabelWidth
                    textFormat: Text.PlainText
                    text: root.t("shotKey")
                    wrapMode: Text.WordWrap
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                  ToggleSwitch {
                    id: shotToggle
                    x: root.settingsLabelWidth + Style.space(10)
                    anchors.verticalCenter: parent.verticalCenter
                    cursorRing: false
                    rounded: root.corners.pill > 0
                    checked: root.screenshotKey
                    foreground: root.fg
                    onToggled: if (root.hostWidget) root.hostWidget.setScreenshotKey(!root.screenshotKey)
                  }
                }
                Text {
                  x: root.settingsLabelWidth + Style.space(10)
                  width: parent.width - x
                  textFormat: Text.PlainText
                  text: root.t("shotKeyHint", ["WLAN Monitor"])
                  wrapMode: Text.WordWrap
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }
              }

              Item {
                visible: root.trusted
                width: parent.width
                height: alertsToggle.implicitHeight
                Text {
                  anchors.verticalCenter: parent.verticalCenter
                  width: root.settingsLabelWidth
                  textFormat: Text.PlainText
                  text: root.t("newAlerts")
                  wrapMode: Text.WordWrap
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }
                ToggleSwitch {
                  id: alertsToggle
                  rounded: root.corners.pill > 0
                  x: root.settingsLabelWidth + Style.space(10)
                  anchors.verticalCenter: parent.verticalCenter
                  cursorRing: false
                  checked: root.alertsOn
                  foreground: root.fg
                  onToggled: if (root.hostWidget) root.hostWidget.sendJson({ cmd: "alerts", on: !root.alertsOn })
                }
              }
            }

            // ---------------------------------------------------------------- main view
            Column {
              visible: !root.settingsOpen && !root.infoPageOpen
              width: parent.width
              spacing: Style.space(10)

              Flow {
                width: parent.width
                spacing: Style.space(2)
                PageTab {
                  label: root.t("tabDevices")
                  icon: 0xF0279
                  active: root.activePage === "devices"
                  onActivated: root.setPage("devices")
                }
                PageTab {
                  label: root.t("tabMapShort")
                  icon: 0xF0003
                  active: root.activePage === "map"
                  onActivated: root.setPage("map")
                }
                PageTab {
                  label: root.t("tabMonitor")
                  icon: 0xF012A
                  active: root.activePage === "monitor"
                  onActivated: root.setPage("monitor")
                }
                PageTab {
                  label: root.t("tabSetup")
                  icon: 0xF05A9
                  active: root.activePage === "setup"
                  onActivated: root.setPage("setup")
                }
              }

              // A VPN blocks the home network: explain why everything looks idle, and how to fix it.
              Rectangle {
                visible: root.lanBlocked
                width: parent.width
                height: vpnColumn.implicitHeight + Style.space(14)
                radius: root.corners.radius
                readonly property color tint: root.hostWidget && root.hostWidget.vpnBlue ? root.hostWidget.vpnBlue : Commons.Color.accent
                color: Qt.rgba(tint.r, tint.g, tint.b, 0.14)
                border.width: 1
                border.color: Qt.rgba(tint.r, tint.g, tint.b, 0.6)
                Column {
                  id: vpnColumn
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.margins: Style.space(8)
                  spacing: Style.space(4)
                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.glyph(0xF099D) + "  " + root.t("vpnBlocks", [root.vpn ? root.vpn.name : root.t("aVpn")])
                    color: root.fg
                    font.family: root.font
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                  }
                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.t("vpnExplain") + " " + (root.vpn ? root.vpnHint.replace(/([^.])$/, "$1.") : "") + " " + root.t("disconnectVpn")
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                  LinkAction {
                    visible: root.vpnCommand !== ""
                    icon: root.glyph(root.vpnCopied ? 0xF012C : 0xF018F)
                    label: root.vpnCopied ? root.t("copied") : root.t("copyCommand", [root.vpnCommand])
                    onActivated: if (root.copyText(root.vpnCommand)) { root.vpnCopied = true; vpnCopiedTimer.restart() }
                  }
                }
              }

              // The FRITZ!Box login needs to be typed again (new certificate, changed password).
              Rectangle {
                visible: root.fritzNeedsLogin && !root.fritzFormOpen && !root.lanBlocked
                width: parent.width
                height: fritzColumn.implicitHeight + Style.space(14)
                radius: root.corners.radius
                readonly property color tint: Commons.Color.accent
                color: Qt.rgba(tint.r, tint.g, tint.b, 0.14)
                border.width: 1
                border.color: Qt.rgba(tint.r, tint.g, tint.b, 0.6)
                Column {
                  id: fritzColumn
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.margins: Style.space(8)
                  spacing: Style.space(4)
                  Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.glyph(0xF0026) + "  " + root.t(root.fritz.message_code || "fzCert", root.fritz.message_args || [])
                    color: root.fg
                    font.family: root.font
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                  }
                  LinkAction {
                    icon: root.glyph(0xF0306)
                    label: root.t("fritzReconnect")
                    onActivated: root.startFritzLogin()
                  }
                }
              }

              Column {
                id: devicesPage
                visible: root.activePage === "devices"
                width: parent.width
                spacing: column.spacing

                PanelSeparator { width: parent.width; foreground: root.fg }

                // Disconnected guidance card: explains Wi-Fi off vs not connected and offers 1-click actions.
                Rectangle {
                  visible: root.stats && root.stats.time !== undefined && root.stats.active !== true
                  width: parent.width
                  height: disconnectedCol.implicitHeight + Style.space(16)
                  radius: root.corners.radius
                  color: Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.12)
                  border.width: 1
                  border.color: Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.5)
                  Column {
                    id: disconnectedCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.margins: Style.space(8)
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      wrapMode: Text.WordWrap
                      text: root.glyph(0xF05A9) + "  " + root.t("notConnected")
                      color: root.fg
                      font.family: root.font
                      font.pixelSize: Style.font.bodySmall
                      font.bold: true
                    }
                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      wrapMode: Text.WordWrap
                      text: (root.hasWifiDevice && !root.wifiRadioOn) ? root.t("wifiOffHint") : root.t("disconnectedHint")
                      color: root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                    Flow {
                      width: parent.width
                      spacing: Style.space(8)
                      Button {
                        visible: root.hasWifiDevice && !root.wifiRadioOn
                        radius: root.corners.control
                        text: root.t("turnWifiOn")
                        iconText: root.glyph(0xF05A9)
                        bordered: true
                        foreground: root.fg
                        fontFamily: root.font
                        enabled: !root.wifiBusy
                        onClicked: root.toggleWifiRadio(true)
                      }
                      Button {
                        radius: root.corners.control
                        text: (root.hasWifiDevice && root.wifiRadioOn) ? root.t("connectWifi") : root.t("wifiSetup")
                        iconText: root.glyph(0xF05A9)
                        bordered: true
                        foreground: root.fg
                        fontFamily: root.font
                        onClicked: root.setPage("setup")
                      }
                    }
                  }
                }

                PanelSectionHeader { text: root.t("connection").toUpperCase(); foreground: root.fg; fontFamily: root.font }

                Item {
                  width: parent.width
                  height: ipText.height
                  Text {
                    textFormat: Text.PlainText
                    id: ipText
                    text: root.t("thisPc") + "  " + (root.link.ip || "—")
                    color: root.fg
                    font.family: root.font
                    font.pixelSize: Style.font.body
                    font.bold: true
                  }
                  Text {
                    textFormat: Text.PlainText
                    anchors.right: parent.right
                    anchors.baseline: ipText.baseline
                    text: root.link.gateway ? root.t("router") + "  " + root.link.gateway : ""
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                  MouseArea { id: ipMouse; anchors.fill: parent; hoverEnabled: true; acceptedButtons: Qt.NoButton }
                  PanelToolTip {
                    visible: ipMouse.containsMouse && root.stats.active === true
                    fontFamily: root.font
                    text: root.t("addressOn", [root.link.cidr || root.link.ip || "—", root.link.iface || "?"])
                      + (root.link.mac ? "\n" + root.t("macN", [root.link.mac]) : "")
                      + (root.link.domain ? "\n" + root.t("localDomain", [root.link.domain]) : "")
                  }
                }

                Meter {
                  visible: root.link.quality !== null && root.link.quality !== undefined
                  readonly property real sigFrac: Math.max(0, Math.min(1, Number(root.link.quality || 0) / 100))
                  label: root.t("signal") + "  ·  " + root.signalWord(root.link.quality)
                  value: (root.link.quality || 0) + " %"
                  fraction: sigFrac
                  fillColor: root.signalColor(sigFrac)
                  tip: (root.link.signal_dbm !== null && root.link.signal_dbm !== undefined ? root.link.signal_dbm + " dBm" : "")
                    + (root.link.channel ? "  ·  " + root.t("channelN", [root.link.channel]) : "")
                    + (root.link.tx_mbps ? "  ·  " + root.t("linkN", [root.link.tx_mbps + (root.link.rx_mbps ? " / " + root.link.rx_mbps : "")]) : "")
                    + "\n" + root.t("signalScale")
                    + "\n" + root.t("signalWeakTip")
                }

                Meter {
                  label: root.t("trafficNow")
                  value: "↓ " + root.formatRate(root.traffic.rx_rate) + "  ·  ↑ " + root.formatRate(root.traffic.tx_rate)
                  // Logarithmic-like visual activity bar up to ~10 MB/s
                  fraction: {
                    var totalRate = Number(root.traffic.rx_rate || 0) + Number(root.traffic.tx_rate || 0)
                    if (totalRate <= 0) return 0
                    return Math.min(1, Math.log10(1 + totalRate / 1024) / 4)
                  }
                  fillColor: Commons.Color.accent
                  tip: root.t("trafficTip", [root.formatBytes(root.traffic.rx_bytes), root.formatBytes(root.traffic.tx_bytes)])
                }

                // Always say when a VPN is on, also when it lets the home network through.
                Item {
                  visible: root.vpn !== null
                  width: parent.width
                  height: vpnLine.implicitHeight
                  readonly property color tint: root.hostWidget && root.hostWidget.vpnBlue ? root.hostWidget.vpnBlue : Commons.Color.accent
                  Text {
                    id: vpnLine
                    textFormat: Text.PlainText
                    width: parent.width
                    elide: Text.ElideRight
                    text: root.glyph(0xF099D) + "  " + root.t("vpnOn", [root.vpn ? root.vpn.name : ""])
                      + "  ·  " + root.t(root.lanBlocked ? "blocksHome" : "homeReachable")
                    color: parent.tint
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                    font.bold: true
                  }
                  MouseArea { id: vpnMouse; anchors.fill: parent; hoverEnabled: true; acceptedButtons: Qt.NoButton }
                  PanelToolTip {
                    visible: vpnMouse.containsMouse
                    fontFamily: root.font
                    text: root.vpn ? root.t("vpnIface", [root.vpn.iface, root.vpn.name])
                      + "\n" + (root.lanBlocked ? root.vpnHint : root.t("homeStillReachable")) : ""
                  }
                }

                // One summary line; the explanations, "connected via" and the FRITZ!Box login
                // open on click, so the device list keeps the space. The choice is remembered.
                Item {
                  visible: root.stats.active === true
                  width: parent.width
                  height: infoSummary.implicitHeight + Style.space(6)
                  Rectangle {
                    anchors.fill: parent
                    anchors.leftMargin: -Style.space(4)
                    anchors.rightMargin: -Style.space(4)
                    radius: root.corners.control
                    color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.06)
                    visible: infoMouse.containsMouse
                  }
                  Text {
                    id: infoSummary
                    textFormat: Text.PlainText
                    anchors.left: parent.left
                    anchors.right: infoChevron.left
                    anchors.rightMargin: Style.space(8)
                    anchors.verticalCenter: parent.verticalCenter
                    elide: Text.ElideRight
                    text: root.glyph(root.trusted ? 0xF0565 : 0xF099C) + "  "
                      + (root.trusted ? root.t("yourNetwork") : root.t("notYourNetwork"))
                      + (root.link.via ? "  ·  " + root.t("viaN", [String(root.link.via).replace(/^Router \((.*)\)$/, "$1")])
                        + (root.link.via_band ? " · " + root.link.via_band : "") : "")
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                  Text {
                    id: infoChevron
                    textFormat: Text.PlainText
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.glyph(root.infoOpen ? 0xF0140 : 0xF0142)
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                  MouseArea {
                    id: infoMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.toggleGroup("showinfo")
                  }
                }

                Column {
                  visible: root.infoOpen || root.fritzFormOpen || root.fritz.state === "error" || root.fritz.state === "connecting"
                  width: parent.width
                  spacing: Style.space(8)

                  Text {
                    textFormat: Text.PlainText
                    visible: root.stats.active === true
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.trusted
                      ? root.t(root.alertsOn ? "trustedAlertsOn" : "trustedAlertsOff")
                      : root.t("untrustedInfo")
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }

                  // Optional FRITZ!Box login for mesh details (which access point, band and speed).
                  Column {
                    visible: root.fritz.available === true
                    width: parent.width
                    spacing: Style.space(6)

                    Flow {
                      width: parent.width
                      spacing: Style.space(12)
                      Text {
                        textFormat: Text.PlainText
                        visible: root.fritz.state === "connected"
                        text: root.glyph(0xF0003) + "  " + root.tn("fritzConnected", (root.fritz.aps || []).length)
                        color: root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                      LinkAction {
                        visible: root.fritz.state !== "connected" && root.fritz.state !== "connecting" && !root.fritzFormOpen
                        icon: root.glyph(0xF0306)
                        label: root.fritz.state === "error" && root.fritz.user ? root.t("fritzReconnect") : root.t("fritzShow")
                        baseColor: root.dim
                        onActivated: root.startFritzLogin()
                      }
                      LinkAction {
                        visible: root.fritz.user !== undefined && root.fritz.user !== "" && !root.fritzFormOpen
                        icon: root.glyph(0xF0209)
                        label: root.t("disconnect")
                        baseColor: root.dim
                        onActivated: if (root.hostWidget) root.hostWidget.send("fritz_logout")
                      }
                    }
                    Text {
                      textFormat: Text.PlainText
                      visible: (root.fritz.state === "error" || root.fritz.state === "connecting") && String(root.fritz.message || "") !== ""
                      width: parent.width
                      wrapMode: Text.WordWrap
                      text: root.fritz.message_code ? root.t(root.fritz.message_code, root.fritz.message_args || []) : String(root.fritz.message || "")
                      color: root.fritz.state === "error" ? Commons.Color.accent : root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                    Column {
                      visible: root.fritzFormOpen
                      width: parent.width
                      spacing: Style.space(6)
                      Text {
                        textFormat: Text.PlainText
                        width: parent.width
                        wrapMode: Text.WordWrap
                        text: root.t("fritzExplain")
                        color: root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                      KeyTextField {
                        id: fritzUser
                        radius: root.corners.control
                        width: parent.width
                        maximumLength: 64
                        placeholderText: root.t("userPlaceholder")
                        foreground: root.fg
                        font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                        Keys.onPressed: function(event) {
                          if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Tab) {
                            fritzPassword.forceActiveFocus(); event.accepted = true
                          } else if (event.key === Qt.Key_Escape) {
                            root.closeFritzForm(); event.accepted = true
                          }
                        }
                      }
                      LinkAction {
                        icon: root.glyph(root.fritzHelpOpen ? 0xF0140 : 0xF0142)
                        label: root.t("whereFind")
                        baseColor: root.dim
                        onActivated: root.fritzHelpOpen = !root.fritzHelpOpen
                      }
                      Text {
                        textFormat: Text.PlainText
                        visible: root.fritzHelpOpen
                        width: parent.width
                        leftPadding: Style.space(12)
                        wrapMode: Text.WordWrap
                        text: root.t("fritzHelp")
                        color: root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                      KeyTextField {
                        id: fritzPassword
                        radius: root.corners.control
                        width: parent.width
                        password: !root.showPassword
                        maximumLength: 128
                        placeholderText: root.t("password")
                        foreground: root.fg
                        font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                        onAccepted: root.fritzConnect()
                        Keys.onPressed: function(event) {
                          if (event.key === Qt.Key_Escape) {
                            root.closeFritzForm(); event.accepted = true
                          }
                        }
                        // Eye icon: show or hide the typed password.
                        Text {
                          id: eyeIcon
                          textFormat: Text.PlainText
                          anchors.right: parent.right
                          anchors.rightMargin: Style.space(8)
                          anchors.verticalCenter: parent.verticalCenter
                          text: root.glyph(root.showPassword ? 0xF0209 : 0xF0208)
                          color: eyeMouse.containsMouse ? Commons.Color.accent : root.dim
                          font.family: root.font
                          font.pixelSize: Style.font.body
                          MouseArea {
                            id: eyeMouse
                            anchors.fill: parent
                            anchors.margins: -Style.space(4)
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                              root.showPassword = !root.showPassword
                              fritzPassword.forceActiveFocus()
                            }
                          }
                          PanelToolTip {
                            visible: eyeMouse.containsMouse
                            text: root.showPassword ? root.t("hidePassword") : root.t("showPassword")
                            fontFamily: root.font
                          }
                        }
                      }
                      Flow {
                        width: parent.width
                        spacing: Style.space(8)
                        Button {
                          radius: root.corners.control
                          text: root.t("connect")
                          iconText: root.glyph(0xF0306)
                          bordered: true
                          foreground: root.fg
                          fontFamily: root.font
                          enabled: fritzPassword.text !== ""
                          onClicked: root.fritzConnect()
                        }
                        Button {
                          radius: root.corners.control
                          text: root.t("cancel")
                          bordered: true
                          foreground: root.fg
                          fontFamily: root.font
                          onClicked: root.closeFritzForm()
                        }
                      }
                    }
                  }
                }

                PanelSeparator { width: parent.width; foreground: root.fg }
                Item {
                  width: parent.width
                  height: Math.max(devicesHeader.implicitHeight, devicesViewDrop.implicitHeight, listFoldButtons.implicitHeight)
                  PanelSectionHeader {
                    id: devicesHeader
                    anchors.left: parent.left
                    anchors.right: devicesViewDrop.left
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.rightMargin: Style.space(8)
                    // Online / idle / sleeping counts are in the title chip and the bar tooltip.
                    text: root.t("devicesN", [root.totalCount]).toUpperCase()
                    foreground: root.fg
                    fontFamily: root.font
                  }
                  // Grouping, shared with the Network map.
                  CompactDropdown {
                    id: devicesViewDrop
                    controlRadius: root.corners.control
                    popupRadius: root.corners.radius
                    anchors.right: listFoldButtons.left
                    anchors.rightMargin: Style.space(6)
                    anchors.verticalCenter: parent.verticalCenter
                    width: Style.space(150)
                    showLabel: false
                    fontFamily: root.font
                    options: root.viewOptions
                    value: root.viewMode
                    onChanged: function(value) {
                      root.setViewMode(value)
                      devicesViewDrop.value = Qt.binding(function() { return root.viewMode })   // picking cut the binding
                    }
                  }
                  Row {
                    id: listFoldButtons
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(4)
                    Button {
                      radius: root.corners.control
                      iconText: root.glyph(0xF084F)
                      bordered: true
                      enabled: root.viewMode !== "list" && root.filterText === ""
                      foreground: root.fg
                      fontFamily: root.font
                      tooltipText: root.t("expandAll")
                      onClicked: root.foldAll(false, root.listFoldIds)
                    }
                    Button {
                      radius: root.corners.control
                      iconText: root.glyph(0xF084D)
                      bordered: true
                      enabled: root.viewMode !== "list" && root.filterText === ""
                      foreground: root.fg
                      fontFamily: root.font
                      tooltipText: root.t("collapseAll")
                      onClicked: root.foldAll(true, root.listFoldIds)
                    }
                  }
                }

                // New devices since the user last checked (trusted networks only).
                Rectangle {
                  visible: root.newCount > 0
                  width: parent.width
                  height: newRow.implicitHeight + Style.space(12)
                  radius: root.corners.radius
                  color: Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.14)
                  border.width: 1
                  border.color: Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.5)
                  Item {
                    id: newRow
                    anchors.fill: parent
                    anchors.margins: Style.space(6)
                    implicitHeight: newText.implicitHeight
                    Text {
                      id: newText
                      textFormat: Text.PlainText
                      anchors.left: parent.left
                      anchors.right: newAction.left
                      anchors.rightMargin: Style.space(8)
                      anchors.verticalCenter: parent.verticalCenter
                      wrapMode: Text.WordWrap
                      text: root.glyph(0xF009A) + "  " + root.tn("newJoined", root.newCount) + ". " + root.t("notYours")
                      color: root.fg
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                    LinkAction {
                      id: newAction
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      icon: root.glyph(0xF05E0)
                      label: root.t("allKnown")
                      onActivated: if (root.hostWidget) root.hostWidget.send("known_all")
                    }
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  visible: root.namedCount === 0 && root.devices.length > 1 && root.newCount === 0
                  width: parent.width
                  wrapMode: Text.WordWrap
                  text: root.t("tip")
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }

                KeyTextField {
                  id: searchField
                  radius: root.corners.control
                  visible: root.showSearch
                  width: parent.width
                  placeholderText: root.glyph(0xF0349) + "  " + root.t("search")
                  maximumLength: 40
                  foreground: root.fg
                  font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                  onTextChanged: root.filterText = text
                  Keys.onPressed: function(event) {
                    if (event.key === Qt.Key_Escape) {
                      searchField.clear()
                      keyCatcher.forceActiveFocus()
                      event.accepted = true
                    }
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  visible: root.stats.active === true && !root.trusted && root.totalCount <= 3
                  width: parent.width
                  wrapMode: Text.WordWrap
                  text: root.t("fewDevices")
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }

                // Only the device list scrolls, so the link info and buttons stay visible.
                Flickable {
                  id: deviceScroller
                  width: parent.width
                  height: Math.min(deviceColumn.implicitHeight, root.maxDeviceListHeight)
                  contentWidth: width
                  contentHeight: deviceColumn.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  interactive: contentHeight > height

                  Column {
                    id: deviceColumn
                    width: deviceScroller.width
                    spacing: Style.space(8)

                    Repeater {
                      model: root.listEntries
                      delegate: Loader {
                        id: entry
                        required property var modelData
                        x: modelData.inGroup ? Style.space(10) : 0
                        width: deviceColumn.width - x
                        sourceComponent: modelData.type === "header" ? groupHeaderComponent : deviceRowComponent
                        onLoaded: {
                          item.width = Qt.binding(function() { return entry.width })
                          if (modelData.type === "header") item.group = modelData
                          else item.dev = modelData.dev
                        }
                      }
                    }

                    Text {
                      visible: root.listEntries.length === 0 && root.filterText !== ""
                      textFormat: Text.PlainText
                      text: root.t("noMatch", [root.filterText])
                      color: root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                  }
                }

                Flow {
                  width: parent.width
                  spacing: Style.space(16)
                  LinkAction {
                    visible: root.devices.length > 0
                    icon: root.glyph(root.listCopied ? 0xF012C : 0xF014D)
                    label: root.listCopied ? root.t("copied") : root.t("copyList")
                    baseColor: root.dim
                    onActivated: root.copyList()
                  }
                  LinkAction {
                    visible: root.hiddenCount > 0
                    icon: root.glyph(root.showHidden ? 0xF0209 : 0xF0208)
                    label: root.t(root.showHidden ? "hideHidden" : "showHidden", [root.hiddenCount])
                    baseColor: root.dim
                    onActivated: root.showHidden = !root.showHidden
                  }
                }
              }

              // Network map: Internet → router → bands / access points → devices.
              Column {
                id: mapPageColumn
                visible: root.mapPage
                width: parent.width
                spacing: Style.space(8)

                PanelSeparator { width: parent.width; foreground: root.fg }
                Item {
                  width: parent.width
                  height: Math.max(mapSummaryText.implicitHeight, mapViewDrop.implicitHeight, mapFoldButtons.implicitHeight)
                  Text {
                    id: mapSummaryText
                    textFormat: Text.PlainText
                    anchors.left: parent.left
                    anchors.right: mapViewDrop.left
                    anchors.rightMargin: Style.space(8)
                    anchors.verticalCenter: parent.verticalCenter
                    elide: Text.ElideRight
                    text: root.mapSummary
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                  // Same grouping as on the Devices page.
                  CompactDropdown {
                    id: mapViewDrop
                    controlRadius: root.corners.control
                    popupRadius: root.corners.radius
                    anchors.right: mapFoldButtons.left
                    anchors.rightMargin: Style.space(6)
                    anchors.verticalCenter: parent.verticalCenter
                    width: Style.space(150)
                    showLabel: false
                    fontFamily: root.font
                    options: root.viewOptions
                    value: root.viewMode
                    onChanged: function(value) {
                      root.setViewMode(value)
                      mapViewDrop.value = Qt.binding(function() { return root.viewMode })   // picking cut the binding
                    }
                  }
                  Row {
                    id: mapFoldButtons
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(4)
                    readonly property bool usable: root.viewMode !== "list" && root.viewMode !== "ap"
                    Button {
                      radius: root.corners.control
                      iconText: root.glyph(0xF084F)
                      bordered: true
                      enabled: mapFoldButtons.usable
                      foreground: root.fg
                      fontFamily: root.font
                      tooltipText: root.t("expandAll")
                      onClicked: root.foldAll(false)
                    }
                    Button {
                      radius: root.corners.control
                      iconText: root.glyph(0xF084D)
                      bordered: true
                      enabled: mapFoldButtons.usable
                      foreground: root.fg
                      fontFamily: root.font
                      tooltipText: root.t("collapseAll")
                      onClicked: root.foldAll(true)
                    }
                  }
                }
                Flickable {
                  id: mapScroller
                  width: parent.width
                  height: Math.min(mapColumn.implicitHeight, Style.space(470))
                  contentWidth: width
                  contentHeight: mapColumn.implicitHeight
                  clip: true
                  boundsBehavior: Flickable.StopAtBounds
                  interactive: contentHeight > height
                  Column {
                    id: mapColumn
                    width: mapScroller.width
                    Repeater {
                      model: root.mapRows
                      delegate: MapRow {
                        required property var modelData
                        width: mapColumn.width
                        row: modelData
                      }
                    }
                  }
                }
                Text {
                  textFormat: Text.PlainText
                  visible: !root.meshActive
                  width: parent.width
                  wrapMode: Text.WordWrap
                  text: root.fritz.available === true
                    ? root.t("connectFritzForBand")
                    : root.t("bandForFritz")
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }
                Text {
                  textFormat: Text.PlainText
                  width: parent.width
                  wrapMode: Text.WordWrap
                  text: root.t("mapTip")
                  color: root.dim
                  font.family: root.font
                  font.pixelSize: Style.font.caption
                }
              }

              // ---------------------------------------------------------------- monitor page
              Column {
                id: monitorPageColumn
                visible: root.activePage === "monitor"
                width: parent.width
                spacing: Style.space(8)

                PanelSeparator { width: parent.width; foreground: root.fg }

                // Live summary, 30-sample sparkline, sub-view chips, pause & DNS toggles.
                Rectangle {
                  width: parent.width
                  height: monitorSummaryCol.implicitHeight + Style.space(16)
                  radius: root.corners.radius
                  color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.05)
                  border.width: 1
                  border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.14)

                  Column {
                    id: monitorSummaryCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.margins: Style.space(8)
                    spacing: Style.space(6)

                    Item {
                      width: parent.width
                      height: Math.max(liveTitle.implicitHeight, liveRates.implicitHeight)
                      Text {
                        id: liveTitle
                        textFormat: Text.PlainText
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.t("liveTraffic")
                        color: root.fg
                        font.family: root.font
                        font.pixelSize: Style.font.bodySmall
                        font.bold: true
                      }
                      Text {
                        id: liveRates
                        textFormat: Text.PlainText
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        text: "↓ " + root.formatRate(root.netmonSummary.rx_rate) + "  ·  ↑ " + root.formatRate(root.netmonSummary.tx_rate)
                        color: root.fg
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                    }

                    // 30-bar throughput sparkline.
                    Row {
                      id: sparkRow
                      width: parent.width
                      height: Style.space(34)
                      spacing: Style.space(2)
                      Repeater {
                        model: root.sparklineBars
                        delegate: Item {
                          required property var modelData
                          width: Math.max(2, (sparkRow.width - 29 * sparkRow.spacing) / 30)
                          height: sparkRow.height
                          Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            height: Math.max(Style.space(2), Math.round(parent.height * modelData.frac))
                            radius: Math.min(root.corners.small, 2)
                            color: modelData.active
                              ? (modelData.txDominant ? Commons.Color.accent : root.signalColor(0.85))
                              : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.14)
                          }
                        }
                      }
                    }

                    Item {
                      width: parent.width
                      height: Math.max(monCountsText.implicitHeight, monTotalText.implicitHeight)
                      Text {
                        id: monCountsText
                        textFormat: Text.PlainText
                        anchors.left: parent.left
                        anchors.right: monTotalText.left
                        anchors.rightMargin: Style.space(8)
                        anchors.verticalCenter: parent.verticalCenter
                        elide: Text.ElideRight
                        text: root.t("monCounts", [
                          Number(root.netmonSummary.established || 0),
                          Number(root.netmonSummary.listening || 0),
                          Number(root.netmonSummary.external || 0)
                        ])
                        color: root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                      Text {
                        id: monTotalText
                        textFormat: Text.PlainText
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.netmonPaused ? root.t("paused") : root.t("totalN", [Number(root.netmonSummary.total || 0)])
                        color: root.netmonPaused ? Commons.Color.accent : root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                        font.bold: root.netmonPaused
                      }
                    }

                    Flow {
                      width: parent.width
                      spacing: Style.space(4)
                      FilterChip {
                        label: root.t("monConnections")
                        selected: root.netmonView === "connections"
                        onActivated: root.netmonView = "connections"
                      }
                      FilterChip {
                        label: root.t("monByApp")
                        selected: root.netmonView === "byapp"
                        onActivated: root.netmonView = "byapp"
                      }
                      FilterChip {
                        label: root.t("monInterfaces")
                        selected: root.netmonView === "interfaces"
                        onActivated: root.netmonView = "interfaces"
                      }
                      Button {
                        radius: root.corners.control
                        iconText: root.glyph(root.netmonPaused ? 0xF040A : 0xF03E4)
                        bordered: true
                        foreground: root.fg
                        fontFamily: root.font
                        tooltipText: root.netmonPaused ? root.t("resumeTip") : root.t("pauseTip")
                        onClicked: root.netmonPaused = !root.netmonPaused
                      }
                      Button {
                        radius: root.corners.control
                        text: root.netmonResolve ? root.t("dnsOn") : root.t("dnsOff")
                        bordered: true
                        foreground: root.netmonResolve ? Commons.Color.accent : root.fg
                        fontFamily: root.font
                        tooltipText: root.t("dnsResolveTip")
                        onClicked: root.netmonResolve = !root.netmonResolve
                      }
                    }
                  }
                }

                KeyTextField {
                  id: netmonSearchField
                  radius: root.corners.control
                  visible: root.netmonView !== "interfaces"
                  width: parent.width
                  placeholderText: root.glyph(0xF0349) + "  " + root.t("monSearch")
                  maximumLength: 64
                  foreground: root.fg
                  font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                  onTextChanged: root.netmonSearchText = text
                  Keys.onPressed: function(event) {
                    if (event.key === Qt.Key_Escape) {
                      netmonSearchField.clear()
                      keyCatcher.forceActiveFocus()
                      event.accepted = true
                    }
                  }
                }

                // Sub-view 1: Connections
                Column {
                  visible: root.netmonView === "connections"
                  width: parent.width
                  spacing: Style.space(6)

                  Item {
                    width: parent.width
                    height: Math.max(protoChips.implicitHeight, sortBtn.implicitHeight)
                    Row {
                      id: protoChips
                      anchors.left: parent.left
                      anchors.verticalCenter: parent.verticalCenter
                      spacing: Style.space(4)
                      FilterChip { label: root.t("filterAll"); selected: root.netmonProto === "all"; onActivated: root.netmonProto = "all" }
                      FilterChip { label: "TCP"; selected: root.netmonProto === "tcp"; onActivated: root.netmonProto = "tcp" }
                      FilterChip { label: "UDP"; selected: root.netmonProto === "udp"; onActivated: root.netmonProto = "udp" }
                    }
                    Button {
                      id: sortBtn
                      radius: root.corners.control
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.t("sortByN", [root.netmonSortLabel(root.netmonSort)])
                      bordered: true
                      foreground: root.fg
                      fontFamily: root.font
                      onClicked: root.nextNetmonSort()
                    }
                  }

                  Flow {
                    width: parent.width
                    spacing: Style.space(4)
                    FilterChip { label: root.t("filterAll"); selected: root.netmonScope === "all"; onActivated: root.netmonScope = "all" }
                    FilterChip { label: root.t("filterActive"); selected: root.netmonScope === "active"; onActivated: root.netmonScope = "active" }
                    FilterChip { label: root.t("filterListening"); selected: root.netmonScope === "listening"; onActivated: root.netmonScope = "listening" }
                    FilterChip { label: root.t("filterExternal"); selected: root.netmonScope === "external"; onActivated: root.netmonScope = "external" }
                    FilterChip { label: "LAN"; selected: root.netmonScope === "lan"; onActivated: root.netmonScope = "lan" }
                    FilterChip { label: root.t("filterLocal"); selected: root.netmonScope === "loopback"; onActivated: root.netmonScope = "loopback" }
                  }

                  Item {
                    width: parent.width
                    height: Math.max(showingCountText.implicitHeight, clearFiltersAction.implicitHeight)
                    Text {
                      id: showingCountText
                      textFormat: Text.PlainText
                      anchors.left: parent.left
                      anchors.verticalCenter: parent.verticalCenter
                      text: root.t("showingConns", [root.filteredConnections.length, ((root.netmon && root.netmon.connections) || []).length])
                      color: root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                    LinkAction {
                      id: clearFiltersAction
                      visible: root.netmonIsFiltered
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      icon: root.glyph(0xF0156)
                      label: root.t("clearFilters")
                      onActivated: root.clearNetmonFilters()
                    }
                  }

                  Text {
                    visible: !root.netmonHasData
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.t("collectingConns")
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }

                  Text {
                    visible: root.netmonHasData && root.filteredConnections.length === 0
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.t("noConnsMatch")
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }

                  Repeater {
                    model: root.filteredConnections.slice(0, 150)
                    delegate: ConnRow {
                      required property var modelData
                      width: monitorPageColumn.width
                      conn: modelData
                    }
                  }

                  Text {
                    visible: root.filteredConnections.length > 150
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.t("showingFirst150", [root.filteredConnections.length])
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }
                }

                // Sub-view 2: By app
                Column {
                  visible: root.netmonView === "byapp"
                  width: parent.width
                  spacing: Style.space(5)

                  Text {
                    visible: root.filteredProcesses.length === 0
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.netmonHasData ? root.t("noAppsMatch") : root.t("collectingConns")
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }

                  Repeater {
                    model: root.filteredProcesses
                    delegate: Item {
                      id: appRow
                      required property var modelData
                      width: monitorPageColumn.width
                      height: appCol.implicitHeight + Style.space(8)
                      readonly property string pname: String(modelData.name || "")
                      readonly property real rxR: Number(modelData.rx_rate || 0)
                      readonly property real txR: Number(modelData.tx_rate || 0)
                      readonly property real rxB: Number(modelData.rx_bytes || 0)
                      readonly property real txB: Number(modelData.tx_bytes || 0)
                      readonly property int connsN: Number(modelData.connections || 0)
                      readonly property string rightText: (rxR + txR) > 0
                        ? ("↓ " + root.formatRate(rxR) + " · ↑ " + root.formatRate(txR))
                        : ((rxB + txB) > 0
                          ? ("↓ " + root.formatBytes(rxB) + " · ↑ " + root.formatBytes(txB))
                          : root.t("connsShortN", [connsN]))
                      readonly property string subText: {
                        var parts = [root.t("connsN", [connsN])]
                        if (Number(modelData.external || 0) > 0) parts.push(root.t("extN", [Number(modelData.external)]))
                        if (Number(modelData.lan || 0) > 0) parts.push(Number(modelData.lan) + " LAN")
                        if (Number(modelData.listening || 0) > 0) parts.push(root.t("listenN", [Number(modelData.listening)]))
                        return parts.join("  ·  ")
                      }

                      Rectangle {
                        anchors.fill: parent
                        radius: root.corners.control
                        color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, appMouse.containsMouse ? 0.08 : 0.03)
                      }
                      Column {
                        id: appCol
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.leftMargin: Style.space(6)
                        anchors.rightMargin: Style.space(6)
                        y: Style.space(4)
                        spacing: Style.space(2)
                        Item {
                          width: parent.width
                          height: Math.max(appNameText.implicitHeight, appRightText.implicitHeight)
                          Text {
                            id: appIcon
                            textFormat: Text.PlainText
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.glyph(0xF08C6)
                            color: Commons.Color.accent
                            font.family: root.font
                            font.pixelSize: Style.font.caption
                          }
                          Text {
                            id: appNameText
                            textFormat: Text.PlainText
                            anchors.left: appIcon.right
                            anchors.leftMargin: Style.space(6)
                            anchors.right: appRightText.left
                            anchors.rightMargin: Style.space(6)
                            anchors.verticalCenter: parent.verticalCenter
                            elide: Text.ElideRight
                            text: appRow.pname !== "" ? appRow.pname : root.t("systemOther")
                            color: root.fg
                            font.family: root.font
                            font.pixelSize: Style.font.bodySmall
                            font.bold: true
                          }
                          Text {
                            id: appRightText
                            textFormat: Text.PlainText
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            text: appRow.rightText
                            color: Commons.Color.accent
                            font.family: root.font
                            font.pixelSize: Style.font.caption
                          }
                        }
                        Text {
                          textFormat: Text.PlainText
                          width: parent.width
                          leftPadding: Style.space(18)
                          elide: Text.ElideRight
                          text: appRow.subText
                          color: root.dim
                          font.family: root.font
                          font.pixelSize: Style.font.caption
                        }
                      }
                      MouseArea {
                        id: appMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        enabled: appRow.pname !== ""
                        cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                        onClicked: root.filterByApp(appRow.pname)
                      }
                    }
                  }
                }

                // Sub-view 3: Interfaces & DNS
                Column {
                  visible: root.netmonView === "interfaces"
                  width: parent.width
                  spacing: Style.space(6)

                  Text {
                    visible: ((root.netmon && root.netmon.interfaces) || []).length === 0
                    textFormat: Text.PlainText
                    width: parent.width
                    wrapMode: Text.WordWrap
                    text: root.t("collectingIfaces")
                    color: root.dim
                    font.family: root.font
                    font.pixelSize: Style.font.caption
                  }

                  Repeater {
                    model: (root.netmon && root.netmon.interfaces) || []
                    delegate: Rectangle {
                      id: ifaceCard
                      required property var modelData
                      width: monitorPageColumn.width
                      height: ifaceCol.implicitHeight + Style.space(14)
                      radius: root.corners.radius
                      color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.05)
                      border.width: 1
                      border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.12)
                      readonly property bool isUp: String(modelData.state || "") === "up"
                      readonly property int kindCode: modelData.kind === "wifi" ? 0xF05A9
                        : (modelData.kind === "ethernet" ? 0xF0200
                          : (modelData.kind === "vpn" ? 0xF099D : 0xF048B))
                      readonly property string metaLine: {
                        var parts = []
                        if (modelData.ip) parts.push("IPv4 " + modelData.ip)
                        if (modelData.ipv6) parts.push("IPv6 " + modelData.ipv6)
                        if (modelData.mac) parts.push("MAC " + modelData.mac)
                        return parts.join("  ·  ")
                      }
                      readonly property int errs: Number(modelData.rx_errors || 0) + Number(modelData.tx_errors || 0)
                      readonly property int drops: Number(modelData.rx_dropped || 0) + Number(modelData.tx_dropped || 0)

                      Column {
                        id: ifaceCol
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        anchors.margins: Style.space(7)
                        spacing: Style.space(3)
                        Item {
                          width: parent.width
                          height: Math.max(ifaceName.implicitHeight, ifaceState.implicitHeight)
                          Text {
                            id: ifaceIcon
                            textFormat: Text.PlainText
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.glyph(ifaceCard.kindCode)
                            color: ifaceCard.isUp ? Commons.Color.accent : root.dim
                            font.family: root.font
                            font.pixelSize: Style.font.bodySmall
                          }
                          Text {
                            id: ifaceName
                            textFormat: Text.PlainText
                            anchors.left: ifaceIcon.right
                            anchors.leftMargin: Style.space(6)
                            anchors.right: ifaceState.left
                            anchors.rightMargin: Style.space(6)
                            anchors.verticalCenter: parent.verticalCenter
                            elide: Text.ElideRight
                            text: String(ifaceCard.modelData.name || "")
                            color: root.fg
                            font.family: root.font
                            font.pixelSize: Style.font.bodySmall
                            font.bold: true
                          }
                          Text {
                            id: ifaceState
                            textFormat: Text.PlainText
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            text: ifaceCard.isUp ? root.t("ifaceUp") : root.t("ifaceDown")
                            color: ifaceCard.isUp ? Commons.Color.accent : root.dim
                            font.family: root.font
                            font.pixelSize: Style.font.caption
                            font.bold: ifaceCard.isUp
                          }
                        }
                        Text {
                          textFormat: Text.PlainText
                          width: parent.width
                          wrapMode: Text.WordWrap
                          text: "↓ " + root.formatRate(ifaceCard.modelData.rx_rate) + "  ·  ↑ " + root.formatRate(ifaceCard.modelData.tx_rate)
                            + "   (" + root.formatBytes(ifaceCard.modelData.rx_bytes) + " / " + root.formatBytes(ifaceCard.modelData.tx_bytes) + ")"
                          color: root.dim
                          font.family: root.font
                          font.pixelSize: Style.font.caption
                        }
                        Text {
                          visible: ifaceCard.metaLine !== ""
                          textFormat: Text.PlainText
                          width: parent.width
                          wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                          text: ifaceCard.metaLine
                          color: root.dim
                          font.family: root.font
                          font.pixelSize: Style.font.caption
                        }
                        Text {
                          visible: ifaceCard.errs > 0 || ifaceCard.drops > 0
                          textFormat: Text.PlainText
                          width: parent.width
                          text: root.t("errorsDropped", [ifaceCard.errs, ifaceCard.drops])
                          color: Commons.Color.urgent
                          font.family: root.font
                          font.pixelSize: Style.font.caption
                        }
                      }
                    }
                  }

                  Rectangle {
                    visible: ((root.netmon && root.netmon.dns) || []).length > 0
                    width: parent.width
                    height: dnsCol.implicitHeight + Style.space(14)
                    radius: root.corners.radius
                    color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.05)
                    border.width: 1
                    border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.12)
                    Column {
                      id: dnsCol
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.margins: Style.space(7)
                      spacing: Style.space(3)
                      PanelSectionHeader { text: root.t("dnsServers").toUpperCase(); foreground: root.fg; fontFamily: root.font }
                      Text {
                        textFormat: Text.PlainText
                        width: parent.width
                        wrapMode: Text.WordWrap
                        text: ((root.netmon && root.netmon.dns) || []).join(", ")
                        color: root.fg
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                    }
                  }
                }
              }

              // ---------------------------------------------------------------- setup page
              Column {
                id: setupPageColumn
                visible: root.activePage === "setup"
                width: parent.width
                spacing: Style.space(8)

                PanelSeparator { width: parent.width; foreground: root.fg }

                // NetworkManager unavailable warning card.
                Rectangle {
                  visible: !root.nmAvailable
                  width: parent.width
                  height: nmMissingCol.implicitHeight + Style.space(16)
                  radius: root.corners.radius
                  color: Qt.rgba(Commons.Color.urgent.r, Commons.Color.urgent.g, Commons.Color.urgent.b, 0.14)
                  border.width: 1
                  border.color: Qt.rgba(Commons.Color.urgent.r, Commons.Color.urgent.g, Commons.Color.urgent.b, 0.5)
                  Column {
                    id: nmMissingCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.margins: Style.space(8)
                    spacing: Style.space(6)
                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      wrapMode: Text.WordWrap
                      text: root.t("nmUnavailable")
                      color: root.fg
                      font.family: root.font
                      font.pixelSize: Style.font.bodySmall
                      font.bold: true
                    }
                    Text {
                      textFormat: Text.PlainText
                      width: parent.width
                      wrapMode: Text.WordWrap
                      text: root.t("nmUnavailableHint")
                      color: root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                    Button {
                      radius: root.corners.control
                      text: root.t("sysNetSettings")
                      iconText: root.glyph(0xF05A9)
                      bordered: true
                      foreground: root.fg
                      fontFamily: root.font
                      onClicked: root.openSystemNetSettings()
                    }
                  }
                }

                Column {
                  visible: root.nmAvailable
                  width: parent.width
                  spacing: Style.space(8)

                  // Action status / error banner.
                  Rectangle {
                    readonly property string errFallback: String(root.wifiState.error || "")
                    readonly property string bannerMsg: root.wifiStatusText !== "" ? root.wifiStatusText : errFallback
                    readonly property bool isOk: root.wifiStatusText !== "" && root.wifiStatusOk
                    visible: bannerMsg !== ""
                    width: parent.width
                    height: statusBannerText.implicitHeight + Style.space(14)
                    radius: root.corners.radius
                    readonly property color tint: isOk ? root.signalColor(0.85) : Commons.Color.urgent
                    color: Qt.rgba(tint.r, tint.g, tint.b, 0.14)
                    border.width: 1
                    border.color: Qt.rgba(tint.r, tint.g, tint.b, 0.55)
                    Text {
                      id: statusBannerText
                      textFormat: Text.PlainText
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.margins: Style.space(7)
                      wrapMode: Text.WordWrap
                      text: root.glyph(parent.isOk ? 0xF012C : 0xF0026) + "  " + parent.bannerMsg
                      color: root.fg
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                  }

                  // Wi-Fi Radio & Controls card.
                  Rectangle {
                    width: parent.width
                    height: radioCardCol.implicitHeight + Style.space(14)
                    radius: root.corners.radius
                    color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.05)
                    border.width: 1
                    border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.12)
                    Column {
                      id: radioCardCol
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.margins: Style.space(7)
                      spacing: Style.space(6)

                      Item {
                        visible: root.hasWifiDevice
                        width: parent.width
                        height: Math.max(wifiRadioLabel.implicitHeight, wifiRadioSwitch.implicitHeight, rescanWifiBtn.implicitHeight)
                        Text {
                          id: wifiRadioLabel
                          textFormat: Text.PlainText
                          anchors.left: parent.left
                          anchors.verticalCenter: parent.verticalCenter
                          text: root.glyph(0xF05A9) + "  " + root.t("wifiLabel")
                          color: root.fg
                          font.family: root.font
                          font.pixelSize: Style.font.bodySmall
                          font.bold: true
                        }
                        ToggleSwitch {
                          id: wifiRadioSwitch
                          anchors.left: wifiRadioLabel.right
                          anchors.leftMargin: Style.space(10)
                          anchors.verticalCenter: parent.verticalCenter
                          cursorRing: false
                          rounded: root.corners.pill > 0
                          checked: root.wifiRadioOn
                          enabled: !root.wifiBusy
                          foreground: root.fg
                          onToggled: root.toggleWifiRadio(!root.wifiRadioOn)
                        }
                        Button {
                          id: rescanWifiBtn
                          radius: root.corners.control
                          anchors.right: parent.right
                          anchors.verticalCenter: parent.verticalCenter
                          text: root.wifiScanning ? root.t("scanningWifi") : root.t("rescanWifi")
                          iconText: root.glyph(0xF0450)
                          iconSpinning: root.wifiScanning
                          bordered: true
                          foreground: root.fg
                          fontFamily: root.font
                          enabled: !root.wifiScanning && !root.wifiBusy && root.wifiRadioOn
                          onClicked: root.triggerWifiScan(true)
                        }
                      }

                      Text {
                        visible: !root.hasWifiDevice
                        textFormat: Text.PlainText
                        width: parent.width
                        wrapMode: Text.WordWrap
                        text: root.t("noWifiAdapter")
                        color: root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }

                      Text {
                        visible: root.stats.active === true
                        textFormat: Text.PlainText
                        width: parent.width
                        wrapMode: Text.WordWrap
                        text: {
                          var parts = [(root.link.ssid || root.link.iface || "") + (root.link.ip ? " · " + root.link.ip : "")]
                          if (root.link.gateway) parts.push(root.t("router") + " " + root.link.gateway)
                          var dnsList = (root.wifiState && root.wifiState.dns) || []
                          if (dnsList.length > 0) parts.push("DNS " + dnsList.join(", "))
                          return parts.join("  ·  ")
                        }
                        color: root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                    }
                  }

                  // Inline Wi-Fi Password Form (secured network, change password, or auth_failed re-prompt).
                  Rectangle {
                    visible: root.wifiFormOpen
                    width: parent.width
                    height: wifiFormCol.implicitHeight + Style.space(16)
                    radius: root.corners.radius
                    color: Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.12)
                    border.width: 1
                    border.color: Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.6)
                    Column {
                      id: wifiFormCol
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.margins: Style.space(8)
                      spacing: Style.space(6)

                      Text {
                        textFormat: Text.PlainText
                        width: parent.width
                        wrapMode: Text.WordWrap
                        text: root.glyph(0xF05A9) + "  " + root.t("connectToN", [root.wifiFormSsid])
                        color: root.fg
                        font.family: root.font
                        font.pixelSize: Style.font.bodySmall
                        font.bold: true
                      }

                      Text {
                        visible: root.wifiFormNote !== ""
                        textFormat: Text.PlainText
                        width: parent.width
                        wrapMode: Text.WordWrap
                        text: root.wifiFormNote
                        color: Commons.Color.urgent
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }

                      KeyTextField {
                        id: wifiPasswordField
                        radius: root.corners.control
                        width: parent.width
                        password: !root.wifiShowPassword
                        maximumLength: 64
                        placeholderText: root.t("wifiPasswordHint")
                        foreground: root.fg
                        font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                        onAccepted: root.submitWifiPassword()
                        Keys.onPressed: function(event) {
                          if (event.key === Qt.Key_Escape) {
                            root.closeWifiForm()
                            event.accepted = true
                          }
                        }
                        Text {
                          id: wifiEyeIcon
                          textFormat: Text.PlainText
                          anchors.right: parent.right
                          anchors.rightMargin: Style.space(8)
                          anchors.verticalCenter: parent.verticalCenter
                          text: root.glyph(root.wifiShowPassword ? 0xF0209 : 0xF0208)
                          color: wifiEyeMouse.containsMouse ? Commons.Color.accent : root.dim
                          font.family: root.font
                          font.pixelSize: Style.font.body
                          MouseArea {
                            id: wifiEyeMouse
                            anchors.fill: parent
                            anchors.margins: -Style.space(4)
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
                            onClicked: {
                              root.wifiShowPassword = !root.wifiShowPassword
                              wifiPasswordField.forceActiveFocus()
                            }
                          }
                          PanelToolTip {
                            visible: wifiEyeMouse.containsMouse
                            text: root.wifiShowPassword ? root.t("hidePassword") : root.t("showPassword")
                            fontFamily: root.font
                          }
                        }
                      }

                      Flow {
                        width: parent.width
                        spacing: Style.space(8)
                        Button {
                          radius: root.corners.control
                          text: root.wifiBusy ? root.t("connecting") : root.t("connect")
                          iconText: root.glyph(0xF0306)
                          bordered: true
                          foreground: root.fg
                          fontFamily: root.font
                          enabled: !root.wifiBusy && root.wifiPasswordValid(wifiPasswordField.text)
                          onClicked: root.submitWifiPassword()
                        }
                        Button {
                          radius: root.corners.control
                          text: root.t("cancel")
                          bordered: true
                          foreground: root.fg
                          fontFamily: root.font
                          onClicked: root.closeWifiForm()
                        }
                      }
                    }
                  }

                  // Saved Wi-Fi networks
                  Column {
                    visible: root.hasWifiDevice && ((root.wifiState.known || []).length > 0)
                    width: parent.width
                    spacing: Style.space(5)
                    PanelSectionHeader { text: root.t("savedWifi").toUpperCase(); foreground: root.fg; fontFamily: root.font }

                    Repeater {
                      model: (root.wifiState && root.wifiState.known) || []
                      delegate: Rectangle {
                        id: knownCard
                        required property var modelData
                        width: setupPageColumn.width
                        height: knownRow.implicitHeight + Style.space(12)
                        radius: root.corners.control
                        color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.04)
                        border.width: 1
                        border.color: modelData.active === true
                          ? Qt.rgba(Commons.Color.accent.r, Commons.Color.accent.g, Commons.Color.accent.b, 0.45)
                          : Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.10)
                        Item {
                          id: knownRow
                          anchors.left: parent.left
                          anchors.right: parent.right
                          anchors.verticalCenter: parent.verticalCenter
                          anchors.leftMargin: Style.space(7)
                          anchors.rightMargin: Style.space(7)
                          implicitHeight: Math.max(knownInfo.implicitHeight, knownActions.implicitHeight)

                          Text {
                            id: knownIcon
                            textFormat: Text.PlainText
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.glyph(0xF05A9)
                            color: knownCard.modelData.active === true ? Commons.Color.accent : root.dim
                            font.family: root.font
                            font.pixelSize: Style.font.body
                          }
                          Column {
                            id: knownInfo
                            anchors.left: knownIcon.right
                            anchors.leftMargin: Style.space(6)
                            anchors.right: knownActions.left
                            anchors.rightMargin: Style.space(6)
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: Style.space(1)
                            Text {
                              textFormat: Text.PlainText
                              width: parent.width
                              elide: Text.ElideRight
                              text: String(knownCard.modelData.name || "")
                              color: root.fg
                              font.family: root.font
                              font.pixelSize: Style.font.bodySmall
                              font.bold: true
                            }
                            Text {
                              textFormat: Text.PlainText
                              width: parent.width
                              elide: Text.ElideRight
                              text: knownCard.modelData.active === true ? root.t("stConnected") : root.t("stSaved")
                              color: knownCard.modelData.active === true ? Commons.Color.accent : root.dim
                              font.family: root.font
                              font.pixelSize: Style.font.caption
                            }
                          }
                          Row {
                            id: knownActions
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: Style.space(4)
                            Button {
                              radius: root.corners.control
                              text: knownCard.modelData.active === true ? root.t("disconnect") : root.t("connect")
                              bordered: true
                              foreground: root.fg
                              fontFamily: root.font
                              enabled: !root.wifiBusy
                              onClicked: {
                                if (knownCard.modelData.active === true) root.disconnectWifi(knownCard.modelData.uuid)
                                else root.connectKnownWifi(knownCard.modelData.uuid, knownCard.modelData.ssid || knownCard.modelData.name)
                              }
                            }
                            Button {
                              radius: root.corners.control
                              iconText: root.glyph(0xF03EB)
                              bordered: true
                              foreground: root.fg
                              fontFamily: root.font
                              enabled: !root.wifiBusy
                              tooltipText: root.t("changePassword")
                              onClicked: root.openWifiPasswordForm(knownCard.modelData.ssid || knownCard.modelData.name, knownCard.modelData.uuid, root.t("changePwHint"))
                            }
                            Button {
                              radius: root.corners.control
                              iconText: root.glyph(0xF0A7A)
                              bordered: true
                              foreground: root.fg
                              fontFamily: root.font
                              enabled: !root.wifiBusy
                              tooltipText: root.t("forget")
                              onClicked: root.forgetWifi(knownCard.modelData.uuid)
                            }
                          }
                        }
                      }
                    }
                  }

                  // Available Wi-Fi networks
                  Column {
                    visible: root.hasWifiDevice && root.wifiRadioOn
                    width: parent.width
                    spacing: Style.space(5)
                    PanelSectionHeader { text: root.t("availableNetworks").toUpperCase(); foreground: root.fg; fontFamily: root.font }

                    KeyTextField {
                      id: wifiSearchField
                      radius: root.corners.control
                      visible: root.unseenWifiNetworks.length > 8 || root.wifiSearchText !== ""
                      width: parent.width
                      placeholderText: root.glyph(0xF0349) + "  " + root.t("filterWifi")
                      maximumLength: 40
                      foreground: root.fg
                      font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                      onTextChanged: root.wifiSearchText = text
                      Keys.onPressed: function(event) {
                        if (event.key === Qt.Key_Escape) {
                          wifiSearchField.clear()
                          keyCatcher.forceActiveFocus()
                          event.accepted = true
                        }
                      }
                    }

                    Text {
                      visible: root.filteredVisibleWifi.length === 0
                      textFormat: Text.PlainText
                      width: parent.width
                      wrapMode: Text.WordWrap
                      text: root.wifiScanning ? root.t("scanningForWifi") : root.t("noOtherWifi")
                      color: root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }

                    Repeater {
                      model: root.filteredVisibleWifi
                      delegate: Rectangle {
                        id: visCard
                        required property var modelData
                        width: setupPageColumn.width
                        height: visRow.implicitHeight + Style.space(12)
                        radius: root.corners.control
                        color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.04)
                        border.width: 1
                        border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.10)
                        readonly property string sec: String(modelData.security || "")
                        readonly property bool isOpen: sec.trim() === "" || sec === "--"
                        readonly property bool isEnterprise: sec.toUpperCase().indexOf("802.1X") !== -1
                        readonly property string metaText: {
                          var parts = [isOpen ? root.t("openNetwork") : sec]
                          if (modelData.band) parts.push(String(modelData.band))
                          if (modelData.channel !== null && modelData.channel !== undefined && String(modelData.channel) !== "")
                            parts.push(root.t("chN", [modelData.channel]))
                          parts.push(Math.round(Number(modelData.signal || 0)) + " %")
                          return parts.join(" · ")
                        }

                        Item {
                          id: visRow
                          anchors.left: parent.left
                          anchors.right: parent.right
                          anchors.verticalCenter: parent.verticalCenter
                          anchors.leftMargin: Style.space(7)
                          anchors.rightMargin: Style.space(7)
                          implicitHeight: Math.max(visInfo.implicitHeight, visBtn.implicitHeight)

                          SignalBars {
                            id: visBars
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            quality: Number(visCard.modelData.signal || 0)
                          }
                          Column {
                            id: visInfo
                            anchors.left: visBars.right
                            anchors.leftMargin: Style.space(8)
                            anchors.right: visBtn.left
                            anchors.rightMargin: Style.space(6)
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: Style.space(1)
                            Text {
                              textFormat: Text.PlainText
                              width: parent.width
                              elide: Text.ElideRight
                              text: String(visCard.modelData.ssid || "")
                              color: root.fg
                              font.family: root.font
                              font.pixelSize: Style.font.bodySmall
                              font.bold: true
                            }
                            Text {
                              textFormat: Text.PlainText
                              width: parent.width
                              elide: Text.ElideRight
                              text: visCard.metaText
                              color: root.dim
                              font.family: root.font
                              font.pixelSize: Style.font.caption
                            }
                          }
                          Button {
                            id: visBtn
                            radius: root.corners.control
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            text: visCard.isEnterprise ? root.t("settings") : root.t("connect")
                            bordered: true
                            foreground: root.fg
                            fontFamily: root.font
                            enabled: visCard.isEnterprise || !root.wifiBusy
                            onClicked: {
                              if (visCard.isEnterprise) root.openSystemNetSettings()
                              else root.connectVisibleWifi(visCard.modelData.ssid, !visCard.isOpen)
                            }
                          }
                        }
                      }
                    }
                  }

                  // Wired (Ethernet) connections
                  Column {
                    visible: ((root.wifiState.wired || []).length > 0) || ((root.wifiState.wired_devices || []).length > 0)
                    width: parent.width
                    spacing: Style.space(5)
                    PanelSectionHeader { text: root.t("wired").toUpperCase(); foreground: root.fg; fontFamily: root.font }

                    Text {
                      visible: root.allWiredUnplugged
                      textFormat: Text.PlainText
                      width: parent.width
                      wrapMode: Text.WordWrap
                      text: root.t("noCable")
                      color: root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }

                    Repeater {
                      model: (root.wifiState && root.wifiState.wired) || []
                      delegate: Rectangle {
                        id: wiredCard
                        required property var modelData
                        width: setupPageColumn.width
                        height: wiredRow.implicitHeight + Style.space(12)
                        radius: root.corners.control
                        color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.04)
                        border.width: 1
                        border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.10)
                        Item {
                          id: wiredRow
                          anchors.left: parent.left
                          anchors.right: parent.right
                          anchors.verticalCenter: parent.verticalCenter
                          anchors.leftMargin: Style.space(7)
                          anchors.rightMargin: Style.space(7)
                          implicitHeight: Math.max(wiredName.implicitHeight, wiredToggle.implicitHeight)
                          Text {
                            id: wiredIcon
                            textFormat: Text.PlainText
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.glyph(0xF0200)
                            color: wiredCard.modelData.active === true ? Commons.Color.accent : root.dim
                            font.family: root.font
                            font.pixelSize: Style.font.body
                          }
                          Text {
                            id: wiredName
                            textFormat: Text.PlainText
                            anchors.left: wiredIcon.right
                            anchors.leftMargin: Style.space(8)
                            anchors.right: wiredToggle.left
                            anchors.rightMargin: Style.space(8)
                            anchors.verticalCenter: parent.verticalCenter
                            elide: Text.ElideRight
                            text: String(wiredCard.modelData.name || "")
                            color: root.fg
                            font.family: root.font
                            font.pixelSize: Style.font.bodySmall
                            font.bold: true
                          }
                          ToggleSwitch {
                            id: wiredToggle
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            cursorRing: false
                            rounded: root.corners.pill > 0
                            checked: wiredCard.modelData.active === true
                            enabled: !root.wifiBusy
                            foreground: root.fg
                            onToggled: root.toggleConn(wiredCard.modelData.uuid, !(wiredCard.modelData.active === true))
                          }
                        }
                      }
                    }
                  }

                  // VPN connections
                  Column {
                    visible: (root.wifiState.vpn || []).length > 0
                    width: parent.width
                    spacing: Style.space(5)
                    PanelSectionHeader { text: root.t("vpnLabel").toUpperCase(); foreground: root.fg; fontFamily: root.font }

                    Repeater {
                      model: (root.wifiState && root.wifiState.vpn) || []
                      delegate: Rectangle {
                        id: vpnCard
                        required property var modelData
                        width: setupPageColumn.width
                        height: vpnCardRow.implicitHeight + Style.space(12)
                        radius: root.corners.control
                        color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.04)
                        border.width: 1
                        border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.10)
                        Item {
                          id: vpnCardRow
                          anchors.left: parent.left
                          anchors.right: parent.right
                          anchors.verticalCenter: parent.verticalCenter
                          anchors.leftMargin: Style.space(7)
                          anchors.rightMargin: Style.space(7)
                          implicitHeight: Math.max(vpnNameText.implicitHeight, vpnToggle.implicitHeight)
                          Text {
                            id: vpnCardIcon
                            textFormat: Text.PlainText
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.glyph(0xF099D)
                            color: vpnCard.modelData.active === true ? Commons.Color.accent : root.dim
                            font.family: root.font
                            font.pixelSize: Style.font.body
                          }
                          Text {
                            id: vpnNameText
                            textFormat: Text.PlainText
                            anchors.left: vpnCardIcon.right
                            anchors.leftMargin: Style.space(8)
                            anchors.right: vpnToggle.left
                            anchors.rightMargin: Style.space(8)
                            anchors.verticalCenter: parent.verticalCenter
                            elide: Text.ElideRight
                            text: String(vpnCard.modelData.name || "")
                            color: root.fg
                            font.family: root.font
                            font.pixelSize: Style.font.bodySmall
                            font.bold: true
                          }
                          ToggleSwitch {
                            id: vpnToggle
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            cursorRing: false
                            rounded: root.corners.pill > 0
                            checked: vpnCard.modelData.active === true
                            enabled: !root.wifiBusy
                            foreground: root.fg
                            onToggled: root.toggleConn(vpnCard.modelData.uuid, !(vpnCard.modelData.active === true))
                          }
                        }
                      }
                    }
                  }
                }
              }

              PanelSeparator { width: parent.width; foreground: root.fg }

              Flow {
                width: parent.width
                spacing: Style.space(8)
                Button {
                  visible: root.activePage === "devices" || root.activePage === "map"
                  radius: root.corners.control
                  // Same label and glyph while scanning (the icon just spins), so the
                  // button keeps its width and the buttons next to it do not move.
                  text: root.t("rescan")
                  iconText: root.glyph(0xF0450)
                  iconSpinning: root.scanning
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  enabled: !root.scanning
                  tooltipText: root.t("rescanTip")
                  onClicked: if (root.hostWidget) root.hostWidget.rescan()
                }
                Button {
                  visible: (root.activePage === "devices" || root.activePage === "map")
                    && root.gatewayDevice !== null && String(root.gatewayDevice.web_url || "") !== ""
                  radius: root.corners.control
                  text: root.t("kRouter")
                  iconText: root.glyph(0xF0469)
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  tooltipText: root.gatewayDevice ? root.t("routerTip", [root.gatewayDevice.web_url]) : ""
                  onClicked: if (root.gatewayDevice) root.openWeb(root.gatewayDevice.web_url)
                }
                Button {
                  visible: (root.activePage === "devices" || root.activePage === "map") && root.stats.active === true
                  radius: root.corners.control
                  text: root.trusted ? root.t("untrust") : root.t("trust")
                  iconText: root.glyph(root.trusted ? 0xF099C : 0xF0565)
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  enabled: root.link.can_trust === true
                  tooltipText: root.trusted
                    ? root.t("untrustTip")
                    : root.t("trustTip")
                  onClicked: if (root.hostWidget) root.hostWidget.setTrusted(!root.trusted)
                }
                Button {
                  visible: root.activePage === "devices" || root.activePage === "map"
                  radius: root.corners.control
                  iconText: root.glyph(0xF05A9)
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  tooltipText: root.t("wifiTip")
                  onClicked: root.openSystemNetSettings()
                }
                Button {
                  visible: root.activePage === "monitor"
                  radius: root.corners.control
                  text: root.netmonPaused ? root.t("resume") : root.t("pause")
                  iconText: root.glyph(root.netmonPaused ? 0xF040A : 0xF03E4)
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  tooltipText: root.netmonPaused ? root.t("resumeTip") : root.t("pauseTip")
                  onClicked: root.netmonPaused = !root.netmonPaused
                }
                Button {
                  visible: root.activePage === "monitor"
                  radius: root.corners.control
                  text: root.netmonTableCopied ? root.t("copied") : root.t("copyTable")
                  iconText: root.glyph(root.netmonTableCopied ? 0xF012C : 0xF018F)
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  onClicked: root.copyNetmonTable()
                }
                Button {
                  visible: root.activePage === "setup"
                  radius: root.corners.control
                  text: root.t("sysNetSettings")
                  iconText: root.glyph(0xF05A9)
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  tooltipText: root.t("wifiTip")
                  onClicked: root.openSystemNetSettings()
                }
              }
            }
          }
        }
      }
    }
  }
}
