pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui as Ui
import "I18n.js" as I18n

// Bar indicator for the local WLAN. Dim radar icon while disconnected; green radar
// icon (theme green) while connected, blue (theme blue) while a VPN is active, with a thin signal-quality bar underneath. Pulses while scanning the subnet. Left click opens the panel;
// right click triggers an immediate rescan. A small dot marks devices that joined
// recently. Commands (rescan, panel open/closed, trust/untrust network, per-device
// rename / pin / hide as one-line JSON) go to the collector over stdin.
Ui.BarWidget {
  id: root
  moduleName: "ubruckhaus.wlan-monitor"

  property var stats: ({})
  // Push every snapshot into the panel; never let it read from an older widget instance.
  onStatsChanged: if (panelLoader.item && "stats" in panelLoader.item) panelLoader.item.stats = root.stats
  readonly property bool active: stats.active === true
  readonly property int onlineCount: Number(stats.online_count || 0)
  readonly property int totalCount: Number(stats.total_count || 0)
  readonly property int newCount: Number(stats.new_count || 0)
  property bool scanBusy: false       // collector reported that a sweep is running
  property bool rescanPending: false  // user asked for a rescan, waiting for the result
  readonly property bool scanning: scanBusy || rescanPending
  readonly property bool trusted: active && stats.link && stats.link.trusted === true
  // A VPN is up (blue icon); lanBlocked: it also blocks the home network.
  readonly property var vpn: active && stats.link && stats.link.vpn ? stats.link.vpn : null
  readonly property bool lanBlocked: vpn !== null && vpn.lan_blocked === true
  readonly property color vpnBlue: button.vpnColor  // shared with the panel's VPN notice
  readonly property string scriptDir: Qt.resolvedUrl("scripts").toString().replace(/^file:\/\//, "")

  // Signal quality fraction in 0..1, or -1 when unknown (e.g. Ethernet fallback).
  readonly property real signalFraction: {
    var link = stats.link
    if (!active || !link || link.quality === null || link.quality === undefined) return -1
    return Math.max(0, Math.min(1, Number(link.quality) / 100))
  }

  // Signal level in the theme's named colours: green >= 70%, yellow >= 50%, orange >= 30%, red < 30%.
  property var levelPalette: ({ green: "#9cba64", yellow: "#d9ab5e", orange: "#e09355", red: "#db6c4f", blue: "#6fa3d8" })
  function signalColor(fraction) {
    return fraction < 0 ? Commons.Color.accent
      : fraction >= 0.7 ? levelPalette.green
      : fraction >= 0.5 ? levelPalette.yellow
      : fraction >= 0.3 ? levelPalette.orange
      : levelPalette.red
  }
  readonly property color linkColor: signalColor(signalFraction)

  FileView {
    id: themeColors
    path: Commons.Color.currentThemePath + "/colors.toml"
    printErrors: false
    onLoaded: {
      var found = {}
      var lines = text().split("\n")
      for (var i = 0; i < lines.length; i++) {
        var match = lines[i].match(/^\s*(green|yellow|orange|red|blue)\s*=\s*["']?(#[0-9A-Fa-f]{6})["']?/)
        if (match) found[match[1]] = match[2]
      }
      var merged = {}
      for (var key in root.levelPalette) merged[key] = found[key] || root.levelPalette[key]
      root.levelPalette = merged
    }
  }
  Connections {
    target: Commons.Color
    function onAccentChanged() { themeColors.reload() }
  }

  readonly property string barText: "󰐻"

  readonly property string summary: {
    if (!active || !stats.link) return "WLAN Monitor\n" + t("tipNotConnected")
    var link = stats.link
    var idle = Number(stats.idle_count || 0)
    var sleeping = Math.max(0, totalCount - onlineCount - idle)
    var q = Number(link.quality || 0)
    var header = (link.ssid || link.iface) + (link.band ? " · " + link.band : "")
      + (link.quality !== null && link.quality !== undefined
        ? " · " + t("tipSignal", [t(q >= 70 ? "sigExcellent" : q >= 50 ? "sigGood" : q >= 30 ? "sigFair" : "sigWeak").toLowerCase(), q]) : "")
    var counts = t("tipCounts", [tn("devices", totalCount), onlineCount])
      + (idle > 0 ? ", " + t("tipIdle", [idle]) : "") + (sleeping > 0 ? ", " + t("tipSleeping", [sleeping]) : "")
      + (root.newCount > 0 ? " · " + t("tipNew", [root.newCount]) : "")
    var mode = root.trusted ? "" : "\n" + t("tipPassive")
    if (root.vpn) {
      var hint = String(root.vpn.hint || "")
      hint = hint.indexOf("Allow it with: ") === 0 ? t("allowWith", [hint.slice(15)]) : t("vpnHintGeneric")
      mode = "\n" + (root.lanBlocked ? t("tipVpnBlocks", [root.vpn.name, hint]) : t("tipVpnOk", [root.vpn.name])) + mode
    }
    var names = (stats.devices || []).filter(function(d) { return d.online && !d.hidden }).slice(0, 6).map(function(d) {
      return "• " + d.name + (d.new ? "  " + t("newMark") : "")
    }).join("\n")
    return header + "\n" + counts + mode + (names ? "\n" + names : "")
  }

  // Interface language: the system's unless one is picked in the panel's
  // settings (stored in this widget's own shell.json entry).
  readonly property string systemLang: I18n.systemLanguage(Quickshell.env("LC_ALL"), Quickshell.env("LC_MESSAGES"), Quickshell.env("LANG"))
  readonly property string languageSetting: String(root.setting("language", "auto"))
  readonly property string lang: I18n.resolve(languageSetting, systemLang)
  function t(key, args) { return I18n.tr(lang, key, args) }
  function tn(key, n, args) { return I18n.trn(lang, key, n, args) }
  function setLanguage(code) {
    if (!root.bar || !root.bar.shell || typeof root.bar.shell.updateEntryInline !== "function") return
    var next = Object.assign({}, root.settings || {})
    if (code === "auto") delete next.language
    else next.language = code
    root.bar.shell.updateEntryInline(root.moduleName, next)
  }

  // The collector writes new-device notifications; tell it the language.
  onLangChanged: sendJson({ cmd: "lang", lang: root.lang })

  function send(command) {
    if (collector.running) collector.write(command + "\n")
  }
  function rescan() {
    if (rescanPending) return
    rescanPending = true
    send("rescan")
  }
  function setTrusted(trust) { send(trust ? "trust" : "untrust") }
  // Per-device commands; JSON.stringify keeps them on one line, the collector validates them.
  function sendJson(payload) { send(JSON.stringify(payload)) }

  // Background collector streaming a JSON snapshot every 3 s (panel open) / 6 s (closed).
  Process {
    id: collector
    command: ["python3", root.scriptDir + "/wlan-monitor.py"]
    running: true
    stdinEnabled: true
    stdout: SplitParser {
      onRead: function(line) {
        try {
          var data = JSON.parse(line)
          if (data.event === "scanning") { root.scanBusy = true; return }
          if (data.error) return
          root.stats = data
          root.scanBusy = false
          root.rescanPending = false
        } catch (e) { /* partial line during shutdown */ }
      }
    }
    onRunningChanged: if (running) Qt.callLater(function() {
      root.sendJson({ cmd: "lang", lang: root.lang })
      if (root.opened) root.send("open")
    })
    onExited: { root.scanBusy = false; root.rescanPending = false; restart.start() }
  }
  Timer { id: restart; interval: 5000; onTriggered: collector.running = true }
  onOpenedChanged: send(opened ? "open" : "closed")

  function injectPanel() {
    var target = panelLoader.item
    if (!target) return
    if ("bar" in target) target.bar = root.bar
    if ("anchorItem" in target) target.anchorItem = button
    if ("hostWidget" in target) target.hostWidget = root
    if ("stats" in target) target.stats = root.stats
  }

  // Shape contract for shell summon/hide/toggle routing.
  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false
  function open() { if (panelLoader.item) panelLoader.item.open() }
  function close() { if (panelLoader.item) panelLoader.item.close() }
  function toggle() { if (panelLoader.item) panelLoader.item.toggle() }
  function closeForPopoutSwitch() { if (panelLoader.item) panelLoader.item.closeForPopoutSwitch() }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight
  onBarChanged: injectPanel()

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml") + "?load=" + Date.now()
    visible: false
    onLoaded: { root.injectPanel(); Qt.callLater(root.injectPanel) }
  }

  // 0..1 glow while actively scanning the subnet.
  property real glow: 0
  SequentialAnimation on glow {
    running: root.scanning
    loops: Animation.Infinite
    NumberAnimation { to: 1; duration: 650; easing.type: Easing.InOutSine }
    NumberAnimation { to: 0; duration: 650; easing.type: Easing.InOutSine }
    onRunningChanged: if (!running) root.glow = 0
  }

  Ui.WidgetButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.barText
    dimmed: !root.active
    readonly property color base: root.bar ? root.bar.barForeground : Commons.Color.foreground
    // Theme green when it really is green (hue ~75-165°); some themes map "green"
    // to teal, so fall back to a fixed green there.
    readonly property color themeGreen: root.levelPalette.green
    readonly property color connectedColor: themeGreen.hslHue >= 0.21 && themeGreen.hslHue <= 0.46
      && themeGreen.hslSaturation > 0.2 ? themeGreen : "#5fb760"
    // Blue while a VPN is active (theme blue when it really is blue, hue ~190-260°).
    readonly property color themeBlue: root.levelPalette.blue
    readonly property color vpnColor: themeBlue.hslHue >= 0.52 && themeBlue.hslHue <= 0.73
      && themeBlue.hslSaturation > 0.2 ? themeBlue : "#5b9bd5"
    readonly property color iconColor: root.vpn ? vpnColor : connectedColor
    foreground: root.active ? Qt.tint(iconColor, Qt.rgba(base.r, base.g, base.b, root.glow * 0.75)) : base
    tooltipText: root.opened ? "" : root.summary
    onPressed: function(code) {
      if (code === Qt.LeftButton) root.toggle()
      else if (code === Qt.RightButton) root.rescan()
    }

    // Accent dot: devices joined recently and are not marked as known yet.
    Rectangle {
      visible: root.newCount > 0
      anchors.top: parent.top
      anchors.right: parent.right
      anchors.topMargin: Style.space(4)
      anchors.rightMargin: Style.space(4)
      width: Style.space(6)
      height: width
      radius: width / 2
      color: Commons.Color.accent
    }

    // Signal quality bar under the chip: grows with Wi-Fi signal strength, coloured by level.
    Rectangle {
      visible: root.signalFraction >= 0 && !(root.bar && root.bar.vertical)
      anchors.bottom: parent.bottom
      anchors.bottomMargin: Style.space(3)
      x: Style.space(6)
      width: (parent.width - 2 * x) * Math.max(0.05, root.signalFraction)
      height: Style.space(2)
      radius: height / 2
      color: root.linkColor
      Behavior on width { NumberAnimation { duration: 400; easing.type: Easing.OutCubic } }
      Behavior on color { ColorAnimation { duration: 400 } }
    }
  }
}
