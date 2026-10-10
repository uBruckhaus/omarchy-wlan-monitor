pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui as Ui

// Bar indicator for the local WLAN. Dim radar icon while disconnected; coloured
// radar chip plus online device count while connected, with a thin signal-quality
// bar underneath. Pulses while scanning the subnet. Left click opens the panel;
// right click triggers an immediate rescan.
Ui.BarWidget {
  id: root
  moduleName: "ubruckhaus.wlan-monitor"

  property var stats: ({})
  // Push every snapshot into the panel; never let it read from an older widget instance.
  onStatsChanged: if (panelLoader.item && "stats" in panelLoader.item) panelLoader.item.stats = root.stats
  readonly property bool active: stats.active === true
  readonly property int onlineCount: Number(stats.online_count || 0)
  readonly property int totalCount: Number(stats.total_count || 0)
  readonly property bool scanning: stats.scanning === true || onDemandScanner.running
  readonly property string scriptDir: Qt.resolvedUrl("scripts").toString().replace(/^file:\/\//, "")

  // Signal quality fraction in 0..1, or -1 when unknown (e.g. Ethernet fallback).
  readonly property real signalFraction: {
    var link = stats.link
    if (!active || !link || link.quality === null || link.quality === undefined) return -1
    return Math.max(0, Math.min(1, Number(link.quality) / 100))
  }

  // Signal level in the theme's named colours: green >= 70%, yellow >= 50%, orange >= 30%, red < 30%.
  property var levelPalette: ({ green: "#9cba64", yellow: "#d9ab5e", orange: "#e09355", red: "#db6c4f" })
  function signalColor(fraction) {
    return fraction < 0 ? Color.accent
      : fraction >= 0.7 ? levelPalette.green
      : fraction >= 0.5 ? levelPalette.yellow
      : fraction >= 0.3 ? levelPalette.orange
      : levelPalette.red
  }
  readonly property color linkColor: signalColor(signalFraction)

  FileView {
    id: themeColors
    path: Color.currentThemePath + "/colors.toml"
    printErrors: false
    onLoaded: {
      var found = {}
      var lines = text().split("\n")
      for (var i = 0; i < lines.length; i++) {
        var match = lines[i].match(/^\s*(green|yellow|orange|red)\s*=\s*["']?(#[0-9A-Fa-f]{6})["']?/)
        if (match) found[match[1]] = match[2]
      }
      var merged = {}
      for (var key in root.levelPalette) merged[key] = found[key] || root.levelPalette[key]
      root.levelPalette = merged
    }
  }
  Connections {
    target: Color
    function onAccentChanged() { themeColors.reload() }
  }

  readonly property string barText: {
    if (!active) return "󰐻"
    return "󰐻 " + onlineCount
  }

  readonly property string summary: {
    if (!active || !stats.link) return "WLAN Monitor\nNot connected to a local network"
    var link = stats.link
    var sleeping = Math.max(0, totalCount - onlineCount)
    var header = (link.ssid || link.iface) + (link.band ? " · " + link.band : "")
      + (link.signal_dbm !== null && link.signal_dbm !== undefined ? " · " + link.signal_dbm + " dBm (" + link.quality + "%)" : "")
    var addr = "IP: " + (link.cidr || link.ip) + (link.gateway ? " · Gateway " + link.gateway : "")
    var counts = "Devices: " + onlineCount + " online" + (sleeping > 0 ? ", " + sleeping + " sleeping" : "")
    var names = (stats.devices || []).filter(function(d) { return d.online }).slice(0, 6).map(function(d) {
      return "• " + d.name + " (" + d.ip + ")"
    }).join("\n")
    return header + "\n" + addr + "\n" + counts + (names ? "\n" + names : "")
  }

  function rescan() {
    if (!onDemandScanner.running) onDemandScanner.running = true
  }

  // Continuous background collector streaming a JSON snapshot every 3 seconds.
  Process {
    id: collector
    command: ["python3", root.scriptDir + "/wlan-monitor.py"]
    running: true
    stdout: SplitParser {
      onRead: function(line) {
        try {
          var data = JSON.parse(line)
          if (!data.error) root.stats = data
        } catch (e) { /* partial line during shutdown */ }
      }
    }
    onExited: restart.start()
  }
  Timer { id: restart; interval: 5000; onTriggered: collector.running = true }

  // On-demand active subnet + mDNS scan when the user clicks "Rescan WLAN" or right-clicks.
  Process {
    id: onDemandScanner
    command: ["python3", root.scriptDir + "/wlan-monitor.py", "--once"]
    running: false
    stdout: SplitParser {
      onRead: function(line) {
        try {
          var data = JSON.parse(line)
          if (!data.error) root.stats = data
        } catch (e) {}
      }
    }
  }

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
    readonly property color base: root.bar ? root.bar.barForeground : Color.foreground
    foreground: root.active ? Qt.tint(root.linkColor, Qt.rgba(base.r, base.g, base.b, root.glow * 0.75)) : base
    tooltipText: root.opened ? "" : root.summary
    onPressed: function(code) {
      if (code === Qt.LeftButton) root.toggle()
      else if (code === Qt.RightButton) root.rescan()
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
