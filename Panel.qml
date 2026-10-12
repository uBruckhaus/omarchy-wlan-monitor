pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

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
  readonly property var link: stats.link || ({})
  readonly property var traffic: stats.traffic || ({})
  // Only replace the device list when its content changed, so rows are not rebuilt every
  // tick, and never while a name is being edited (a rebuild would drop the text field).
  property var devices: []
  property string devicesRev: ""
  onStatsChanged: refreshDevices()
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
  readonly property var fritz: stats.fritz || ({})
  property bool fritzFormOpen: false
  property bool fritzHelpOpen: false
  property bool showPassword: false
  function fritzConnect() {
    if (!root.hostWidget || fritzPassword.text === "") return
    root.hostWidget.sendJson({ cmd: "fritz_login", user: fritzUser.text.trim(), password: fritzPassword.text })
    fritzPassword.clear()
    root.fritzFormOpen = false
    root.showPassword = false
    keyCatcher.forceActiveFocus()
  }
  readonly property int sleepingCount: Math.max(0, totalCount - onlineCount - idleCount)
  readonly property bool scanning: root.hostWidget ? root.hostWidget.scanning === true : (stats.scanning === true)
  readonly property color fg: Color.popups.text
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
  readonly property string viewMode: view.mode === "ap" && !meshActive ? "platform" : String(view.mode || "list")
  readonly property var viewModes: meshActive ? ["list", "platform", "type", "ap"] : ["list", "platform", "type"]
  readonly property var viewLabels: ({ list: "List", platform: "Groups by platform", type: "Groups by type", ap: "Groups by access point" })
  function saveView(mode, collapsed) {
    root.localView = { mode: mode, collapsed: collapsed }
    if (root.hostWidget) root.hostWidget.sendJson({ cmd: "view", mode: mode, collapsed: collapsed })
  }
  function cycleView() {
    var i = root.viewModes.indexOf(root.viewMode)
    root.saveView(root.viewModes[(i + 1) % root.viewModes.length], root.view.collapsed || [])
  }
  function toggleGroup(id) {
    var collapsed = (root.view.collapsed || []).slice()
    var at = collapsed.indexOf(id)
    if (at === -1) collapsed.push(id)
    else collapsed.splice(at, 1)
    root.saveView(root.viewMode, collapsed.slice(0, 32))
  }

  readonly property var groupInfo: ({
    favourites: { title: "Favourites", icon: 0xF04CE },
    apple: { title: "Apple", icon: 0xF0035 },
    android: { title: "Android", icon: 0xF0032 },
    mobile: { title: "Phones & tablets", icon: 0xF011C },
    computers: { title: "Computers", icon: 0xF0379 },
    media: { title: "TV & audio", icon: 0xF07F4 },
    smarthome: { title: "Smart home", icon: 0xF07D0 },
    office: { title: "Printers & storage", icon: 0xF042A },
    network: { title: "Network & mesh", icon: 0xF0003 },
    other: { title: "Other devices", icon: 0xF0625 },
    none: { title: "Not reported by the FRITZ!Box", icon: 0xF0625 }
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
        buckets[ap.mac] = { title: ap.name || "Access point", icon: 0xF0003,
          detail: ap.role === "master" ? "main router" : (ap.via ? "via " + ap.via + (ap.band ? " " + ap.band : "") : "repeater"), devs: [] }
      })
      order.push("none")
    } else {
      order = root.platformOrder
    }
    devs.forEach(function(dev) {
      if (dev.is_gateway || (dev.is_self && root.viewMode !== "ap")) { top.push(dev); return }
      var id
      if (root.viewMode === "ap") id = dev.mesh && buckets[dev.mesh.via_mac] ? dev.mesh.via_mac : "none"
      else if (dev.pinned) id = "favourites"
      else if (root.viewMode === "platform") id = dev.group || "other"
      else id = root.kindGroups[dev.kind] || "other"
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
        hasNew: hasNew, collapsed: isCollapsed && !hasNew
      })
      if (!isCollapsed || hasNew) bucket.devs.forEach(function(dev) { out.push({ type: "device", dev: dev, inGroup: true }) })
    })
    return out
  }

  function glyph(code) { return String.fromCodePoint(code) }
  readonly property var kindIcons: ({
    router: 0xF0469, computer: 0xF0379, laptop: 0xF0322, phone: 0xF011C, tablet: 0xF04F6,
    watch: 0xF0597, tv: 0xF07F4, speaker: 0xF04C3, printer: 0xF042A, console: 0xF0297,
    camera: 0xF07AE, light: 0xF0335, nas: 0xF048B, appliance: 0xF0176, smarthome: 0xF07D0,
    unknown: 0xF0625
  })
  readonly property var kindLabels: ({
    router: "Router", computer: "Computer", laptop: "Laptop", phone: "Phone", tablet: "Tablet",
    watch: "Watch", tv: "TV", speaker: "Speaker", printer: "Printer", console: "Game console",
    camera: "Camera", light: "Lighting", nas: "Storage / server", appliance: "Appliance",
    smarthome: "Smart-home device", unknown: "Device"
  })
  function kindIcon(kind) { return glyph(kindIcons[kind] || kindIcons.unknown) }
  function kindLabel(kind) { return kindLabels[kind] || kindLabels.unknown }
  function deviceKindLabel(dev) {
    return dev.kind === "router" && !dev.is_gateway ? "Repeater / access point" : kindLabel(dev.kind)
  }
  function meshText(dev) {
    var m = dev.mesh
    if (!m || !m.via) return ""
    // With a single access point "via …" says nothing new; the band is enough.
    if (((root.fritz.aps || []).length) <= 1) return m.band === "LAN" ? "cable" : (m.band || "")
    return "via " + m.via + (m.band ? " · " + m.band : "")
  }
  function meshDetail(dev) {
    var m = dev.mesh
    if (!m || (!m.band && !m.rate_mbps)) return ""
    var parts = []
    if (m.band) parts.push(m.band === "LAN" ? "cable (LAN)" : m.band)
    if (m.rate_mbps) parts.push(m.rate_mbps + " Mbit/s")
    if (m.signal_dbm !== null && m.signal_dbm !== undefined) {
      var q = Math.max(0, Math.min(100, 2 * (Number(m.signal_dbm) + 100)))
      parts.push(signalWord(q).toLowerCase() + " signal (" + m.signal_dbm + " dBm)")
    }
    return parts.join(" · ")
  }

  function signalColor(fraction) {
    return root.hostWidget && root.hostWidget.signalColor ? root.hostWidget.signalColor(fraction) : Color.accent
  }
  function signalWord(quality) {
    var q = Number(quality || 0)
    return q >= 70 ? "Excellent" : q >= 50 ? "Good" : q >= 30 ? "Fair" : "Weak"
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
    if (m < 1) return "just now"
    if (m < 60) return m + " min ago"
    return Math.floor(m / 60) + " h ago"
  }
  function statusWord(dev) {
    if (dev.is_gateway) return "router"
    if (dev.is_self) return "this PC"
    if (dev.online) return "online"
    if (dev.state === "idle") return "idle"
    var ago = agoText(dev.seen_min)
    return "sleeping" + (ago ? " · " + ago : "")
  }
  function statusExplain(dev) {
    if (dev.is_gateway) return "Your router: it connects all devices here to each other and to the internet."
    if (dev.is_self) return "This computer."
    if (dev.online) return "Online: the device answered just now."
    if (dev.state === "idle")
      return "Idle: connected recently but quiet for a while. On a network you have not trusted, the monitor does not ask devices directly, so it cannot tell whether they are asleep."
    var ago = agoText(dev.seen_min)
    return "Sleeping: not answering right now. Phones and tablets do this to save battery and still count as connected. "
      + (ago ? "Last seen " + ago + "." : "Known from your router's address list.")
  }
  function deviceRightLabel(dev) {
    var word = statusWord(dev)
    return (word === "online" || word === "router" ? "" : word + " · ") + dev.ip
  }
  function deviceSubtitle(dev) {
    var label = deviceKindLabel(dev)
    var parts = dev.name.indexOf(label) === 0 ? [] : [label]
    if (dev.is_gateway && dev.model && dev.name.indexOf(dev.model) === -1) parts.push("model " + dev.model)
    if (meshText(dev)) parts.push(meshText(dev))
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
  // Copy a device IP via wl-copy (fixed argv, no shell); only plain IPv4 literals.
  readonly property var ipPattern: /^(\d{1,3}\.){3}\d{1,3}$/
  function copyIp(ip) {
    var text = String(ip || "")
    if (!ipPattern.test(text)) return false
    Quickshell.execDetached(["wl-copy", text])
    return true
  }
  // The device list as a Markdown table on the clipboard (text from the collector is
  // already sanitized; `|` is replaced so cells stay intact). One argv entry, no shell.
  property bool listCopied: false
  Timer { id: listCopiedTimer; interval: 1600; onTriggered: root.listCopied = false }
  function copyList() {
    function cell(value) { return String(value || "").replace(/[|\r\n]/g, " ").trim() }
    var lines = [
      "# Devices on " + cell(root.link.ssid || "the network") + " (" + new Date().toLocaleString(Qt.locale(), Locale.ShortFormat) + ")",
      "",
      "| Name | Type | Status | IP | Maker | Model | MAC |",
      "| --- | --- | --- | --- | --- | --- | --- |"
    ]
    root.devices.slice(0, 256).forEach(function(dev) {
      lines.push("| " + [dev.name, root.kindLabel(dev.kind), root.statusWord(dev) + (dev.hidden ? " (hidden)" : ""),
        dev.ip, dev.vendor, dev.model, dev.mac].map(cell).join(" | ") + " |")
    })
    Quickshell.execDetached(["wl-copy", "--", lines.join("\n") + "\n"])
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
    root.editingKey = ""
    root.controller.hide()
  }
  function toggle() { if (root.opened) root.close(); else root.open() }

  component Meter: Item {
    id: meter
    property string label: ""
    property string value: ""
    property string tip: ""
    property real fraction: 0
    property color fillColor: Color.accent
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
      radius: height / 2
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
    color: actionMouse.containsMouse ? Color.accent : baseColor
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
      radius: Style.space(6)
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
          color: block.online ? Color.accent : root.dim
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
            anchors.fill: parent
            maximumLength: 40
            placeholderText: block.dev.auto_name || "Device name"
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
            text: "NEW"
            color: Color.accent
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
            color: webMouse.containsMouse ? Color.accent : root.fg
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
            PanelToolTip { visible: webMouse.containsMouse; text: "Open " + block.webUrl; fontFamily: root.font }
          }
        }
        Text {
          textFormat: Text.PlainText
          id: deviceIp
          anchors.right: copyIcon.left
          anchors.rightMargin: Style.space(6)
          anchors.verticalCenter: parent.verticalCenter
          text: block.copied ? "copied to clipboard" : root.deviceRightLabel(block.dev)
          color: (block.dev.is_gateway || block.dev.is_self)
            ? Color.accent
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
          color: block.copied || copyMouse.containsMouse ? Color.accent : root.dim
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
          PanelToolTip { visible: copyMouse.containsMouse && !block.copied; text: "Copy IP address"; fontFamily: root.font }
        }
      }

      Text {
        textFormat: Text.PlainText
        visible: text !== ""
        width: parent.width
        leftPadding: Style.space(24)
        elide: Text.ElideRight
        text: block.editing ? "Enter saves · Esc cancels · empty restores the automatic name" : root.deviceSubtitle(block.dev)
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
            ["Connected via", block.dev.mesh && block.dev.mesh.via && !block.dev.is_gateway ? block.dev.mesh.via : ""],
            ["Connection", root.meshDetail(block.dev)],
            ["Maker", block.dev.vendor === "Private MAC"
              ? "unknown (hidden by a private address)" : block.dev.vendor],
            ["Model", block.dev.model],
            ["Automatic name", block.dev.custom_name ? block.dev.auto_name : ""],
            ["Network name", block.dev.hostname && block.dev.hostname !== block.dev.name ? block.dev.hostname : ""],
            ["IP address", block.dev.ip],
            ["MAC address", block.dev.mac]
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
            label: "Rename"
            onActivated: root.startRename(block.dev)
          }
          LinkAction {
            visible: block.editing
            icon: root.glyph(0xF012C)
            label: "Save"
            onActivated: root.finishRename(block.dev, nameField.text)
          }
          LinkAction {
            visible: block.dev.can_edit === true && !block.dev.is_gateway && !block.dev.is_self && !block.editing
            icon: root.glyph(block.dev.pinned ? 0xF0404 : 0xF0403)
            label: block.dev.pinned ? "Unpin" : "Pin to top"
            onActivated: root.deviceCommand("pin", block.dev, { on: !block.dev.pinned })
          }
          LinkAction {
            visible: block.dev.can_edit === true && !block.dev.is_gateway && !block.dev.is_self && !block.editing
            icon: root.glyph(block.dev.hidden ? 0xF0208 : 0xF0209)
            label: block.dev.hidden ? "Show" : "Hide"
            onActivated: {
              root.deviceCommand("hide", block.dev, { on: !block.dev.hidden })
              if (!block.dev.hidden) root.expandedKey = ""
            }
          }
          LinkAction {
            visible: block.webUrl !== "" && !block.editing
            icon: root.glyph(0xF059F)
            label: "Open web page"
            onActivated: root.openWeb(block.webUrl)
          }
          LinkAction {
            visible: block.dev.new === true && !block.editing
            icon: root.glyph(0xF05E0)
            label: "It's mine"
            onActivated: root.deviceCommand("known", block.dev, { on: true })
          }
        }
        Text {
          visible: block.dev.can_edit !== true
          textFormat: Text.PlainText
          width: parent.width - parent.leftPadding
          wrapMode: Text.WordWrap
          text: "This device's hardware address is unknown, so it cannot be renamed yet. Try again when it is online."
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
      radius: Style.space(6)
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
        color: header.group.online > 0 ? Color.accent : root.dim
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
        text: (header.group.hasNew ? "NEW  " : "") + header.group.count + (header.group.online !== header.group.count
          ? " · " + header.group.online + " online" : "")
        color: header.group.hasNew ? Color.accent : root.dim
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
  Component { id: groupHeaderComponent; GroupHeader {} }
  Component { id: deviceRowComponent; DeviceRow {} }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem
    owner: root.barIdentity
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(410))
    contentHeight: panel.fittedContentHeight(column.implicitHeight)

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // Text fields need every key while they have focus.
      blocked: searchField.activeFocus || root.editingKey !== "" || fritzUser.activeFocus || fritzPassword.activeFocus
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(t) {
        if (t === "/" && root.showSearch) searchField.forceActiveFocus()
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
              : "Not connected"
            detail: root.stats.active ? root.onlineCount + " online" : ""
            iconComponent: Component {
              Text {
                textFormat: Text.PlainText
                text: root.glyph(0xF043B)
                color: root.stats.active ? Color.accent : root.dim
                font.family: root.font
                font.pixelSize: Style.font.display
              }
            }
          }

          PanelSeparator { width: parent.width; foreground: root.fg }
          PanelSectionHeader { text: "CONNECTION"; foreground: root.fg; fontFamily: root.font }

          Item {
            width: parent.width
            height: ipText.height
            Text {
              textFormat: Text.PlainText
              id: ipText
              text: "This PC  " + (root.link.ip || "—")
              color: root.fg
              font.family: root.font
              font.pixelSize: Style.font.body
              font.bold: true
            }
            Text {
              textFormat: Text.PlainText
              anchors.right: parent.right
              anchors.baseline: ipText.baseline
              text: root.link.gateway ? "Router  " + root.link.gateway : ""
              color: root.dim
              font.family: root.font
              font.pixelSize: Style.font.caption
            }
            MouseArea { id: ipMouse; anchors.fill: parent; hoverEnabled: true; acceptedButtons: Qt.NoButton }
            PanelToolTip {
              visible: ipMouse.containsMouse && root.stats.active === true
              fontFamily: root.font
              text: "Address " + (root.link.cidr || root.link.ip || "—") + " on " + (root.link.iface || "?")
                + (root.link.mac ? "\nMAC " + root.link.mac : "")
                + (root.link.domain ? "\nLocal domain " + root.link.domain : "")
            }
          }

          Meter {
            visible: root.link.quality !== null && root.link.quality !== undefined
            readonly property real sigFrac: Math.max(0, Math.min(1, Number(root.link.quality || 0) / 100))
            label: "Signal  ·  " + root.signalWord(root.link.quality)
            value: (root.link.quality || 0) + " %"
            fraction: sigFrac
            fillColor: root.signalColor(sigFrac)
            tip: (root.link.signal_dbm !== null && root.link.signal_dbm !== undefined ? root.link.signal_dbm + " dBm" : "")
              + (root.link.channel ? "  ·  channel " + root.link.channel : "")
              + (root.link.tx_mbps ? "  ·  link " + root.link.tx_mbps + (root.link.rx_mbps ? " / " + root.link.rx_mbps : "") + " Mbit/s" : "")
              + "\nExcellent 70 %+, Good 50 %+, Fair 30 %+, Weak below 30 %."
              + "\nWeak? Move closer to the router or remove obstacles between you."
          }

          Meter {
            label: "Traffic now"
            value: "↓ " + root.formatRate(root.traffic.rx_rate) + "  ·  ↑ " + root.formatRate(root.traffic.tx_rate)
            // Logarithmic-like visual activity bar up to ~10 MB/s
            fraction: {
              var totalRate = Number(root.traffic.rx_rate || 0) + Number(root.traffic.tx_rate || 0)
              if (totalRate <= 0) return 0
              return Math.min(1, Math.log10(1 + totalRate / 1024) / 4)
            }
            fillColor: Color.accent
            tip: "↓ download, ↑ upload of this PC.\nSince connecting: " + root.formatBytes(root.traffic.rx_bytes)
              + " down, " + root.formatBytes(root.traffic.tx_bytes) + " up."
          }

          Text {
            textFormat: Text.PlainText
            visible: root.stats.active === true
            width: parent.width
            wrapMode: Text.WordWrap
            text: root.trusted
              ? "Your network (trusted): looks for devices every 2 minutes"
                + (root.alertsOn ? " and tells you when a new one joins." : ". New-device alerts are off.")
              : "Not marked as your network, so only devices that announce themselves are shown. "
                + "If this is your home network, click Trust to find every device and get alerts about new ones."
            color: root.dim
            font.family: root.font
            font.pixelSize: Style.font.caption
          }

          Text {
            textFormat: Text.PlainText
            visible: String(root.link.via || "") !== ""
            width: parent.width
            elide: Text.ElideRight
            text: root.glyph(0xF0003) + "  Connected via " + root.link.via + (root.link.via_band ? " · " + root.link.via_band : "")
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
                text: root.glyph(0xF0003) + "  FRITZ!Box connected · " + (root.fritz.aps || []).length + " access point"
                  + ((root.fritz.aps || []).length === 1 ? "" : "s")
                color: root.dim
                font.family: root.font
                font.pixelSize: Style.font.caption
              }
              LinkAction {
                visible: root.fritz.state !== "connected" && root.fritz.state !== "connecting" && !root.fritzFormOpen
                icon: root.glyph(0xF0306)
                label: root.fritz.state === "error" && root.fritz.user ? "Connect FRITZ!Box again" : "Show mesh details from the FRITZ!Box"
                baseColor: root.dim
                onActivated: {
                  root.fritzFormOpen = true
                  if (root.fritz.user && fritzUser.text === "") fritzUser.text = root.fritz.user
                  Qt.callLater(function() { (fritzUser.text === "" ? fritzUser : fritzPassword).forceActiveFocus() })
                }
              }
              LinkAction {
                visible: root.fritz.user !== undefined && root.fritz.user !== "" && !root.fritzFormOpen
                icon: root.glyph(0xF0209)
                label: "Disconnect"
                baseColor: root.dim
                onActivated: if (root.hostWidget) root.hostWidget.send("fritz_logout")
              }
            }
            Text {
              textFormat: Text.PlainText
              visible: (root.fritz.state === "error" || root.fritz.state === "connecting") && String(root.fritz.message || "") !== ""
              width: parent.width
              wrapMode: Text.WordWrap
              text: String(root.fritz.message || "")
              color: root.fritz.state === "error" ? Color.accent : root.dim
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
                text: "Shows which access point, band and speed every device uses, and the names from your FRITZ!Box. "
                  + "Use a FRITZ!Box user with the right \u201cFRITZ!Box settings\u201d (System \u203a FRITZ!Box Users). "
                  + "The password is stored only on this PC (readable by you alone) and used only with this FRITZ!Box."
                color: root.dim
                font.family: root.font
                font.pixelSize: Style.font.caption
              }
              KeyTextField {
                id: fritzUser
                width: parent.width
                maximumLength: 64
                placeholderText: "User name, e.g. fritz1234"
                foreground: root.fg
                font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                Keys.onPressed: function(event) {
                  if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Tab) {
                    fritzPassword.forceActiveFocus(); event.accepted = true
                  } else if (event.key === Qt.Key_Escape) {
                    root.fritzFormOpen = false; keyCatcher.forceActiveFocus(); event.accepted = true
                  }
                }
              }
              LinkAction {
                icon: root.glyph(root.fritzHelpOpen ? 0xF0140 : 0xF0142)
                label: "Where do I find user name and password?"
                baseColor: root.dim
                onActivated: root.fritzHelpOpen = !root.fritzHelpOpen
              }
              Text {
                textFormat: Text.PlainText
                visible: root.fritzHelpOpen
                width: parent.width
                leftPadding: Style.space(12)
                wrapMode: Text.WordWrap
                text: "• There is no fixed default user name.\n"
                  + "• FRITZ!OS before 7.24: the FRITZ!Box asks only for a password. Leave the user name empty.\n"
                  + "• FRITZ!OS 7.24 and newer: if you never created a user, an update created one named \u201cfritz\u201d "
                  + "plus four random digits (for example fritz1234). Log in at http://fritz.box and look under "
                  + "System \u203a FRITZ!Box Users.\n"
                  + "• Password: unless you changed it, it is printed on the label on the bottom or back of the "
                  + "FRITZ!Box (4 to 6 lowercase letters followed by 4 digits)."
                color: root.dim
                font.family: root.font
                font.pixelSize: Style.font.caption
              }
              KeyTextField {
                id: fritzPassword
                width: parent.width
                password: !root.showPassword
                maximumLength: 128
                placeholderText: "Password"
                foreground: root.fg
                font: Qt.font({ family: root.font, pixelSize: Style.font.caption })
                onAccepted: root.fritzConnect()
                Keys.onPressed: function(event) {
                  if (event.key === Qt.Key_Escape) {
                    fritzPassword.clear(); root.fritzFormOpen = false; root.showPassword = false
                    keyCatcher.forceActiveFocus(); event.accepted = true
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
                  color: eyeMouse.containsMouse ? Color.accent : root.dim
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
                    text: root.showPassword ? "Hide password" : "Show password"
                    fontFamily: root.font
                  }
                }
              }
              Flow {
                width: parent.width
                spacing: Style.space(8)
                Button {
                  text: "Connect"
                  iconText: root.glyph(0xF0306)
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  enabled: fritzPassword.text !== ""
                  onClicked: root.fritzConnect()
                }
                Button {
                  text: "Cancel"
                  bordered: true
                  foreground: root.fg
                  fontFamily: root.font
                  onClicked: {
                    fritzPassword.clear()
                    root.fritzFormOpen = false
                    root.showPassword = false
                    keyCatcher.forceActiveFocus()
                  }
                }
              }
            }
          }

          PanelSeparator { width: parent.width; foreground: root.fg }
          Item {
            width: parent.width
            height: devicesHeader.implicitHeight
            PanelSectionHeader {
              id: devicesHeader
              anchors.left: parent.left
              anchors.right: viewSwitch.left
              anchors.rightMargin: Style.space(8)
              text: "DEVICES (" + root.onlineCount + " ONLINE"
                + (root.idleCount > 0 ? " · " + root.idleCount + " IDLE" : "")
                + (root.sleepingCount > 0 ? " · " + root.sleepingCount + " SLEEPING" : "") + ")"
              foreground: root.fg
              fontFamily: root.font
            }
            LinkAction {
              id: viewSwitch
              anchors.right: parent.right
              anchors.verticalCenter: devicesHeader.verticalCenter
              icon: root.glyph(root.viewMode === "list" ? 0xF0279 : 0xF0570)
              label: root.viewLabels[root.viewMode] || "List"
              baseColor: root.dim
              onActivated: root.cycleView()
              MouseArea { id: viewTipMouse; anchors.fill: parent; hoverEnabled: true; acceptedButtons: Qt.NoButton }
              PanelToolTip {
                visible: viewTipMouse.containsMouse
                fontFamily: root.font
                text: "Switch between list and groups"
              }
            }
          }

          // New devices since the user last checked (trusted networks only).
          Rectangle {
            visible: root.newCount > 0
            width: parent.width
            height: newRow.implicitHeight + Style.space(12)
            radius: Style.space(6)
            color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.14)
            border.width: 1
            border.color: Qt.rgba(Color.accent.r, Color.accent.g, Color.accent.b, 0.5)
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
                text: root.glyph(0xF009A) + "  " + (root.newCount === 1 ? "1 new device joined" : root.newCount + " new devices joined")
                  + ". Not yours? Change your Wi-Fi password in the router."
                color: root.fg
                font.family: root.font
                font.pixelSize: Style.font.caption
              }
              LinkAction {
                id: newAction
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                icon: root.glyph(0xF05E0)
                label: "All known"
                onActivated: if (root.hostWidget) root.hostWidget.send("known_all")
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            visible: root.namedCount === 0 && root.devices.length > 1 && root.newCount === 0
            width: parent.width
            wrapMode: Text.WordWrap
            text: "Tip: click a device to see what it is, give it a name you recognise, pin it to the top or open its web page."
            color: root.dim
            font.family: root.font
            font.pixelSize: Style.font.caption
          }

          KeyTextField {
            id: searchField
            visible: root.showSearch
            width: parent.width
            placeholderText: root.glyph(0xF0349) + "  Search devices (/)"
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
            text: "Only a few devices visible. Click Rescan to look for more."
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
                text: "No device matches “" + root.filterText + "”."
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
              label: root.listCopied ? "Copied" : "Copy list"
              baseColor: root.dim
              onActivated: root.copyList()
            }
            LinkAction {
              visible: root.trusted
              icon: root.glyph(root.alertsOn ? 0xF009A : 0xF009B)
              label: root.alertsOn ? "Alerts on" : "Alerts off"
              baseColor: root.dim
              onActivated: if (root.hostWidget) root.hostWidget.sendJson({ cmd: "alerts", on: !root.alertsOn })
            }
            LinkAction {
              visible: root.hiddenCount > 0
              icon: root.glyph(root.showHidden ? 0xF0209 : 0xF0208)
              label: (root.showHidden ? "Hide " : "Show ") + root.hiddenCount + " hidden"
              baseColor: root.dim
              onActivated: root.showHidden = !root.showHidden
            }
          }

          PanelSeparator { width: parent.width; foreground: root.fg }

          Flow {
            width: parent.width
            spacing: Style.space(8)
            Button {
              // Same label and glyph while scanning (the icon just spins), so the
              // button keeps its width and the buttons next to it do not move.
              text: "Rescan"
              iconText: root.glyph(0xF0450)
              iconSpinning: root.scanning
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              enabled: !root.scanning
              tooltipText: "Look for devices on this network right now"
              onClicked: if (root.hostWidget) root.hostWidget.rescan()
            }
            Button {
              visible: root.gatewayDevice !== null && String(root.gatewayDevice.web_url || "") !== ""
              text: "Router"
              iconText: root.glyph(0xF0469)
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              tooltipText: root.gatewayDevice ? "Open your router's settings page (" + root.gatewayDevice.web_url + ")" : ""
              onClicked: if (root.gatewayDevice) root.openWeb(root.gatewayDevice.web_url)
            }
            Button {
              visible: root.stats.active === true
              text: root.trusted ? "Untrust" : "Trust"
              iconText: root.glyph(root.trusted ? 0xF099C : 0xF0565)
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              enabled: root.link.can_trust === true
              tooltipText: root.trusted
                ? "Stop looking for devices actively on this network and stop new-device alerts"
                : "This is my network: look for all devices every 2 minutes and alert me about new ones. Only do this at home or at work."
              onClicked: if (root.hostWidget) root.hostWidget.setTrusted(!root.trusted)
            }
            Button {
              iconText: root.glyph(0xF05A9)
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              tooltipText: "Open Omarchy's Wi-Fi settings"
              onClicked: {
                root.close()
                // Third-party plugins may not summon built-in panels directly, so go
                // through the shell CLI (fixed argv, no shell string).
                Quickshell.execDetached(["omarchy-shell", "shell", "summon", "omarchy.network", "{}"])
              }
            }
          }
        }
      }
    }
  }
}
