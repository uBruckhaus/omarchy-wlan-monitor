pragma ComponentBehavior: Bound
import QtQuick
import Quickshell
import qs.Commons
import qs.Ui

// Detail popup: Wi-Fi link & signal quality, live throughput, and the list of
// discovered devices on the local WLAN (online and sleeping) with IP, hostname,
// manufacturer, model and MAC address. Rows of devices with a web interface
// (router, devices announcing _http._tcp / printer admin pages) open it on click.
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
  // Only replace the device list when its content changed, so rows are not rebuilt every tick.
  property var devices: []
  property string devicesRev: ""
  onStatsChanged: {
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
  // About five device rows; together with the link section this matches the LLM Monitor panel.
  readonly property real maxDeviceListHeight: Style.space(244)
  readonly property int onlineCount: Number(stats.online_count || 0)
  readonly property int totalCount: Number(stats.total_count || 0)
  readonly property int idleCount: Number(stats.idle_count || 0)
  readonly property int sleepingCount: Math.max(0, totalCount - onlineCount - idleCount)
  readonly property bool scanning: root.hostWidget ? root.hostWidget.scanning === true : (stats.scanning === true)
  readonly property color fg: Color.popups.text
  readonly property color dim: Qt.darker(fg, 1.45)
  readonly property string font: root.bar ? root.bar.fontFamily : Style.font.family

  function signalColor(fraction) {
    return root.hostWidget && root.hostWidget.signalColor ? root.hostWidget.signalColor(fraction) : Color.accent
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
  function deviceRightLabel(dev) {
    var web = dev.web_url ? "󰖟  " : ""
    if (dev.is_gateway) return web + "router · " + dev.ip
    if (dev.is_self) return "this PC · " + dev.ip
    if (!dev.online) return web + (dev.state === "idle" ? "idle · " : "sleeping · ") + dev.ip
    return web + dev.ip
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
  function deviceSubtitle(dev) {
    var parts = []
    if (dev.vendor) parts.push(dev.vendor)
    if (dev.model && dev.model !== dev.vendor) parts.push(dev.model)
    if (dev.hostname && dev.hostname.toLowerCase() !== dev.name.toLowerCase()) parts.push(dev.hostname)
    if (dev.mac) parts.push(dev.mac)
    return parts.join("  ·  ")
  }

  function open() { root.controller.show() }
  function close() { root.controller.hide() }
  function toggle() { if (root.opened) root.close(); else root.open() }

  component Meter: Item {
    id: meter
    property string label: ""
    property string value: ""
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
  }

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
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

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
                text: "󰐻"
                color: root.stats.active ? Color.accent : root.dim
                font.family: root.font
                font.pixelSize: Style.font.display
              }
            }
          }

          PanelSeparator { width: parent.width; foreground: root.fg }
          PanelSectionHeader { text: "WLAN LINK"; foreground: root.fg; fontFamily: root.font }

          Item {
            width: parent.width
            height: ipText.height
            Text {
              textFormat: Text.PlainText
              id: ipText
              text: (root.link.cidr || root.link.ip || "—") + (root.link.iface ? "  (" + root.link.iface + ")" : "")
              color: root.fg
              font.family: root.font
              font.pixelSize: Style.font.body
              font.bold: true
            }
            Text {
              textFormat: Text.PlainText
              anchors.right: parent.right
              anchors.baseline: ipText.baseline
              text: root.link.gateway ? "Gateway " + root.link.gateway : ""
              color: root.dim
              font.family: root.font
              font.pixelSize: Style.font.caption
            }
          }

          Meter {
            visible: root.link.quality !== null && root.link.quality !== undefined
            readonly property real sigFrac: Math.max(0, Math.min(1, Number(root.link.quality || 0) / 100))
            label: "Signal"
              + (root.link.channel ? "  ·  Ch " + root.link.channel : "")
              + (root.link.tx_mbps ? "  ·  " + root.link.tx_mbps + (root.link.rx_mbps ? " / " + root.link.rx_mbps : "") + " Mbit/s" : "")
            value: (root.link.quality || 0) + "%" + (root.link.signal_dbm !== null && root.link.signal_dbm !== undefined ? " (" + root.link.signal_dbm + " dBm)" : "")
            fraction: sigFrac
            fillColor: root.signalColor(sigFrac)
          }

          Meter {
            label: "Traffic  ·  " + root.formatBytes(root.traffic.rx_bytes) + " / " + root.formatBytes(root.traffic.tx_bytes)
            value: "↓ " + root.formatRate(root.traffic.rx_rate) + "  ·  ↑ " + root.formatRate(root.traffic.tx_rate)
            // Logarithmic-like visual activity bar up to ~10 MB/s
            fraction: {
              var totalRate = Number(root.traffic.rx_rate || 0) + Number(root.traffic.tx_rate || 0)
              if (totalRate <= 0) return 0
              return Math.min(1, Math.log10(1 + totalRate / 1024) / 4)
            }
            fillColor: Color.accent
          }

          Text {
            textFormat: Text.PlainText
            visible: root.stats.active === true
            width: parent.width
            wrapMode: Text.WordWrap
            text: root.trusted
              ? "Active scanning: trusted network, subnet sweep every 2 min"
              : "Passive mode: this network is not trusted, so the subnet is not probed. Rescan once, or trust the network."
            color: root.dim
            font.family: root.font
            font.pixelSize: Style.font.caption
          }

          PanelSeparator { width: parent.width; foreground: root.fg }
          PanelSectionHeader {
            text: "DEVICES ON WLAN (" + root.onlineCount + " ONLINE"
              + (root.idleCount > 0 ? " · " + root.idleCount + " IDLE" : "")
              + (root.sleepingCount > 0 ? " · " + root.sleepingCount + " SLEEPING" : "") + ")"
            foreground: root.fg
            fontFamily: root.font
          }

          // Only the device list scrolls, so the panel keeps the LLM Monitor's height
          // and the link info and buttons stay visible.
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
              spacing: column.spacing

              Repeater {
                model: root.devices
                delegate: Item {
                  id: block
                  required property var modelData
                  width: deviceColumn.width
                  height: rows.implicitHeight + Style.space(4)
                  readonly property bool online: modelData.online === true
                  readonly property string subtitle: root.deviceSubtitle(modelData)
                  readonly property string webUrl: String(modelData.web_url || "")

                  Rectangle {
                    anchors.fill: parent
                    anchors.margins: -Style.space(3)
                    radius: Style.space(6)
                    color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.08)
                    visible: rowMouse.containsMouse && block.webUrl !== ""
                  }

                  Column {
                    id: rows
                    width: parent.width
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(2)

                    Item {
                      width: parent.width
                      height: deviceName.height
                      Rectangle {
                        id: dot
                        anchors.verticalCenter: parent.verticalCenter
                        width: Style.space(8); height: width; radius: width / 2
                        color: block.online ? Color.accent : "transparent"
                        border.width: 1
                        border.color: block.online ? Color.accent : root.dim
                      }
                      Text {
                        textFormat: Text.PlainText
                        id: deviceName
                        anchors.left: dot.right
                        anchors.leftMargin: Style.space(8)
                        anchors.right: deviceIp.left
                        anchors.rightMargin: Style.space(8)
                        elide: Text.ElideRight
                        text: block.modelData.name
                        color: block.online ? root.fg : root.dim
                        font.family: root.font
                        font.pixelSize: Style.font.body
                        font.bold: block.online
                        font.underline: rowMouse.containsMouse && block.webUrl !== ""
                      }
                      Text {
                        textFormat: Text.PlainText
                        id: deviceIp
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        text: root.deviceRightLabel(block.modelData)
                        color: (block.modelData.is_gateway || block.modelData.is_self)
                          ? Color.accent
                          : (block.online ? root.fg : root.dim)
                        font.family: root.font
                        font.pixelSize: Style.font.caption
                      }
                    }

                    Text {
                      textFormat: Text.PlainText
                      visible: text !== ""
                      width: parent.width
                      leftPadding: Style.space(16)
                      elide: Text.ElideRight
                      text: rowMouse.containsMouse && block.webUrl !== ""
                        ? "Open " + block.webUrl
                        : block.subtitle
                      color: root.dim
                      font.family: root.font
                      font.pixelSize: Style.font.caption
                    }
                  }

                  MouseArea {
                    id: rowMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    enabled: block.webUrl !== ""
                    cursorShape: block.webUrl !== "" ? Qt.PointingHandCursor : Qt.ArrowCursor
                    onClicked: root.openWeb(block.webUrl)
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
              // Same label and glyph while scanning (the icon just spins), so the
              // button keeps its width and the buttons next to it do not move.
              text: "Rescan"
              iconText: "󰑐"
              iconSpinning: root.scanning
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              enabled: !root.scanning
              tooltipText: "Actively probe the local subnet and refresh mDNS / router DNS names"
              onClicked: if (root.hostWidget) root.hostWidget.rescan()
            }
            Button {
              visible: root.gatewayDevice !== null && String(root.gatewayDevice.web_url || "") !== ""
              text: "Router"
              iconText: "󰑩"
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              tooltipText: root.gatewayDevice ? "Open " + root.gatewayDevice.web_url : ""
              onClicked: if (root.gatewayDevice) root.openWeb(root.gatewayDevice.web_url)
            }
            Button {
              visible: root.stats.active === true
              text: root.trusted ? "Untrust" : "Trust"
              iconText: root.trusted ? "󰦜" : "󰕥"
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              enabled: root.link.can_trust === true
              tooltipText: root.trusted
                ? "Stop active scanning on this network (passive discovery only)"
                : "Allow periodic active scans (ICMP + router DNS) on this network"
              onClicked: if (root.hostWidget) root.hostWidget.setTrusted(!root.trusted)
            }
            Button {
              text: "Network"
              iconText: "󰖩"
              bordered: true
              foreground: root.fg
              fontFamily: root.font
              tooltipText: "Open Omarchy Network settings"
              onClicked: {
                root.close()
                if (root.bar) root.bar.run("omarchy-launch-wifi")
              }
            }
          }
        }
      }
    }
  }
}
