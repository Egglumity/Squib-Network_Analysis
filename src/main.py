#!/usr/bin/env python3
"""
Advanced PyQt5 GUI Template for Network Snapshot Tool

Highlights
- Modern main window with toolbar, menu, status bar
- Left summary panel (host, OS, IPs) + right tabbed results
- Tabs: Interfaces, Connections, Routes, DNS, ARP
- Non-blocking Scan via QThread (worker pattern)
- Export: JSON (with SHA-256) and PDF (Qt print to PDF)
- Read-only collection stubs using psutil/netifaces/standard files
- Clean Model/View using QStandardItemModel for tables

How to use
1) pip install PyQt5 psutil netifaces
2) python advanced_gui.py

Next steps (fill in scanner.py later):
- Replace _collect_* methods with your real scanner logic
- Add suspicious-connection checks in _postprocess_snapshot
- Wire JSON schema checks if needed
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import psutil
import netifaces

from PyQt5 import QtCore, QtGui, QtPrintSupport, QtWidgets

# --------------------------
# Data Model
# --------------------------
@dataclass
class InterfaceRow:
    name: str
    mac: str
    ipv4: str
    ipv6: str
    up: bool
    speed_mbps: Optional[int]

@dataclass
class ConnRow:
    proto: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str
    pid: Optional[int]
    proc: str

@dataclass
class RouteRow:
    destination: str
    gateway: str
    iface: str
    metric: Optional[int]

@dataclass
class ArpRow:
    ip: str
    mac: str
    iface: str

@dataclass
class DnsData:
    nameservers: List[str]
    search: List[str]
    options: Dict[str, Any]

@dataclass
class Snapshot:
    created_utc: str
    host: Dict[str, Any]
    interfaces: List[InterfaceRow]
    connections: List[ConnRow]
    routes: List[RouteRow]
    arp: List[ArpRow]
    dns: DnsData
    sha256: Optional[str] = None

    def to_ordered_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("sha256", None)
        return d

    def to_json_with_sha(self) -> str:
        base = self.to_ordered_dict()
        payload = json.dumps(base, indent=2, sort_keys=True)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        base["sha256"] = digest
        self.sha256 = digest
        return json.dumps(base, indent=2, sort_keys=True)

# --------------------------
# Background Worker
# --------------------------
class ScanWorker(QtCore.QThread):
    finished_with_snapshot = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(str)

    def run(self):
        try:
            snapshot = self._build_snapshot()
            self.finished_with_snapshot.emit(snapshot)
        except Exception as e:
            self.failed.emit(str(e))

    # ---- Collector functions (read-only) ----
    def _collect_interfaces(self) -> List[InterfaceRow]:
        out: List[InterfaceRow] = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, info in addrs.items():
            mac, ipv4s, ipv6s = "", [], []
            for a in info:
                if getattr(a, 'family', None) == psutil.AF_LINK:
                    mac = a.address or ""
                elif getattr(a, 'family', None) == socket.AF_INET:
                    ipv4s.append(a.address)
                elif getattr(a, 'family', None) == socket.AF_INET6:
                    ipv6s.append(a.address.split('%')[0])
            st = stats.get(name)
            out.append(InterfaceRow(
                name=name,
                mac=mac,
                ipv4=", ".join(ipv4s),
                ipv6=", ".join(ipv6s),
                up=bool(st.isup) if st else False,
                speed_mbps=getattr(st, 'speed', None) if st else None,
            ))
        return out

    def _collect_connections(self) -> List[ConnRow]:
        rows: List[ConnRow] = []
        # TCP
        for c in psutil.net_connections(kind='tcp'):
            laddr = f"{c.laddr.ip if c.laddr else ''}"
            lport = c.laddr.port if c.laddr else 0
            raddr = f"{c.raddr.ip if c.raddr else ''}"
            rport = c.raddr.port if c.raddr else 0
            pid = c.pid
            pname = ""
            if pid:
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = ""
            rows.append(ConnRow(proto='TCP', laddr=laddr, lport=lport, raddr=raddr, rport=rport,
                                status=c.status or '', pid=pid, proc=pname))
        # UDP
        for c in psutil.net_connections(kind='udp'):
            laddr = f"{c.laddr.ip if c.laddr else ''}"
            lport = c.laddr.port if c.laddr else 0
            pid = c.pid
            pname = ""
            if pid:
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = ""
            rows.append(ConnRow(proto='UDP', laddr=laddr, lport=lport, raddr='', rport=0,
                                status='', pid=pid, proc=pname))
        return rows

    def _collect_routes(self) -> List[RouteRow]:
        rows: List[RouteRow] = []
        try:
            # Best-effort using psutil (limited) + netifaces gateways
            gws = netifaces.gateways()
            default = gws.get('default', {})
            for fam, (gw, iface) in default.items():
                rows.append(RouteRow(destination='0.0.0.0/0', gateway=str(gw), iface=str(iface), metric=None))
        except Exception:
            pass
        # Fallback: parse /proc/net/route for linux
        try:
            if Path('/proc/net/route').exists():
                with open('/proc/net/route') as f:
                    # If duplicates appear, they'll be shown alongside defaults
                    next(f)  # skip header
                    for line in f:
                        parts = line.strip().split('\t')
                        if len(parts) >= 8:
                            iface = parts[0]
                            dest_hex = parts[1]
                            gw_hex = parts[2]
                            metric = int(parts[6]) if parts[6].isdigit() else None
                            destination = _hex_to_ipv4(dest_hex)
                            gateway = _hex_to_ipv4(gw_hex)
                            rows.append(RouteRow(destination=destination, gateway=gateway, iface=iface, metric=metric))
        except Exception:
            pass
        return rows

    def _collect_arp(self) -> List[ArpRow]:
        rows: List[ArpRow] = []
        path = Path('/proc/net/arp')
        if path.exists():
            with open(path) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 6:
                        ip, hw_type, flags, mac, mask, iface = cols[:6]
                        rows.append(ArpRow(ip=ip, mac=mac, iface=iface))
        return rows

    def _collect_dns(self) -> DnsData:
        nameservers, search, options = [], [], {}
        path = Path('/etc/resolv.conf')
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])
                elif line.startswith('search'):
                    parts = line.split()
                    search.extend(parts[1:])
                elif line.startswith('options'):
                    # naive parse: options key=value ...
                    parts = line.split()[1:]
                    for p in parts:
                        if '=' in p:
                            k, v = p.split('=', 1)
                            options[k] = v
                        else:
                            options[p] = True
        return DnsData(nameservers=nameservers, search=search, options=options)

    def _build_snapshot(self) -> Snapshot:
        host = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": platform.platform(),
            "os": platform.system(),
            "os_release": platform.release(),
        }
        interfaces = self._collect_interfaces()
        conns = self._collect_connections()
        routes = self._collect_routes()
        arp = self._collect_arp()
        dns = self._collect_dns()
        snap = Snapshot(
            created_utc=datetime.now(timezone.utc).isoformat(),
            host=host,
            interfaces=interfaces,
            connections=conns,
            routes=routes,
            arp=arp,
            dns=dns,
        )
        # Optional post-processing hooks
        self._postprocess_snapshot(snap)
        return snap

    def _postprocess_snapshot(self, snapshot: Snapshot) -> None:
        # Example: here you could mark suspicious connections (e.g., non-private raddr on sensitive ports)
        pass

# --------------------------
# GUI
# --------------------------
class HostSummary(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.title = QtWidgets.QLabel("Host Overview")
        self.title.setStyleSheet("font-weight:600;font-size:16px;")
        self.lblHostname = QtWidgets.QLabel("Hostname: -")
        self.lblFqdn = QtWidgets.QLabel("FQDN: -")
        self.lblOS = QtWidgets.QLabel("OS: -")
        self.lblCreated = QtWidgets.QLabel("Snapshot: -")
        v = QtWidgets.QVBoxLayout(self)
        v.addWidget(self.title)
        v.addSpacing(6)
        for w in (self.lblHostname, self.lblFqdn, self.lblOS, self.lblCreated):
            v.addWidget(w)
        v.addStretch(1)

    def update_from_snapshot(self, snap: Snapshot):
        self.lblHostname.setText(f"Hostname: {snap.host.get('hostname','-')}")
        self.lblFqdn.setText(f"FQDN: {snap.host.get('fqdn','-')}")
        self.lblOS.setText(f"OS: {snap.host.get('platform','-')}")
        self.lblCreated.setText(f"Snapshot: {snap.created_utc}")

class TableTab(QtWidgets.QWidget):
    def __init__(self, headers: List[str], parent=None):
        super().__init__(parent)
        self.model = QtGui.QStandardItemModel(0, len(headers))
        self.model.setHorizontalHeaderLabels(headers)
        self.view = QtWidgets.QTableView()
        self.view.setModel(self.model)
        self.view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.view.setSortingEnabled(True)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.verticalHeader().setVisible(False)
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.view)

    def clear(self):
        self.model.removeRows(0, self.model.rowCount())

    def add_row(self, values: List[Any]):
        row = [QtGui.QStandardItem(str(v)) for v in values]
        for item in row:
            item.setEditable(False)
        self.model.appendRow(row)

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Analysis Tool")
        self.resize(1100, 700)
        self._build_ui()
        self._wire_actions()
        self._current_snapshot: Optional[Snapshot] = None

    # ---------- UI ----------
    def _build_ui(self):
        self.statusBar().showMessage("Ready")

        # Toolbar
        toolbar = QtWidgets.QToolBar("Main")
        toolbar.setIconSize(QtCore.QSize(18, 18))
        self.addToolBar(toolbar)

        self.actScan = QtWidgets.QAction("Scan", self)
        self.actExportJson = QtWidgets.QAction("Export JSON", self)
        self.actExportPdf = QtWidgets.QAction("Export PDF", self)

        toolbar.addAction(self.actScan)
        toolbar.addSeparator()
        toolbar.addAction(self.actExportJson)
        toolbar.addAction(self.actExportPdf)

        # Menu
        m = self.menuBar()
        fileMenu = m.addMenu("File")
        fileMenu.addAction(self.actScan)
        fileMenu.addSeparator()
        fileMenu.addAction(self.actExportJson)
        fileMenu.addAction(self.actExportPdf)
        fileMenu.addSeparator()
        fileMenu.addAction("Quit", self.close)

        # Central splitter
        splitter = QtWidgets.QSplitter()
        splitter.setOrientation(QtCore.Qt.Horizontal)
        self.setCentralWidget(splitter)

        # Left summary panel
        self.summary = HostSummary()
        splitter.addWidget(self.summary)

        # Right tabs
        self.tabs = QtWidgets.QTabWidget()
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 3)

        # Tabs
        self.tabInterfaces = TableTab(["Name", "MAC", "IPv4", "IPv6", "Up", "Speed(Mbps)"])
        self.tabConnections = TableTab(["Proto", "Laddr", "Lport", "Raddr", "Rport", "Status", "PID", "Process"])
        self.tabRoutes = TableTab(["Destination", "Gateway", "Iface", "Metric"])
        self.tabDNS = TableTab(["Nameservers", "Search", "Options(JSON)"])
        self.tabARP = TableTab(["IP", "MAC", "Iface"])

        self.tabs.addTab(self.tabInterfaces, "Interfaces")
        self.tabs.addTab(self.tabConnections, "Connections")
        self.tabs.addTab(self.tabRoutes, "Routes")
        self.tabs.addTab(self.tabDNS, "DNS")
        self.tabs.addTab(self.tabARP, "ARP")

        # Progress overlay
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)  # busy
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress)

    def _wire_actions(self):
        self.actScan.triggered.connect(self.on_scan)
        self.actExportJson.triggered.connect(self.on_export_json)
        self.actExportPdf.triggered.connect(self.on_export_pdf)

    # ---------- Actions ----------
    def on_scan(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            return
        self.progress.setVisible(True)
        self.statusBar().showMessage("Scanning…")
        self.worker = ScanWorker()
        self.worker.finished_with_snapshot.connect(self.on_scan_done)
        self.worker.failed.connect(self.on_scan_failed)
        self.worker.start()

    def on_scan_done(self, snapshot: Snapshot):
        self._current_snapshot = snapshot
        self.progress.setVisible(False)
        self.statusBar().showMessage("Scan complete")
        self._populate_from_snapshot(snapshot)

    def on_scan_failed(self, msg: str):
        self.progress.setVisible(False)
        QtWidgets.QMessageBox.critical(self, "Scan failed", msg)
        self.statusBar().showMessage("Scan failed")

    def _populate_from_snapshot(self, snap: Snapshot):
        self.summary.update_from_snapshot(snap)

        # Interfaces
        self.tabInterfaces.clear()
        for r in snap.interfaces:
            self.tabInterfaces.add_row([r.name, r.mac, r.ipv4, r.ipv6, r.up, r.speed_mbps if r.speed_mbps is not None else "-"])

        # Connections
        self.tabConnections.clear()
        for c in snap.connections:
            self.tabConnections.add_row([c.proto, c.laddr, c.lport, c.raddr, c.rport, c.status, c.pid or "-", c.proc])

        # Routes
        self.tabRoutes.clear()
        for r in snap.routes:
            self.tabRoutes.add_row([r.destination, r.gateway, r.iface, r.metric if r.metric is not None else "-"])

        # DNS (single row summary)
        self.tabDNS.clear()
        dns = snap.dns
        opts = json.dumps(dns.options, sort_keys=True)
        self.tabDNS.add_row([", ".join(dns.nameservers), ", ".join(dns.search), opts])

        # ARP
        self.tabARP.clear()
        for a in snap.arp:
            self.tabARP.add_row([a.ip, a.mac, a.iface])

    def on_export_json(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save JSON", "snapshot.json", "JSON (*.json)")
        if not path:
            return
        data = self._current_snapshot.to_json_with_sha()
        Path(path).write_text(data)
        self.statusBar().showMessage(f"Saved JSON: {path}")

    def on_export_pdf(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save PDF", "snapshot.pdf", "PDF (*.pdf)")
        if not path:
            return
        self._render_pdf(path)
        self.statusBar().showMessage(f"Saved PDF: {path}")

    def _render_pdf(self, out_path: str):
        # Simple printable report using QTextDocument
        snap = self._current_snapshot
        if not snap:
            return
        html = [
            "<h2>Network Snapshot Report</h2>",
            f"<p><b>Created (UTC):</b> {snap.created_utc}</p>",
            f"<p><b>Host:</b> {snap.host.get('hostname','-')} | {snap.host.get('platform','-')}</p>",
            "<h3>Interfaces</h3>",
            "<table border='1' cellspacing='0' cellpadding='3'>",
            "<tr><th>Name</th><th>MAC</th><th>IPv4</th><th>IPv6</th><th>Up</th><th>Speed</th></tr>",
        ]
        for r in snap.interfaces:
            html.append(f"<tr><td>{_e(r.name)}</td><td>{_e(r.mac)}</td><td>{_e(r.ipv4)}</td><td>{_e(r.ipv6)}</td><td>{r.up}</td><td>{r.speed_mbps or '-'}" \
                        "</td></tr>")
        html.extend(["</table>", "<h3>Connections</h3>",
                     "<table border='1' cellspacing='0' cellpadding='3'>",
                     "<tr><th>Proto</th><th>Laddr</th><th>Lport</th><th>Raddr</th><th>Rport</th><th>Status</th><th>PID</th><th>Process</th></tr>"])
        for c in snap.connections:
            html.append(f"<tr><td>{_e(c.proto)}</td><td>{_e(c.laddr)}</td><td>{c.lport}</td><td>{_e(c.raddr)}</td><td>{c.rport}</td><td>{_e(c.status)}</td><td>{c.pid or '-'}" \
                        f"</td><td>{_e(c.proc)}</td></tr>")
        html.extend(["</table>", "<h3>Routes</h3>",
                     "<table border='1' cellspacing='0' cellpadding='3'>",
                     "<tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th></tr>"])
        for r in snap.routes:
            html.append(f"<tr><td>{_e(r.destination)}</td><td>{_e(r.gateway)}</td><td>{_e(r.iface)}</td><td>{r.metric or '-'}" \
                        "</td></tr>")
        html.extend(["</table>", "<h3>DNS</h3>"])
        html.append(f"<p><b>Nameservers:</b> {_e(', '.join(snap.dns.nameservers))}<br>"
                    f"<b>Search:</b> {_e(', '.join(snap.dns.search))}<br>"
                    f"<b>Options:</b> {_e(json.dumps(snap.dns.options, sort_keys=True))}</p>")
        html.extend(["<h3>ARP</h3>",
                     "<table border='1' cellspacing='0' cellpadding='3'>",
                     "<tr><th>IP</th><th>MAC</th><th>Iface</th></tr>"])
        for a in snap.arp:
            html.append(f"<tr><td>{_e(a.ip)}</td><td>{_e(a.mac)}</td><td>{_e(a.iface)}</td></tr>")
        html.append("</table>")
        if snap.sha256:
            html.append(f"<p><b>SHA-256:</b> {snap.sha256}</p>")

        doc = QtGui.QTextDocument("\n".join(html))
        printer = QtPrintSupport.QPrinter(QtPrintSupport.QPrinter.HighResolution)
        printer.setOutputFormat(QtPrintSupport.QPrinter.PdfFormat)
        printer.setOutputFileName(out_path)
        doc.print_(printer)

# --------------------------
# Helpers
# --------------------------

def _hex_to_ipv4(hex_str: str) -> str:
    try:
        b = bytes.fromhex(hex_str)
        if len(b) == 4:
            return ".".join(str(x) for x in b[::-1])  # little endian
    except Exception:
        pass
    return "-"

def _e(s: Any) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

# --------------------------
# Entry Point
# --------------------------
if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Network Analysis Tool")
    app.setOrganizationName("YourTeam")

    win = MainWindow()
    win.show()

    sys.exit(app.exec_())
