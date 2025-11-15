#!/usr/bin/env python3
"""
main9.py

Network Analysis Tool - GUI with config-driven auto-scan and Suspicious tab

Features included:
- Loads configuration from `config.json` (editable by Paul or user)
- Auto-scan every `scan_interval_minutes` (QTimer)
- Saves each snapshot as JSON into `exports_folder` with SHA-256
- Keeps only `max_logs` files (log rotation)
- Suspicious tab: simple heuristics (remote IP public = suspicious)
- Uses a background QThread (ScanWorker) so UI stays responsive

Dependencies: PyQt5, psutil, netifaces
Install: pip install PyQt5 psutil netifaces

Drop this file into src/main9.py and run with:
    python src/main9.py

"""

from __future__ import annotations

import hashlib
import json
import ipaddress
import os
import socket
import sys
import platform
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import netifaces
import psutil
from PyQt5 import QtCore, QtGui, QtPrintSupport, QtWidgets

# ---------------------------
# Configuration utilities
# ---------------------------

DEFAULT_CONFIG = {
    "scan_interval_minutes": 30,
    "max_logs": 10,
    "exports_folder": "Exports",
    "enable_auto_scan": True,
    "log_filename_prefix": "snapshot",
    "include_process_details": True,
}

CONFIG_PATH = Path("config.json")


def load_config(path: Path = CONFIG_PATH) -> Dict[str, Any]:
    conf = DEFAULT_CONFIG.copy()
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as f:
                user = json.load(f)
            if isinstance(user, dict):
                conf.update(user)
    except Exception as e:
        print("Warning: failed to load config.json, using defaults:", e)
    return conf


def save_config(conf: Dict[str, Any], path: Path = CONFIG_PATH) -> None:
    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(conf, f, indent=2, sort_keys=True)
    except Exception as e:
        print("Warning: failed to save config.json:", e)


# ---------------------------
# Data model
# ---------------------------

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
class SuspiciousRow:
    category: str
    summary: str
    reason: str
    extra: str


@dataclass
class Snapshot:
    created_utc: str
    host: Dict[str, Any]
    interfaces: List[InterfaceRow]
    connections: List[ConnRow]
    routes: List[RouteRow]
    arp: List[ArpRow]
    dns: DnsData
    suspicious: List[SuspiciousRow] = field(default_factory=list)
    sha256: Optional[str] = None

    def to_ordered_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json_with_sha(self) -> str:
        base = self.to_ordered_dict().copy()
        base.pop("sha256", None)
        payload = json.dumps(base, sort_keys=True, indent=2)
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        base["sha256"] = digest
        self.sha256 = digest
        return json.dumps(base, sort_keys=True, indent=2)


# ---------------------------
# Scanner (synchronous helpers used by worker)
# ---------------------------


def _hex_to_ipv4(hex_str: str) -> str:
    try:
        b = bytes.fromhex(hex_str)
        if len(b) == 4:
            return ".".join(str(x) for x in b[::-1])
    except Exception:
        pass
    return "-"


class SnapshotBuilder:
    @staticmethod
    def collect_interfaces() -> List[InterfaceRow]:
        rows: List[InterfaceRow] = []
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, info in addrs.items():
            mac = ""
            ipv4s: List[str] = []
            ipv6s: List[str] = []
            for a in info:
                fam = getattr(a, "family", None)
                if fam == psutil.AF_LINK:
                    mac = a.address or ""
                elif fam == socket.AF_INET:
                    ipv4s.append(a.address)
                elif fam == socket.AF_INET6:
                    ipv6s.append(a.address.split("%")[0])
            st = stats.get(name)
            rows.append(
                InterfaceRow(
                    name=name,
                    mac=mac,
                    ipv4=", ".join(ipv4s),
                    ipv6=", ".join(ipv6s),
                    up=bool(st.isup) if st else False,
                    speed_mbps=getattr(st, "speed", None) if st else None,
                )
            )
        return rows

    @staticmethod
    def collect_connections(include_proc: bool = True) -> List[ConnRow]:
        rows: List[ConnRow] = []

        for c in psutil.net_connections(kind="tcp"):
            laddr = c.laddr.ip if c.laddr else ""
            lport = c.laddr.port if c.laddr else 0
            raddr = c.raddr.ip if c.raddr else ""
            rport = c.raddr.port if c.raddr else 0
            pid = c.pid
            pname = ""
            if include_proc and pid:
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = ""
            rows.append(
                ConnRow(
                    proto="TCP",
                    laddr=laddr,
                    lport=lport,
                    raddr=raddr,
                    rport=rport,
                    status=c.status or "",
                    pid=pid,
                    proc=pname,
                )
            )

        for c in psutil.net_connections(kind="udp"):
            laddr = c.laddr.ip if c.laddr else ""
            lport = c.laddr.port if c.laddr else 0
            pid = c.pid
            pname = ""
            if include_proc and pid:
                try:
                    pname = psutil.Process(pid).name()
                except Exception:
                    pname = ""
            rows.append(
                ConnRow(
                    proto="UDP",
                    laddr=laddr,
                    lport=lport,
                    raddr="",
                    rport=0,
                    status="",
                    pid=pid,
                    proc=pname,
                )
            )

        return rows

    @staticmethod
    def collect_routes() -> List[RouteRow]:
        rows: List[RouteRow] = []
        try:
            gws = netifaces.gateways()
            default = gws.get("default", {})
            for _fam, (gw, iface) in default.items():
                rows.append(RouteRow(destination="0.0.0.0/0", gateway=str(gw), iface=str(iface), metric=None))
        except Exception:
            pass

        route_path = Path("/proc/net/route")
        if route_path.exists():
            try:
                with route_path.open() as f:
                    next(f)
                    for line in f:
                        parts = line.strip().split("\t")
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

    @staticmethod
    def collect_arp() -> List[ArpRow]:
        rows: List[ArpRow] = []
        path = Path("/proc/net/arp")
        if path.exists():
            with path.open() as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if len(cols) >= 6:
                        ip, _hw, _flags, mac, _mask, iface = cols[:6]
                        rows.append(ArpRow(ip=ip, mac=mac, iface=iface))
        return rows

    @staticmethod
    def collect_dns() -> DnsData:
        nameservers: List[str] = []
        search: List[str] = []
        options: Dict[str, Any] = {}
        path = Path("/etc/resolv.conf")
        if path.exists():
            for line in path.read_text().splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        nameservers.append(parts[1])
                elif line.startswith("search"):
                    parts = line.split()
                    search.extend(parts[1:])
                elif line.startswith("options"):
                    parts = line.split()[1:]
                    for p in parts:
                        if "=" in p:
                            k, v = p.split("=", 1)
                            options[k] = v
                        else:
                            options[p] = True
        return DnsData(nameservers=nameservers, search=search, options=options)

    @staticmethod
    def build_snapshot(include_proc: bool = True) -> Snapshot:
        host = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": platform.platform(),
            "os": platform.system(),
            "os_release": platform.release(),
        }
        interfaces = SnapshotBuilder.collect_interfaces()
        conns = SnapshotBuilder.collect_connections(include_proc=include_proc)
        routes = SnapshotBuilder.collect_routes()
        arp = SnapshotBuilder.collect_arp()
        dns = SnapshotBuilder.collect_dns()

        snap = Snapshot(
            created_utc=datetime.now(timezone.utc).isoformat(),
            host=host,
            interfaces=interfaces,
            connections=conns,
            routes=routes,
            arp=arp,
            dns=dns,
        )

        # Simple suspicious heuristics
        SnapshotBuilder._mark_suspicious(snap)

        return snap

    @staticmethod
    def _mark_suspicious(snap: Snapshot) -> None:
        suspicious: List[SuspiciousRow] = []
        for c in snap.connections:
            if not c.raddr:
                continue
            try:
                ipobj = ipaddress.ip_address(c.raddr)
            except Exception:
                continue
            # mark if remote IP is not private and not loopback
            if not ipobj.is_private and not ipobj.is_loopback:
                summary = f"{c.proto} {c.laddr}:{c.lport} -> {c.raddr}:{c.rport}"
                reason = "Remote IP is public (non-private)"
                extra = f"PID {c.pid or '?'} {c.proc or ''}".strip()
                suspicious.append(SuspiciousRow(category="Connection", summary=summary, reason=reason, extra=extra))
        snap.suspicious = suspicious


# ---------------------------
# Background worker (QThread)
# ---------------------------

class ScanWorker(QtCore.QThread):
    finished_with_snapshot = QtCore.pyqtSignal(object)  # Snapshot
    failed = QtCore.pyqtSignal(str)

    def __init__(self, include_proc: bool = True):
        super().__init__()
        self.include_proc = include_proc

    def run(self):
        try:
            snap = SnapshotBuilder.build_snapshot(include_proc=self.include_proc)
            self.finished_with_snapshot.emit(snap)
        except Exception as e:
            self.failed.emit(str(e))


# ---------------------------
# GUI components
# ---------------------------

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
        items = [QtGui.QStandardItem(str(v)) for v in values]
        for it in items:
            it.setEditable(False)
        self.model.appendRow(items)


class HostSummary(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QtWidgets.QFrame.StyledPanel)
        title = QtWidgets.QLabel("Host Overview")
        title.setStyleSheet("font-weight:600; font-size:14px;")
        self.lblHostname = QtWidgets.QLabel("Hostname: -")
        self.lblFqdn = QtWidgets.QLabel("FQDN: -")
        self.lblOS = QtWidgets.QLabel("OS: -")
        self.lblCreated = QtWidgets.QLabel("Snapshot: -")
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(title)
        layout.addSpacing(6)
        for w in (self.lblHostname, self.lblFqdn, self.lblOS, self.lblCreated):
            layout.addWidget(w)
        layout.addStretch(1)

    def update_from_snapshot(self, snap: Snapshot):
        self.lblHostname.setText(f"Hostname: {snap.host.get('hostname','-')}")
        self.lblFqdn.setText(f"FQDN: {snap.host.get('fqdn','-')}")
        self.lblOS.setText(f"OS: {snap.host.get('platform','-')}")
        self.lblCreated.setText(f"Snapshot: {snap.created_utc}")


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Analysis Tool - main9")
        self.resize(1100, 720)

        # load config
        self.config = load_config()

        self._current_snapshot: Optional[Snapshot] = None
        self.worker: Optional[ScanWorker] = None
        self.scan_timer: Optional[QtCore.QTimer] = None

        self._build_ui()
        self._wire_actions()

        # Start auto scanner if enabled
        if self.config.get("enable_auto_scan", True):
            self.start_auto_scanner()

    def _build_ui(self):
        self.statusBar().showMessage("Ready")

        toolbar = QtWidgets.QToolBar("Main")
        toolbar.setIconSize(QtCore.QSize(18, 18))
        self.addToolBar(toolbar)

        self.actScan = QtWidgets.QAction("Scan", self)
        self.actExportJson = QtWidgets.QAction("Export JSON", self)
        self.actExportPdf = QtWidgets.QAction("Export PDF", self)
        self.actOpenConfig = QtWidgets.QAction("Open config.json", self)

        toolbar.addAction(self.actScan)
        toolbar.addSeparator()
        toolbar.addAction(self.actExportJson)
        toolbar.addAction(self.actExportPdf)
        toolbar.addSeparator()
        toolbar.addAction(self.actOpenConfig)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.setCentralWidget(splitter)

        self.summary = HostSummary()
        splitter.addWidget(self.summary)

        self.tabs = QtWidgets.QTabWidget()
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 3)

        self.tabInterfaces = TableTab(["Name", "MAC", "IPv4", "IPv6", "Up", "Speed(Mbps)"])
        self.tabConnections = TableTab(["Proto", "Laddr", "Lport", "Raddr", "Rport", "Status", "PID", "Process"])
        self.tabRoutes = TableTab(["Destination", "Gateway", "Iface", "Metric"])
        self.tabDNS = TableTab(["Nameservers", "Search", "Options(JSON)"])
        self.tabARP = TableTab(["IP", "MAC", "Iface"])
        self.tabSuspicious = TableTab(["Category", "Summary", "Reason", "Extra"])

        self.tabs.addTab(self.tabInterfaces, "Interfaces")
        self.tabs.addTab(self.tabConnections, "Connections")
        self.tabs.addTab(self.tabRoutes, "Routes")
        self.tabs.addTab(self.tabDNS, "DNS")
        self.tabs.addTab(self.tabARP, "ARP")
        self.tabs.addTab(self.tabSuspicious, "Suspicious")

        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress)

    def _wire_actions(self):
        self.actScan.triggered.connect(self.on_scan)
        self.actExportJson.triggered.connect(self.on_export_json)
        self.actExportPdf.triggered.connect(self.on_export_pdf)
        self.actOpenConfig.triggered.connect(self.on_open_config)

    # ------------------ scan flow ------------------

    def on_scan(self):
        # start worker if not running
        if self.worker and self.worker.isRunning():
            QtWidgets.QMessageBox.information(self, "Scan", "A scan is already running.")
            return
        self._start_worker()

    def _start_worker(self):
        self.progress.setVisible(True)
        include_proc = bool(self.config.get("include_process_details", True))
        self.worker = ScanWorker(include_proc=include_proc)
        self.worker.finished_with_snapshot.connect(self._on_worker_finished)
        self.worker.failed.connect(self._on_worker_failed)
        self.worker.start()

    def _on_worker_finished(self, snap: Snapshot):
        self._current_snapshot = snap
        self.progress.setVisible(False)
        self.statusBar().showMessage("Scan complete")
        self._populate_from_snapshot(snap)

        # Save snapshot automatically on each scan (also used by auto-scan)
        try:
            self._save_snapshot_to_exports(snap)
        except Exception as e:
            print("Warning: failed to auto-save snapshot:", e)

    def _on_worker_failed(self, msg: str):
        self.progress.setVisible(False)
        QtWidgets.QMessageBox.critical(self, "Scan failed", msg)
        self.statusBar().showMessage("Scan failed")

    # ------------------ populate UI ------------------

    def _populate_from_snapshot(self, snap: Snapshot):
        self.summary.update_from_snapshot(snap)

        self.tabInterfaces.clear()
        for r in snap.interfaces:
            self.tabInterfaces.add_row([r.name, r.mac, r.ipv4, r.ipv6, "Yes" if r.up else "No", r.speed_mbps or "-"])

        self.tabConnections.clear()
        for c in snap.connections:
            self.tabConnections.add_row([c.proto, c.laddr, c.lport, c.raddr, c.rport, c.status, c.pid or "-", c.proc])

        self.tabRoutes.clear()
        for r in snap.routes:
            self.tabRoutes.add_row([r.destination, r.gateway, r.iface, r.metric if r.metric is not None else "-"])

        self.tabDNS.clear()
        self.tabDNS.add_row([", ".join(snap.dns.nameservers), ", ".join(snap.dns.search), json.dumps(snap.dns.options, sort_keys=True)])

        self.tabARP.clear()
        for a in snap.arp:
            self.tabARP.add_row([a.ip, a.mac, a.iface])

        self.tabSuspicious.clear()
        for s in snap.suspicious:
            self.tabSuspicious.add_row([s.category, s.summary, s.reason, s.extra])

    # ------------------ exports & rotation ------------------

    def _ensure_exports_dir(self) -> Path:
        export_dir = Path(self.config.get("exports_folder", "Exports"))
        export_dir.mkdir(exist_ok=True)
        return export_dir

    def _save_snapshot_to_exports(self, snap: Snapshot) -> Path:
        export_dir = self._ensure_exports_dir()
        prefix = str(self.config.get("log_filename_prefix", "snapshot"))
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{prefix}_{ts}.json"
        out_path = export_dir / filename
        payload = snap.to_json_with_sha()
        out_path.write_text(payload, encoding="utf-8")

        # rotate logs
        self._rotate_exports()
        return out_path

    def _rotate_exports(self):
        export_dir = Path(self.config.get("exports_folder", "Exports"))
        prefix = str(self.config.get("log_filename_prefix", "snapshot"))
        pattern = f"{prefix}_*.json"
        files = sorted(export_dir.glob(pattern), key=lambda p: p.stat().st_mtime)
        try:
            max_logs = int(self.config.get("max_logs", 10))
        except Exception:
            max_logs = 10
        if len(files) <= max_logs:
            return
        remove_count = len(files) - max_logs
        for i in range(remove_count):
            try:
                files[i].unlink()
            except Exception:
                pass

    # ------------------ UI Export actions ------------------

    def on_export_json(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return
        out = self._save_snapshot_to_exports(self._current_snapshot)
        QtWidgets.QMessageBox.information(self, "Exported", f"Saved JSON to: {out}")
        # open folder
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(out.parent.resolve())))

    def on_export_pdf(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return
        export_dir = self._ensure_exports_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = export_dir / f"{self.config.get('log_filename_prefix','snapshot')}_{ts}.pdf"
        self._render_pdf(out_path)
        QtWidgets.QMessageBox.information(self, "Exported", f"Saved PDF to: {out_path}")
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(export_dir.resolve())))

    def _render_pdf(self, out_path: Path):
        snap = self._current_snapshot
        if not snap:
            return
        parts: List[str] = []
        parts.append("<html><head><style>body{font-family:DejaVu Sans, Arial, sans-serif;}table{border-collapse:collapse;}th,td{border:1px solid #444;padding:3px;}</style></head><body>")
        parts.append(f"<h2>Network Snapshot Report</h2>")
        parts.append(f"<p><b>Created (UTC):</b> {snap.created_utc}</p>")
        parts.append(f"<p><b>Host:</b> {_e(snap.host.get('hostname','-'))} | {_e(snap.host.get('platform','-'))}</p>")

        # Interfaces
        parts.append("<h3>Interfaces</h3>")
        parts.append("<table><tr><th>Name</th><th>MAC</th><th>IPv4</th><th>IPv6</th><th>Up</th><th>Speed</th></tr>")
        for r in snap.interfaces:
            parts.append(f"<tr><td>{_e(r.name)}</td><td>{_e(r.mac)}</td><td>{_e(r.ipv4)}</td><td>{_e(r.ipv6)}</td><td>{'Yes' if r.up else 'No'}</td><td>{_e(r.speed_mbps or '-')}</td></tr>")
        parts.append("</table>")

        # Connections
        parts.append("<h3>Connections</h3>")
        parts.append("<table><tr><th>Proto</th><th>Laddr</th><th>Lport</th><th>Raddr</th><th>Rport</th><th>Status</th><th>PID</th><th>Process</th></tr>")
        for c in snap.connections:
            parts.append(f"<tr><td>{_e(c.proto)}</td><td>{_e(c.laddr)}</td><td>{c.lport}</td><td>{_e(c.raddr)}</td><td>{c.rport}</td><td>{_e(c.status)}</td><td>{_e(c.pid or '-')}</td><td>{_e(c.proc)}</td></tr>")
        parts.append("</table>")

        # Routes
        parts.append("<h3>Routes</h3>")
        parts.append("<table><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th></tr>")
        for r in snap.routes:
            parts.append(f"<tr><td>{_e(r.destination)}</td><td>{_e(r.gateway)}</td><td>{_e(r.iface)}</td><td>{_e(r.metric or '-')}</td></tr>")
        parts.append("</table>")

        # DNS
        parts.append("<h3>DNS</h3>")
        parts.append(f"<p><b>Nameservers:</b> {_e(', '.join(snap.dns.nameservers))}<br><b>Search:</b> {_e(', '.join(snap.dns.search))}</p>")

        # ARP
        parts.append("<h3>ARP</h3>")
        parts.append("<table><tr><th>IP</th><th>MAC</th><th>Iface</th></tr>")
        for a in snap.arp:
            parts.append(f"<tr><td>{_e(a.ip)}</td><td>{_e(a.mac)}</td><td>{_e(a.iface)}</td></tr>")
        parts.append("</table>")

        # Suspicious
        parts.append("<h3>Suspicious</h3>")
        if snap.suspicious:
            parts.append("<table><tr><th>Category</th><th>Summary</th><th>Reason</th><th>Extra</th></tr>")
            for s in snap.suspicious:
                parts.append(f"<tr><td>{_e(s.category)}</td><td>{_e(s.summary)}</td><td>{_e(s.reason)}</td><td>{_e(s.extra)}</td></tr>")
            parts.append("</table>")
        else:
            parts.append("<p>No suspicious items detected by current heuristics.</p>")

        if snap.sha256:
            parts.append(f"<p><b>SHA-256:</b> {_e(snap.sha256)}</p>")

        parts.append("</body></html>")
        html = "\n".join(parts)

        doc = QtGui.QTextDocument()
        doc.setHtml(html)
        printer = QtPrintSupport.QPrinter(QtPrintSupport.QPrinter.HighResolution)
        printer.setOutputFormat(QtPrintSupport.QPrinter.PdfFormat)
        printer.setOutputFileName(str(out_path))
        doc.print_(printer)

    # ------------------ auto-scan scheduling ------------------

    def start_auto_scanner(self):
        interval_minutes = int(self.config.get("scan_interval_minutes", 30))
        if interval_minutes <= 0:
            return
        if self.scan_timer and self.scan_timer.isActive():
            self.scan_timer.stop()
        self.scan_timer = QtCore.QTimer(self)
        self.scan_timer.timeout.connect(self._auto_scan_trigger)
        # start after 5 seconds to avoid immediate overlap with init
        self.scan_timer.start(interval_minutes * 60 * 1000)
        self.statusBar().showMessage(f"Auto-scan every {interval_minutes} minute(s)")

    def _auto_scan_trigger(self):
        if hasattr(self, 'worker') and self.worker and self.worker.isRunning():
            # worker busy; skip this interval
            print("Auto-scan skipped: worker is busy")
            return
        # start a worker; when it finishes, _on_worker_finished will save snapshot
        self._start_worker()

    # ------------------ config helper ------------------

    def on_open_config(self):
        # open config.json in the system editor (or default app)
        p = CONFIG_PATH.resolve()
        if not p.exists():
            save_config(self.config, p)
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(p)))

    # ------------------ helpers ------------------


def _e(s: Any) -> str:
    return (str(s) if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------------------------
# Main
# ---------------------------


def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Network Analysis Tool")

    # ensure config exists with defaults if not
    conf = load_config()
    save_config(conf)

    win = MainWindow()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
