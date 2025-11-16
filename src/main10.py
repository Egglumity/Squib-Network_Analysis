#!/usr/bin/env python3
"""
main10.py - Network Analysis Tool with:
- PyQt5 GUI
- Config file (config.json)
- Auto-scan on interval from config
- JSON export + log rotation
- PDF export into Exports/ and open folder after export
- "Suspicious" tab with rule-based detection (no AI yet)
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import netifaces
import psutil
from PyQt5 import QtCore, QtGui, QtPrintSupport, QtWidgets


# -------------------------
# Config handling
# -------------------------

DEFAULT_CONFIG = {
    "scan_interval_minutes": 30,
    "max_logs": 10,
    "exports_folder": "Exports",
    "enable_auto_scan": False,
    "log_filename_prefix": "scan",
    "include_process_details": True,
}


def save_default_config(path: str = "config.json") -> None:
    cfg_path = Path(path)
    if cfg_path.exists():
        return
    cfg_path.write_text(json.dumps(DEFAULT_CONFIG, indent=4))


def load_config(path: str = "config.json") -> Dict[str, Any]:
    save_default_config(path)
    try:
        raw = Path(path).read_text()
        user_cfg = json.loads(raw)
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(user_cfg)
        return cfg
    except Exception as e:
        print(f"Failed to load config.json, using defaults: {e}")
        return DEFAULT_CONFIG.copy()


# -------------------------
# Data model
# -------------------------

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
    exe: Optional[str]  # process binary path


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


# -------------------------
# Suspicious detection helpers
# -------------------------

HIGH_RISK_PORTS = {
    23,      # Telnet
    4444,    # C2 / reverse shells
    1337,    # "leet" port
    31337,   # classic backdoor port
    3389,    # RDP
    6667,    # IRC (botnets)
}

TEMP_DIR_PREFIXES = (
    "/tmp",
    "/dev/shm",
    "/var/tmp",
)


def is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except ValueError:
        return False


# -------------------------
# Snapshot builder
# -------------------------

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


def collect_connections(include_proc: bool = True) -> List[ConnRow]:
    rows: List[ConnRow] = []

    # TCP
    for c in psutil.net_connections(kind="tcp"):
        laddr = c.laddr.ip if c.laddr else ""
        lport = c.laddr.port if c.laddr else 0
        raddr = c.raddr.ip if c.raddr else ""
        rport = c.raddr.port if c.raddr else 0
        pid = c.pid
        pname = ""
        pexe = None

        if include_proc and pid:
            try:
                p = psutil.Process(pid)
                pname = p.name()
                try:
                    pexe = p.exe()
                except Exception:
                    pexe = None
            except Exception:
                pname = ""
                pexe = None

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
                exe=pexe,
            )
        )

    # UDP
    for c in psutil.net_connections(kind="udp"):
        laddr = c.laddr.ip if c.laddr else ""
        lport = c.laddr.port if c.laddr else 0
        pid = c.pid
        pname = ""
        pexe = None

        if include_proc and pid:
            try:
                p = psutil.Process(pid)
                pname = p.name()
                try:
                    pexe = p.exe()
                except Exception:
                    pexe = None
            except Exception:
                pname = ""
                pexe = None

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
                exe=pexe,
            )
        )

    return rows


def collect_routes() -> List[RouteRow]:
    rows: List[RouteRow] = []

    # Default gateways via netifaces
    try:
        gws = netifaces.gateways()
        default = gws.get("default", {})
        for _fam, (gw, iface) in default.items():
            rows.append(
                RouteRow(
                    destination="0.0.0.0/0",
                    gateway=str(gw),
                    iface=str(iface),
                    metric=None,
                )
            )
    except Exception:
        pass

    # Linux /proc/net/route for extra detail
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
                        metric_str = parts[6]
                        metric = int(metric_str) if metric_str.isdigit() else None
                        destination = _hex_to_ipv4(dest_hex)
                        gateway = _hex_to_ipv4(gw_hex)
                        rows.append(
                            RouteRow(
                                destination=destination,
                                gateway=gateway,
                                iface=iface,
                                metric=metric,
                            )
                        )
        except Exception:
            pass

    return rows


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


def build_snapshot(include_proc: bool = True) -> Snapshot:
    host = {
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "platform": platform.platform(),
        "os": platform.system(),
        "os_release": platform.release(),
    }

    interfaces = collect_interfaces()
    connections = collect_connections(include_proc=include_proc)
    routes = collect_routes()
    arp = collect_arp()
    dns = collect_dns()

    snap = Snapshot(
        created_utc=datetime.now(timezone.utc).isoformat(),
        host=host,
        interfaces=interfaces,
        connections=connections,
        routes=routes,
        arp=arp,
        dns=dns,
    )
    postprocess_snapshot(snap)
    return snap


def postprocess_snapshot(snapshot: Snapshot) -> None:
    """Fill snapshot.suspicious using simple rule-based detection."""
    suspicious: List[SuspiciousRow] = []

    for c in snapshot.connections:
        reasons: List[str] = []

        # 1) Remote IP is public
        if c.raddr and is_public_ip(c.raddr):
            reasons.append("Remote IP is public (outside local network)")

        # 2) High-risk port
        if c.rport in HIGH_RISK_PORTS:
            reasons.append(f"High-risk remote port {c.rport}")

        # 3) Unknown / missing process name
        if not c.proc:
            reasons.append("Unknown or missing process name")

        # 4) Process binary in temp/suspicious directory
        if c.exe:
            exe_lower = c.exe.lower()
            if exe_lower.startswith(TEMP_DIR_PREFIXES):
                reasons.append(f"Process binary in temp directory: {c.exe}")

        if not reasons:
            continue

        summary = f"{c.proto} {c.laddr}:{c.lport} -> {c.raddr}:{c.rport}"
        extras: List[str] = []
        if c.pid:
            extras.append(f"PID {c.pid}")
        if c.proc:
            extras.append(c.proc)
        if c.exe:
            extras.append(c.exe)
        extra_str = " | ".join(extras) if extras else ""

        suspicious.append(
            SuspiciousRow(
                category="Connection",
                summary=summary,
                reason=", ".join(reasons),
                extra=extra_str,
            )
        )

    snapshot.suspicious = suspicious


# -------------------------
# Qt Worker
# -------------------------

class ScanWorker(QtCore.QThread):
    finished = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(str)

    def __init__(self, include_proc: bool = True, parent=None):
        super().__init__(parent)
        self.include_proc = include_proc

    def run(self):
        try:
            snap = build_snapshot(include_proc=self.include_proc)
            self.finished.emit(snap)
        except Exception as e:
            self.failed.emit(str(e))


# -------------------------
# GUI widgets
# -------------------------

class HostSummary(QtWidgets.QFrame):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QtWidgets.QFrame.StyledPanel)
        title = QtWidgets.QLabel("Host Overview")
        title.setStyleSheet("font-weight:600;font-size:16px;")

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
        self.lblHostname.setText(f"Hostname: {snap.host.get('hostname', '-')}")
        self.lblFqdn.setText(f"FQDN: {snap.host.get('fqdn', '-')}")
        self.lblOS.setText(f"OS: {snap.host.get('platform', '-')}")
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
        row_items = [QtGui.QStandardItem(str(v)) for v in values]
        for it in row_items:
            it.setEditable(False)
        self.model.appendRow(row_items)


# -------------------------
# Main window
# -------------------------

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Analysis Tool")
        self.resize(1100, 700)

        self.config = load_config()
        self._current_snapshot: Optional[Snapshot] = None
        self.worker: Optional[ScanWorker] = None

        self._build_ui()
        self._wire_actions()
        self._setup_auto_scan()

    def _build_ui(self):
        self.statusBar().showMessage("Ready")

        # Toolbar
        toolbar = QtWidgets.QToolBar("Main")
        toolbar.setIconSize(QtCore.QSize(18, 18))
        self.addToolBar(toolbar)

        self.actScan = QtWidgets.QAction("Scan", self)
        self.actExportJson = QtWidgets.QAction("Export JSON", self)
        self.actExportPdf = QtWidgets.QAction("Export PDF", self)
        self.actOpenConfig = QtWidgets.QAction("Open Config", self)

        toolbar.addAction(self.actScan)
        toolbar.addSeparator()
        toolbar.addAction(self.actExportJson)
        toolbar.addAction(self.actExportPdf)
        toolbar.addSeparator()
        toolbar.addAction(self.actOpenConfig)

        # Splitter
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.setCentralWidget(splitter)

        self.summary = HostSummary()
        splitter.addWidget(self.summary)

        self.tabs = QtWidgets.QTabWidget()
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 3)

        self.tabInterfaces = TableTab(["Name", "MAC", "IPv4", "IPv6", "Up", "Speed(Mbps)"])
        self.tabConnections = TableTab(["Proto", "Laddr", "Lport", "Raddr", "Rport", "Status", "PID", "Process", "Exe"])
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

        # Progress bar
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress)

    def _wire_actions(self):
        self.actScan.triggered.connect(self.on_scan)
        self.actExportJson.triggered.connect(self.on_export_json)
        self.actExportPdf.triggered.connect(self.on_export_pdf)
        self.actOpenConfig.triggered.connect(self.on_open_config)

    # ------------- Auto scan -------------

    def _setup_auto_scan(self):
        if not self.config.get("enable_auto_scan", False):
            return
        minutes = self.config.get("scan_interval_minutes", 30)
        if minutes <= 0:
            return

        self.auto_timer = QtCore.QTimer(self)
        self.auto_timer.timeout.connect(self.on_auto_scan_timeout)
        self.auto_timer.start(int(minutes * 60 * 1000))
        self.statusBar().showMessage(f"Ready (auto-scan every {minutes} min)")

    def on_auto_scan_timeout(self):
        try:
            snap = build_snapshot(include_proc=self.config.get("include_process_details", True))
            self._auto_export_snapshot(snap)
        except Exception as e:
            print(f"Auto scan failed: {e}")

    def _auto_export_snapshot(self, snap: Snapshot):
        export_dir = Path(self.config.get("exports_folder", "Exports"))
        export_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        prefix = self.config.get("log_filename_prefix", "scan")
        path = export_dir / f"{prefix}_{ts}.json"
        data = snap.to_json_with_sha()
        path.write_text(data)
        self._cleanup_old_logs(export_dir, prefix)

    def _cleanup_old_logs(self, folder: Path, prefix: str):
        max_logs = int(self.config.get("max_logs", 10))
        pattern = folder / f"{prefix}_*.json"
        files = sorted(pattern.parent.glob(pattern.name), key=lambda p: p.stat().st_mtime)
        if len(files) <= max_logs:
            return
        to_delete = len(files) - max_logs
        for i in range(to_delete):
            try:
                files[i].unlink()
            except Exception:
                pass

    # ------------- Actions -------------

    def on_scan(self):
        if self.worker and self.worker.isRunning():
            return

        self.progress.setVisible(True)
        self.statusBar().showMessage("Scanning...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)

        self.worker = ScanWorker(include_proc=self.config.get("include_process_details", True))
        self.worker.finished.connect(self.on_scan_done)
        self.worker.failed.connect(self.on_scan_failed)
        self.worker.start()

    def on_scan_done(self, snap: Snapshot):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.progress.setVisible(False)
        self._current_snapshot = snap
        self.statusBar().showMessage("Scan complete")
        self._populate_from_snapshot(snap)

    def on_scan_failed(self, msg: str):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.progress.setVisible(False)
        QtWidgets.QMessageBox.critical(self, "Scan failed", msg)
        self.statusBar().showMessage("Scan failed")

    def _populate_from_snapshot(self, snap: Snapshot):
        self.summary.update_from_snapshot(snap)

        self.tabInterfaces.clear()
        for r in snap.interfaces:
            self.tabInterfaces.add_row(
                [r.name, r.mac, r.ipv4, r.ipv6, "Yes" if r.up else "No", r.speed_mbps or "-"]
            )

        self.tabConnections.clear()
        for c in snap.connections:
            self.tabConnections.add_row(
                [
                    c.proto,
                    c.laddr,
                    c.lport,
                    c.raddr,
                    c.rport,
                    c.status,
                    c.pid or "-",
                    c.proc,
                    c.exe or "-",
                ]
            )

        self.tabRoutes.clear()
        for r in snap.routes:
            self.tabRoutes.add_row(
                [r.destination, r.gateway, r.iface, r.metric if r.metric is not None else "-"]
            )

        self.tabDNS.clear()
        dns = snap.dns
        self.tabDNS.add_row(
            [
                ", ".join(dns.nameservers),
                ", ".join(dns.search),
                json.dumps(dns.options, sort_keys=True),
            ]
        )

        self.tabARP.clear()
        for a in snap.arp:
            self.tabARP.add_row([a.ip, a.mac, a.iface])

        self.tabSuspicious.clear()
        for s in snap.suspicious:
            self.tabSuspicious.add_row(
                [s.category, s.summary, s.reason, s.extra]
            )

    def on_export_json(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return

        export_dir = Path(self.config.get("exports_folder", "Exports"))
        export_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = export_dir / f"snapshot-{ts}.json"

        data = self._current_snapshot.to_json_with_sha()
        path.write_text(data)
        QtGui.QDesktopServices.openUrl(
            QtCore.QUrl.fromLocalFile(str(export_dir.resolve()))
        )
        self.statusBar().showMessage(f"Saved JSON: {path}")

    def on_export_pdf(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return

        export_dir = Path(self.config.get("exports_folder", "Exports"))
        export_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = export_dir / f"snapshot-{ts}.pdf"

        self._render_pdf(str(out_path))

        QtGui.QDesktopServices.openUrl(
            QtCore.QUrl.fromLocalFile(str(export_dir.resolve()))
        )
        self.statusBar().showMessage(f"Saved PDF: {out_path}")

    def on_open_config(self):
        cfg_path = Path("config.json")
        if not cfg_path.exists():
            save_default_config("config.json")

        system = platform.system()
        try:
            if system == "Linux":
                subprocess.Popen(["xdg-open", str(cfg_path)])
            elif system == "Darwin":  # macOS
                subprocess.Popen(["open", str(cfg_path)])
            elif system == "Windows":
                os.startfile(str(cfg_path))  # type: ignore[attr-defined]
            else:
                QtWidgets.QMessageBox.information(
                    self,
                    "Config",
                    f"Config file is at: {cfg_path.resolve()}",
                )
        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self,
                "Config",
                f"Failed to open config file automatically.\nPath: {cfg_path.resolve()}\nError: {e}",
            )

    # ------------- PDF rendering -------------

    def _render_pdf(self, out_path: str):
        snap = self._current_snapshot
        if not snap:
            return

        html: List[str] = []
        html.append("<h2>Network Snapshot Report</h2>")
        html.append(f"<p><b>Created (UTC):</b> {snap.created_utc}</p>")
        html.append(
            f"<p><b>Host:</b> {_e(snap.host.get('hostname','-'))} | "
            f"{_e(snap.host.get('platform','-'))}</p>"
        )

        # Interfaces
        html.append("<h3>Interfaces</h3>")
        html.append("<table border='1' cellspacing='0' cellpadding='3'>")
        html.append(
            "<tr><th>Name</th><th>MAC</th><th>IPv4</th>"
            "<th>IPv6</th><th>Up</th><th>Speed</th></tr>"
        )
        for r in snap.interfaces:
            html.append(
                "<tr>"
                f"<td>{_e(r.name)}</td>"
                f"<td>{_e(r.mac)}</td>"
                f"<td>{_e(r.ipv4)}</td>"
                f"<td>{_e(r.ipv6)}</td>"
                f"<td>{'Yes' if r.up else 'No'}</td>"
                f"<td>{_e(r.speed_mbps or '-')}</td>"
                "</tr>"
            )
        html.append("</table>")

        # Connections
        html.append("<h3>Connections</h3>")
        html.append("<table border='1' cellspacing='0' cellpadding='3'>")
        html.append(
            "<tr><th>Proto</th><th>Laddr</th><th>Lport</th><th>Raddr</th><th>Rport</th>"
            "<th>Status</th><th>PID</th><th>Process</th><th>Exe</th></tr>"
        )
        for c in snap.connections:
            html.append(
                "<tr>"
                f"<td>{_e(c.proto)}</td>"
                f"<td>{_e(c.laddr)}</td>"
                f"<td>{c.lport}</td>"
                f"<td>{_e(c.raddr)}</td>"
                f"<td>{c.rport}</td>"
                f"<td>{_e(c.status)}</td>"
                f"<td>{_e(c.pid or '-')}</td>"
                f"<td>{_e(c.proc)}</td>"
                f"<td>{_e(c.exe or '-')}</td>"
                "</tr>"
            )
        html.append("</table>")

        # Routes
        html.append("<h3>Routes</h3>")
        html.append("<table border='1' cellspacing='0' cellpadding='3'>")
        html.append("<tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th></tr>")
        for r in snap.routes:
            html.append(
                "<tr>"
                f"<td>{_e(r.destination)}</td>"
                f"<td>{_e(r.gateway)}</td>"
                f"<td>{_e(r.iface)}</td>"
                f"<td>{_e(r.metric or '-')}</td>"
                "</tr>"
            )
        html.append("</table>")

        # DNS
        html.append("<h3>DNS</h3>")
        html.append(
            "<p>"
            f"<b>Nameservers:</b> {_e(', '.join(snap.dns.nameservers))}<br>"
            f"<b>Search:</b> {_e(', '.join(snap.dns.search))}<br>"
            f"<b>Options:</b> {_e(json.dumps(snap.dns.options, sort_keys=True))}"
            "</p>"
        )

        # ARP
        html.append("<h3>ARP</h3>")
        html.append("<table border='1' cellspacing='0' cellpadding='3'>")
        html.append("<tr><th>IP</th><th>MAC</th><th>Iface</th></tr>")
        for a in snap.arp:
            html.append(
                "<tr>"
                f"<td>{_e(a.ip)}</td>"
                f"<td>{_e(a.mac)}</td>"
                f"<td>{_e(a.iface)}</td>"
                "</tr>"
            )
        html.append("</table>")

        # Suspicious
        html.append("<h3>Suspicious</h3>")
        if snap.suspicious:
            html.append("<table border='1' cellspacing='0' cellpadding='3'>")
            html.append("<tr><th>Category</th><th>Summary</th><th>Reason</th><th>Extra</th></tr>")
            for s in snap.suspicious:
                html.append(
                    "<tr>"
                    f"<td>{_e(s.category)}</td>"
                    f"<td>{_e(s.summary)}</td>"
                    f"<td>{_e(s.reason)}</td>"
                    f"<td>{_e(s.extra)}</td>"
                    "</tr>"
                )
            html.append("</table>")
        else:
            html.append("<p>No suspicious items detected by current rules.</p>")

        if snap.sha256:
            html.append(f"<p><b>SHA-256:</b> {_e(snap.sha256)}</p>")

        doc = QtGui.QTextDocument("\n".join(html))
        printer = QtPrintSupport.QPrinter(QtPrintSupport.QPrinter.HighResolution)
        printer.setOutputFormat(QtPrintSupport.QPrinter.PdfFormat)
        printer.setOutputFileName(out_path)
        doc.print_(printer)


# -------------------------
# Helpers
# -------------------------

def _hex_to_ipv4(hex_str: str) -> str:
    try:
        b = bytes.fromhex(hex_str)
        if len(b) == 4:
            return ".".join(str(x) for x in b[::-1])
    except Exception:
        pass
    return "-"


def _e(s: Any) -> str:
    text = "" if s is None else str(s)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# -------------------------
# Entry point
# -------------------------

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setApplicationName("Network Analysis Tool")

    win = MainWindow()
    win.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
