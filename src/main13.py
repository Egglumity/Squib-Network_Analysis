#!/usr/bin/env python3
"""
Network Analysis Tool v0.5.0
"""

import sys
import os
import platform
import subprocess

# Check dependencies before importing
def check_dependencies():
    missing_deps = []
    try:
        import PyQt5
    except ImportError:
        missing_deps.append("PyQt5")
    
    try:
        import psutil
    except ImportError:
        missing_deps.append("psutil")
    
    try:
        import netifaces
    except ImportError:
        missing_deps.append("netifaces")
    
    if missing_deps:
        print(f"Missing dependencies: {', '.join(missing_deps)}")
        print("Please install with: pip install PyQt5 psutil netifaces")
        return False
    return True

if not check_dependencies():
    sys.exit(1)

# Now import the rest
import hashlib
import ipaddress
import json
import socket
import time
import zipfile
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import netifaces
import psutil
from PyQt5 import QtCore, QtGui, QtPrintSupport, QtWidgets

__version__ = "0.5"

# -------------------------
# Default Documentation Files
# -------------------------
DEFAULT_README = """# Network Analysis Tool

A Python-based network analysis tool that scans and displays network information.

## Features
- Network interface scanning
- Connection monitoring
- Route table analysis
- DNS configuration
- ARP table inspection
- Suspicious activity detection
- Export capabilities (JSON, PDF, ZIP)
- Dark mode interface
- Auto-scan scheduling
- Notifications system
"""

DEFAULT_CHANGELOG = """# Changelog

## Version 0.3.1
- Fixed application startup issues
- Improved error handling
- Better dependency checking

## Version 0.3.0
- Added export all (ZIP) functionality
- Simple dark mode
- Status bar with countdown
- Notifications system
- Auto-scan configuration
- Documentation generation
"""

# -------------------------
# Config
# -------------------------
DEFAULT_CONFIG = {
    "scan_interval_minutes": 30,
    "max_logs": 10,
    "exports_folder": "Exports",
    "enable_auto_scan": False,
    "log_filename_prefix": "scan",
    "include_process_details": True,
    "dark_mode": False
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

def write_readme_if_missing():
    r = Path("README.md")
    if r.exists():
        return
    r.write_text(DEFAULT_README)

def write_changelog_if_missing():
    p = Path("CHANGELOG.md")
    if p.exists():
        return
    p.write_text(DEFAULT_CHANGELOG)

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
    exe: Optional[str]

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
    hostname: Optional[str] = None

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
# Helpers & collectors
# -------------------------
HIGH_RISK_PORTS = {23, 4444, 1337, 31337, 3389, 6667}
TEMP_DIR_PREFIXES = ("/tmp", "/dev/shm", "/var/tmp")

def is_public_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local)
    except Exception:
        return False

def _hex_to_ipv4(hex_str: str) -> str:
    try:
        b = bytes.fromhex(hex_str)
        if len(b) == 4:
            return ".".join(str(x) for x in b[::-1])
    except Exception:
        pass
    return "-"

def collect_interfaces() -> List[InterfaceRow]:
    rows: List[InterfaceRow] = []
    try:
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
            if st:
                up_status = bool(st.isup)
                speed = getattr(st, "speed", None)
            else:
                up_status = False
                speed = None
                
            rows.append(InterfaceRow(
                name=name, 
                mac=mac, 
                ipv4=", ".join(ipv4s) if ipv4s else "-", 
                ipv6=", ".join(ipv6s) if ipv6s else "-", 
                up=up_status, 
                speed_mbps=speed
            ))
    except Exception as e:
        print(f"Error collecting interfaces: {e}")
    
    return rows

def collect_connections(include_proc: bool = True) -> List[ConnRow]:
    rows: List[ConnRow] = []
    
    # TCP connections
    try:
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
                    
            rows.append(ConnRow(
                proto="TCP", 
                laddr=laddr, 
                lport=lport, 
                raddr=raddr, 
                rport=rport, 
                status=c.status or "", 
                pid=pid, 
                proc=pname, 
                exe=pexe
            ))
    except Exception as e:
        print(f"Warning: Could not collect TCP connections: {e}")
    
    # UDP connections
    try:
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
                    
            rows.append(ConnRow(
                proto="UDP", 
                laddr=laddr, 
                lport=lport, 
                raddr="", 
                rport=0, 
                status="", 
                pid=pid, 
                proc=pname, 
                exe=pexe
            ))
    except Exception as e:
        print(f"Warning: Could not collect UDP connections: {e}")
    
    return rows

def collect_routes() -> List[RouteRow]:
    rows: List[RouteRow] = []
    
    # Get default gateway
    try:
        gws = netifaces.gateways()
        default = gws.get("default", {})
        for fam, (gw, iface, _) in default.items():
            if fam == netifaces.AF_INET:  # IPv4
                rows.append(RouteRow(
                    destination="0.0.0.0/0", 
                    gateway=str(gw), 
                    iface=str(iface), 
                    metric=None
                ))
    except Exception as e:
        print(f"Warning: Could not collect default gateway: {e}")
    
    # Read Linux route table
    route_path = Path("/proc/net/route")
    if route_path.exists():
        try:
            with route_path.open() as f:
                next(f)  # Skip header
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
                        
                        # Skip default route as we already have it from netifaces
                        if destination != "0.0.0.0":
                            rows.append(RouteRow(
                                destination=destination, 
                                gateway=gateway, 
                                iface=iface, 
                                metric=metric
                            ))
        except Exception as e:
            print(f"Warning: Could not read route table: {e}")
    
    return rows

def collect_arp() -> List[ArpRow]:
    rows: List[ArpRow] = []
    path = Path("/proc/net/arp")
    if path.exists():
        try:
            with path.open() as f:
                next(f)  # Skip header
                for line in f:
                    cols = line.split()
                    if len(cols) >= 6:
                        ip, _hw, _flags, mac, _mask, iface = cols[:6]
                        hostname = None
                        try:
                            hostname = socket.getfqdn(ip)
                        except Exception:
                            hostname = None
                        rows.append(ArpRow(ip=ip, mac=mac, iface=iface, hostname=hostname))
        except Exception as e:
            print(f"Warning: Could not read ARP table: {e}")
    return rows

def collect_dns() -> DnsData:
    nameservers: List[str] = []
    search: List[str] = []
    options: Dict[str, Any] = {}
    
    path = Path("/etc/resolv.conf")
    if path.exists():
        try:
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
        except Exception as e:
            print(f"Warning: Could not read DNS config: {e}")
    
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
        dns=dns
    )
    postprocess_snapshot(snap)
    return snap

def postprocess_snapshot(snapshot: Snapshot) -> None:
    suspicious: List[SuspiciousRow] = []
    
    for c in snapshot.connections:
        reasons: List[str] = []
        
        if c.raddr and is_public_ip(c.raddr):
            reasons.append("Remote IP is public (outside local network)")
        
        if c.rport in HIGH_RISK_PORTS:
            reasons.append(f"High-risk remote port {c.rport}")
        
        if not c.proc:
            reasons.append("Unknown or missing process name")
        
        if c.exe:
            exe_lower = c.exe.lower()
            if any(exe_lower.startswith(prefix) for prefix in TEMP_DIR_PREFIXES):
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
        
        suspicious.append(SuspiciousRow(
            category="Connection", 
            summary=summary, 
            reason=", ".join(reasons), 
            extra=extra_str
        ))
    
    snapshot.suspicious = suspicious

# -------------------------
# Worker
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
# GUI components
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
        items = [QtGui.QStandardItem(str(v)) for v in values]
        for it in items:
            it.setEditable(False)
        self.model.appendRow(items)

class Toast(QtWidgets.QWidget):
    def __init__(self, message: str, parent=None, timeout: int = 3000):
        super().__init__(parent, flags=QtCore.Qt.FramelessWindowHint | QtCore.Qt.Tool)
        self.setAttribute(QtCore.Qt.WA_TranslucentBackground)
        self.timeout = timeout
        self.label = QtWidgets.QLabel(message)
        self.label.setStyleSheet("background:#333;color:#fff;padding:8px;border-radius:6px;")
        layout = QtWidgets.QHBoxLayout(self)
        layout.addWidget(self.label)
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.close)

    def show_at(self, x: int, y: int):
        self.move(x, y)
        self.show()
        self.timer.start(self.timeout)

# -------------------------
# Main window
# -------------------------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        print("Initializing MainWindow...")
        self.setWindowTitle(f"Network Analysis Tool v{__version__}")
        self.resize(1200, 780)
        
        try:
            self.config = load_config()
            write_readme_if_missing()
            write_changelog_if_missing()
            self._current_snapshot: Optional[Snapshot] = None
            self.worker: Optional[ScanWorker] = None
            self.next_scan_time: Optional[float] = None
            
            self._build_ui()
            
            if self.config.get("dark_mode", False):
                self.enable_dark_mode(True)
                
            self._wire_actions()
            self._setup_auto_scan()
            
            self._status_timer = QtCore.QTimer(self)
            self._status_timer.timeout.connect(self._update_status_bar)
            self._status_timer.start(1000)
            
            print("MainWindow initialized successfully")
            
        except Exception as e:
            print(f"Error initializing MainWindow: {e}")
            raise

    def _build_ui(self):
        print("Building UI...")
        self.statusBar().showMessage("Ready")
        
        # Create toolbar
        toolbar = QtWidgets.QToolBar("Main")
        toolbar.setIconSize(QtCore.QSize(18, 18))
        self.addToolBar(toolbar)
        
        # Create Scan Button (instead of action)
        self.scanButton = QtWidgets.QPushButton("Scan")
        self.scanButton.setStyleSheet("""
            QPushButton {
                background-color: #0078D4;
                color: white;
                font-weight: bold;
                padding: 6px 12px;
                border: 1px solid #005A9E;
                border-radius: 4px;
                min-width: 60px;
            }
            QPushButton:hover {
                background-color: #106EBE;
            }
            QPushButton:pressed {
                background-color: #005A9E;
            }
            QPushButton:disabled {
                background-color: #CCCCCC;
                color: #666666;
                border: 1px solid #999999;
            }
        """)
        self.scanButton.clicked.connect(self.on_scan)
        
        # Add button to toolbar
        toolbar.addWidget(self.scanButton)
        toolbar.addSeparator()
        
        # Create other actions AFTER the scan button
        self.actExportJson = QtWidgets.QAction("Export JSON", self)
        self.actExportPdf = QtWidgets.QAction("Export PDF", self)
        self.actExportAll = QtWidgets.QAction("Export All (ZIP)", self)
        self.actOpenConfig = QtWidgets.QAction("Open Config", self)
        self.actToggleDark = QtWidgets.QAction("Toggle Dark Mode", self)
        
        # Add other actions to toolbar
        toolbar.addAction(self.actExportJson)
        toolbar.addAction(self.actExportPdf)
        toolbar.addAction(self.actExportAll)
        toolbar.addSeparator()
        toolbar.addAction(self.actOpenConfig)
        toolbar.addSeparator()
        toolbar.addAction(self.actToggleDark)
        
        # Create main splitter
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.setCentralWidget(splitter)
        
        # Left panel - Summary
        self.summary = HostSummary()
        splitter.addWidget(self.summary)
        
        # Right panel - Tabs
        self.tabs = QtWidgets.QTabWidget()
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 3)
        
        # Create tabs
        self.tabInterfaces = TableTab(["Name", "MAC", "IPv4", "IPv6", "Up", "Speed(Mbps)"])
        self.tabConnections = TableTab(["Proto", "Laddr", "Lport", "Raddr", "Rport", "Status", "PID", "Process", "Exe"])
        self.tabServices = TableTab(["Process", "PID", "Protocol", "Port", "Exe"])
        self.tabRoutes = TableTab(["Destination", "Gateway", "Iface", "Metric"])
        self.tabDNS = TableTab(["Nameservers", "Search", "Options(JSON)"])
        self.tabARP = TableTab(["IP", "MAC", "Hostname", "Iface"])
        self.tabSuspicious = TableTab(["Category", "Summary", "Reason", "Extra"])
        
        # Add tabs to tab widget
        self.tabs.addTab(self.tabInterfaces, "Interfaces")
        self.tabs.addTab(self.tabConnections, "Connections")
        self.tabs.addTab(self.tabServices, "Services")
        self.tabs.addTab(self.tabRoutes, "Routes")
        self.tabs.addTab(self.tabDNS, "DNS")
        self.tabs.addTab(self.tabARP, "ARP")
        self.tabs.addTab(self.tabSuspicious, "Suspicious")
        
        # Notifications dock
        self.notifDock = QtWidgets.QDockWidget("Console", self)
        self.notifList = QtWidgets.QListWidget()
        self.notifDock.setWidget(self.notifList)
        self.addDockWidget(QtCore.Qt.BottomDockWidgetArea, self.notifDock)
        self.notifDock.setFloating(False)
        
        # Progress bar
        self.progress = QtWidgets.QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setVisible(False)
        self.statusBar().addPermanentWidget(self.progress)
        
        # Status widgets
        self.lbl_next = QtWidgets.QLabel("Next: -")
        self.lbl_last = QtWidgets.QLabel("Last: -")
        self.lbl_susp = QtWidgets.QLabel("Suspicious: 0")
        self.statusBar().addPermanentWidget(self.lbl_next)
        self.statusBar().addPermanentWidget(self.lbl_last)
        self.statusBar().addPermanentWidget(self.lbl_susp)
        
        print("UI built successfully")

    def _wire_actions(self):
        # self.actScan.triggered.connect(self.on_scan)  # Remove this line
        self.actExportJson.triggered.connect(self.on_export_json)
        self.actExportPdf.triggered.connect(self.on_export_pdf)
        self.actExportAll.triggered.connect(self.on_export_all)
        self.actOpenConfig.triggered.connect(self.on_open_config)
        self.actToggleDark.triggered.connect(self._toggle_dark_mode_handler)

    def _setup_auto_scan(self):
        if not self.config.get("enable_auto_scan", False):
            self.next_scan_time = None
            return
        minutes = int(self.config.get("scan_interval_minutes", 30))
        if minutes <= 0:
            self.next_scan_time = None
            return
        self.auto_timer = QtCore.QTimer(self)
        self.auto_timer.timeout.connect(self._auto_scan_trigger)
        self.auto_timer.start(60 * 1000)
        self.next_scan_time = time.time() + minutes * 60

    def _auto_scan_trigger(self):
        if self.next_scan_time and time.time() >= self.next_scan_time:
            self.on_scan(auto=True)
            minutes = int(self.config.get("scan_interval_minutes", 30))
            self.next_scan_time = time.time() + minutes * 60

    def _update_status_bar(self):
        if self.next_scan_time:
            rem = int(max(0, self.next_scan_time - time.time()))
            m, s = divmod(rem, 60)
            self.lbl_next.setText(f"Next: {m:02d}:{s:02d}")
        else:
            self.lbl_next.setText("Next: -")
            
        if self._current_snapshot:
            try:
                t = datetime.fromisoformat(self._current_snapshot.created_utc)
                self.lbl_last.setText(f"Last: {t.strftime('%Y-%m-%d %H:%M:%S')}")
            except Exception:
                self.lbl_last.setText(f"Last: {self._current_snapshot.created_utc}")
        else:
            self.lbl_last.setText("Last: -")
            
        cnt = len(self._current_snapshot.suspicious) if self._current_snapshot else 0
        self.lbl_susp.setText(f"Suspicious: {cnt}")

    def on_scan(self, auto: bool = False):
        if getattr(self, 'worker', None) and self.worker.isRunning():
            return
        
        # Disable button during scan
        self.scanButton.setEnabled(False)
        self.scanButton.setText("Scanning...")
        
        self.progress.setVisible(True)
        self.statusBar().showMessage("Scanning...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
        self.worker = ScanWorker(include_proc=self.config.get("include_process_details", True))
        self.worker.finished.connect(self._on_scan_done)
        self.worker.failed.connect(self._on_scan_failed)
        self.worker.start()

    def _on_scan_done(self, snap: Snapshot):
        # Re-enable button
        self.scanButton.setEnabled(True)
        self.scanButton.setText("Scan")
        
        QtWidgets.QApplication.restoreOverrideCursor()
        self.progress.setVisible(False)
        self._current_snapshot = snap
        self.statusBar().showMessage("Scan complete")
        self._populate_from_snapshot(snap)
        self._notify("Scan Completed!")
        
        if self.config.get("enable_auto_scan", False):
            try:
                self._auto_export_snapshot(snap)
            except Exception as e:
                print(f"Auto-export failed: {e}")

    def _on_scan_failed(self, msg: str):
        # Re-enable button on failure too
        self.scanButton.setEnabled(True)
        self.scanButton.setText("Scan")
        
        QtWidgets.QApplication.restoreOverrideCursor()
        self.progress.setVisible(False)
        QtWidgets.QMessageBox.critical(self, "Scan failed", msg)
        self.statusBar().showMessage("Scan failed")

    def _populate_from_snapshot(self, snap: Snapshot):
        self.summary.update_from_snapshot(snap)
        
        # Clear all tabs
        self.tabInterfaces.clear()
        self.tabConnections.clear()
        self.tabServices.clear()
        self.tabRoutes.clear()
        self.tabDNS.clear()
        self.tabARP.clear()
        self.tabSuspicious.clear()
        
        # Populate interfaces
        for r in snap.interfaces:
            self.tabInterfaces.add_row([r.name, r.mac, r.ipv4, r.ipv6, "Yes" if r.up else "No", r.speed_mbps or "-"])
        
        # Populate connections
        for c in snap.connections:
            self.tabConnections.add_row([c.proto, c.laddr, c.lport, c.raddr, c.rport, c.status, c.pid or "-", c.proc, c.exe or "-"])
        
        # Populate services (listening ports)
        for c in snap.connections:
            if c.status and c.status.upper() == 'LISTEN':
                self.tabServices.add_row([c.proc or '-', c.pid or '-', 'TCP', c.lport, c.exe or '-'])
        
        # Populate routes
        for r in snap.routes:
            self.tabRoutes.add_row([r.destination, r.gateway, r.iface, r.metric if r.metric is not None else "-"])
        
        # Populate DNS
        dns = snap.dns
        self.tabDNS.add_row([", ".join(dns.nameservers), ", ".join(dns.search), json.dumps(dns.options, sort_keys=True)])
        
        # Populate ARP
        for a in snap.arp:
            self.tabARP.add_row([a.ip, a.mac, a.hostname or '-', a.iface])
        
        # Populate suspicious
        for s in snap.suspicious:
            self.tabSuspicious.add_row([s.category, s.summary, s.reason, s.extra])
        
        # Add notifications for suspicious items
        if snap.suspicious:
            for s in snap.suspicious:
                self._add_notification(f"Suspicious: {s.reason} - {s.summary}")

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
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(export_dir.resolve())))
        self.statusBar().showMessage(f"Saved JSON: {path}")

    def on_export_pdf(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return
        export_dir = Path(self.config.get("exports_folder", "Exports"))
        export_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = export_dir / f"snapshot-{ts}.pdf"
        self._render_pdf(out_path)
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(export_dir.resolve())))
        self.statusBar().showMessage(f"Saved PDF: {out_path}")

    def on_export_all(self):
        if not self._current_snapshot:
            QtWidgets.QMessageBox.information(self, "No data", "Run a scan first.")
            return
        export_dir = Path(self.config.get("exports_folder", "Exports"))
        export_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = export_dir / f"report-{ts}"
        base.mkdir(exist_ok=True)
        
        # JSON
        jpath = base / "snapshot.json"
        jpath.write_text(self._current_snapshot.to_json_with_sha())
        
        # PDF
        pdf_path = base / "snapshot.pdf"
        self._render_pdf(pdf_path)
        
        # Config copy
        cfg_path = base / "config.json"
        try:
            if Path('config.json').exists():
                cfg_path.write_text(Path('config.json').read_text())
        except Exception:
            pass
        
        # Changelog entry
        changelog_path = base / "changelog-entry.txt"
        entry = f"{ts} - Exported report {base.name}\nVersion: {__version__}\nSuspicious count: {len(self._current_snapshot.suspicious)}\n"
        changelog_path.write_text(entry)
        
        # ZIP
        zipname = export_dir / f"report-{ts}.zip"
        with zipfile.ZipFile(zipname, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for p in base.glob('*'):
                zf.write(p, arcname=p.name)
        
        # Cleanup
        try:
            for p in base.glob('*'):
                p.unlink()
            base.rmdir()
        except Exception:
            pass
        
        # Update main changelog
        self._append_changelog_entry(entry)
        QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(str(export_dir.resolve())))
        self.statusBar().showMessage(f"Saved Report ZIP: {zipname}")
        self._add_notification(f"Exported report: {zipname.name}")

    def _auto_export_snapshot(self, snap: Snapshot):
        export_dir = Path(self.config.get("exports_folder", "Exports"))
        export_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = self.config.get("log_filename_prefix", "scan")
        path = export_dir / f"{prefix}_{ts}.json"
        data = snap.to_json_with_sha()
        path.write_text(data)
        self._cleanup_old_logs(export_dir, prefix)

    def _cleanup_old_logs(self, folder: Path, prefix: str):
        max_logs = int(self.config.get("max_logs", 10))
        pattern = f"{prefix}_*.json"
        files = sorted(folder.glob(pattern), key=lambda p: p.stat().st_mtime)
        if len(files) <= max_logs:
            return
        to_delete = len(files) - max_logs
        for i in range(to_delete):
            try:
                files[i].unlink()
            except Exception:
                pass

    def _append_changelog_entry(self, entry: str):
        p = Path('CHANGELOG.md')
        try:
            with p.open('a') as f:
                f.write(f"\n{entry}\n")
        except Exception:
            pass

    def on_open_config(self):
        cfg_path = Path('config.json')
        if not cfg_path.exists():
            save_default_config('config.json')
        system = platform.system()
        try:
            if system == 'Linux':
                subprocess.Popen(['xdg-open', str(cfg_path)])
            elif system == 'Darwin':
                subprocess.Popen(['open', str(cfg_path)])
            elif system == 'Windows':
                os.startfile(str(cfg_path))
            else:
                QtWidgets.QMessageBox.information(self, 'Config', f'Config at: {cfg_path.resolve()}')
        except Exception as e:
            QtWidgets.QMessageBox.warning(self, 'Config', f'Failed to open config: {e}')

    def _render_pdf(self, out_path: Path):
        snap = self._current_snapshot
        if not snap:
            return
        
        def _e(s: Any) -> str:
            text = "" if s is None else str(s)
            return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        html = []
        html.append('<html><head><meta charset="utf-8"></head><body>')
        html.append(f"<h2>Network Snapshot Report</h2>")
        html.append(f"<p><b>Created (UTC):</b> {snap.created_utc}</p>")
        html.append(f"<p><b>Host:</b> {_e(snap.host.get('hostname','-'))} | {_e(snap.host.get('platform','-'))}</p>")
        
        # interfaces
        html.append('<h3>Interfaces</h3>')
        html.append('<table border="1" cellspacing="0" cellpadding="3">')
        html.append('<tr><th>Name</th><th>MAC</th><th>IPv4</th><th>IPv6</th><th>Up</th><th>Speed</th></tr>')
        for r in snap.interfaces:
            html.append(f"<tr><td>{_e(r.name)}</td><td>{_e(r.mac)}</td><td>{_e(r.ipv4)}</td><td>{_e(r.ipv6)}</td><td>{'Yes' if r.up else 'No'}</td><td>{_e(r.speed_mbps or '-')}</td></tr>")
        html.append('</table>')
        
        # connections
        html.append('<h3>Connections</h3>')
        html.append('<table border="1" cellspacing="0" cellpadding="3">')
        html.append('<tr><th>Proto</th><th>Laddr</th><th>Lport</th><th>Raddr</th><th>Rport</th><th>Status</th><th>PID</th><th>Process</th><th>Exe</th></tr>')
        for c in snap.connections:
            html.append(f"<tr><td>{_e(c.proto)}</td><td>{_e(c.laddr)}</td><td>{c.lport}</td><td>{_e(c.raddr)}</td><td>{c.rport}</td><td>{_e(c.status)}</td><td>{_e(c.pid or '-')}</td><td>{_e(c.proc)}</td><td>{_e(c.exe or '-')}</td></tr>")
        html.append('</table>')
        
        # suspicious
        html.append('<h3>Suspicious</h3>')
        if snap.suspicious:
            html.append('<table border="1" cellspacing="0" cellpadding="3">')
            html.append('<tr><th>Category</th><th>Summary</th><th>Reason</th><th>Extra</th></tr>')
            for s in snap.suspicious:
                html.append(f"<tr><td>{_e(s.category)}</td><td>{_e(s.summary)}</td><td>{_e(s.reason)}</td><td>{_e(s.extra)}</td></tr>")
            html.append('</table>')
        else:
            html.append('<p>No suspicious items detected by current rules.</p>')
        
        html.append('</body></html>')
        
        doc = QtGui.QTextDocument()
        doc.setHtml('\n'.join(html))
        printer = QtPrintSupport.QPrinter(QtPrintSupport.QPrinter.HighResolution)
        printer.setOutputFormat(QtPrintSupport.QPrinter.PdfFormat)
        printer.setOutputFileName(str(out_path))
        doc.print_(printer)

    def _notify(self, message: str):
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self._add_notification(f"{message} ({ts})")
        
        toast = Toast(message)
        geo = self.geometry()
        x = geo.x() + geo.width() - 260
        y = geo.y() + geo.height() - 120
        toast.show_at(x, y)

    def _add_notification(self, text: str):
        self.notifList.addItem(text)

    def enable_dark_mode(self, enable: bool):
        if enable:
            palette = QtGui.QPalette()
            palette.setColor(QtGui.QPalette.Window, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.WindowText, QtCore.Qt.white)
            palette.setColor(QtGui.QPalette.Base, QtGui.QColor(35, 35, 35))
            palette.setColor(QtGui.QPalette.AlternateBase, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.ToolTipBase, QtCore.Qt.white)
            palette.setColor(QtGui.QPalette.ToolTipText, QtCore.Qt.white)
            palette.setColor(QtGui.QPalette.Text, QtCore.Qt.white)
            palette.setColor(QtGui.QPalette.Button, QtGui.QColor(53, 53, 53))
            palette.setColor(QtGui.QPalette.ButtonText, QtCore.Qt.white)
            palette.setColor(QtGui.QPalette.BrightText, QtCore.Qt.red)
            palette.setColor(QtGui.QPalette.Link, QtGui.QColor(42, 130, 218))
            palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(42, 130, 218))
            palette.setColor(QtGui.QPalette.HighlightedText, QtCore.Qt.black)
            QtWidgets.QApplication.instance().setPalette(palette)
            self.config["dark_mode"] = True
        else:
            QtWidgets.QApplication.instance().setPalette(QtWidgets.QApplication.instance().style().standardPalette())
            self.config["dark_mode"] = False
        
        try:
            Path('config.json').write_text(json.dumps(self.config, indent=4))
        except Exception:
            pass

    def _toggle_dark_mode_handler(self):
        current = bool(self.config.get("dark_mode", False))
        self.enable_dark_mode(not current)

# -------------------------
# Main entry point
# -------------------------
def main():
    print("Starting Network Analysis Tool...")
    
    # Check if we're in a graphical environment
    if platform.system() == "Linux" and "DISPLAY" not in os.environ:
        print("Error: No display found. This application requires a graphical environment.")
        print("If you're using SSH, make sure to enable X11 forwarding with -X or -Y")
        sys.exit(1)
    
    try:
        app = QtWidgets.QApplication(sys.argv)
        app.setApplicationName("Network Analysis Tool")
        app.setApplicationVersion(__version__)
        
        print("Creating main window...")
        window = MainWindow()
        window.show()
        
        print("Application started successfully!")
        print("You should see the main window now.")
        
        return app.exec_()
        
    except Exception as e:
        print(f"Failed to start application: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
