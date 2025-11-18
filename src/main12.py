#!/usr/bin/env python3
"""
main12.py - Network Analysis Tool v0.5.0
Repository: https://github.com/Egglumity/Network-Analysis-Tool
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

__version__ = "0.5.0"

# -------------------------
# Default Documentation Files
# -------------------------
DEFAULT_README = """# Network Analysis Tool

A Python-based network analysis tool that scans and displays network information.

**Repository**: https://github.com/Egglumity/Network-Analysis-Tool

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
- Console output

## Installation
```bash
pip install PyQt5 psutil netifaces
