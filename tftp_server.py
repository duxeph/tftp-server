#!/usr/bin/env python3
"""
TFTP Server — raw-packet implementation via Scapy / Npcap with PyQt6 GUI.

Requirements:  pip install scapy PyQt6
On Windows:    Npcap must be installed (https://npcap.com/)
On Linux:      libpcap-dev + root or CAP_NET_RAW
"""

import sys
import os
import time
import struct
import socket
import threading
import random
from queue import Queue, Empty
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Tuple, List

# ── dependency bootstrap ──────────────────────────────────────────────────────

def _ensure_deps() -> None:
    import importlib.util
    import subprocess
    needed = []
    if not importlib.util.find_spec("scapy"):
        needed.append("scapy")
    if not importlib.util.find_spec("PyQt6"):
        needed.append("PyQt6")
    if needed:
        print(f"[bootstrap] Installing: {', '.join(needed)} ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + needed
        )

_ensure_deps()

import scapy.all as _scapy                          # noqa: E402
from scapy.layers.inet import IP, UDP, ICMP          # noqa: E402
from scapy.layers.l2 import ARP, Ether              # noqa: E402
from scapy.packet import Raw                         # noqa: E402

from PyQt6.QtWidgets import (                        # noqa: E402
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QGroupBox, QLabel, QLineEdit, QPushButton,
    QComboBox, QSpinBox, QDoubleSpinBox, QTextEdit, QTableWidget,
    QTableWidgetItem, QHeaderView, QFileDialog, QSplitter, QMessageBox,
    QSizePolicy,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject  # noqa: E402
from PyQt6.QtGui import QFont, QColor, QTextCursor, QIcon  # noqa: E402


# ══════════════════════════════════════════════════════════════════════════════
#  TFTP PROTOCOL BACKEND
# ══════════════════════════════════════════════════════════════════════════════

OP_RRQ   = 1
OP_WRQ   = 2
OP_DATA  = 3
OP_ACK   = 4
OP_ERROR = 5
OP_OACK  = 6

ERR_NOT_FOUND  = 1
ERR_ACCESS     = 2
ERR_ILLEGAL_OP = 4

DEFAULT_BLOCK_SIZE = 512
MAX_BLOCK_SIZE     = 65464
MIN_BLOCK_SIZE     = 8


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / 1024 ** 2:.2f} MB"


def _next_block(block_num: int) -> int:
    return (block_num % 65535) + 1


def _find_iface_for_ip(target_ip: str) -> Optional[str]:
    for iface in _scapy.get_if_list():
        try:
            if _scapy.get_if_addr(iface) == target_ip:
                return iface
        except Exception:
            pass
    return None


def _get_interfaces() -> List[Tuple[str, str]]:
    """Return list of (iface_name, ip_address) tuples."""
    result = []
    for iface in _scapy.get_if_list():
        try:
            ip = _scapy.get_if_addr(iface)
        except Exception:
            ip = "—"
        result.append((iface, ip))
    return result


class Config:
    def __init__(self, **kw):
        self.filepath:   Path          = Path(".")
        self.server_ip:  str           = "0.0.0.0"
        self.client_ip:  Optional[str] = None
        self.block_size: int           = DEFAULT_BLOCK_SIZE
        self.delay:      float         = 0.0
        self.iface:      Optional[str] = None
        self.timeout:    float         = 5.0
        self.retries:    int           = 5
        self.port:       int           = 69
        for k, v in kw.items():
            setattr(self, k, v)


class TransferSession:
    def __init__(self, client_ip: str, client_port: int, server_ip: str,
                 filepath: Path, block_size: int, delay: float) -> None:
        self.client_ip   = client_ip
        self.client_port = client_port
        self.server_ip   = server_ip
        self.filepath    = filepath
        self.block_size  = block_size
        self.delay       = delay
        self.tid: int    = random.randint(10_000, 60_000)

        self.status:        str                = "init"
        self.start_time:    datetime           = datetime.now()
        self.end_time:      Optional[datetime] = None
        self.bytes_sent:    int                = 0
        self.total_bytes:   int                = 0
        self.current_block: int                = 0
        self.retransmits:   int                = 0
        self.error_msg:     str                = ""
        self._ack_queue: Queue                 = Queue()

    @property
    def duration(self) -> float:
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    @property
    def progress_pct(self) -> float:
        if self.total_bytes == 0:
            return 100.0
        return min(100.0, 100.0 * self.bytes_sent / self.total_bytes)

    @property
    def speed_kbps(self) -> float:
        d = self.duration
        return (self.bytes_sent / d / 1024.0) if d > 0.001 else 0.0

    def notify_ack(self, block_num: int) -> None:
        self._ack_queue.put(block_num)

    def wait_ack(self, expected: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                ack = self._ack_queue.get(timeout=remaining)
                if ack == expected:
                    return True
            except Empty:
                return False


class TFTPServer:
    def __init__(self, config: Config) -> None:
        self.config  = config
        self.running = False
        self._sessions:      Dict[Tuple, TransferSession] = {}
        self._sessions_lock: threading.Lock                = threading.Lock()
        self._log_entries: List[dict] = []
        self._log_lock:    threading.Lock = threading.Lock()
        self.stats = {"requests": 0, "completed": 0, "failed": 0, "filtered": 0}
        self._absorb_sock: Optional[socket.socket] = None

    def _log(self, level: str, msg: str, client: str = "") -> None:
        entry = {
            "ts":     datetime.now().strftime("%H:%M:%S.%f")[:12],
            "level":  level,
            "msg":    msg,
            "client": client,
        }
        with self._log_lock:
            self._log_entries.append(entry)
            if len(self._log_entries) > 500:
                self._log_entries = self._log_entries[-500:]

    def get_log(self, n: int = 50) -> List[dict]:
        with self._log_lock:
            return list(self._log_entries[-n:])

    def get_sessions(self) -> List[TransferSession]:
        with self._sessions_lock:
            return list(self._sessions.values())

    def _bind_absorb_socket(self) -> None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_addr = "" if self.config.server_ip == "0.0.0.0" else self.config.server_ip
            s.bind((bind_addr, self.config.port))
            self._absorb_sock = s
            self._log("INFO", f"Absorb socket bound on :{self.config.port}")
        except PermissionError:
            self._log("WARN", f"Cannot bind port {self.config.port} - need Administrator")
        except OSError as exc:
            self._log("WARN", f"Absorb socket: {exc}")

    def _resolve_iface(self) -> Optional[str]:
        iface = self.config.iface
        if iface:
            return iface
        if self.config.server_ip not in ("0.0.0.0", ""):
            iface = _find_iface_for_ip(self.config.server_ip)
        return iface

    def _bpf_filter(self) -> str:
        parts = ["udp"]
        if self.config.server_ip not in ("0.0.0.0", ""):
            parts.append(f"dst host {self.config.server_ip}")
        if self.config.client_ip:
            parts.append(f"src host {self.config.client_ip}")
        return " and ".join(parts)

    def _send(self, session: TransferSession, payload: bytes) -> None:
        pkt = (
            IP(src=session.server_ip, dst=session.client_ip)
            / UDP(sport=session.tid, dport=session.client_port)
            / Raw(load=payload)
        )
        _scapy.send(pkt, iface=self._resolve_iface(), verbose=False)

    def _send_error_from_port(self, client_ip: str, client_port: int,
                              server_ip: str, src_port: int,
                              code: int, msg: str) -> None:
        payload = struct.pack("!HH", OP_ERROR, code) + msg.encode() + b"\x00"
        pkt = (
            IP(src=server_ip, dst=client_ip)
            / UDP(sport=src_port, dport=client_port)
            / Raw(load=payload)
        )
        _scapy.send(pkt, iface=self._resolve_iface(), verbose=False)

    def _send_with_retry(self, session: TransferSession, payload: bytes,
                         expected_ack: int) -> bool:
        for attempt in range(self.config.retries):
            self._send(session, payload)
            if session.wait_ack(expected_ack, self.config.timeout):
                return True
            if attempt < self.config.retries - 1:
                session.retransmits += 1
                self._log("WARN",
                          f"Retransmit #{attempt + 1} - ACK {expected_ack} - {session.client_ip}",
                          session.client_ip)
        return False

    def _on_packet(self, pkt) -> None:
        try:
            if IP not in pkt or UDP not in pkt:
                return
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            sport  = pkt[UDP].sport
            dport  = pkt[UDP].dport
            raw    = bytes(pkt[UDP].payload)
            if len(raw) < 2:
                return
            opcode = struct.unpack("!H", raw[:2])[0]

            if dport == self.config.port and opcode == OP_RRQ:
                self._handle_rrq(src_ip, sport, dst_ip, raw)
            elif opcode == OP_ACK and len(raw) >= 4:
                block_num = struct.unpack("!H", raw[2:4])[0]
                key = (src_ip, sport, dport)
                with self._sessions_lock:
                    session = self._sessions.get(key)
                if session:
                    session.notify_ack(block_num)
            elif opcode == OP_WRQ and dport == self.config.port:
                self._log("WARN", "WRQ rejected - read-only server", src_ip)
                self._send_error_from_port(
                    src_ip, sport, dst_ip, self.config.port,
                    ERR_ILLEGAL_OP, "Server is read-only")
        except Exception as exc:
            self._log("ERROR", f"Packet handler: {exc}")

    def _handle_rrq(self, client_ip: str, client_port: int,
                    dst_ip: str, raw: bytes) -> None:
        if self.config.client_ip and client_ip != self.config.client_ip:
            self.stats["filtered"] += 1
            self._log("WARN", f"Filtered RRQ from {client_ip}", client_ip)
            return

        self.stats["requests"] += 1
        parts = raw[2:].split(b"\x00")
        if len(parts) < 2:
            return

        req_filename = parts[0].decode("ascii", errors="replace")
        mode         = parts[1].decode("ascii", errors="replace").lower()

        options: Dict[str, str] = {}
        i = 2
        while i + 1 < len(parts) and parts[i]:
            try:
                options[parts[i].decode().lower()] = parts[i + 1].decode()
                i += 2
            except Exception:
                break

        blksize = self.config.block_size
        if "blksize" in options:
            try:
                blksize = min(blksize, max(MIN_BLOCK_SIZE, int(options["blksize"])))
            except ValueError:
                pass

        server_ip = dst_ip if self.config.server_ip == "0.0.0.0" else self.config.server_ip

        session = TransferSession(
            client_ip=client_ip, client_port=client_port,
            server_ip=server_ip, filepath=self.config.filepath,
            block_size=blksize, delay=self.config.delay,
        )
        key = (client_ip, client_port, session.tid)
        with self._sessions_lock:
            self._sessions[key] = session

        self._log("INFO",
                  f"RRQ '{req_filename}' [{mode}] blk={blksize} from {client_ip}:{client_port}",
                  client_ip)

        threading.Thread(target=self._run_transfer, args=(session, options),
                         daemon=True).start()

    def _run_transfer(self, session: TransferSession, options: Dict[str, str]) -> None:
        key = (session.client_ip, session.client_port, session.tid)
        try:
            try:
                file_data = session.filepath.read_bytes()
            except FileNotFoundError:
                self._send_error_from_port(
                    session.client_ip, session.client_port,
                    session.server_ip, self.config.port,
                    ERR_NOT_FOUND, "File not found")
                session.status = "error"
                session.error_msg = "File not found"
                self.stats["failed"] += 1
                return
            except PermissionError:
                self._send_error_from_port(
                    session.client_ip, session.client_port,
                    session.server_ip, self.config.port,
                    ERR_ACCESS, "Access violation")
                session.status = "error"
                session.error_msg = "Access violation"
                self.stats["failed"] += 1
                return

            session.total_bytes = len(file_data)
            session.status = "transferring"

            oack_opts: Dict[str, object] = {}
            if "blksize" in options:
                oack_opts["blksize"] = session.block_size
            if "tsize" in options:
                oack_opts["tsize"] = len(file_data)
            if "timeout" in options:
                try:
                    oack_opts["timeout"] = max(1, min(255, int(options["timeout"])))
                except ValueError:
                    pass

            if oack_opts:
                oack_payload = struct.pack("!H", OP_OACK)
                for k, v in oack_opts.items():
                    oack_payload += k.encode() + b"\x00" + str(v).encode() + b"\x00"
                if not self._send_with_retry(session, oack_payload, expected_ack=0):
                    session.status = "timeout"
                    session.error_msg = "Timeout on OACK"
                    self.stats["failed"] += 1
                    return

            block_num = 1
            offset = 0
            while True:
                chunk = file_data[offset:offset + session.block_size]
                offset += session.block_size
                if session.delay > 0:
                    time.sleep(session.delay)
                data_payload = struct.pack("!HH", OP_DATA, block_num & 0xFFFF) + chunk
                if not self._send_with_retry(session, data_payload,
                                             expected_ack=block_num & 0xFFFF):
                    session.status = "timeout"
                    session.error_msg = f"Timeout at block {block_num}"
                    self.stats["failed"] += 1
                    return
                session.current_block = block_num
                session.bytes_sent = min(offset, len(file_data))
                if len(chunk) < session.block_size:
                    break
                block_num = _next_block(block_num)

            session.status = "completed"
            session.end_time = datetime.now()
            self.stats["completed"] += 1
            self._log("INFO",
                      f"Done {session.client_ip} {_fmt_bytes(session.total_bytes)} "
                      f"{session.speed_kbps:.1f} KB/s {session.duration:.2f}s",
                      session.client_ip)

        except Exception as exc:
            session.status = "error"
            session.error_msg = str(exc)
            self.stats["failed"] += 1
            self._log("ERROR", f"Transfer error ({session.client_ip}): {exc}",
                      session.client_ip)
        finally:
            def _cleanup():
                time.sleep(15)
                with self._sessions_lock:
                    self._sessions.pop(key, None)
            threading.Thread(target=_cleanup, daemon=True).start()

    def start(self) -> None:
        self.running = True
        self._bind_absorb_socket()
        iface = self._resolve_iface()
        bpf = self._bpf_filter()
        self._log("INFO", f"Server started | file={self.config.filepath}")
        self._log("INFO", f"Block size={self.config.block_size}B  Delay={self.config.delay:.3f}s")
        self._log("INFO", f"Server IP={self.config.server_ip}  Client filter={self.config.client_ip or 'any'}")
        self._log("INFO", f"Interface={iface or 'auto'}  BPF='{bpf}'")

        while self.running:
            try:
                _scapy.sniff(
                    iface=iface, filter=bpf, prn=self._on_packet,
                    store=False, timeout=1.0,
                )
            except Exception as exc:
                if self.running:
                    self._log("ERROR", f"Sniff error: {exc}")
                    time.sleep(1)

    def stop(self) -> None:
        self.running = False
        if self._absorb_sock:
            try:
                self._absorb_sock.close()
            except Exception:
                pass


# ══════════════════════════════════════════════════════════════════════════════
#  PyQt6 GUI
# ══════════════════════════════════════════════════════════════════════════════

DARK_STYLE = """
QMainWindow, QWidget {
    background-color: #1e1e2e;
    color: #cdd6f4;
    font-family: "Segoe UI", "Consolas", monospace;
    font-size: 13px;
}
QGroupBox {
    border: 1px solid #45475a;
    border-radius: 6px;
    margin-top: 10px;
    padding: 14px 10px 10px 10px;
    font-weight: bold;
    color: #89b4fa;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
}
QLabel {
    color: #bac2de;
    font-weight: normal;
}
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox {
    background-color: #313244;
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 4px 8px;
    color: #cdd6f4;
    selection-background-color: #585b70;
}
QLineEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
    border: 1px solid #89b4fa;
}
QComboBox::drop-down {
    border: none;
    width: 20px;
}
QComboBox QAbstractItemView {
    background-color: #313244;
    border: 1px solid #45475a;
    color: #cdd6f4;
    selection-background-color: #585b70;
}
QPushButton {
    border: 1px solid #45475a;
    border-radius: 4px;
    padding: 6px 16px;
    background-color: #313244;
    color: #cdd6f4;
    font-weight: bold;
}
QPushButton:hover {
    background-color: #45475a;
}
QPushButton#startBtn {
    background-color: #1a5c2e;
    border-color: #2e8b4a;
    color: #a6e3a1;
    font-size: 14px;
    padding: 8px 28px;
}
QPushButton#startBtn:hover {
    background-color: #2e8b4a;
}
QPushButton#stopBtn {
    background-color: #6b2028;
    border-color: #d44050;
    color: #f38ba8;
    font-size: 14px;
    padding: 8px 28px;
}
QPushButton#stopBtn:hover {
    background-color: #d44050;
}
QPushButton#browseBtn {
    padding: 4px 12px;
}
QPushButton#pingBtn {
    background-color: #1c3a5e;
    border-color: #3b82c4;
    color: #89b4fa;
    padding: 4px 10px;
}
QPushButton#pingBtn:hover { background-color: #3b82c4; }
QPushButton#pingBtn:disabled { background-color: #1a1a2e; color: #45475a; border-color: #313244; }
QPushButton#arpBtn {
    background-color: #3b2a1a;
    border-color: #c47d3b;
    color: #fab387;
    padding: 4px 10px;
}
QPushButton#arpBtn:hover { background-color: #c47d3b; }
QPushButton#arpBtn:disabled { background-color: #1a1a2e; color: #45475a; border-color: #313244; }
QTableWidget {
    background-color: #1e1e2e;
    alternate-background-color: #252536;
    border: 1px solid #45475a;
    border-radius: 4px;
    gridline-color: #313244;
    color: #cdd6f4;
    selection-background-color: #45475a;
}
QTableWidget::item {
    padding: 3px 6px;
}
QHeaderView::section {
    background-color: #313244;
    color: #89b4fa;
    border: none;
    border-right: 1px solid #45475a;
    border-bottom: 1px solid #45475a;
    padding: 5px 8px;
    font-weight: bold;
}
QTextEdit {
    background-color: #181825;
    border: 1px solid #45475a;
    border-radius: 4px;
    color: #cdd6f4;
    font-family: "Consolas", "Courier New", monospace;
    font-size: 12px;
    padding: 4px;
}
QSplitter::handle {
    background-color: #45475a;
    height: 2px;
}
QLabel#statValue {
    font-size: 18px;
    font-weight: bold;
}
"""


class MainWindow(QMainWindow):

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("TFTP Server (Scapy / Npcap)")
        self.setMinimumSize(900, 700)
        self.resize(1050, 780)

        self._server: Optional[TFTPServer] = None
        self._server_thread: Optional[threading.Thread] = None
        self._log_seen = 0
        self._probe_messages: List[Tuple[str, str]] = []   # (color, html-line)
        self._probe_lock = threading.Lock()

        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(12, 12, 12, 12)
        root_layout.setSpacing(8)

        # ── settings group ──
        settings_box = QGroupBox("Configuration")
        sg = QGridLayout(settings_box)
        sg.setHorizontalSpacing(12)
        sg.setVerticalSpacing(6)

        # Row 0: file path
        sg.addWidget(QLabel("File to serve:"), 0, 0)
        self._file_edit = QLineEdit()
        self._file_edit.setPlaceholderText("Select a file to serve via TFTP...")
        sg.addWidget(self._file_edit, 0, 1, 1, 3)
        browse_btn = QPushButton("Browse...")
        browse_btn.setObjectName("browseBtn")
        browse_btn.clicked.connect(self._browse_file)
        sg.addWidget(browse_btn, 0, 4)

        # Row 1
        sg.addWidget(QLabel("Server IP:"), 1, 0)
        self._server_ip = QComboBox()
        self._server_ip.setEditable(True)
        self._server_ip.addItem("0.0.0.0  (all interfaces)")
        for iface_name, ip in _get_interfaces():
            if ip and ip != "—" and ip != "0.0.0.0":
                self._server_ip.addItem(f"{ip}  ({iface_name})")
        sg.addWidget(self._server_ip, 1, 1)

        sg.addWidget(QLabel("Client IP filter:"), 1, 2)
        self._client_ip = QLineEdit()
        self._client_ip.setPlaceholderText("(empty = accept any client)")
        sg.addWidget(self._client_ip, 1, 3)

        probe_layout = QHBoxLayout()
        probe_layout.setSpacing(4)
        probe_layout.setContentsMargins(0, 0, 0, 0)
        self._ping_btn = QPushButton("Ping")
        self._ping_btn.setObjectName("pingBtn")
        self._ping_btn.setToolTip("Send ICMP echo request to Client IP")
        self._ping_btn.clicked.connect(self._do_ping)
        probe_layout.addWidget(self._ping_btn)
        self._arp_btn = QPushButton("ARP")
        self._arp_btn.setObjectName("arpBtn")
        self._arp_btn.setToolTip("Send ARP who-has request to Client IP")
        self._arp_btn.clicked.connect(self._do_arp)
        probe_layout.addWidget(self._arp_btn)
        probe_widget = QWidget()
        probe_widget.setLayout(probe_layout)
        sg.addWidget(probe_widget, 1, 4)

        # Row 2
        sg.addWidget(QLabel("Interface:"), 2, 0)
        self._iface_combo = QComboBox()
        self._iface_combo.addItem("(auto-detect)")
        for iface_name, ip in _get_interfaces():
            self._iface_combo.addItem(f"{iface_name}  [{ip}]")
        sg.addWidget(self._iface_combo, 2, 1)

        sg.addWidget(QLabel("Port:"), 2, 2)
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(69)
        sg.addWidget(self._port_spin, 2, 3, 1, 2)

        # Row 3
        sg.addWidget(QLabel("Block size (B):"), 3, 0)
        self._blksize_spin = QSpinBox()
        self._blksize_spin.setRange(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE)
        self._blksize_spin.setValue(DEFAULT_BLOCK_SIZE)
        self._blksize_spin.setSingleStep(512)
        sg.addWidget(self._blksize_spin, 3, 1)

        sg.addWidget(QLabel("Response delay (s):"), 3, 2)
        self._delay_spin = QDoubleSpinBox()
        self._delay_spin.setRange(0.0, 60.0)
        self._delay_spin.setDecimals(3)
        self._delay_spin.setSingleStep(0.001)
        self._delay_spin.setValue(0.0)
        sg.addWidget(self._delay_spin, 3, 3, 1, 2)

        # Row 4
        sg.addWidget(QLabel("ACK timeout (s):"), 4, 0)
        self._timeout_spin = QDoubleSpinBox()
        self._timeout_spin.setRange(1.0, 120.0)
        self._timeout_spin.setDecimals(1)
        self._timeout_spin.setValue(5.0)
        sg.addWidget(self._timeout_spin, 4, 1)

        sg.addWidget(QLabel("Max retries:"), 4, 2)
        self._retries_spin = QSpinBox()
        self._retries_spin.setRange(1, 20)
        self._retries_spin.setValue(5)
        sg.addWidget(self._retries_spin, 4, 3, 1, 2)

        root_layout.addWidget(settings_box)

        # ── control bar + stats ──
        ctrl_layout = QHBoxLayout()
        ctrl_layout.setSpacing(16)

        self._start_btn = QPushButton("Start Server")
        self._start_btn.setObjectName("startBtn")
        self._start_btn.clicked.connect(self._start_server)
        ctrl_layout.addWidget(self._start_btn)

        self._stop_btn = QPushButton("Stop Server")
        self._stop_btn.setObjectName("stopBtn")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_server)
        ctrl_layout.addWidget(self._stop_btn)

        ctrl_layout.addStretch()

        # stat counters
        self._stat_labels: Dict[str, QLabel] = {}
        for name, color in [("Requests", "#89b4fa"), ("Completed", "#a6e3a1"),
                            ("Failed", "#f38ba8"), ("Filtered", "#f9e2af"),
                            ("Active", "#cba6f7")]:
            vbox = QVBoxLayout()
            vbox.setSpacing(0)
            val_label = QLabel("0")
            val_label.setObjectName("statValue")
            val_label.setStyleSheet(f"color: {color}; font-size: 18px; font-weight: bold;")
            val_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            name_label = QLabel(name)
            name_label.setStyleSheet(f"color: {color}; font-size: 11px;")
            name_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            vbox.addWidget(val_label)
            vbox.addWidget(name_label)
            self._stat_labels[name.lower()] = val_label
            ctrl_layout.addLayout(vbox)

        root_layout.addLayout(ctrl_layout)

        # ── transfers table + log  (splitter) ──
        splitter = QSplitter(Qt.Orientation.Vertical)

        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels(
            ["Client", "Status", "Progress", "Sent", "Total", "Speed", "Retx", "Duration"])
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 8):
            hdr.setSectionResizeMode(col, QHeaderView.ResizeMode.ResizeToContents)
        splitter.addWidget(self._table)

        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setPlaceholderText("Server log output will appear here...")
        splitter.addWidget(self._log_text)

        splitter.setSizes([300, 200])
        root_layout.addWidget(splitter, stretch=1)

        # ── refresh timer ──
        self._timer = QTimer()
        self._timer.timeout.connect(self._refresh_ui)
        self._timer.start(250)

    # ── helpers ──

    def _parse_ip_from_combo(self, combo: QComboBox) -> str:
        text = combo.currentText().strip()
        return text.split("(")[0].strip().split("[")[0].strip()

    def _parse_iface_from_combo(self) -> Optional[str]:
        idx = self._iface_combo.currentIndex()
        if idx <= 0:
            return None
        text = self._iface_combo.currentText()
        return text.split("[")[0].strip()

    # ── slots ──

    def _browse_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file to serve", "",
                                              "All Files (*)")
        if path:
            self._file_edit.setText(path)

    def _start_server(self) -> None:
        filepath = self._file_edit.text().strip()
        if not filepath or not Path(filepath).is_file():
            QMessageBox.warning(self, "Error", "Please select a valid file to serve.")
            return

        server_ip = self._parse_ip_from_combo(self._server_ip)
        if not server_ip:
            server_ip = "0.0.0.0"

        client_ip = self._client_ip.text().strip() or None
        iface = self._parse_iface_from_combo()

        config = Config(
            filepath   = Path(filepath),
            server_ip  = server_ip,
            client_ip  = client_ip,
            block_size = self._blksize_spin.value(),
            delay      = self._delay_spin.value(),
            iface      = iface,
            timeout    = self._timeout_spin.value(),
            retries    = self._retries_spin.value(),
            port       = self._port_spin.value(),
        )

        self._server = TFTPServer(config)
        self._log_seen = 0
        self._server_thread = threading.Thread(target=self._server.start, daemon=True)
        self._server_thread.start()

        self._start_btn.setEnabled(False)
        self._stop_btn.setEnabled(True)
        self._set_settings_enabled(False)

    def _stop_server(self) -> None:
        if self._server:
            self._server.stop()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._set_settings_enabled(True)

    def _set_settings_enabled(self, enabled: bool) -> None:
        for w in (self._file_edit, self._server_ip, self._client_ip,
                  self._iface_combo, self._port_spin, self._blksize_spin,
                  self._delay_spin, self._timeout_spin, self._retries_spin):
            w.setEnabled(enabled)

    # ── probe helpers ──

    def _probe_log(self, color: str, line: str) -> None:
        """Thread-safe append to probe message queue (drained by timer)."""
        with self._probe_lock:
            self._probe_messages.append((color, line))

    def _get_probe_ip_and_iface(self):
        """Return (client_ip, iface_or_None) or show warning and return (None, None)."""
        ip = self._client_ip.text().strip()
        if not ip:
            QMessageBox.warning(self, "Client IP required",
                                "Enter a Client IP address before probing.")
            return None, None
        iface = self._parse_iface_from_combo()
        return ip, iface

    def _do_ping(self) -> None:
        ip, iface = self._get_probe_ip_and_iface()
        if not ip:
            return
        self._ping_btn.setEnabled(False)
        self._probe_log("#89b4fa", f"PING → {ip}  (ICMP echo, 4 packets) ...")

        def _run():
            try:
                results = []
                for seq in range(1, 5):
                    pkt = IP(dst=ip) / ICMP(id=0x1234, seq=seq)
                    t0 = time.monotonic()
                    reply = _scapy.sr1(pkt, iface=iface, timeout=2, verbose=False)
                    rtt = (time.monotonic() - t0) * 1000
                    if reply is not None:
                        results.append(rtt)
                        self._probe_log("#a6e3a1",
                                        f"  Reply from {reply[IP].src}  seq={seq}  ttl={reply[IP].ttl}  time={rtt:.1f} ms")
                    else:
                        self._probe_log("#f38ba8", f"  Request timeout  seq={seq}")

                if results:
                    avg = sum(results) / len(results)
                    self._probe_log("#a6e3a1",
                                    f"PING done: {len(results)}/4 replies  avg={avg:.1f} ms  min={min(results):.1f} ms  max={max(results):.1f} ms")
                else:
                    self._probe_log("#f38ba8", f"PING done: no replies from {ip}")
            except Exception as exc:
                self._probe_log("#f38ba8", f"PING error: {exc}")
            finally:
                # Re-enable button on main thread via timer
                self._ping_btn.setEnabled(True)

        threading.Thread(target=_run, daemon=True).start()

    def _do_arp(self) -> None:
        ip, iface = self._get_probe_ip_and_iface()
        if not ip:
            return
        self._arp_btn.setEnabled(False)
        self._probe_log("#fab387", f"ARP  → who has {ip}?  ...")

        def _run():
            try:
                ans, unans = _scapy.arping(ip, iface=iface, timeout=2, verbose=False)
                if ans:
                    for sent, received in ans:
                        mac = received[Ether].src
                        src_ip = received[ARP].psrc
                        self._probe_log("#a6e3a1",
                                        f"  ARP reply: {src_ip} is at {mac}")
                    self._probe_log("#a6e3a1",
                                    f"ARP done: {len(ans)} host(s) responded")
                else:
                    self._probe_log("#f38ba8", f"ARP done: no reply from {ip}")
            except Exception as exc:
                self._probe_log("#f38ba8", f"ARP error: {exc}")
            finally:
                self._arp_btn.setEnabled(True)

        threading.Thread(target=_run, daemon=True).start()

    # ── periodic refresh ──

    def _refresh_ui(self) -> None:
        # drain probe messages regardless of server state
        with self._probe_lock:
            pending = self._probe_messages[:]
            self._probe_messages.clear()
        if pending:
            cursor = self._log_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            for color, line in pending:
                cursor.insertHtml(
                    f'<span style="color:{color};">{_html_escape(line)}</span><br>'
                )
            self._log_text.setTextCursor(cursor)
            self._log_text.ensureCursorVisible()

        if not self._server:
            return

        # stats
        s = self._server.stats
        self._stat_labels["requests"].setText(str(s["requests"]))
        self._stat_labels["completed"].setText(str(s["completed"]))
        self._stat_labels["failed"].setText(str(s["failed"]))
        self._stat_labels["filtered"].setText(str(s["filtered"]))
        sessions = self._server.get_sessions()
        active = sum(1 for sx in sessions if sx.status == "transferring")
        self._stat_labels["active"].setText(str(active))

        # transfers table
        self._table.setRowCount(len(sessions))
        STATUS_COLORS = {
            "init":         "#6c7086",
            "transferring": "#89b4fa",
            "completed":    "#a6e3a1",
            "timeout":      "#f9e2af",
            "error":        "#f38ba8",
        }
        for row, sx in enumerate(sessions):
            color = QColor(STATUS_COLORS.get(sx.status, "#cdd6f4"))
            pct = sx.progress_pct
            bar_w = 12
            filled = int(bar_w * pct / 100)
            bar = "[" + "#" * filled + "-" * (bar_w - filled) + f"] {pct:.0f}%"

            items = [
                f"{sx.client_ip}:{sx.client_port}",
                sx.status + (f" ({sx.error_msg})" if sx.error_msg else ""),
                bar,
                _fmt_bytes(sx.bytes_sent),
                _fmt_bytes(sx.total_bytes),
                f"{sx.speed_kbps:.1f} KB/s",
                str(sx.retransmits),
                f"{sx.duration:.1f}s",
            ]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                item.setForeground(color)
                self._table.setItem(row, col, item)

        # log
        log_entries = self._server.get_log(200)
        new_entries = log_entries[self._log_seen:]
        if new_entries:
            self._log_seen = len(log_entries)
            LEVEL_COLORS = {
                "INFO":  "#cdd6f4",
                "WARN":  "#f9e2af",
                "ERROR": "#f38ba8",
            }
            cursor = self._log_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            for e in new_entries:
                c = LEVEL_COLORS.get(e["level"], "#cdd6f4")
                client_str = f" [{e['client']}]" if e["client"] else ""
                line = f"{e['ts']} {e['level']:<5}{client_str} {e['msg']}"
                cursor.insertHtml(
                    f'<span style="color:{c};">{_html_escape(line)}</span><br>'
                )
            self._log_text.setTextCursor(cursor)
            self._log_text.ensureCursorVisible()

    def closeEvent(self, event) -> None:
        if self._server:
            self._server.stop()
        event.accept()


def _html_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(DARK_STYLE)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
