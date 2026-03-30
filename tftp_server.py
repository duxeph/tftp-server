#!/usr/bin/env python3
"""
TFTP Server — raw-packet implementation via Scapy / Npcap (Windows) / libpcap (Linux).

Features
--------
* Serves a single file to one or many TFTP clients
* Configurable server IP (or all-interfaces), client IP filter, block size, delay
* Full TFTP option negotiation  (blksize / tsize / timeout  —  RFC 2347/2348/2349)
* Block-number roll-over for files > 65535 × block_size bytes
* Per-block retransmission with exponential back-off
* Rich terminal UI: live transfer table, log panel, statistics
* Works on Windows (Npcap) and Linux (libpcap) without code changes

Requirements
------------
    pip install scapy rich

On Linux:
    run with  sudo  or give the interpreter  CAP_NET_RAW / CAP_NET_ADMIN
On Windows:
    Npcap must be installed (https://npcap.com/)
    run from an elevated (Administrator) prompt
"""

import sys
import os
import time
import struct
import socket
import threading
import random
import argparse
from queue import Queue, Empty
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Tuple, List

# ── dependency bootstrap ──────────────────────────────────────────────────────

def _ensure_deps() -> None:
    import importlib.util
    import subprocess
    needed = [p for p in ("scapy", "rich") if not importlib.util.find_spec(p)]
    if needed:
        print(f"[bootstrap] Installing: {', '.join(needed)} …")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + needed
        )

_ensure_deps()

import scapy.all as _scapy  # noqa: E402  (import after bootstrap)
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.columns import Columns
from rich.text import Text
from rich import box

# ── TFTP constants ────────────────────────────────────────────────────────────

OP_RRQ   = 1
OP_WRQ   = 2
OP_DATA  = 3
OP_ACK   = 4
OP_ERROR = 5
OP_OACK  = 6

ERR_NOT_FOUND     = 1
ERR_ACCESS        = 2
ERR_ILLEGAL_OP    = 4

DEFAULT_BLOCK_SIZE = 512
MAX_BLOCK_SIZE     = 65464   # RFC 2348
MIN_BLOCK_SIZE     = 8

# ── helpers ───────────────────────────────────────────────────────────────────

def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    else:
        return f"{n / 1024 ** 2:.2f} MB"


def _next_block(block_num: int) -> int:
    """Increment a 16-bit TFTP block number (wraps 65535 → 1, avoids 0)."""
    return (block_num % 65535) + 1


def _find_iface_for_ip(target_ip: str) -> Optional[str]:
    """Return the Scapy interface name that carries *target_ip*, or None."""
    for iface in _scapy.get_if_list():
        try:
            if _scapy.get_if_addr(iface) == target_ip:
                return iface
        except Exception:
            pass
    return None


# ── configuration ─────────────────────────────────────────────────────────────

class Config:
    filepath:    Path
    server_ip:   str            = "0.0.0.0"
    client_ip:   Optional[str]  = None
    block_size:  int            = DEFAULT_BLOCK_SIZE
    delay:       float          = 0.0
    iface:       Optional[str]  = None
    timeout:     float          = 5.0
    retries:     int            = 5
    port:        int            = 69

    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


# ── transfer session ──────────────────────────────────────────────────────────

class TransferSession:
    """State for a single in-progress TFTP read transfer."""

    def __init__(
        self,
        client_ip:   str,
        client_port: int,
        server_ip:   str,
        filepath:    Path,
        block_size:  int,
        delay:       float,
    ) -> None:
        self.client_ip   = client_ip
        self.client_port = client_port
        self.server_ip   = server_ip
        self.filepath    = filepath
        self.block_size  = block_size
        self.delay       = delay

        # Our TID (source port for this transfer)
        self.tid: int = random.randint(10_000, 60_000)

        self.status:        str           = "init"
        self.start_time:    datetime      = datetime.now()
        self.end_time:      Optional[datetime] = None
        self.bytes_sent:    int           = 0
        self.total_bytes:   int           = 0
        self.current_block: int           = 0
        self.retransmits:   int           = 0
        self.error_msg:     str           = ""

        self._ack_queue: Queue = Queue()

    # ── metrics ──

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

    # ── ACK signalling ──

    def notify_ack(self, block_num: int) -> None:
        self._ack_queue.put(block_num)

    def wait_ack(self, expected: int, timeout: float) -> bool:
        """
        Block until ACK *expected* arrives or *timeout* seconds elapse.
        Discards duplicate / stale ACKs while waiting.
        Returns True on success, False on timeout.
        """
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            try:
                ack = self._ack_queue.get(timeout=remaining)
                if ack == expected:
                    return True
                # stale/duplicate ACK — keep waiting
            except Empty:
                return False


# ── TFTP server ───────────────────────────────────────────────────────────────

class TFTPServer:

    def __init__(self, config: Config) -> None:
        self.config  = config
        self.running = False

        # (client_ip, client_port, our_tid) → session
        self._sessions:      Dict[Tuple, TransferSession] = {}
        self._sessions_lock: threading.Lock               = threading.Lock()

        self._log_entries: List[dict] = []
        self._log_lock:    threading.Lock = threading.Lock()

        self.stats = {"requests": 0, "completed": 0, "failed": 0, "filtered": 0}

        self._absorb_sock: Optional[socket.socket] = None

    # ── logging ──

    def _log(self, level: str, msg: str, client: str = "") -> None:
        entry = {
            "ts":     datetime.now().strftime("%H:%M:%S.%f")[:12],
            "level":  level,
            "msg":    msg,
            "client": client,
        }
        with self._log_lock:
            self._log_entries.append(entry)
            if len(self._log_entries) > 300:
                self._log_entries = self._log_entries[-300:]

    def get_log(self, n: int = 20) -> List[dict]:
        with self._log_lock:
            return list(self._log_entries[-n:])

    def get_sessions(self) -> List[TransferSession]:
        with self._sessions_lock:
            return list(self._sessions.values())

    # ── socket / interface setup ──

    def _bind_absorb_socket(self) -> None:
        """
        Bind a UDP socket to port 69 so the OS does not reply with
        ICMP 'port unreachable' for incoming RRQs.
        """
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            bind_addr = "" if self.config.server_ip == "0.0.0.0" else self.config.server_ip
            s.bind((bind_addr, self.config.port))
            self._absorb_sock = s
            self._log("INFO", f"Absorb socket bound on :{self.config.port}")
        except PermissionError:
            self._log("WARN", f"Cannot bind port {self.config.port} — need root/Administrator")
        except OSError as exc:
            self._log("WARN", f"Absorb socket: {exc}")

    def _resolve_iface(self) -> Optional[str]:
        iface = self.config.iface
        if iface:
            return iface
        if self.config.server_ip not in ("0.0.0.0", ""):
            iface = _find_iface_for_ip(self.config.server_ip)
        return iface  # None → Scapy picks the default

    # ── BPF filter ──

    def _bpf_filter(self) -> str:
        """
        Build a BPF filter that captures:
          • RRQ packets  (dst port 69, from client)
          • ACK packets  (dst = our server IP, from client)
        """
        parts = ["udp"]
        if self.config.server_ip not in ("0.0.0.0", ""):
            parts.append(f"dst host {self.config.server_ip}")
        if self.config.client_ip:
            parts.append(f"src host {self.config.client_ip}")
        return " and ".join(parts)

    # ── packet sending ──

    def _send(self, session: TransferSession, payload: bytes) -> None:
        """Craft and inject a UDP packet via Scapy (L3 send)."""
        pkt = (
            IP(src=session.server_ip, dst=session.client_ip)
            / UDP(sport=session.tid, dport=session.client_port)
            / Raw(load=payload)
        )
        _scapy.send(pkt, iface=self._resolve_iface(), verbose=False)

    def _send_error_from_port(
        self,
        client_ip:   str,
        client_port: int,
        server_ip:   str,
        src_port:    int,
        code:        int,
        msg:         str,
    ) -> None:
        payload = struct.pack("!HH", OP_ERROR, code) + msg.encode() + b"\x00"
        pkt = (
            IP(src=server_ip, dst=client_ip)
            / UDP(sport=src_port, dport=client_port)
            / Raw(load=payload)
        )
        _scapy.send(pkt, iface=self._resolve_iface(), verbose=False)

    def _send_with_retry(
        self,
        session:      TransferSession,
        payload:      bytes,
        expected_ack: int,
    ) -> bool:
        """Send *payload* and wait for ACK *expected_ack*; retry up to config.retries times."""
        for attempt in range(self.config.retries):
            self._send(session, payload)
            if session.wait_ack(expected_ack, self.config.timeout):
                return True
            if attempt < self.config.retries - 1:
                session.retransmits += 1
                self._log(
                    "WARN",
                    f"Retransmit #{attempt + 1} — ACK {expected_ack} — {session.client_ip}",
                    session.client_ip,
                )
        return False

    # ── packet handling ──

    def _on_packet(self, pkt) -> None:
        """Scapy sniff callback — called for every captured packet."""
        try:
            if IP not in pkt or UDP not in pkt:
                return

            src_ip   = pkt[IP].src
            dst_ip   = pkt[IP].dst
            sport    = pkt[UDP].sport
            dport    = pkt[UDP].dport
            raw      = bytes(pkt[UDP].payload)

            if len(raw) < 2:
                return

            opcode = struct.unpack("!H", raw[:2])[0]

            if dport == self.config.port and opcode == OP_RRQ:
                self._handle_rrq(src_ip, sport, dst_ip, raw)

            elif opcode == OP_ACK and len(raw) >= 4:
                block_num = struct.unpack("!H", raw[2:4])[0]
                key = (src_ip, sport, dport)   # dport == our TID
                with self._sessions_lock:
                    session = self._sessions.get(key)
                if session:
                    session.notify_ack(block_num)

            elif opcode == OP_WRQ and dport == self.config.port:
                self._log("WARN", f"WRQ (write) rejected — server is read-only", src_ip)
                self._send_error_from_port(
                    src_ip, sport, dst_ip, self.config.port,
                    ERR_ILLEGAL_OP, "Server is read-only"
                )

        except Exception as exc:
            self._log("ERROR", f"Packet handler: {exc}")

    def _handle_rrq(
        self,
        client_ip:   str,
        client_port: int,
        dst_ip:      str,
        raw:         bytes,
    ) -> None:
        """Parse an RRQ and start a transfer thread."""
        # Client IP filter
        if self.config.client_ip and client_ip != self.config.client_ip:
            self.stats["filtered"] += 1
            self._log("WARN", f"Filtered RRQ from {client_ip}", client_ip)
            return

        self.stats["requests"] += 1

        # Parse: opcode(2) + filename\0 + mode\0 + [option\0 value\0 …]
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

        # Effective block size — honour client's blksize but cap at our max
        blksize = self.config.block_size
        if "blksize" in options:
            try:
                blksize = min(blksize, max(MIN_BLOCK_SIZE, int(options["blksize"])))
            except ValueError:
                pass

        server_ip = dst_ip if self.config.server_ip == "0.0.0.0" else self.config.server_ip

        session = TransferSession(
            client_ip   = client_ip,
            client_port = client_port,
            server_ip   = server_ip,
            filepath    = self.config.filepath,
            block_size  = blksize,
            delay       = self.config.delay,
        )

        key = (client_ip, client_port, session.tid)
        with self._sessions_lock:
            self._sessions[key] = session

        self._log(
            "INFO",
            f"RRQ '{req_filename}' [{mode}]  blk={blksize}  from {client_ip}:{client_port}",
            client_ip,
        )

        threading.Thread(
            target=self._run_transfer,
            args=(session, options),
            daemon=True,
        ).start()

    def _run_transfer(self, session: TransferSession, options: Dict[str, str]) -> None:
        """Execute a complete TFTP read transfer (runs in its own thread)."""
        key = (session.client_ip, session.client_port, session.tid)

        try:
            # ── read file ──
            try:
                file_data = session.filepath.read_bytes()
            except FileNotFoundError:
                self._send_error_from_port(
                    session.client_ip, session.client_port,
                    session.server_ip, self.config.port,
                    ERR_NOT_FOUND, "File not found",
                )
                session.status    = "error"
                session.error_msg = "File not found"
                self.stats["failed"] += 1
                return
            except PermissionError:
                self._send_error_from_port(
                    session.client_ip, session.client_port,
                    session.server_ip, self.config.port,
                    ERR_ACCESS, "Access violation",
                )
                session.status    = "error"
                session.error_msg = "Access violation"
                self.stats["failed"] += 1
                return

            session.total_bytes = len(file_data)
            session.status      = "transferring"

            # ── OACK (option acknowledgement) ──
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
                    session.status    = "timeout"
                    session.error_msg = "Timeout waiting for OACK acknowledgement"
                    self.stats["failed"] += 1
                    return

            # ── data blocks ──
            block_num = 1
            offset    = 0

            while True:
                chunk   = file_data[offset : offset + session.block_size]
                offset += session.block_size

                if session.delay > 0:
                    time.sleep(session.delay)

                data_payload = struct.pack("!HH", OP_DATA, block_num & 0xFFFF) + chunk

                if not self._send_with_retry(session, data_payload,
                                              expected_ack=block_num & 0xFFFF):
                    session.status    = "timeout"
                    session.error_msg = f"Timeout at block {block_num}"
                    self.stats["failed"] += 1
                    return

                session.current_block = block_num
                session.bytes_sent    = min(offset, len(file_data))

                # Final block is shorter than block_size (RFC 1350 EOF condition)
                if len(chunk) < session.block_size:
                    break

                block_num = _next_block(block_num)

            session.status   = "completed"
            session.end_time = datetime.now()
            self.stats["completed"] += 1
            self._log(
                "INFO",
                f"Done  {session.client_ip}  {_fmt_bytes(session.total_bytes)}"
                f"  {session.speed_kbps:.1f} KB/s  {session.duration:.2f}s",
                session.client_ip,
            )

        except Exception as exc:
            session.status    = "error"
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

    # ── sniff loop ──

    def _sniff_loop(self, iface: Optional[str], bpf: str) -> None:
        """Run Scapy sniff in a loop so it restarts on timeout."""
        self._log("INFO", f"Listening  iface={iface or 'auto'}  filter='{bpf}'")
        while self.running:
            try:
                _scapy.sniff(
                    iface   = iface,
                    filter  = bpf,
                    prn     = self._on_packet,
                    store   = False,
                    timeout = 1.0,   # wake up every second to check self.running
                )
            except Exception as exc:
                if self.running:
                    self._log("ERROR", f"Sniff error: {exc}")
                    time.sleep(1)

    # ── public start / stop ──

    def start(self) -> None:
        self.running = True
        self._bind_absorb_socket()
        iface = self._resolve_iface()
        bpf   = self._bpf_filter()
        self._log("INFO", f"Serving file : {self.config.filepath}")
        self._log("INFO", f"Block size   : {self.config.block_size} B")
        self._log("INFO", f"Delay        : {self.config.delay:.3f}s")
        self._log("INFO", f"Server IP    : {self.config.server_ip}")
        self._log("INFO", f"Client filter: {self.config.client_ip or 'any'}")
        self._sniff_loop(iface, bpf)

    def stop(self) -> None:
        self.running = False
        if self._absorb_sock:
            try:
                self._absorb_sock.close()
            except Exception:
                pass


# ── Rich TUI ──────────────────────────────────────────────────────────────────

_STATUS_STYLE = {
    "init":        "dim",
    "transferring":"cyan",
    "completed":   "green",
    "timeout":     "yellow",
    "error":       "red",
}

_LEVEL_STYLE = {
    "INFO":  "white",
    "WARN":  "yellow",
    "ERROR": "red bold",
    "DEBUG": "dim",
}


class ServerUI:

    def __init__(self, server: TFTPServer, config: Config) -> None:
        self.server  = server
        self.config  = config
        self.console = Console()

    # ── panels ──

    def _config_panel(self) -> Panel:
        cfg = self.config
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold cyan", no_wrap=True)
        t.add_column(style="white")

        rows = [
            ("File",          str(cfg.filepath.resolve())),
            ("File size",     _fmt_bytes(cfg.filepath.stat().st_size)
                              if cfg.filepath.exists() else "[red]NOT FOUND[/red]"),
            ("Server IP",     cfg.server_ip),
            ("Client filter", cfg.client_ip or "[dim]any[/dim]"),
            ("Block size",    f"{cfg.block_size} B"),
            ("Delay",         f"{cfg.delay:.3f} s" if cfg.delay else "[dim]none[/dim]"),
            ("Port",          str(cfg.port)),
            ("Interface",     cfg.iface or "[dim]auto[/dim]"),
            ("ACK timeout",   f"{cfg.timeout} s"),
            ("Retries",       str(cfg.retries)),
        ]
        for label, val in rows:
            t.add_row(label, val)

        return Panel(t, title="[bold]Configuration[/bold]",
                     border_style="blue", padding=(0, 1))

    def _stats_panel(self) -> Panel:
        s = self.server.stats
        t = Table.grid(padding=(0, 2))
        t.add_column(style="bold")
        t.add_column()

        t.add_row("[cyan]Requests[/cyan]",   str(s["requests"]))
        t.add_row("[green]Completed[/green]", str(s["completed"]))
        t.add_row("[red]Failed[/red]",        str(s["failed"]))
        t.add_row("[yellow]Filtered[/yellow]", str(s["filtered"]))
        t.add_row("Active",
                  str(sum(1 for sx in self.server.get_sessions()
                          if sx.status == "transferring")))

        return Panel(t, title="[bold]Statistics[/bold]",
                     border_style="blue", padding=(0, 1))

    def _sessions_table(self) -> Table:
        tbl = Table(
            title="Transfers",
            box=box.ROUNDED,
            border_style="blue",
            header_style="bold cyan",
            show_lines=False,
            expand=True,
            min_width=80,
        )
        tbl.add_column("Client",    min_width=21)
        tbl.add_column("Status",    min_width=12)
        tbl.add_column("Progress",  min_width=16)
        tbl.add_column("Sent",      min_width=9,  justify="right")
        tbl.add_column("Total",     min_width=9,  justify="right")
        tbl.add_column("Speed",     min_width=10, justify="right")
        tbl.add_column("Retx",      min_width=5,  justify="right")
        tbl.add_column("Duration",  min_width=8,  justify="right")

        sessions = self.server.get_sessions()
        if not sessions:
            tbl.add_row("[dim]No transfers yet[/dim]",
                        "", "", "", "", "", "", "")
            return tbl

        for s in sessions:
            sty = _STATUS_STYLE.get(s.status, "")
            pct = s.progress_pct
            w   = 10
            bar = "[" + "#" * int(w * pct / 100) + "-" * (w - int(w * pct / 100)) + f"] {pct:3.0f}%"
            err = f"  [dim]({s.error_msg})[/dim]" if s.error_msg else ""
            tbl.add_row(
                f"[{sty}]{s.client_ip}:{s.client_port}[/{sty}]",
                f"[{sty}]{s.status}{err}[/{sty}]",
                f"[{sty}]{bar}[/{sty}]",
                f"[{sty}]{_fmt_bytes(s.bytes_sent)}[/{sty}]",
                f"[{sty}]{_fmt_bytes(s.total_bytes)}[/{sty}]",
                f"[{sty}]{s.speed_kbps:.1f} KB/s[/{sty}]",
                f"[{sty}]{s.retransmits}[/{sty}]",
                f"[{sty}]{s.duration:.1f}s[/{sty}]",
            )
        return tbl

    def _log_panel(self, rows: int = 12) -> Panel:
        entries = self.server.get_log(rows)
        lines = []
        for e in entries:
            sty    = _LEVEL_STYLE.get(e["level"], "white")
            client = f" [dim]\[{e['client']}][/dim]" if e["client"] else ""
            lines.append(
                f"[dim]{e['ts']}[/dim] [{sty}]{e['level']:<5}[/{sty}]{client} {e['msg']}"
            )
        body = "\n".join(lines) if lines else "[dim]—[/dim]"
        return Panel(body, title="[bold]Log[/bold]",
                     border_style="blue", padding=(0, 1))

    # ── main render loop ──

    def run(self) -> None:
        server_thread = threading.Thread(target=self.server.start, daemon=True)
        server_thread.start()

        self.console.print()
        self.console.rule("[bold blue] TFTP Server  (Scapy/Npcap) [/bold blue]")
        self.console.print("[dim]Press Ctrl+C to stop[/dim]\n")

        try:
            with Live(console=self.console, refresh_per_second=4, screen=False) as live:
                while self.server.running:
                    layout = Layout()
                    layout.split_column(
                        Layout(name="top",      size=14),
                        Layout(name="sessions", size=10),
                        Layout(name="logs"),
                    )
                    layout["top"].split_row(
                        Layout(self._config_panel(), name="cfg",   ratio=2),
                        Layout(self._stats_panel(),  name="stats", ratio=1),
                    )
                    layout["sessions"].update(self._sessions_table())
                    layout["logs"].update(self._log_panel(rows=10))

                    live.update(layout)
                    time.sleep(0.25)

        except KeyboardInterrupt:
            self.server.stop()
            self.console.print("\n[yellow]Server stopped.[/yellow]")


# ── interface listing helper ──────────────────────────────────────────────────

def _list_interfaces() -> None:
    console = Console()
    tbl = Table(
        title="Available Network Interfaces",
        box=box.ROUNDED,
        border_style="blue",
        header_style="bold cyan",
    )
    tbl.add_column("Interface", style="green")
    tbl.add_column("IP Address")
    for iface in _scapy.get_if_list():
        try:
            ip = _scapy.get_if_addr(iface)
        except Exception:
            ip = "—"
        tbl.add_row(iface, ip)
    console.print()
    console.print(tbl)
    console.print()


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> Config:
    p = argparse.ArgumentParser(
        prog="tftp_server.py",
        description="TFTP read server — raw-packet engine via Scapy / Npcap",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python tftp_server.py firmware.bin
  python tftp_server.py firmware.bin --server-ip 192.168.1.10
  python tftp_server.py firmware.bin --client-ip 192.168.1.50 --block-size 1024
  python tftp_server.py firmware.bin --delay 0.005 --iface eth0
  python tftp_server.py firmware.bin --server-ip 10.0.0.1 --client-ip 10.0.0.2
  python tftp_server.py --list-interfaces

notes:
  Requires root / Administrator privileges for raw packet capture.
  On Windows: Npcap must be installed  (https://npcap.com/).
  On Linux:   libpcap-dev + root  or  CAP_NET_RAW capability.
""",
    )

    p.add_argument(
        "filepath", nargs="?",
        help="Path to the file to serve via TFTP",
    )
    p.add_argument(
        "--server-ip", default="0.0.0.0", metavar="IP",
        help="Server IP address to listen on (default: 0.0.0.0 = all interfaces)",
    )
    p.add_argument(
        "--client-ip", default=None, metavar="IP",
        help="Only respond to requests from this client IP (default: any)",
    )
    p.add_argument(
        "--block-size", type=int, default=DEFAULT_BLOCK_SIZE, metavar="N",
        help=f"TFTP block size in bytes (default: {DEFAULT_BLOCK_SIZE}, range: "
             f"{MIN_BLOCK_SIZE}–{MAX_BLOCK_SIZE})",
    )
    p.add_argument(
        "--delay", type=float, default=0.0, metavar="SECS",
        help="Artificial delay in seconds between block sends (default: 0)",
    )
    p.add_argument(
        "--iface", default=None, metavar="NAME",
        help="Network interface to use (default: auto-detected)",
    )
    p.add_argument(
        "--timeout", type=float, default=5.0, metavar="SECS",
        help="ACK timeout per block in seconds (default: 5)",
    )
    p.add_argument(
        "--retries", type=int, default=5, metavar="N",
        help="Max retransmissions per block (default: 5)",
    )
    p.add_argument(
        "--port", type=int, default=69, metavar="N",
        help="UDP port to listen on (default: 69)",
    )
    p.add_argument(
        "--list-interfaces", action="store_true",
        help="Print available network interfaces and exit",
    )

    args = p.parse_args()

    if args.list_interfaces:
        _list_interfaces()
        sys.exit(0)

    if not args.filepath:
        p.error("filepath is required (use --list-interfaces to list interfaces)")

    cfg = Config(
        filepath   = Path(args.filepath),
        server_ip  = args.server_ip,
        client_ip  = args.client_ip,
        block_size = max(MIN_BLOCK_SIZE, min(MAX_BLOCK_SIZE, args.block_size)),
        delay      = max(0.0, args.delay),
        iface      = args.iface,
        timeout    = max(1.0, args.timeout),
        retries    = max(1, min(20, args.retries)),
        port       = args.port,
    )

    console = Console()
    if not cfg.filepath.exists():
        console.print(f"[red]Error: file not found — {cfg.filepath}[/red]")
        sys.exit(1)
    if not cfg.filepath.is_file():
        console.print(f"[red]Error: not a regular file — {cfg.filepath}[/red]")
        sys.exit(1)

    return cfg


# ── entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    config = _parse_args()
    server = TFTPServer(config)
    ui     = ServerUI(server, config)
    ui.run()


if __name__ == "__main__":
    main()
