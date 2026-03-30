# TFTP Server — Scapy / Npcap + PyQt6 GUI

A TFTP read server (RFC 1350 + options RFC 2347/2348/2349) built on raw packet
I/O via **Scapy** and **Npcap** (Windows) / **libpcap** (Linux).
GUI powered by **PyQt6** with a dark Catppuccin-style theme.

---

## Features

| Feature | Detail |
|---|---|
| Transport | Raw UDP via Scapy — no OS TFTP stack needed |
| Packet backend | Npcap (Windows) / libpcap (Linux) |
| TFTP options | `blksize`, `tsize`, `timeout` (RFC 2347/2348/2349) |
| Block-size | Configurable 8 – 65 464 B; honours client negotiation |
| Response delay | Artificial inter-block delay (network simulation) |
| Server IP | Bind to a specific IP or all interfaces (`0.0.0.0`) |
| Client IP filter | Only serve one client — ignore all others |
| Retransmission | Per-block retry with configurable count and timeout |
| Large files | 16-bit block-number roll-over (> 65535 x block_size) |
| Write requests | Rejected with TFTP error (read-only server) |
| GUI | PyQt6 dark-themed window with file picker, live transfers table, and log |

---

## Requirements

```
Python 3.8+
pip install -r requirements.txt
```

**Windows** — [Npcap](https://npcap.com/) must be installed.
Run from an **elevated (Administrator) command prompt**.

**Linux** — `libpcap-dev` must be installed:
```bash
sudo apt install libpcap-dev   # Debian / Ubuntu
sudo dnf install libpcap-devel # Fedora / RHEL
```
Run with `sudo` or grant `CAP_NET_RAW`/`CAP_NET_ADMIN` to the interpreter.

---

## Usage

```bash
# Just launch the GUI — no arguments needed
python tftp_server.py
```

Everything is configured through the GUI:

1. **Browse** for the file you want to serve
2. Select **Server IP** from the dropdown (auto-detects your interfaces)
3. Optionally set a **Client IP filter** to restrict who can connect
4. Choose **Interface**, **Block size**, **Delay**, **Port**, **Timeout**, **Retries**
5. Click **Start Server**
6. Watch live transfer progress and logs in real time
7. Click **Stop Server** when done

---

## Screenshot layout

```
+--[ Configuration ]------------------------------------------+
| File to serve: [________________________] [Browse...]       |
| Server IP: [0.0.0.0 (all) v]  Client IP: [___________]     |
| Interface: [(auto) v]          Port: [69]                   |
| Block size: [512]              Delay: [0.000]               |
| Timeout: [5.0]                 Retries: [5]                 |
+-------------------------------------------------------------+
| [Start Server]  [Stop Server]   Req:0  OK:0  Fail:0  Flt:0 |
+-------------------------------------------------------------+
| Client          | Status | Progress     | Sent | Speed  |...|
| 192.168.1.50:.. | trans  | [####--] 60% | 2 MB | 300K/s |   |
+-------------------------------------------------------------+
| 14:22:01 INFO  Server started | file=firmware.bin           |
| 14:22:05 INFO  RRQ 'firmware.bin' from 192.168.1.50:49312   |
+-------------------------------------------------------------+
```

---

## How it works

```
Client                              Server (this program)
  |                                       |
  |-- RRQ (port 69) --------------------->|  Scapy sniff captures RRQ
  |                                       |  New thread + random TID port
  |<-- OACK (our TID -> client port) -----|  option negotiation (if requested)
  |-- ACK 0 ----------------------------->|
  |                                       |
  |<-- DATA block 1 ----------------------|  Scapy send() at L3
  |-- ACK 1 ----------------------------->|  Queue-based ACK delivery
  |<-- DATA block 2 ----------------------|
  |   ...                                 |
  |<-- DATA block N (< blksize) ----------|  last block signals EOF
  |-- ACK N ----------------------------->|
```

* **Capture**: Scapy `sniff()` with a BPF filter captures all relevant UDP
  traffic at the raw packet level via Npcap/libpcap.
* **Routing**: The packet callback routes RRQs to new threads and ACKs to the
  matching session via a `queue.Queue`.
* **Sending**: `scapy.send()` injects IP/UDP packets at L3.
* **Absorb socket**: A plain UDP socket is bound to port 69 to prevent the OS
  from sending ICMP "port unreachable" replies.

---

## Limitations

* **Read-only** — write requests (WRQ) are rejected.
* **One file** — the server always serves the file selected in the GUI,
  regardless of the filename the client requests.
* **Concurrency** — multiple simultaneous transfers are supported; each runs in
  its own thread.
* **Windows Firewall** — may block incoming UDP on port 69; add an inbound rule
  if needed.
