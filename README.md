# TFTP Server — Scapy / Npcap

A TFTP read server (RFC 1350 + options RFC 2347/2348/2349) built on raw packet
I/O via **Scapy** and **Npcap** (Windows) / **libpcap** (Linux).
Terminal UI powered by **Rich**.

---

## Features

| Feature | Detail |
|---|---|
| Transport | Raw UDP via Scapy — no OS TFTP stack needed |
| Packet backend | Npcap (Windows) · libpcap (Linux) |
| TFTP options | `blksize`, `tsize`, `timeout` (RFC 2347/2348/2349) |
| Block-size | Configurable 8 – 65 464 B; honours client negotiation |
| Response delay | Artificial inter-block delay (network simulation) |
| Server IP filter | Bind to a specific IP or all interfaces (`0.0.0.0`) |
| Client IP filter | Only serve one client — ignore all others |
| Retransmission | Per-block retry with configurable count and timeout |
| Large files | 16-bit block-number roll-over (> 65535 × block_size) |
| Write requests | Rejected with TFTP error (read-only server) |
| UI | Live Rich TUI: config panel, transfer table, log view |

---

## Requirements

```
Python 3.8+
pip install scapy rich
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

```
usage: tftp_server.py [-h] [--server-ip IP] [--client-ip IP]
                      [--block-size N] [--delay SECS] [--iface NAME]
                      [--timeout SECS] [--retries N] [--port N]
                      [--list-interfaces]
                      [filepath]
```

### Quick-start

```bash
# Serve a file on all interfaces (any client)
sudo python tftp_server.py firmware.bin

# Bind to a specific server IP
sudo python tftp_server.py firmware.bin --server-ip 192.168.1.10

# Restrict to one client
sudo python tftp_server.py firmware.bin --client-ip 192.168.1.50

# Larger blocks (faster transfers on LAN)
sudo python tftp_server.py firmware.bin --block-size 1468

# Simulate a slow link (10 ms inter-block delay)
sudo python tftp_server.py firmware.bin --delay 0.01

# Use a specific NIC
sudo python tftp_server.py firmware.bin --iface eth0

# Full example
sudo python tftp_server.py firmware.bin \
    --server-ip 10.0.0.1 \
    --client-ip 10.0.0.2 \
    --block-size 1024 \
    --delay 0.005 \
    --timeout 10 \
    --retries 3

# List available interfaces
sudo python tftp_server.py --list-interfaces
```

### Options

| Option | Default | Description |
|---|---|---|
| `filepath` | *(required)* | File to serve |
| `--server-ip IP` | `0.0.0.0` | IP to advertise / filter on; `0.0.0.0` = all |
| `--client-ip IP` | *(any)* | Accept requests only from this IP |
| `--block-size N` | `512` | TFTP block size in bytes (8 – 65464) |
| `--delay SECS` | `0` | Sleep between block sends (0 = none) |
| `--iface NAME` | auto | Network interface (e.g. `eth0`, `Ethernet`) |
| `--timeout SECS` | `5` | Seconds to wait for each ACK |
| `--retries N` | `5` | Max retransmissions per block |
| `--port N` | `69` | UDP port to listen on |
| `--list-interfaces` | — | Print interfaces and exit |

---

## How it works

```
Client                              Server (this program)
  │                                       │
  │── RRQ (port 69) ──────────────────────▶│  Scapy sniff captures RRQ
  │                                       │  New thread + random TID port
  │◀── OACK (our TID → client port) ──────│  option negotiation (if requested)
  │── ACK 0 ───────────────────────────────▶│
  │                                       │
  │◀── DATA block 1 ──────────────────────│  Scapy send() at L3
  │── ACK 1 ───────────────────────────────▶│  Queue-based ACK delivery
  │◀── DATA block 2 ──────────────────────│
  │   …                                   │
  │◀── DATA block N (< blksize) ──────────│  last block signals EOF
  │── ACK N ───────────────────────────────▶│
```

* **Capture**: Scapy `sniff()` with a BPF filter (`udp [and dst host X] [and src host Y]`)
  captures all relevant UDP traffic at packet level.
* **Routing**: The packet callback routes RRQs to new threads and ACKs to the
  matching session via a `queue.Queue`.
* **Sending**: `scapy.send()` injects IP/UDP packets at L3, bypassing the OS
  TFTP stack entirely.
* **Absorb socket**: A plain UDP socket is bound to port 69 to prevent the OS
  from sending ICMP "port unreachable" replies to incoming RRQs.

---

## Terminal UI

```
─────────────────── TFTP Server (Scapy/Npcap) ──────────────────────
┌─ Configuration ──────────────────┐  ┌─ Statistics ───────────┐
│ File        /srv/firmware.bin    │  │ Requests    12         │
│ File size   4.20 MB              │  │ Completed   11         │
│ Server IP   192.168.1.10         │  │ Failed       0         │
│ Client      any                  │  │ Filtered     1         │
│ Block size  1024 B               │  │ Active       1         │
│ Delay       none                 │  └────────────────────────┘
│ Port        69                   │
└──────────────────────────────────┘
┌─ Transfers ──────────────────────────────────────────────────────┐
│ Client             Status        Progress        Sent   …        │
│ 192.168.1.50:1234  transferring  [#####-----] 50%  2.1 MB  …    │
└──────────────────────────────────────────────────────────────────┘
┌─ Log ────────────────────────────────────────────────────────────┐
│ 14:22:01.3  INFO  RRQ 'firmware.bin' [octet] blk=1024 from …    │
│ 14:22:06.8  INFO  Done 192.168.1.50 4.20 MB 312.4 KB/s 13.7s    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Limitations / notes

* **Read-only** — write requests (WRQ) are rejected.
* **One file** — the server always serves the file given on the command line,
  regardless of the filename requested by the client.
* **Concurrency** — multiple simultaneous transfers are supported; each runs in
  its own thread.
* **Windows Firewall** — may block incoming UDP on port 69; add an inbound rule
  if needed.
