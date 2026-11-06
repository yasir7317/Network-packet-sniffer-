# Network Packet Sniffer & Protocol Analyzer

> **LEGAL AND ETHICAL NOTICE**  
> This packet sniffer is designed solely for educational purposes, security research, and authorized network diagnostics on networks you own or have explicit, documented permission to monitor. Unauthorized interception, eavesdropping, or packet capture on third-party networks may violate local, national, and international laws (such as the US Wiretap Act, Computer Fraud and Abuse Act, GDPR, and regional cybersecurity legislation). Always obtain proper authorization before monitoring network interfaces.

---

## Table of Contents
1. [Overview & Architecture](#overview--architecture)
2. [Project Structure](#project-structure)
3. [Deep Dive: How Packet Headers are Structured & Parsed](#deep-dive-how-packet-headers-are-structured--parsed)
   - [Ethernet Frame (Layer 2)](#1-ethernet-ii-frame-layer-2)
   - [ARP Header (Layer 2/3)](#2-arp-header-layer-23)
   - [IPv4 Header (Layer 3)](#3-ipv4-header-layer-3)
   - [IPv6 Header (Layer 3)](#4-ipv6-header-layer-3)
   - [TCP Header & Flags (Layer 4)](#5-tcp-header--flags-layer-4)
   - [UDP Header (Layer 4)](#6-udp-header-layer-4)
   - [ICMP Header (Layer 3/4)](#7-icmp-header-layer-34)
   - [Application Layer Decoders & Privacy Guard (Layer 7)](#8-application-layer-decoders--privacy-guard)
4. [Platform Setup & Permissions](#platform-setup--permissions)
   - [Windows Setup (Npcap Guide)](#windows-setup)
   - [Linux Setup](#linux-setup)
   - [macOS Setup](#macos-setup)
5. [Installation](#installation)
6. [Command-Line Usage & Examples](#command-line-usage--examples)
7. [Defensive IDS Alert Engine](#defensive-ids-alert-engine)
8. [Test Plan & Traffic Generation](#test-plan--traffic-generation)
9. [Suggestions for Next Steps & Extensions](#suggestions-for-next-steps--extensions)

---

## Overview & Architecture

This tool is a modular, high-performance command-line packet sniffer and protocol analyzer built in Python using **Scapy** and **Rich**. It is engineered with the following design principles:

- **Multithreaded Capture Queue**: A dedicated capture thread ingests raw packets and buffers them into a thread-safe `queue.Queue(maxsize=10000)`. This decouples packet acquisition from terminal rendering and disk I/O, preventing dropped frames during high-throughput traffic bursts.
- **Strict Privacy Safeguards**: Credentials, session tokens (`Cookie`, `Set-Cookie`), and authentication headers (`Authorization`, `Bearer`) are automatically redacted (`[REDACTED FOR PRIVACY]`). Raw HTTP payloads and packet bodies are suppressed by default unless explicitly requested with `--show-payload`.
- **Defensive Threat Detection (Mini-IDS)**: An embedded anomaly detection engine tracks sliding time windows to alert on port scans, ARP cache poisoning, and SYN floods.
- **Unified Engine for Live Capture & PCAP Replay**: The exact same parsing, decoding, filtering, detection, and reporting pipeline runs identically on live network interfaces and offline `.pcap` files.

---

## Project Structure

```text
network_packet_sniffer/
├── sniffer/
│   ├── __init__.py         # Package metadata and versioning
│   ├── capture.py          # Multithreaded capture engine, interface resolver, PCAP streaming
│   ├── parser.py           # Layer 2, 3, and 4 header parsing (Ethernet, ARP, IPv4/6, TCP, UDP, ICMP)
│   ├── decoders.py         # Application decoders (DNS, HTTP, DHCP) with privacy redaction
│   ├── stats.py            # Real-time traffic metrics, top talkers, bandwidth calculator
│   ├── detector.py         # Defensive IDS rule engine (Port scan, ARP spoofing, SYN flood)
│   ├── display.py          # Rich terminal formatting, packet trees, badges, and alerts
│   └── exporter.py         # Structured CSV and JSON session export
├── tests/
│   ├── __init__.py         # Test package initialization
│   ├── generate_sample.py  # Synthesizes an authentic multi-protocol sample PCAP with anomalies
│   └── test_parser.py      # Automated unit test suite verifying parsers, decoders, and alerts
├── main.py                 # Interactive CLI entrypoint and argument parser
├── requirements.txt        # Project dependencies (scapy, rich)
└── README.md               # Complete architecture, header guide, and operational manual
```

---

## Deep Dive: How Packet Headers are Structured & Parsed

Network communications operate using encapsulation across the OSI and TCP/IP models. As data travels down the stack, each layer prepends a header containing routing and control metadata.

```text
+-------------------+--------------------+--------------------+-----------------------+
|  Ethernet Header  |     IP Header      |  Transport Header  |    Payload / Data     |
|     (Layer 2)     |     (Layer 3)      |  (TCP/UDP Layer 4) | (DNS, HTTP, Layer 7)  |
+-------------------+--------------------+--------------------+-----------------------+
```

### 1. Ethernet II Frame (Layer 2)
The Ethernet frame transports raw bits across a local physical link (switch, Wi-Fi access point, network card).

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Destination MAC Address (Bytes 0-3)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Dst MAC (Bytes 4-5)         |   Source MAC (Bytes 0-1)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Source MAC Address (Bytes 2-5)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       EtherType (2 Bytes)     |           Payload...          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Destination MAC (6 bytes)**: Physical address of the next-hop hardware device.
- **Source MAC (6 bytes)**: Physical address of the transmitting network card.
- **EtherType (2 bytes)**: Identifies the payload protocol. Common values: `0x0800` (IPv4), `0x86DD` (IPv6), `0x0806` (ARP).

### 2. ARP Header (Layer 2/3)
Address Resolution Protocol (ARP) resolves an IP address to a physical MAC address on a local broadcast domain.
- **Hardware Type (2 bytes)**: Usually `1` for Ethernet.
- **Protocol Type (2 bytes)**: Usually `0x0800` for IPv4.
- **Opcode (2 bytes)**: `1` for Request (*who-has 192.168.1.1?*), `2` for Reply (*192.168.1.1 is-at c0:ff:ee...*).
- **Sender/Target Hardware & Protocol Addresses**: 6-byte MACs and 4-byte IPv4 addresses.

### 3. IPv4 Header (Layer 3)
The Internet Protocol version 4 header routes packets across interconnected networks.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|     Fragment Offset     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source IPv4 Address                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination IPv4 Address                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **Version (4 bits)**: Always `4`.
- **IHL (4 bits)**: Internet Header Length in 32-bit words (minimum `5` = 20 bytes).
- **Total Length (16 bits)**: Entire packet length including header and data (up to 65,535 bytes).
- **TTL (8 bits)**: Decremented by every router. Drops to 0 to prevent routing loops.
- **Protocol (8 bits)**: Layer 4 protocol. Key values: `1` (ICMP), `6` (TCP), `17` (UDP).
- **Source & Destination IP (32 bits each)**: End-to-end IP addresses.

### 4. IPv6 Header (Layer 3)
IPv6 features a fixed 40-byte base header:
- **Version (4 bits)**: Always `6`.
- **Traffic Class & Flow Label (28 bits)**: QoS classification and packet flow tracking.
- **Payload Length (16 bits)**: Size of payload following the 40-byte base header.
- **Next Header (8 bits)**: Analogous to IPv4 Protocol field (`6` for TCP, `17` for UDP, `58` for ICMPv6).
- **Hop Limit (8 bits)**: Equivalent to IPv4 TTL.
- **Source & Destination (128 bits / 16 bytes each)**: Expanded 128-bit addresses.

### 5. TCP Header & Flags (Layer 4)
Transmission Control Protocol provides reliable, ordered byte-stream delivery.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |        Urgent Pointer         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
#### TCP Control Flags:
- **SYN (Synchronize)**: Initiates a TCP connection (First step of 3-way handshake).
- **ACK (Acknowledgment)**: Confirms receipt of bytes / packets.
- **FIN (Finish)**: Initiates graceful connection teardown.
- **RST (Reset)**: Abruptly terminates an invalid or closed connection.
- **PSH (Push)**: Informs receiving stack to push data immediately to the application.
- **URG (Urgent)**: Urgent pointer field is valid.
- **ECE / CWR**: Explicit Congestion Notification flags.

### 6. UDP Header (Layer 4)
User Datagram Protocol provides a lightweight, connectionless transmission model.
- **Source Port (16 bits)** & **Destination Port (16 bits)**
- **Length (16 bits)**: Length of UDP header + UDP payload.
- **Checksum (16 bits)**: Error-detection checksum.

### 7. ICMP Header (Layer 3/4)
Internet Control Message Protocol reports diagnostic network conditions:
- **Type 8, Code 0**: Echo Request (`ping` packet).
- **Type 0, Code 0**: Echo Reply (`ping` response).
- **Type 3**: Destination Unreachable (Port, Network, Host, or Protocol unreachable).
- **Type 11**: Time Exceeded (TTL expired in transit; used by `traceroute`).

### 8. Application Layer Decoders & Privacy Guard
- **DNS (Port 53)**: Decodes Transaction ID, Query/Response flag (`QR`), Question Names (`qname`), Question Types (`A`, `AAAA`, `MX`, `CNAME`), and Answer RData records.
- **HTTP (Port 80/8080/etc.)**: Decodes request methods (`GET`, `POST`), paths, status codes (`200 OK`, `404 Not Found`), and server headers.
  - **Privacy Redaction**: Headers such as `Cookie`, `Set-Cookie`, and `Authorization` are automatically redacted with `[REDACTED FOR PRIVACY]`.
  - Raw POST / Request bodies are never printed by default.
- **DHCP (Ports 67/68)**: Decodes message types (`DISCOVER`, `OFFER`, `REQUEST`, `ACK`), client MAC addresses, offered IP addresses, subnet masks, and default gateway routers.

---

## Platform Setup & Permissions

Packet sniffing operates at the data link layer (Layer 2) and requires elevated operating system privileges to place network cards into promiscuous mode.

### Windows Setup
On Windows, the native network stack restricts raw sockets. Live packet sniffing requires **Npcap**:
1. Download Npcap from the official website: [https://npcap.com/](https://npcap.com/)
2. Run the installer. **CRITICAL STEP**: Make sure to check:
   - `[x] Install Npcap in WinPcap API-compatible Mode`
3. Open **PowerShell** or **Command Prompt** as **Administrator** (*Right-click -> Run as Administrator*).
4. Run the sniffer.

> **Offline Mode Note**: If Npcap is not yet installed on Windows, you can still test all parsing, statistics, IDS detection, filtering, and JSON/CSV export capabilities using `.pcap` files:
> ```powershell
> python tests/generate_sample.py
> python main.py -r sample_traffic.pcap -v
> ```

### Linux Setup
On Linux, raw packet sockets require `root` or `CAP_NET_RAW` capability:
```bash
# Option 1: Run with sudo
sudo python3 main.py -i eth0

# Option 2: Grant Python the capability without full root
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
python3 main.py -i eth0
```

### macOS Setup
On macOS, BPF devices (`/dev/bpf*`) require root permissions:
```bash
sudo python3 main.py -i en0
```

---

## Installation

Ensure Python 3.10+ is installed:

```bash
# Clone or navigate to the project directory
cd "network packet sniffer"

# Install dependencies
python -m pip install -r requirements.txt
```

---

## Command-Line Usage & Examples

### 1. Enumerate Interfaces
```bash
python main.py -l
```
Displays all network interfaces with ID, friendly name, IPv4, MAC address, and hardware description.

To include virtual lightweight filter drivers:
```bash
python main.py -l --all-ifaces
```

---

### 2. Live Capture on Selected Interface
```bash
# By interface ID:
python main.py -i 0

# By interface Name:
python main.py -i "Wi-Fi 2"
```

---

### 3. Capture with BPF Filters and Save to PCAP
Capture only HTTP traffic or DNS lookups, and save directly to a PCAP file:
```bash
python main.py -i 0 -f "tcp port 80 or udp port 53" -w session_capture.pcap
```

---

### 4. Read & Inspect an Existing PCAP File
No administrative privileges or Npcap required:
```bash
python main.py -r sample_traffic.pcap
```

---

### 5. Deep Header Inspection (Verbose Mode)
Inspect every header layer (Ethernet, IPv4/6, TCP/UDP, DNS/HTTP/DHCP) in a structured tree view:
```bash
python main.py -r sample_traffic.pcap -v -c 5
```

---

### 6. Filter by Protocol, IP, or Port
```bash
# Show only HTTP traffic:
python main.py -r sample_traffic.pcap --proto http

# Show only DNS traffic:
python main.py -r sample_traffic.pcap --proto dns

# Filter by IP address:
python main.py -r sample_traffic.pcap --ip 93.184.216.34

# Filter by destination port:
python main.py -r sample_traffic.pcap --port 80
```

---

### 7. Structured JSON & CSV Export
Export captured packets and session summary metrics for SIEM ingestion or spreadsheet analysis:
```bash
python main.py -r sample_traffic.pcap --export-json analysis.json --export-csv capture.csv
```

---

## Defensive IDS Alert Engine

The built-in detection engine identifies three prevalent network security anomalies:

### 1. Port Scan Detection
- **Mechanism**: Tracks distinct destination ports contacted by a single source IP within a sliding 5-second window.
- **Threshold**: >= 10 unique ports within 5 seconds.
- **Alert Output**:
  ```text
  ┌─────────────────────── ! SECURITY ANOMALY DETECTED ! ───────────────────────┐
  │ ALERT: Port Scan Detected                                                   │
  │ Severity: MEDIUM  |  Time: 15:50:09.529                                     │
  │ Source: 10.0.0.99  -->  Destination: 192.168.1.50                           │
  │ Detail: Host 10.0.0.99 probed 10 distinct ports on 192.168.1.50 within 5.0s │
  │ (e.g. [21, 22, 23, 25, 53, 80, 110, 143]...)                                │
  └─────────────────────────────────────────────────────────────────────────────┘
  ```

### 2. ARP Cache Poisoning / Spoofing Detection
- **Mechanism**: Caches IP-to-MAC associations. Triggers when an ARP reply advertises an existing IP with a conflicting hardware MAC address.
- **Severity**: HIGH.

### 3. SYN Flood Anomaly
- **Mechanism**: Monitors TCP connection initiation bursts. Flags hosts emitting excessive SYN packets without ACK responses within a 2-second window.
- **Severity**: CRITICAL.

---

## Test Plan & Traffic Generation

### Automated Test Suite
Run the 9 unit test scenarios covering all layers:
```bash
python -m unittest tests/test_parser.py
```

### Synthetic Multi-Protocol Traffic Generator
Generate an authentic `sample_traffic.pcap` with ARP, DHCP, ICMP, DNS, TCP handshakes, HTTP transactions, port scan attacks, and ARP spoofing:
```bash
python tests/generate_sample.py
```

### Generating Live Traffic for Manual Testing
Open a second terminal while the sniffer is active:

1. **ICMP (Ping)**:
   ```bash
   ping 8.8.8.8 -n 2        # Windows
   ping -c 2 8.8.8.8        # Linux/macOS
   ```
2. **DNS (Domain Name Lookup)**:
   ```bash
   nslookup example.com
   ```
3. **HTTP / Web Traffic**:
   ```bash
   curl -I http://example.com
   ```
4. **TCP Port Probe**:
   ```powershell
   # Windows PowerShell:
   Test-NetConnection -ComputerName example.com -Port 80
   ```

Verify that each packet appears immediately on the sniffer terminal with accurate protocol tags and flags.

---

## Suggestions for Next Steps & Extensions

1. **TLS / HTTPS SNI Extraction**: Parse TLS Client Hello handshakes to extract Server Name Indication (SNI) hostnames without decrypting traffic.
2. **Web Dashboard**: Connect a lightweight Flask / WebSocket or FastAPI server to stream captured packets in real-time to a browser-based UI.
3. **Geo-IP Location**: Integrate MaxMind GeoLite2 or a local database to display the geographic country and ASN of remote talkers.
4. **Bandwidth Graphing**: Implement an ASCII line chart (using `plotext` or Rich) showing real-time Kbps throughput over time.
5. **Decryption Support**: Support importing TLS session keys (`SSLKEYLOGFILE`) for authorized debugging of encrypted traffic.
