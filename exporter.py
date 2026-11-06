"""
Data Exporter Module
Exports captured packet flows and diagnostic analysis to CSV and JSON formats.
"""

import sys
from pathlib import Path

# Enable direct script execution from IDE or CLI without ModuleNotFoundError
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import csv
import json
import os
from typing import List, Dict, Any, Optional

from sniffer.parser import ParsedPacket
from sniffer.stats import PacketStats


class PacketExporter:
    """Handles structured serialization to CSV and JSON."""

    def __init__(self, csv_path: Optional[str] = None, json_path: Optional[str] = None):
        self.csv_path = csv_path
        self.json_path = json_path
        self.csv_file = None
        self.csv_writer = None
        self.json_packets: List[Dict[str, Any]] = []

        if self.csv_path:
            self._init_csv()

    def _init_csv(self) -> None:
        """Initialize CSV file with standard network analysis headers."""
        self.csv_file = open(self.csv_path, mode="w", newline="", encoding="utf-8")
        headers = [
            "packet_num",
            "time",
            "length_bytes",
            "protocol",
            "src_mac",
            "dst_mac",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "tcp_flags",
            "summary",
        ]
        self.csv_writer = csv.writer(self.csv_file)
        self.csv_writer.writerow(headers)
        self.csv_file.flush()

    def record_packet(self, pkt: ParsedPacket) -> None:
        """Write packet record to active export sinks."""
        # CSV writing
        if self.csv_writer:
            src_mac = pkt.ethernet.src_mac if pkt.ethernet else ""
            dst_mac = pkt.ethernet.dst_mac if pkt.ethernet else ""
            src_ip = pkt.ip.src_ip if pkt.ip else (pkt.arp.src_ip if pkt.arp else "")
            dst_ip = pkt.ip.dst_ip if pkt.ip else (pkt.arp.dst_ip if pkt.arp else "")
            src_port = pkt.transport.src_port if (pkt.transport and pkt.transport.src_port) else ""
            dst_port = pkt.transport.dst_port if (pkt.transport and pkt.transport.dst_port) else ""
            tcp_flags = pkt.transport.flags_str if (pkt.transport and pkt.transport.flags_str) else ""

            self.csv_writer.writerow([
                pkt.packet_num,
                pkt.time_str,
                pkt.length,
                pkt.highest_layer,
                src_mac,
                dst_mac,
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                tcp_flags,
                pkt.summary,
            ])
            self.csv_file.flush()

        # In-memory accumulator for JSON output
        if self.json_path:
            pkt_dict: Dict[str, Any] = {
                "packet_num": pkt.packet_num,
                "timestamp": pkt.timestamp,
                "time": pkt.time_str,
                "length": pkt.length,
                "highest_layer": pkt.highest_layer,
                "summary": pkt.summary,
            }

            if pkt.ethernet:
                pkt_dict["ethernet"] = {
                    "src_mac": pkt.ethernet.src_mac,
                    "dst_mac": pkt.ethernet.dst_mac,
                    "type": pkt.ethernet.type_name,
                }
            if pkt.ip:
                pkt_dict["ip"] = {
                    "version": pkt.ip.version,
                    "src_ip": pkt.ip.src_ip,
                    "dst_ip": pkt.ip.dst_ip,
                    "protocol": pkt.ip.protocol_name,
                    "ttl": pkt.ip.ttl_or_hop_limit,
                    "flags": pkt.ip.flags,
                }
            if pkt.arp:
                pkt_dict["arp"] = {
                    "operation": pkt.arp.op_name,
                    "src_mac": pkt.arp.src_mac,
                    "src_ip": pkt.arp.src_ip,
                    "dst_mac": pkt.arp.dst_mac,
                    "dst_ip": pkt.arp.dst_ip,
                }
            if pkt.transport:
                pkt_dict["transport"] = {
                    "protocol": pkt.transport.protocol,
                    "src_port": pkt.transport.src_port,
                    "dst_port": pkt.transport.dst_port,
                    "flags": pkt.transport.flags,
                    "flags_str": pkt.transport.flags_str,
                    "seq": pkt.transport.seq,
                    "ack": pkt.transport.ack,
                    "icmp_type": pkt.transport.icmp_type_name,
                }
            if pkt.app:
                pkt_dict["app"] = {
                    k: v for k, v in pkt.app.items() if k not in ("payload_preview",)
                }

            self.json_packets.append(pkt_dict)

    def finalize(self, stats: Optional[PacketStats] = None) -> None:
        """Close open files and dump structured JSON report."""
        if self.csv_file:
            try:
                self.csv_file.close()
            except Exception:
                pass
            self.csv_file = None

        if self.json_path:
            report: Dict[str, Any] = {
                "summary": stats.to_dict() if stats else {},
                "packets_count": len(self.json_packets),
                "packets": self.json_packets,
            }
            try:
                with open(self.json_path, mode="w", encoding="utf-8") as f:
                    json.dump(report, f, indent=2)
            except Exception as e:
                print(f"[!] Failed to write JSON output: {e}", file=sys.stderr)


if __name__ == "__main__":
    from scapy.all import Ether, IP, TCP
    from sniffer.parser import parse_packet
    import tempfile

    print("[*] Running PacketExporter Self-Test Demo...\n")

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f_csv:
        tmp_csv = f_csv.name
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f_json:
        tmp_json = f_json.name

    exp = PacketExporter(csv_path=tmp_csv, json_path=tmp_json)
    pkt = parse_packet(Ether() / IP(src="1.2.3.4", dst="5.6.7.8") / TCP(sport=1234, dport=80, flags="S"))
    exp.record_packet(pkt)
    exp.finalize()

    print(f"  - Recorded 1 packet to CSV ({os.path.getsize(tmp_csv)} bytes)")
    print(f"  - Recorded 1 packet to JSON ({os.path.getsize(tmp_json)} bytes)")

    os.remove(tmp_csv)
    os.remove(tmp_json)
    print("\n[+] Exporter self-test finished successfully!")
