"""
Live Statistics & Metrics Tracker
Tracks protocol distributions, top talkers (source & destination IPs),
conversations, and bandwidth usage in real-time.
"""

import sys
from pathlib import Path

# Enable direct script execution from IDE or CLI without ModuleNotFoundError
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from collections import Counter, defaultdict
import time
from typing import Dict, Any, List, Tuple
from sniffer.parser import ParsedPacket


class PacketStats:
    """
    Maintains real-time packet metrics, protocol distributions,
    bandwidth rates, and conversation rankings.
    """

    def __init__(self):
        self.start_time: float = time.time()
        self.last_update_time: float = self.start_time
        self.total_packets: int = 0
        self.total_bytes: int = 0

        # Protocol counts
        self.protocol_counts: Counter[str] = Counter()

        # Talker trackers
        self.src_ip_packets: Counter[str] = Counter()
        self.src_ip_bytes: Counter[str] = Counter()
        self.dst_ip_packets: Counter[str] = Counter()
        self.dst_ip_bytes: Counter[str] = Counter()

        # Conversations (pair: src -> dst)
        self.conversations_packets: Counter[str] = Counter()
        self.conversations_bytes: Counter[str] = Counter()

        # Sliding window for current rate (last 2 seconds)
        self.recent_bytes: int = 0
        self.recent_packets: int = 0
        self.window_start: float = time.time()

    def update(self, packet: ParsedPacket) -> None:
        """Update metrics with a newly captured packet."""
        now = time.time()
        self.total_packets += 1
        self.total_bytes += packet.length

        # Protocol accounting
        proto = packet.highest_layer
        self.protocol_counts[proto] += 1

        # IP layer accounting
        if packet.ip:
            src = packet.ip.src_ip
            dst = packet.ip.dst_ip
            length = packet.length

            self.src_ip_packets[src] += 1
            self.src_ip_bytes[src] += length
            self.dst_ip_packets[dst] += 1
            self.dst_ip_bytes[dst] += length

            conv = f"{src} -> {dst}"
            self.conversations_packets[conv] += 1
            self.conversations_bytes[conv] += length

        # Sliding window rate tracking
        self.recent_bytes += packet.length
        self.recent_packets += 1
        if now - self.window_start >= 1.0:
            self.recent_bytes = 0
            self.recent_packets = 0
            self.window_start = now

        self.last_update_time = now

    @property
    def elapsed_seconds(self) -> float:
        """Total duration since statistics tracking began."""
        return max(0.001, time.time() - self.start_time)

    @property
    def average_packet_rate(self) -> float:
        """Average packets captured per second."""
        return self.total_packets / self.elapsed_seconds

    @property
    def average_bandwidth_kbps(self) -> float:
        """Average bandwidth in Kilobits per second (Kbps)."""
        bits = self.total_bytes * 8
        return (bits / self.elapsed_seconds) / 1000.0

    @property
    def formatted_bytes(self) -> str:
        """Format total bytes to human-readable string (B, KB, MB, GB)."""
        b = self.total_bytes
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if b < 1024.0 or unit == "TB":
                return f"{b:.2f} {unit}"
            b /= 1024.0
        return f"{self.total_bytes} B"

    def get_top_src_ips(self, limit: int = 5) -> List[Tuple[str, int, int]]:
        """Returns list of (src_ip, packet_count, byte_count) sorted by packets."""
        return [
            (ip, count, self.src_ip_bytes[ip])
            for ip, count in self.src_ip_packets.most_common(limit)
        ]

    def get_top_dst_ips(self, limit: int = 5) -> List[Tuple[str, int, int]]:
        """Returns list of (dst_ip, packet_count, byte_count) sorted by packets."""
        return [
            (ip, count, self.dst_ip_bytes[ip])
            for ip, count in self.dst_ip_packets.most_common(limit)
        ]

    def get_top_conversations(self, limit: int = 5) -> List[Tuple[str, int, int]]:
        """Returns list of (conversation_str, packet_count, byte_count)."""
        return [
            (conv, count, self.conversations_bytes[conv])
            for conv, count in self.conversations_packets.most_common(limit)
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Convert statistics to dictionary for JSON export."""
        return {
            "elapsed_seconds": round(self.elapsed_seconds, 2),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "average_packets_per_sec": round(self.average_packet_rate, 2),
            "average_kbps": round(self.average_bandwidth_kbps, 2),
            "protocols": dict(self.protocol_counts),
            "top_source_ips": [
                {"ip": ip, "packets": pkts, "bytes": b}
                for ip, pkts, b in self.get_top_src_ips(10)
            ],
            "top_destination_ips": [
                {"ip": ip, "packets": pkts, "bytes": b}
                for ip, pkts, b in self.get_top_dst_ips(10)
            ],
            "top_conversations": [
                {"conversation": conv, "packets": pkts, "bytes": b}
                for conv, pkts, b in self.get_top_conversations(10)
            ],
        }


if __name__ == "__main__":
    from scapy.all import Ether, IP, TCP, UDP
    from sniffer.parser import parse_packet
    from sniffer.display import print_statistics_dashboard

    print("[*] Running PacketStats Self-Test Demo...\n")

    stats = PacketStats()

    # Simulate 5 packets
    p1 = parse_packet(Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=50001, dport=80))
    p2 = parse_packet(Ether() / IP(src="93.184.216.34", dst="192.168.1.50") / TCP(sport=80, dport=50001))
    p3 = parse_packet(Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=53000, dport=53))
    p4 = parse_packet(Ether() / IP(src="10.0.0.99", dst="192.168.1.50") / TCP(sport=40001, dport=22))
    p5 = parse_packet(Ether() / IP(src="10.0.0.99", dst="192.168.1.50") / TCP(sport=40002, dport=23))

    for pkt in [p1, p2, p3, p4, p5]:
        stats.update(pkt)

    print_statistics_dashboard(stats)
    print("\n[+] PacketStats self-test finished successfully!")
