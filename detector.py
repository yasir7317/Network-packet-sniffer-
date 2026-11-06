"""
Intrusion Detection System (IDS) Alert Engine
Monitors packet streams for suspicious anomalies and attack patterns:
1. Port Scan Detection (Horizontal & Vertical scans)
2. ARP Spoofing / Cache Poisoning Detection
3. SYN Flood Anomaly Detection
"""

import sys
from pathlib import Path

# Enable direct script execution from IDE or CLI without ModuleNotFoundError
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Any

from sniffer.parser import ParsedPacket


@dataclass
class Alert:
    timestamp: float
    time_str: str
    alert_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    message: str
    src: str
    dst: str
    details: Dict[str, Any] = field(default_factory=dict)


class TrafficDetector:
    """
    Lightweight rule-based intrusion detector for defensive network monitoring.
    Maintains bounded temporal windows to detect scans, floods, and ARP tampering.
    """

    def __init__(
        self,
        port_scan_threshold: int = 10,
        port_scan_window: float = 5.0,
        syn_flood_threshold: int = 25,
        syn_flood_window: float = 2.0,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.syn_flood_threshold = syn_flood_threshold
        self.syn_flood_window = syn_flood_window

        # Port scan tracking: src_ip -> deque of (timestamp, dst_ip, dst_port)
        self.scan_history: Dict[str, deque] = defaultdict(deque)
        self.reported_scans: Set[str] = set()

        # ARP spoofing tracking: ip -> mac
        self.arp_table: Dict[str, str] = {}

        # SYN flood tracking: (src_ip, dst_ip) -> deque of timestamps
        self.syn_history: Dict[str, deque] = defaultdict(deque)
        self.reported_syn_floods: Set[str] = set()

    def analyze(self, packet: ParsedPacket) -> List[Alert]:
        """Analyze a parsed packet and return any triggered alerts."""
        alerts: List[Alert] = []

        # 1. ARP Spoofing Detection
        arp_alert = self._check_arp_spoof(packet)
        if arp_alert:
            alerts.append(arp_alert)

        # 2. Port Scan Detection
        scan_alert = self._check_port_scan(packet)
        if scan_alert:
            alerts.append(scan_alert)

        # 3. SYN Flood Detection
        syn_alert = self._check_syn_flood(packet)
        if syn_alert:
            alerts.append(syn_alert)

        return alerts

    def _check_arp_spoof(self, packet: ParsedPacket) -> Optional[Alert]:
        """Detect when an ARP reply binds an already-known IP to a different MAC."""
        if not packet.arp:
            return None

        arp = packet.arp
        claimed_ip = arp.src_ip
        claimed_mac = arp.src_mac.lower()

        # Skip unspecified/broadcast IP
        if not claimed_ip or claimed_ip in ("0.0.0.0", "255.255.255.255"):
            return None

        if claimed_ip in self.arp_table:
            known_mac = self.arp_table[claimed_ip].lower()
            if known_mac != claimed_mac:
                return Alert(
                    timestamp=packet.timestamp,
                    time_str=packet.time_str,
                    alert_type="ARP Cache Poisoning / Spoofing",
                    severity="HIGH",
                    message=(
                        f"IP {claimed_ip} previously mapped to MAC {known_mac}, "
                        f"now claimed by conflicting MAC {claimed_mac}"
                    ),
                    src=f"{claimed_ip} ({claimed_mac})",
                    dst=f"Target: {arp.dst_ip} ({arp.dst_mac})",
                    details={
                        "ip": claimed_ip,
                        "original_mac": known_mac,
                        "conflicting_mac": claimed_mac,
                        "arp_opcode": arp.op_name,
                    },
                )
        else:
            # Learn the initial IP-to-MAC mapping
            self.arp_table[claimed_ip] = claimed_mac

        return None

    def _check_port_scan(self, packet: ParsedPacket) -> Optional[Alert]:
        """Detect rapid port probe behavior from a single source host."""
        if not packet.ip or not packet.transport or not packet.transport.dst_port:
            return None

        src_ip = packet.ip.src_ip
        dst_ip = packet.ip.dst_ip
        dst_port = packet.transport.dst_port
        now = packet.timestamp

        history = self.scan_history[src_ip]
        history.append((now, dst_ip, dst_port))

        # Evict old events outside time window
        while history and (now - history[0][0]) > self.port_scan_window:
            history.popleft()

        # Count distinct destination ports touched within window
        unique_ports = {entry[2] for entry in history}
        if len(unique_ports) >= self.port_scan_threshold:
            alert_key = f"{src_ip}->{len(unique_ports) // self.port_scan_threshold}"
            if alert_key not in self.reported_scans:
                self.reported_scans.add(alert_key)
                sample_ports = sorted(list(unique_ports))[:8]
                return Alert(
                    timestamp=now,
                    time_str=packet.time_str,
                    alert_type="Port Scan Detected",
                    severity="MEDIUM",
                    message=(
                        f"Host {src_ip} probed {len(unique_ports)} distinct ports on {dst_ip} "
                        f"within {self.port_scan_window:.1f}s (e.g. {sample_ports}...)"
                    ),
                    src=src_ip,
                    dst=dst_ip,
                    details={
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "unique_ports_count": len(unique_ports),
                        "ports_sample": sample_ports,
                        "window_seconds": self.port_scan_window,
                    },
                )

        return None

    def _check_syn_flood(self, packet: ParsedPacket) -> Optional[Alert]:
        """Detect burst of TCP SYN packets without ACK indicating potential SYN flood."""
        if not packet.ip or not packet.transport or packet.transport.protocol != "TCP":
            return None

        flags = packet.transport.flags
        # Pure SYN packet: SYN flag is set, ACK is not set
        if "SYN" in flags and "ACK" not in flags:
            src_ip = packet.ip.src_ip
            dst_ip = packet.ip.dst_ip
            key = f"{src_ip}->{dst_ip}"
            now = packet.timestamp

            history = self.syn_history[key]
            history.append(now)

            # Evict timestamps older than window
            while history and (now - history[0]) > self.syn_flood_window:
                history.popleft()

            if len(history) >= self.syn_flood_threshold:
                alert_key = f"{key}-{int(now // 5)}"
                if alert_key not in self.reported_syn_floods:
                    self.reported_syn_floods.add(alert_key)
                    return Alert(
                        timestamp=now,
                        time_str=packet.time_str,
                        alert_type="SYN Flood Anomaly",
                        severity="CRITICAL",
                        message=(
                            f"Host {src_ip} sent {len(history)} SYN packets to {dst_ip} "
                            f"in {self.syn_flood_window:.1f}s without establishing handshakes"
                        ),
                        src=src_ip,
                        dst=dst_ip,
                        details={
                            "source_ip": src_ip,
                            "target_ip": dst_ip,
                            "syn_count": len(history),
                            "window_seconds": self.syn_flood_window,
                        },
                    )

        return None


if __name__ == "__main__":
    from scapy.all import Ether, ARP, IP, TCP
    from sniffer.parser import parse_packet
    from sniffer.display import print_alert, print_banner

    print_banner()
    print("[*] Running Defensive IDS Rule Engine Demo...\n")

    detector = TrafficDetector(port_scan_threshold=5, port_scan_window=2.0)

    # 1. Simulate Port Scan Anomaly
    print("[1] Simulating Port Scan (10.0.0.99 probing 6 distinct ports on 192.168.1.50)...")
    for port in [21, 22, 23, 80, 443, 8080]:
        pkt = parse_packet(
            Ether() / IP(src="10.0.0.99", dst="192.168.1.50") / TCP(sport=50000, dport=port, flags="S")
        )
        for alert in detector.analyze(pkt):
            print_alert(alert)

    # 2. Simulate ARP Poisoning / Spoofing Anomaly
    print("\n[2] Simulating ARP Cache Poisoning Anomaly...")
    # Normal gateway ARP announcement
    legit_arp = parse_packet(
        Ether(src="c0:ff:ee:00:11:22", dst="00:1a:2b:3c:4d:5e")
        / ARP(op=2, hwsrc="c0:ff:ee:00:11:22", psrc="192.168.1.1", hwdst="00:1a:2b:3c:4d:5e", pdst="192.168.1.50")
    )
    detector.analyze(legit_arp)

    # Conflicting attacker ARP claiming 192.168.1.1
    spoof_arp = parse_packet(
        Ether(src="aa:bb:cc:dd:ee:ff", dst="00:1a:2b:3c:4d:5e")
        / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1", hwdst="00:1a:2b:3c:4d:5e", pdst="192.168.1.50")
    )
    for alert in detector.analyze(spoof_arp):
        print_alert(alert)

    # 3. Simulate SYN Flood Anomaly
    print("\n[3] Simulating SYN Flood Anomaly (Host sending rapid burst of SYN packets without ACK)...")
    for seq_num in range(30):
        syn_pkt = parse_packet(
            Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
            / IP(src="10.0.0.99", dst="192.168.1.50")
            / TCP(sport=30000 + seq_num, dport=80, flags="S", seq=seq_num)
        )
        for alert in detector.analyze(syn_pkt):
            print_alert(alert)

    print("\n[+] TrafficDetector self-test finished successfully!")
