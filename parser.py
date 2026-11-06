"""
Packet Parser Module
Extracts and structures headers across Layer 2 (Ethernet), Layer 3 (IPv4/IPv6/ARP),
Layer 4 (TCP/UDP/ICMP), and coordinates with application decoders.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6


# Known EtherType codes
ETHER_TYPES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q (VLAN)",
    0x88CC: "LLDP",
}

# Known IP protocol codes
IP_PROTOCOLS = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6-Encap",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

# ICMP type mapping
ICMP_TYPES = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    4: "Source Quench",
    5: "Redirect",
    8: "Echo Request",
    9: "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
}

# ARP Opcode mapping
ARP_OPCODES = {
    1: "Request (who-has)",
    2: "Reply (is-at)",
    3: "RARP-Request",
    4: "RARP-Reply",
}


@dataclass
class EthernetHeader:
    src_mac: str
    dst_mac: str
    type_code: int
    type_name: str


@dataclass
class IPHeader:
    version: int
    src_ip: str
    dst_ip: str
    protocol_num: int
    protocol_name: str
    length: int
    ttl_or_hop_limit: int
    id: Optional[int] = None
    flags: List[str] = field(default_factory=list)
    chksum: Optional[int] = None


@dataclass
class ARPHeader:
    op_code: int
    op_name: str
    src_mac: str
    src_ip: str
    dst_mac: str
    dst_ip: str


@dataclass
class TransportHeader:
    protocol: str  # TCP, UDP, ICMP
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    seq: Optional[int] = None
    ack: Optional[int] = None
    flags: List[str] = field(default_factory=list)
    flags_str: str = ""
    window: Optional[int] = None
    chksum: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_type_name: Optional[str] = None
    icmp_code: Optional[int] = None


@dataclass
class ParsedPacket:
    packet_num: int
    timestamp: float
    time_str: str
    length: int
    ethernet: Optional[EthernetHeader] = None
    ip: Optional[IPHeader] = None
    arp: Optional[ARPHeader] = None
    transport: Optional[TransportHeader] = None
    app: Optional[Dict[str, Any]] = None
    highest_layer: str = "Unknown"
    summary: str = ""
    raw_packet: Any = None

    @property
    def src_display(self) -> str:
        """Friendly source string with port if present."""
        if self.ip and self.transport and self.transport.src_port:
            return f"{self.ip.src_ip}:{self.transport.src_port}"
        if self.ip:
            return self.ip.src_ip
        if self.arp:
            return f"{self.arp.src_ip} ({self.arp.src_mac})"
        if self.ethernet:
            return self.ethernet.src_mac
        return "Unknown"

    @property
    def dst_display(self) -> str:
        """Friendly destination string with port if present."""
        if self.ip and self.transport and self.transport.dst_port:
            return f"{self.ip.dst_ip}:{self.transport.dst_port}"
        if self.ip:
            return self.ip.dst_ip
        if self.arp:
            return f"{self.arp.dst_ip} ({self.arp.dst_mac})"
        if self.ethernet:
            return self.ethernet.dst_mac
        return "Unknown"


def parse_tcp_flags(tcp_layer: TCP) -> tuple[List[str], str]:
    """
    Parse TCP flags from a Scapy TCP layer into a human-readable list and formatted string.
    Flags include: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR.
    """
    flags_list = []
    flag_val = int(tcp_layer.flags)

    # Flag bit positions
    if flag_val & 0x01:
        flags_list.append("FIN")
    if flag_val & 0x02:
        flags_list.append("SYN")
    if flag_val & 0x04:
        flags_list.append("RST")
    if flag_val & 0x08:
        flags_list.append("PSH")
    if flag_val & 0x10:
        flags_list.append("ACK")
    if flag_val & 0x20:
        flags_list.append("URG")
    if flag_val & 0x40:
        flags_list.append("ECE")
    if flag_val & 0x80:
        flags_list.append("CWR")

    flags_str = f"[{', '.join(flags_list)}]" if flags_list else "[None]"
    return flags_list, flags_str


def parse_packet(pkt: Any, packet_num: int = 1) -> ParsedPacket:
    """
    Parse a raw Scapy packet into a structured ParsedPacket object.
    Gracefully handles all standard protocol layers.
    """
    ts = float(getattr(pkt, "time", datetime.now().timestamp()))
    time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
    pkt_len = len(pkt)

    parsed = ParsedPacket(
        packet_num=packet_num,
        timestamp=ts,
        time_str=time_str,
        length=pkt_len,
        raw_packet=pkt,
    )

    # Layer 2: Ethernet
    if Ether in pkt:
        eth = pkt[Ether]
        type_code = eth.type
        type_name = ETHER_TYPES.get(type_code, f"0x{type_code:04x}")
        parsed.ethernet = EthernetHeader(
            src_mac=eth.src,
            dst_mac=eth.dst,
            type_code=type_code,
            type_name=type_name,
        )
        parsed.highest_layer = "Ethernet"

    # Layer 2/3: ARP
    if ARP in pkt:
        arp = pkt[ARP]
        op_code = int(arp.op)
        op_name = ARP_OPCODES.get(op_code, f"Opcode-{op_code}")
        parsed.arp = ARPHeader(
            op_code=op_code,
            op_name=op_name,
            src_mac=arp.hwsrc,
            src_ip=arp.psrc,
            dst_mac=arp.hwdst,
            dst_ip=arp.pdst,
        )
        parsed.highest_layer = "ARP"
        if op_code == 1:
            parsed.summary = f"Who has {arp.pdst}? Tell {arp.psrc}"
        elif op_code == 2:
            parsed.summary = f"{arp.psrc} is at {arp.hwsrc}"
        else:
            parsed.summary = f"ARP {op_name}"

    # Layer 3: IPv4
    elif IP in pkt:
        ip = pkt[IP]
        proto_code = ip.proto
        proto_name = IP_PROTOCOLS.get(proto_code, f"Proto-{proto_code}")

        ip_flags = []
        if ip.flags.DF:
            ip_flags.append("DF")
        if ip.flags.MF:
            ip_flags.append("MF")

        parsed.ip = IPHeader(
            version=4,
            src_ip=ip.src,
            dst_ip=ip.dst,
            protocol_num=proto_code,
            protocol_name=proto_name,
            length=ip.len,
            ttl_or_hop_limit=ip.ttl,
            id=ip.id,
            flags=ip_flags,
            chksum=ip.chksum,
        )
        parsed.highest_layer = "IPv4"

    # Layer 3: IPv6
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        nh_code = ip6.nh
        nh_name = IP_PROTOCOLS.get(nh_code, f"NextHdr-{nh_code}")
        parsed.ip = IPHeader(
            version=6,
            src_ip=ip6.src,
            dst_ip=ip6.dst,
            protocol_num=nh_code,
            protocol_name=nh_name,
            length=ip6.plen,
            ttl_or_hop_limit=ip6.hlim,
        )
        parsed.highest_layer = "IPv6"

    # Layer 4: TCP
    if TCP in pkt:
        tcp = pkt[TCP]
        flags_list, flags_str = parse_tcp_flags(tcp)
        parsed.transport = TransportHeader(
            protocol="TCP",
            src_port=tcp.sport,
            dst_port=tcp.dport,
            seq=tcp.seq,
            ack=tcp.ack,
            flags=flags_list,
            flags_str=flags_str,
            window=tcp.window,
            chksum=tcp.chksum,
        )
        parsed.highest_layer = "TCP"
        parsed.summary = f"{tcp.sport} -> {tcp.dport} {flags_str} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={pkt_len}"

    # Layer 4: UDP
    elif UDP in pkt:
        udp = pkt[UDP]
        parsed.transport = TransportHeader(
            protocol="UDP",
            src_port=udp.sport,
            dst_port=udp.dport,
            chksum=udp.chksum,
        )
        parsed.highest_layer = "UDP"
        parsed.summary = f"{udp.sport} -> {udp.dport} Len={udp.len}"

    # Layer 4: ICMP
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        type_code = icmp.type
        type_name = ICMP_TYPES.get(type_code, f"Type {type_code}")
        parsed.transport = TransportHeader(
            protocol="ICMP",
            icmp_type=type_code,
            icmp_type_name=type_name,
            icmp_code=icmp.code,
            chksum=icmp.chksum,
        )
        parsed.highest_layer = "ICMP"
        parsed.summary = f"ICMP {type_name} (type={type_code}, code={icmp.code})"

    # Fallback summary if still blank
    if not parsed.summary:
        if parsed.ip:
            parsed.summary = f"{parsed.ip.src_ip} -> {parsed.ip.dst_ip} ({parsed.ip.protocol_name})"
        elif parsed.ethernet:
            parsed.summary = f"{parsed.ethernet.src_mac} -> {parsed.ethernet.dst_mac} ({parsed.ethernet.type_name})"
        else:
            parsed.summary = f"Raw packet length {pkt_len} bytes"

    return parsed


if __name__ == "__main__":
    print("[*] Running PacketParser Self-Test Demo...\n")

    # Sample TCP packet with SYN-ACK flags
    sample_pkt = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
        / IP(src="192.168.1.50", dst="93.184.216.34", ttl=64)
        / TCP(sport=51234, dport=80, flags="SA", seq=1000, ack=2000, window=65535)
    )

    p = parse_packet(sample_pkt, packet_num=1)
    print("Parsed Packet #1:")
    print(f"  - Highest Layer: {p.highest_layer}")
    print(f"  - Source:        {p.src_display}")
    print(f"  - Destination:   {p.dst_display}")
    print(f"  - TCP Flags:     {p.transport.flags_str}")
    print(f"  - Summary:       {p.summary}")
    print("\n[+] Parser self-test finished successfully!")
