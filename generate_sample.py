"""
Sample Traffic Generator
Synthesizes authentic network packets across Ethernet, ARP, IPv4, TCP, UDP, ICMP,
DNS, HTTP, and DHCP to test the packet sniffer pipeline without requiring live root/Npcap access.
"""

import os
import sys
import time

# Suppress Scapy warning banners
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import warnings
warnings.filterwarnings("ignore")

from scapy.all import (
    Ether,
    ARP,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    DNSRR,
    BOOTP,
    DHCP,
    Raw,
    wrpcap,
)


def generate_sample_pcap(output_file: str = "sample_traffic.pcap") -> None:
    """Generate a realistic test PCAP file containing diverse protocols and security anomalies."""
    print(f"[*] Generating synthetic test traffic into: {output_file}...")
    packets = []
    base_time = time.time()

    # 1. ARP Request & Reply (Gateway discovery)
    arp_req = Ether(src="00:1a:2b:3c:4d:5e", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc="00:1a:2b:3c:4d:5e",
        psrc="192.168.1.50",
        hwdst="00:00:00:00:00:00",
        pdst="192.168.1.1",
    )
    arp_req.time = base_time + 0.01
    packets.append(arp_req)

    arp_rep = Ether(src="c0:ff:ee:00:11:22", dst="00:1a:2b:3c:4d:5e") / ARP(
        op=2,
        hwsrc="c0:ff:ee:00:11:22",
        psrc="192.168.1.1",
        hwdst="00:1a:2b:3c:4d:5e",
        pdst="192.168.1.50",
    )
    arp_rep.time = base_time + 0.02
    packets.append(arp_rep)

    # 2. DHCP Discover & Offer
    dhcp_discover = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr="00:1a:2b:3c:4d:5e", ciaddr="0.0.0.0", xid=0x12345678)
        / DHCP(options=[("message-type", 1), ("hostname", "alice-laptop"), "end"])
    )
    dhcp_discover.time = base_time + 0.05
    packets.append(dhcp_discover)

    dhcp_offer = (
        Ether(src="c0:ff:ee:00:11:22", dst="00:1a:2b:3c:4d:5e")
        / IP(src="192.168.1.1", dst="192.168.1.50")
        / UDP(sport=67, dport=68)
        / BOOTP(chaddr="00:1a:2b:3c:4d:5e", yiaddr="192.168.1.50", siaddr="192.168.1.1", xid=0x12345678)
        / DHCP(options=[
            ("message-type", 2),
            ("router", "192.168.1.1"),
            ("subnet_mask", "255.255.255.0"),
            ("name_server", "8.8.8.8"),
            ("lease_time", 86400),
            "end",
        ])
    )
    dhcp_offer.time = base_time + 0.08
    packets.append(dhcp_offer)

    # 3. ICMP Echo Request & Reply (Ping)
    icmp_req = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
        / IP(src="192.168.1.50", dst="8.8.8.8", ttl=64)
        / ICMP(type=8, code=0, id=0x0001, seq=1)
        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
    )
    icmp_req.time = base_time + 0.12
    packets.append(icmp_req)

    icmp_rep = (
        Ether(src="c0:ff:ee:00:11:22", dst="00:1a:2b:3c:4d:5e")
        / IP(src="8.8.8.8", dst="192.168.1.50", ttl=118)
        / ICMP(type=0, code=0, id=0x0001, seq=1)
        / Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
    )
    icmp_rep.time = base_time + 0.15
    packets.append(icmp_rep)

    # 4. DNS Query & Response
    dns_query = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
        / IP(src="192.168.1.50", dst="8.8.8.8")
        / UDP(sport=54321, dport=53)
        / DNS(id=0xCAFE, rd=1, qd=DNSQR(qname="example.com", qtype="A"))
    )
    dns_query.time = base_time + 0.20
    packets.append(dns_query)

    dns_resp = (
        Ether(src="c0:ff:ee:00:11:22", dst="00:1a:2b:3c:4d:5e")
        / IP(src="8.8.8.8", dst="192.168.1.50")
        / UDP(sport=53, dport=54321)
        / DNS(
            id=0xCAFE,
            qr=1,
            aa=0,
            rcode=0,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300),
        )
    )
    dns_resp.time = base_time + 0.24
    packets.append(dns_resp)

    # 5. TCP 3-Way Handshake (192.168.1.50 -> 93.184.216.34:80)
    syn = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
        / IP(src="192.168.1.50", dst="93.184.216.34", flags="DF")
        / TCP(sport=51234, dport=80, seq=1000, ack=0, flags="S", window=64240)
    )
    syn.time = base_time + 0.30
    packets.append(syn)

    syn_ack = (
        Ether(src="c0:ff:ee:00:11:22", dst="00:1a:2b:3c:4d:5e")
        / IP(src="93.184.216.34", dst="192.168.1.50")
        / TCP(sport=80, dport=51234, seq=5000, ack=1001, flags="SA", window=65535)
    )
    syn_ack.time = base_time + 0.34
    packets.append(syn_ack)

    ack = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
        / IP(src="192.168.1.50", dst="93.184.216.34", flags="DF")
        / TCP(sport=51234, dport=80, seq=1001, ack=5001, flags="A", window=64240)
    )
    ack.time = base_time + 0.35
    packets.append(ack)

    # 6. HTTP Request & Response (with privacy demonstration)
    http_req_data = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        b"Accept: text/html\r\n"
        b"Cookie: session_id=SECRET123; user=alice\r\n"
        b"Authorization: Bearer SECRET_ACCESS_TOKEN_456\r\n\r\n"
    )
    http_req = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
        / IP(src="192.168.1.50", dst="93.184.216.34", flags="DF")
        / TCP(sport=51234, dport=80, seq=1001, ack=5001, flags="PA", window=64240)
        / Raw(load=http_req_data)
    )
    http_req.time = base_time + 0.38
    packets.append(http_req)

    http_resp_data = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=UTF-8\r\n"
        b"Server: ECS (dcb/7F83)\r\n"
        b"Content-Length: 48\r\n\r\n"
        b"<!doctype html><html><body>Hello</body></html>\r\n"
    )
    http_resp = (
        Ether(src="c0:ff:ee:00:11:22", dst="00:1a:2b:3c:4d:5e")
        / IP(src="93.184.216.34", dst="192.168.1.50")
        / TCP(sport=80, dport=51234, seq=5001, ack=1001 + len(http_req_data), flags="PA", window=65535)
        / Raw(load=http_resp_data)
    )
    http_resp.time = base_time + 0.45
    packets.append(http_resp)

    # 7. TCP Teardown
    fin_ack = (
        Ether(src="00:1a:2b:3c:4d:5e", dst="c0:ff:ee:00:11:22")
        / IP(src="192.168.1.50", dst="93.184.216.34")
        / TCP(sport=51234, dport=80, seq=1001 + len(http_req_data), ack=5001 + len(http_resp_data), flags="FA")
    )
    fin_ack.time = base_time + 0.50
    packets.append(fin_ack)

    # 8. Simulated Port Scan (Security Anomaly: 12 rapid TCP SYN probes)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]
    for i, port in enumerate(scan_ports):
        scan_pkt = (
            Ether(src="de:ad:be:ef:00:01", dst="c0:ff:ee:00:11:22")
            / IP(src="10.0.0.99", dst="192.168.1.50")
            / TCP(sport=40000 + i, dport=port, seq=100 + i, flags="S")
        )
        scan_pkt.time = base_time + 0.60 + (i * 0.05)
        packets.append(scan_pkt)

    # 9. Simulated ARP Poisoning / Spoofing Anomaly
    # Attacker MAC claims existing Gateway IP 192.168.1.1
    spoof_arp = Ether(src="aa:bb:cc:dd:ee:ff", dst="00:1a:2b:3c:4d:5e") / ARP(
        op=2,
        hwsrc="aa:bb:cc:dd:ee:ff",  # Rogue MAC claiming 192.168.1.1
        psrc="192.168.1.1",
        hwdst="00:1a:2b:3c:4d:5e",
        pdst="192.168.1.50",
    )
    spoof_arp.time = base_time + 1.50
    packets.append(spoof_arp)

    wrpcap(output_file, packets)
    print(f"[+] Successfully generated {len(packets)} test packets into {output_file}!")


if __name__ == "__main__":
    generate_sample_pcap()
