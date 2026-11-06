"""
Unit Tests for Packet Sniffer Subsystems
Tests header parsers, application decoders, metrics tracking, and IDS detectors.
"""

import unittest
import time
import logging

# Suppress Scapy runtime logging in tests
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import warnings
warnings.filterwarnings("ignore")

from scapy.all import Ether, ARP, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, DHCP, BOOTP, Raw

from sniffer.parser import parse_packet, parse_tcp_flags
from sniffer.decoders import decode_dns, decode_http, decode_dhcp, enrich_with_application_layer
from sniffer.stats import PacketStats
from sniffer.detector import TrafficDetector


class TestPacketParser(unittest.TestCase):
    """Test Layer 2, 3, and 4 header parsing."""

    def test_ethernet_and_arp_parsing(self):
        pkt = Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff") / ARP(
            op=1,
            hwsrc="00:11:22:33:44:55",
            psrc="192.168.1.100",
            hwdst="00:00:00:00:00:00",
            pdst="192.168.1.1",
        )
        parsed = parse_packet(pkt, packet_num=1)

        self.assertIsNotNone(parsed.ethernet)
        self.assertEqual(parsed.ethernet.src_mac, "00:11:22:33:44:55")
        self.assertEqual(parsed.ethernet.dst_mac, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(parsed.ethernet.type_name, "ARP")

        self.assertIsNotNone(parsed.arp)
        self.assertEqual(parsed.arp.op_code, 1)
        self.assertEqual(parsed.arp.src_ip, "192.168.1.100")
        self.assertEqual(parsed.arp.dst_ip, "192.168.1.1")
        self.assertEqual(parsed.highest_layer, "ARP")

    def test_ipv4_and_tcp_parsing(self):
        pkt = (
            Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff")
            / IP(src="192.168.1.10", dst="93.184.216.34", ttl=64, flags="DF")
            / TCP(sport=54321, dport=443, seq=1000, ack=2000, flags="SA", window=65535)
        )
        parsed = parse_packet(pkt, packet_num=2)

        self.assertIsNotNone(parsed.ip)
        self.assertEqual(parsed.ip.version, 4)
        self.assertEqual(parsed.ip.src_ip, "192.168.1.10")
        self.assertEqual(parsed.ip.dst_ip, "93.184.216.34")
        self.assertEqual(parsed.ip.protocol_name, "TCP")
        self.assertIn("DF", parsed.ip.flags)

        self.assertIsNotNone(parsed.transport)
        self.assertEqual(parsed.transport.protocol, "TCP")
        self.assertEqual(parsed.transport.src_port, 54321)
        self.assertEqual(parsed.transport.dst_port, 443)
        self.assertEqual(parsed.transport.seq, 1000)
        self.assertEqual(parsed.transport.ack, 2000)
        self.assertIn("SYN", parsed.transport.flags)
        self.assertIn("ACK", parsed.transport.flags)
        self.assertIn("SYN, ACK", parsed.transport.flags_str)

    def test_udp_and_icmp_parsing(self):
        # UDP
        udp_pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=6000)
        parsed_udp = parse_packet(udp_pkt)
        self.assertEqual(parsed_udp.highest_layer, "UDP")
        self.assertEqual(parsed_udp.transport.src_port, 5000)
        self.assertEqual(parsed_udp.transport.dst_port, 6000)

        # ICMP
        icmp_pkt = Ether() / IP(src="10.0.0.1", dst="8.8.8.8") / ICMP(type=8, code=0)
        parsed_icmp = parse_packet(icmp_pkt)
        self.assertEqual(parsed_icmp.highest_layer, "ICMP")
        self.assertEqual(parsed_icmp.transport.icmp_type, 8)
        self.assertEqual(parsed_icmp.transport.icmp_type_name, "Echo Request")


class TestApplicationDecoders(unittest.TestCase):
    """Test DNS, HTTP, and DHCP application layer decoding and privacy protection."""

    def test_dns_decoder(self):
        dns_query = (
            Ether()
            / IP(src="192.168.1.5", dst="8.8.8.8")
            / UDP(sport=12345, dport=53)
            / DNS(id=0x1234, rd=1, qd=DNSQR(qname="google.com", qtype="A"))
        )
        parsed = parse_packet(dns_query)
        enrich_with_application_layer(parsed)

        self.assertEqual(parsed.highest_layer, "DNS")
        self.assertIsNotNone(parsed.app)
        self.assertFalse(parsed.app["is_response"])
        self.assertEqual(parsed.app["questions"][0]["name"], "google.com")
        self.assertEqual(parsed.app["questions"][0]["type"], "A")

    def test_http_privacy_redaction(self):
        raw_http = (
            b"GET /admin/dashboard HTTP/1.1\r\n"
            b"Host: internal.corp\r\n"
            b"User-Agent: curl/7.81.0\r\n"
            b"Cookie: session_token=SUPER_SECRET_COOKIE_12345\r\n"
            b"Authorization: Bearer SECRET_JWT_TOKEN\r\n\r\n"
            b"secret_post_body_data_here"
        )
        http_pkt = (
            Ether()
            / IP(src="192.168.1.5", dst="10.0.0.1")
            / TCP(sport=50000, dport=80, flags="PA")
            / Raw(load=raw_http)
        )
        parsed = parse_packet(http_pkt)
        enrich_with_application_layer(parsed, show_payload=False)

        self.assertEqual(parsed.highest_layer, "HTTP")
        headers = parsed.app["headers"]

        # Sensitive headers must be redacted
        self.assertEqual(headers["Cookie"], "[REDACTED FOR PRIVACY]")
        self.assertEqual(headers["Authorization"], "[REDACTED FOR PRIVACY]")
        # Standard diagnostic headers must remain visible
        self.assertEqual(headers["Host"], "internal.corp")
        self.assertEqual(headers["User-Agent"], "curl/7.81.0")
        # Body must NOT be displayed by default
        self.assertIsNone(parsed.app.get("payload_preview"))
        self.assertIn("body suppressed for privacy", parsed.app["payload_notice"])

    def test_dhcp_decoder(self):
        dhcp_pkt = (
            Ether()
            / IP(src="192.168.1.1", dst="192.168.1.100")
            / UDP(sport=67, dport=68)
            / BOOTP(yiaddr="192.168.1.100")
            / DHCP(options=[("message-type", 2), ("router", "192.168.1.1"), "end"])
        )
        parsed = parse_packet(dhcp_pkt)
        enrich_with_application_layer(parsed)

        self.assertEqual(parsed.highest_layer, "DHCP")
        self.assertEqual(parsed.app["message_type"], "DHCPOFFER")
        self.assertEqual(parsed.app["your_ip"], "192.168.1.100")
        self.assertEqual(parsed.app["router"], "192.168.1.1")


class TestStatsAndDetectors(unittest.TestCase):
    """Test statistics tracking and IDS alert triggers."""

    def test_stats_accounting(self):
        stats = PacketStats()
        pkt1 = parse_packet(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=100, dport=80))
        pkt2 = parse_packet(Ether() / IP(src="1.1.1.1", dst="3.3.3.3") / UDP(sport=200, dport=53))

        stats.update(pkt1)
        stats.update(pkt2)

        self.assertEqual(stats.total_packets, 2)
        self.assertEqual(stats.protocol_counts["TCP"], 1)
        self.assertEqual(stats.protocol_counts["UDP"], 1)
        top_talkers = stats.get_top_src_ips()
        self.assertEqual(top_talkers[0][0], "1.1.1.1")
        self.assertEqual(top_talkers[0][1], 2)

    def test_port_scan_detector(self):
        detector = TrafficDetector(port_scan_threshold=5, port_scan_window=2.0)
        alerts = []
        base_t = time.time()

        for port in [21, 22, 23, 80, 443, 8080]:
            pkt = parse_packet(Ether() / IP(src="10.0.0.50", dst="192.168.1.1") / TCP(sport=50000, dport=port, flags="S"))
            pkt.timestamp = base_t
            a = detector.analyze(pkt)
            if a:
                alerts.extend(a)

        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "Port Scan Detected")
        self.assertEqual(alerts[0].src, "10.0.0.50")

    def test_arp_spoof_detector(self):
        detector = TrafficDetector()

        # Legitimate gateway ARP
        legit_arp = parse_packet(Ether() / ARP(op=2, hwsrc="00:11:22:33:44:55", psrc="192.168.1.1", pdst="192.168.1.50"))
        a1 = detector.analyze(legit_arp)
        self.assertEqual(len(a1), 0)

        # Conflicting attacker ARP for same IP
        spoof_arp = parse_packet(Ether() / ARP(op=2, hwsrc="aa:bb:cc:dd:ee:ff", psrc="192.168.1.1", pdst="192.168.1.50"))
        a2 = detector.analyze(spoof_arp)
        self.assertEqual(len(a2), 1)
        self.assertEqual(a2[0].alert_type, "ARP Cache Poisoning / Spoofing")
        self.assertEqual(a2[0].details["original_mac"], "00:11:22:33:44:55")
        self.assertEqual(a2[0].details["conflicting_mac"], "aa:bb:cc:dd:ee:ff")


if __name__ == "__main__":
    unittest.main()
