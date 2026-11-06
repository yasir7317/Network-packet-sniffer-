"""
Application-Layer Decoders Module
Parses DNS, HTTP headers, and DHCP/BOOTP traffic.
Enforces privacy guards: Does NOT capture or display credentials, auth tokens,
cookies, or full application payloads by default.
"""

import sys
from pathlib import Path

# Enable direct script execution from IDE or CLI without ModuleNotFoundError
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import Dict, Any, List, Optional
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.packet import Raw

from sniffer.parser import ParsedPacket

# DNS Query Type numbers to names
DNS_QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

# DHCP Message types
DHCP_TYPES = {
    1: "DHCPDISCOVER",
    2: "DHCPOFFER",
    3: "DHCPREQUEST",
    4: "DHCPDECLINE",
    5: "DHCPACK",
    6: "DHCPNAK",
    7: "DHCPRELEASE",
    8: "DHCPINFORM",
}

# Sensitive HTTP headers to redact for privacy
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-auth-token",
    "x-api-key",
    "token",
    "password",
    "secret",
}


def decode_dns(pkt: Any) -> Optional[Dict[str, Any]]:
    """Decode DNS query or response from packet."""
    if DNS not in pkt:
        return None

    dns = pkt[DNS]
    is_response = bool(dns.qr)
    details: Dict[str, Any] = {
        "protocol": "DNS",
        "is_response": is_response,
        "id": int(dns.id),
        "opcode": int(dns.opcode),
        "rcode": int(dns.rcode),
        "questions": [],
        "answers": [],
        "summary": "",
    }

    # Extract questions
    if dns.qd:
        qd_items = dns.qd if hasattr(dns.qd, "__iter__") else [dns.qd]
        for q in qd_items:
            if hasattr(q, "qname") and q.qname:
                qname = q.qname.decode("utf-8", errors="replace").rstrip(".")
                qtype_val = int(q.qtype)
                qtype_name = DNS_QTYPES.get(qtype_val, str(qtype_val))
                details["questions"].append({"name": qname, "type": qtype_name})

    # Extract answers
    if is_response and dns.an:
        an_items = dns.an if hasattr(dns.an, "__iter__") else [dns.an]
        for a in an_items:
            if hasattr(a, "rrname") and a.rrname:
                rr_name = a.rrname.decode("utf-8", errors="replace").rstrip(".")
                rr_type = DNS_QTYPES.get(int(a.type), str(a.type))
                rdata = a.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="replace")
                elif isinstance(rdata, str):
                    rdata = rdata.rstrip(".")
                else:
                    rdata = str(rdata)

                details["answers"].append(
                    {"name": rr_name, "type": rr_type, "ttl": int(a.ttl), "data": rdata}
                )

    # Generate DNS summary
    q_str = details["questions"][0]["name"] if details["questions"] else "query"
    q_type = details["questions"][0]["type"] if details["questions"] else ""
    if is_response:
        ans_str = ", ".join(a["data"] for a in details["answers"][:2]) if details["answers"] else "No answer"
        details["summary"] = f"DNS Resp: {q_str} ({q_type}) -> {ans_str}"
    else:
        details["summary"] = f"DNS Query: {q_str} ({q_type})"

    return details


def decode_http(pkt: Any, show_payload: bool = False) -> Optional[Dict[str, Any]]:
    """
    Decode HTTP request or response headers.
    Enforces privacy by suppressing payloads and redacting authentication / cookies.
    """
    if Raw not in pkt:
        return None

    raw_data: bytes = pkt[Raw].load
    if not raw_data:
        return None

    # Check for HTTP request or response signatures
    methods = [b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH "]
    is_http_req = any(raw_data.startswith(m) for m in methods)
    is_http_resp = raw_data.startswith(b"HTTP/1.0 ") or raw_data.startswith(b"HTTP/1.1 ")

    if not (is_http_req or is_http_resp):
        return None

    # Split header section from body (delimited by \r\n\r\n or \n\n)
    parts = raw_data.split(b"\r\n\r\n", 1)
    if len(parts) == 1:
        parts = raw_data.split(b"\n\n", 1)

    header_bytes = parts[0]
    body_bytes = parts[1] if len(parts) > 1 else b""

    try:
        header_text = header_bytes.decode("iso-8859-1")
    except Exception:
        header_text = header_bytes.decode("utf-8", errors="replace")

    lines = [line.strip("\r") for line in header_text.split("\n") if line.strip("\r")]
    if not lines:
        return None

    start_line = lines[0]
    headers: Dict[str, str] = {}

    for line in lines[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            key_clean = key.strip()
            val_clean = val.strip()

            # PRIVACY GUARD: Redact sensitive credentials/cookie values
            if key_clean.lower() in SENSITIVE_HEADERS:
                headers[key_clean] = "[REDACTED FOR PRIVACY]"
            else:
                headers[key_clean] = val_clean

    details: Dict[str, Any] = {
        "protocol": "HTTP",
        "first_line": start_line,
        "headers": headers,
        "is_request": is_http_req,
        "payload_bytes": len(body_bytes),
        "payload_preview": None,
        "summary": "",
    }

    if is_http_req:
        parts_start = start_line.split(" ", 2)
        method = parts_start[0] if len(parts_start) > 0 else "REQ"
        path = parts_start[1] if len(parts_start) > 1 else "/"
        host = headers.get("Host", "")
        host_str = f" [{host}]" if host else ""
        details["method"] = method
        details["path"] = path
        details["host"] = host
        details["summary"] = f"HTTP {method} {path}{host_str}"
    else:
        parts_start = start_line.split(" ", 2)
        code = parts_start[1] if len(parts_start) > 1 else ""
        reason = parts_start[2] if len(parts_start) > 2 else ""
        details["status_code"] = code
        details["reason"] = reason
        details["summary"] = f"HTTP {code} {reason}"

    # Handle body payload visibility constraint
    if show_payload and body_bytes:
        # Show safe preview if user explicitly requested
        preview_len = min(200, len(body_bytes))
        details["payload_preview"] = body_bytes[:preview_len].decode("utf-8", errors="replace")
    elif body_bytes:
        details["payload_notice"] = f"{len(body_bytes)} bytes body suppressed for privacy"

    return details


def decode_dhcp(pkt: Any) -> Optional[Dict[str, Any]]:
    """Decode DHCP / BOOTP messages."""
    if DHCP not in pkt and BOOTP not in pkt:
        return None

    details: Dict[str, Any] = {
        "protocol": "DHCP",
        "message_type": "Unknown",
        "client_mac": "",
        "client_ip": "0.0.0.0",
        "your_ip": "0.0.0.0",
        "server_ip": "0.0.0.0",
        "router": "",
        "subnet_mask": "",
        "summary": "",
    }

    if BOOTP in pkt:
        bootp = pkt[BOOTP]
        details["client_mac"] = str(bootp.chaddr)
        details["client_ip"] = str(bootp.ciaddr)
        details["your_ip"] = str(bootp.yiaddr)
        details["server_ip"] = str(bootp.siaddr)

    if DHCP in pkt:
        dhcp = pkt[DHCP]
        for opt in dhcp.options:
            if isinstance(opt, tuple):
                opt_name, opt_val = opt[0], opt[1]
                if opt_name == "message-type":
                    if isinstance(opt_val, int):
                        details["message_type"] = DHCP_TYPES.get(opt_val, f"Type-{opt_val}")
                    else:
                        details["message_type"] = f"DHCP{str(opt_val).upper()}"
                elif opt_name == "router":
                    details["router"] = str(opt_val)
                elif opt_name == "subnet_mask":
                    details["subnet_mask"] = str(opt_val)

    msg_type = details["message_type"]
    offered_ip = details["your_ip"]
    if offered_ip and offered_ip != "0.0.0.0":
        details["summary"] = f"DHCP {msg_type} (Offered: {offered_ip})"
    else:
        details["summary"] = f"DHCP {msg_type}"

    return details


def enrich_with_application_layer(parsed: ParsedPacket, show_payload: bool = False) -> None:
    """
    Check for application-layer protocols (DNS, HTTP, DHCP) and enrich the ParsedPacket object.
    Updates parsed.app, parsed.highest_layer, and parsed.summary.
    """
    raw_pkt = parsed.raw_packet
    if raw_pkt is None:
        return

    # Check DNS
    dns_info = decode_dns(raw_pkt)
    if dns_info:
        parsed.app = dns_info
        parsed.highest_layer = "DNS"
        parsed.summary = dns_info["summary"]
        return

    # Check DHCP / BOOTP
    dhcp_info = decode_dhcp(raw_pkt)
    if dhcp_info:
        parsed.app = dhcp_info
        parsed.highest_layer = "DHCP"
        parsed.summary = dhcp_info["summary"]
        return

    # Check HTTP
    http_info = decode_http(raw_pkt, show_payload=show_payload)
    if http_info:
        parsed.app = http_info
        parsed.highest_layer = "HTTP"
        parsed.summary = http_info["summary"]
        return


if __name__ == "__main__":
    from scapy.all import Ether, IP, TCP, UDP
    from sniffer.parser import parse_packet

    print("[*] Running Application Decoders Self-Test Demo...\n")

    # 1. DNS Query Demo
    dns_pkt = (
        Ether()
        / IP(src="192.168.1.50", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(id=0xABCD, rd=1, qd=DNSQR(qname="google.com", qtype="A"))
    )
    p_dns = parse_packet(dns_pkt)
    enrich_with_application_layer(p_dns)
    print("1. DNS Decoder:")
    print(f"   Summary: {p_dns.summary}")
    print(f"   Decoded: {p_dns.app}\n")

    # 2. HTTP Privacy Protection Demo
    http_payload = (
        b"GET /api/user HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Cookie: auth_token=SECRET_JWT_TOKEN\r\n"
        b"Authorization: Bearer SECRET_KEY\r\n\r\n"
        b"sensitive_body_data"
    )
    http_pkt = (
        Ether()
        / IP(src="192.168.1.50", dst="93.184.216.34")
        / TCP(sport=51234, dport=80, flags="PA")
        / Raw(load=http_payload)
    )
    p_http = parse_packet(http_pkt)
    enrich_with_application_layer(p_http, show_payload=False)
    print("2. HTTP Privacy Filter Demo:")
    print(f"   Summary: {p_http.summary}")
    print(f"   Headers: {p_http.app['headers']}")
    print(f"   Payload: {p_http.app.get('payload_notice')}\n")

    print("[+] Decoders self-test finished successfully!")
