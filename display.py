"""
Terminal Display & Visualization Module
Provides colored, formatted terminal output using Rich:
- Protocol badges & colorized packet stream
- Verbose deep header dissection
- IDS Alert callout boxes
- Live statistics summary dashboards
"""

import sys
from pathlib import Path

# Enable direct script execution from IDE or CLI without ModuleNotFoundError
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from typing import List, Dict, Any, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

from sniffer.parser import ParsedPacket
from sniffer.stats import PacketStats
from sniffer.detector import Alert

# Ensure UTF-8 output across all platforms and Windows code pages
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console = Console(safe_box=True)

# Theme colors for network protocols
PROTO_COLORS = {
    "TCP": "cyan",
    "UDP": "bright_blue",
    "ICMP": "magenta",
    "ARP": "yellow",
    "DNS": "green",
    "HTTP": "bright_cyan",
    "DHCP": "bright_magenta",
    "IPv4": "white",
    "IPv6": "bright_white",
    "Ethernet": "dim white",
}


def print_banner() -> None:
    """Print application banner and authorized usage warning."""
    banner_text = Text()
    banner_text.append("+---------------------------------------------------------------+\n", style="bold cyan")
    banner_text.append("|           NETWORK PACKET SNIFFER & ANALYZER                   |\n", style="bold cyan")
    banner_text.append("|           Educational & Authorized Network Inspection         |\n", style="bold white")
    banner_text.append("+---------------------------------------------------------------+\n", style="bold cyan")
    banner_text.append(" [!] NOTICE: Use strictly on authorized networks and owned lab environments.\n", style="bold yellow")
    console.print(banner_text)


def print_interfaces(interfaces: List[Dict[str, Any]]) -> None:
    """Print an aesthetic table of selectable network interfaces."""
    table = Table(
        title="Available Network Interfaces",
        show_header=True,
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("ID", style="bold cyan", justify="right", width=4)
    table.add_column("Interface Name", style="bold white", min_width=18)
    table.add_column("IPv4 Address", style="green", min_width=16)
    table.add_column("MAC Address", style="dim", min_width=18)
    table.add_column("Description", style="dim white")

    for iface in interfaces:
        table.add_row(
            str(iface["id"]),
            str(iface["name"]),
            str(iface["ipv4"]),
            str(iface["mac"]),
            str(iface["description"]),
        )

    console.print(table)
    console.print("[dim]Select an interface with: [bold cyan]python main.py -i <ID or Name>[/bold cyan][/dim]\n")


def print_packet_line(pkt: ParsedPacket) -> None:
    """Print a single concise, color-coded line representing a captured packet."""
    proto = pkt.highest_layer
    color = PROTO_COLORS.get(proto, "white")

    # Format endpoints
    src_str = pkt.src_display
    dst_str = pkt.dst_display

    # TCP flag tag if present
    flags_badge = ""
    if pkt.transport and pkt.transport.flags_str:
        flags_badge = f" {pkt.transport.flags_str}"

    line = Text()
    line.append(f"{pkt.packet_num:5d} ", style="dim")
    line.append(f"{pkt.time_str} ", style="dim cyan")
    line.append(f"[{proto:^6}] ", style=f"bold {color}")
    line.append(f"{src_str:21} -> {dst_str:21} ", style="white")
    line.append(f"{flags_badge:16} ", style="yellow" if flags_badge else "")
    line.append(f"{pkt.length:4d}B ", style="dim")
    line.append(f"{pkt.summary}", style=color)

    console.print(line)


def print_packet_detail(pkt: ParsedPacket, show_payload: bool = False) -> None:
    """Print deep header dissection tree for a packet."""
    tree = Tree(f"[bold white]Packet #{pkt.packet_num}[/bold white] at {pkt.time_str} ({pkt.length} bytes)")

    # Layer 2: Ethernet
    if pkt.ethernet:
        eth_node = tree.add("[bold yellow]Ethernet II (Layer 2)[/bold yellow]")
        eth_node.add(f"Source MAC: [cyan]{pkt.ethernet.src_mac}[/cyan]")
        eth_node.add(f"Destination MAC: [cyan]{pkt.ethernet.dst_mac}[/cyan]")
        eth_node.add(f"EtherType: [cyan]{pkt.ethernet.type_name} (0x{pkt.ethernet.type_code:04x})[/cyan]")

    # Layer 2/3: ARP
    if pkt.arp:
        arp_node = tree.add("[bold yellow]ARP (Address Resolution Protocol)[/bold yellow]")
        arp_node.add(f"Opcode: [cyan]{pkt.arp.op_name} ({pkt.arp.op_code})[/cyan]")
        arp_node.add(f"Sender MAC: [cyan]{pkt.arp.src_mac}[/cyan] | Sender IP: [cyan]{pkt.arp.src_ip}[/cyan]")
        arp_node.add(f"Target MAC: [cyan]{pkt.arp.dst_mac}[/cyan] | Target IP: [cyan]{pkt.arp.dst_ip}[/cyan]")

    # Layer 3: IPv4 / IPv6
    if pkt.ip:
        ip_name = f"IPv{pkt.ip.version}"
        ip_node = tree.add(f"[bold blue]{ip_name} (Layer 3)[/bold blue]")
        ip_node.add(f"Source IP: [green]{pkt.ip.src_ip}[/green]")
        ip_node.add(f"Destination IP: [green]{pkt.ip.dst_ip}[/green]")
        ip_node.add(f"Protocol: [cyan]{pkt.ip.protocol_name} ({pkt.ip.protocol_num})[/cyan]")
        ip_node.add(f"TTL/Hop Limit: [cyan]{pkt.ip.ttl_or_hop_limit}[/cyan]")
        if pkt.ip.version == 4:
            ip_node.add(f"Flags: [cyan]{pkt.ip.flags}[/cyan] | Checksum: [dim]0x{pkt.ip.chksum or 0:04x}[/dim]")

    # Layer 4: Transport
    if pkt.transport:
        proto = pkt.transport.protocol
        t_node = tree.add(f"[bold cyan]{proto} (Layer 4)[/bold cyan]")
        if pkt.transport.src_port:
            t_node.add(f"Source Port: [green]{pkt.transport.src_port}[/green]")
            t_node.add(f"Destination Port: [green]{pkt.transport.dst_port}[/green]")

        if proto == "TCP":
            t_node.add(f"Flags: [bold yellow]{pkt.transport.flags_str}[/bold yellow]")
            t_node.add(f"Sequence: [cyan]{pkt.transport.seq}[/cyan] | Ack: [cyan]{pkt.transport.ack}[/cyan]")
            t_node.add(f"Window Size: [cyan]{pkt.transport.window}[/cyan]")

        elif proto == "ICMP":
            t_node.add(f"Type: [yellow]{pkt.transport.icmp_type_name} ({pkt.transport.icmp_type})[/yellow]")
            t_node.add(f"Code: [cyan]{pkt.transport.icmp_code}[/cyan]")

    # Layer 7: Application
    if pkt.app:
        app_proto = pkt.app.get("protocol", "App")
        app_node = tree.add(f"[bold green]{app_proto} (Layer 7)[/bold green]")
        if app_proto == "DNS":
            app_node.add(f"Query ID: [cyan]0x{pkt.app.get('id', 0):04x}[/cyan]")
            for q in pkt.app.get("questions", []):
                app_node.add(f"Question: [bold]{q['name']}[/bold] ({q['type']})")
            for a in pkt.app.get("answers", []):
                app_node.add(f"Answer: [cyan]{a['name']}[/cyan] -> [green]{a['data']}[/green] (TTL: {a['ttl']})")

        elif app_proto == "HTTP":
            app_node.add(f"Start-Line: [bold white]{pkt.app.get('first_line')}[/bold white]")
            hdr_node = app_node.add("Headers (Privacy Filtered)")
            for k, v in pkt.app.get("headers", {}).items():
                hdr_node.add(f"[dim]{k}:[/dim] [yellow]{v}[/yellow]")
            if pkt.app.get("payload_notice"):
                app_node.add(f"[dim]{pkt.app.get('payload_notice')}[/dim]")
            if show_payload and pkt.app.get("payload_preview"):
                app_node.add(f"Payload Preview:\n[dim]{pkt.app.get('payload_preview')}[/dim]")

        elif app_proto == "DHCP":
            app_node.add(f"Message Type: [bold magenta]{pkt.app.get('message_type')}[/bold magenta]")
            app_node.add(f"Offered IP: [green]{pkt.app.get('your_ip')}[/green]")
            app_node.add(f"Router: [cyan]{pkt.app.get('router')}[/cyan]")
            app_node.add(f"Subnet Mask: [cyan]{pkt.app.get('subnet_mask')}[/cyan]")

    console.print(tree)
    console.print()


def print_alert(alert: Alert) -> None:
    """Print an intrusion detection alert in a highlighted panel."""
    sev_colors = {
        "LOW": "blue",
        "MEDIUM": "yellow",
        "HIGH": "bold red",
        "CRITICAL": "bold white on red",
    }
    color = sev_colors.get(alert.severity, "red")

    panel_content = Text()
    panel_content.append(f"ALERT: {alert.alert_type}\n", style=f"bold {color}")
    panel_content.append(f"Severity: {alert.severity}  |  Time: {alert.time_str}\n", style="bold")
    panel_content.append(f"Source: {alert.src}  -->  Destination: {alert.dst}\n", style="white")
    panel_content.append(f"Detail: {alert.message}\n", style="dim")

    console.print(Panel(panel_content, title="[bold red]! SECURITY ANOMALY DETECTED ![/bold red]", border_style="red"))


def print_statistics_dashboard(stats: PacketStats) -> None:
    """Render comprehensive live summary statistics dashboard."""
    console.print("\n" + "=" * 70, style="dim cyan")
    console.print("               TRAFFIC SUMMARY & NETWORK STATISTICS               ", style="bold cyan")
    console.print("=" * 70, style="dim cyan")

    # Metrics Table
    m_table = Table(title="Throughput & Volume", show_header=True, header_style="bold green")
    m_table.add_column("Total Packets", justify="center")
    m_table.add_column("Total Bytes", justify="center")
    m_table.add_column("Elapsed Time", justify="center")
    m_table.add_column("Packet Rate", justify="center")
    m_table.add_column("Avg Bandwidth", justify="center")

    m_table.add_row(
        str(stats.total_packets),
        stats.formatted_bytes,
        f"{stats.elapsed_seconds:.1f}s",
        f"{stats.average_packet_rate:.1f} pkts/s",
        f"{stats.average_bandwidth_kbps:.2f} Kbps",
    )
    console.print(m_table)

    # Protocols Table
    p_table = Table(title="Protocol Distribution", show_header=True, header_style="bold magenta")
    p_table.add_column("Protocol", style="bold white")
    p_table.add_column("Packets", justify="right")
    p_table.add_column("Percentage", justify="right")

    total = max(1, stats.total_packets)
    for proto, count in stats.protocol_counts.most_common():
        pct = (count / total) * 100
        color = PROTO_COLORS.get(proto, "white")
        p_table.add_row(f"[{color}]{proto}[/{color}]", str(count), f"{pct:5.1f}%")

    console.print(p_table)

    # Top Talkers
    t_table = Table(title="Top Talkers (Source IPs)", show_header=True, header_style="bold yellow")
    t_table.add_column("Source IP", style="bold cyan")
    t_table.add_column("Packets", justify="right")
    t_table.add_column("Bytes", justify="right")

    for ip, pkts, b in stats.get_top_src_ips(5):
        t_table.add_row(ip, str(pkts), f"{b:,} B")
    console.print(t_table)

    # Top Conversations
    c_table = Table(title="Top Conversations", show_header=True, header_style="bold blue")
    c_table.add_column("Flow (Source -> Destination)", style="bold white")
    c_table.add_column("Packets", justify="right")
    c_table.add_column("Bytes", justify="right")

    for conv, pkts, b in stats.get_top_conversations(5):
        c_table.add_row(conv, str(pkts), f"{b:,} B")
    console.print(c_table)


if __name__ == "__main__":
    from scapy.all import Ether, IP, TCP
    from sniffer.parser import parse_packet
    from sniffer.stats import PacketStats

    print_banner()
    print("[*] Running Terminal Display Self-Test Demo...\n")

    # Sample packet row
    pkt = parse_packet(Ether() / IP(src="192.168.1.50", dst="93.184.216.34") / TCP(sport=51234, dport=80, flags="SA"))
    print_packet_line(pkt)
    print()

    # Sample packet detail tree
    print_packet_detail(pkt)

    print("\n[+] Display self-test finished successfully!")
