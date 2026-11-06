#!/usr/bin/env python3
"""
Network Packet Sniffer & Protocol Analyzer (CLI Entrypoint)
===========================================================
Notice: For educational purposes and authorized network analysis only.
"""

import argparse
import os
import signal
import sys
import time
from typing import Optional

# Mute noisy Scapy warnings on startup
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import warnings
warnings.filterwarnings("ignore")

from sniffer.capture import (
    is_admin,
    get_interfaces,
    resolve_interface,
    PacketCaptureEngine,
)
from sniffer.parser import parse_packet, ParsedPacket
from sniffer.decoders import enrich_with_application_layer
from sniffer.stats import PacketStats
from sniffer.detector import TrafficDetector
from sniffer.display import (
    console,
    print_banner,
    print_interfaces,
    print_packet_line,
    print_packet_detail,
    print_alert,
    print_statistics_dashboard,
)
from sniffer.exporter import PacketExporter


def passes_filters(
    pkt: ParsedPacket,
    protocol_filter: Optional[str] = None,
    ip_filter: Optional[str] = None,
    port_filter: Optional[int] = None,
) -> bool:
    """Evaluate application-level filter criteria."""
    if protocol_filter:
        p_filter = protocol_filter.upper()
        # Check against highest_layer or transport protocol
        transport_proto = pkt.transport.protocol.upper() if pkt.transport else ""
        if p_filter != pkt.highest_layer.upper() and p_filter != transport_proto:
            return False

    if ip_filter:
        src = pkt.ip.src_ip if pkt.ip else (pkt.arp.src_ip if pkt.arp else "")
        dst = pkt.ip.dst_ip if pkt.ip else (pkt.arp.dst_ip if pkt.arp else "")
        if ip_filter not in (src, dst):
            return False

    if port_filter:
        if not pkt.transport or (
            pkt.transport.src_port != port_filter and pkt.transport.dst_port != port_filter
        ):
            return False

    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Network Packet Sniffer & Protocol Analyzer (Authorized Use Only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. List available network interfaces
  python main.py -l

  # 2. Live capture on interface 0 (requires Admin/root + Npcap on Windows)
  python main.py -i 0

  # 3. Capture with BPF filter and write to PCAP
  python main.py -i "Wi-Fi" -f "tcp port 80 or udp port 53" -w session.pcap

  # 4. Read and inspect existing PCAP file (no admin/Npcap required)
  python main.py -r sample_traffic.pcap -v

  # 5. Filter for DNS queries and export results to JSON & CSV
  python main.py -r sample_traffic.pcap --proto dns --export-json dns_analysis.json --export-csv log.csv
        """,
    )

    # Operational modes
    parser.add_argument("-l", "--list", action="store_true", help="List available network interfaces and exit")
    parser.add_argument("--all-ifaces", action="store_true", help="Include virtual filter drivers when listing interfaces")
    parser.add_argument("-i", "--interface", type=str, help="Network interface ID, name, or GUID to capture from")
    parser.add_argument("-r", "--read", type=str, help="Read and analyze an existing .pcap file")
    parser.add_argument("-w", "--write", type=str, help="Save captured packets in real-time to .pcap file")

    # Filters
    parser.add_argument("-f", "--filter", type=str, help="BPF filter syntax (e.g., 'tcp port 80', 'icmp', 'udp')")
    parser.add_argument("--proto", "--protocol", type=str, help="Filter by protocol (tcp, udp, icmp, arp, dns, http, dhcp)")
    parser.add_argument("--ip", type=str, help="Filter by source or destination IP address")
    parser.add_argument("--port", type=int, help="Filter by source or destination port number")
    parser.add_argument("-c", "--count", type=int, default=0, help="Stop after capturing N packets (0 = unlimited)")

    # Output options
    parser.add_argument("-v", "--verbose", action="store_true", help="Display detailed header dissection tree for each packet")
    parser.add_argument("--show-payload", action="store_true", help="Display application payload preview (suppressed by default for privacy)")
    parser.add_argument("--no-alerts", action="store_true", help="Disable suspicious pattern / IDS anomaly alerts")
    parser.add_argument("--export-json", type=str, help="Export session analysis and parsed packets to JSON file")
    parser.add_argument("--export-csv", type=str, help="Export captured packet stream to CSV file")

    args = parser.parse_args()

    print_banner()

    # Handle interface listing
    if args.list:
        interfaces = get_interfaces(all_adapters=args.all_ifaces)
        print_interfaces(interfaces)
        return

    # Check if either live interface or PCAP file was provided
    if not args.interface and not args.read:
        interfaces = get_interfaces(all_adapters=args.all_ifaces)
        console.print("[yellow]No capture target specified.[/yellow]\n")
        print_interfaces(interfaces)
        console.print(
            "[bold green]Quick Start Options:[/bold green]\n"
            "  • To capture live traffic: [cyan]python main.py -i <ID or Name>[/cyan]\n"
            "  • To analyze a PCAP file:  [cyan]python main.py -r <file.pcap>[/cyan]\n"
            "  • To generate test data:   [cyan]python tests/generate_sample.py[/cyan]\n"
        )
        return

    # Initialize subsystems
    stats = PacketStats()
    detector = None if args.no_alerts else TrafficDetector()
    exporter = PacketExporter(csv_path=args.export_csv, json_path=args.export_json)

    packet_counter = 0

    # Graceful exit handler
    def handle_shutdown(sig, frame):
        console.print("\n[bold yellow][!] Capture interrupted by user. Finalizing...[/bold yellow]")
        print_statistics_dashboard(stats)
        exporter.finalize(stats)
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_shutdown)

    # =========================================================================
    # MODE 1: OFFLINE PCAP FILE ANALYSIS
    # =========================================================================
    if args.read:
        if not os.path.isfile(args.read):
            console.print(f"[bold red][!] PCAP file not found: {args.read}[/bold red]")
            return

        console.print(f"[*] Reading and analyzing PCAP file: [bold cyan]{args.read}[/bold cyan]...\n")
        engine = PacketCaptureEngine(output_pcap=args.write)

        try:
            for raw_pkt in engine.read_pcap_stream(args.read, bpf_filter=args.filter):
                packet_counter += 1
                parsed = parse_packet(raw_pkt, packet_num=packet_counter)
                enrich_with_application_layer(parsed, show_payload=args.show_payload)

                # Filter checks
                if not passes_filters(parsed, args.proto, args.ip, args.port):
                    continue

                stats.update(parsed)
                exporter.record_packet(parsed)

                # IDS Anomaly check
                if detector:
                    alerts = detector.analyze(parsed)
                    for alert in alerts:
                        print_alert(alert)

                # Terminal Display
                if args.verbose:
                    print_packet_detail(parsed, show_payload=args.show_payload)
                else:
                    print_packet_line(parsed)

                if args.count > 0 and packet_counter >= args.count:
                    console.print(f"\n[green][*] Reached target count of {args.count} packets.[/green]")
                    break

        except KeyboardInterrupt:
            pass
        except Exception as e:
            console.print(f"[bold red][!] Error processing PCAP: {e}[/bold red]")
        finally:
            print_statistics_dashboard(stats)
            exporter.finalize(stats)
            if args.write:
                console.print(f"[green][+] Saved capture to {args.write}[/green]")
            if args.export_json:
                console.print(f"[green][+] Exported analysis to {args.export_json}[/green]")
            if args.export_csv:
                console.print(f"[green][+] Exported CSV to {args.export_csv}[/green]")
        return

    # =========================================================================
    # MODE 2: LIVE NETWORK CAPTURE
    # =========================================================================
    resolved = resolve_interface(args.interface)
    if not resolved:
        console.print(f"[bold red][!] Interface '{args.interface}' not found.[/bold red]")
        print_interfaces(get_interfaces())
        return

    # Permission and driver checks
    admin_status = is_admin()
    if not admin_status:
        console.print(
            "[bold yellow][!] WARNING: Packet capture requires Administrative / Root privileges.[/bold yellow]\n"
            "    On Windows: Run PowerShell or Command Prompt as Administrator.\n"
            "    On Linux/macOS: Run with 'sudo python main.py ...'\n"
        )

    target_device = resolved.get("device") or resolved.get("name")
    console.print(f"[*] Binding to interface: [bold green]{resolved['name']}[/bold green] ({resolved['description']})")
    console.print(f"[*] IP: {resolved['ipv4']} | MAC: {resolved['mac']}")
    if args.filter:
        console.print(f"[*] BPF Filter: [cyan]{args.filter}[/cyan]")
    if args.write:
        console.print(f"[*] Saving packets in real-time to: [cyan]{args.write}[/cyan]")
    console.print("[dim]Press Ctrl+C at any time to stop capture and display summary metrics.\n[/dim]")

    engine = PacketCaptureEngine(
        interface=target_device,
        bpf_filter=args.filter,
        output_pcap=args.write,
    )

    try:
        engine.start_live()
    except Exception as e:
        console.print(f"[bold red][!] Failed to start capture engine: {e}[/bold red]")
        return

    # Main packet processing loop
    try:
        while engine.is_running or not engine.packet_queue.empty():
            try:
                item = engine.packet_queue.get(timeout=0.2)
            except Exception:
                continue

            # Check if background thread reported a fatal error
            if isinstance(item, Exception):
                err_msg = str(item)
                if "winpcap is not installed" in err_msg.lower() or "libpcap" in err_msg.lower():
                    console.print(
                        "\n[bold red][!] Npcap / WinPcap driver is missing on Windows.[/bold red]\n\n"
                        "[bold white]How to enable live packet capture on Windows:[/bold white]\n"
                        " 1. Download and install Npcap from: [link=https://npcap.com/]https://npcap.com/[/link]\n"
                        " 2. During installation, check [bold cyan]'Install Npcap in WinPcap API-compatible Mode'[/bold cyan].\n"
                        " 3. Run PowerShell / CMD as Administrator.\n\n"
                        "[bold green]Immediate Testing Alternative (No Npcap required!):[/bold green]\n"
                        " You can generate authentic sample packets and test all features offline:\n"
                        "   [cyan]python tests/generate_sample.py[/cyan]\n"
                        "   [cyan]python main.py -r sample_traffic.pcap -v[/cyan]\n"
                    )
                else:
                    console.print(f"[bold red][!] Capture engine error: {item}[/bold red]")
                break

            packet_counter += 1
            parsed = parse_packet(item, packet_num=packet_counter)
            enrich_with_application_layer(parsed, show_payload=args.show_payload)

            # High-level filters
            if not passes_filters(parsed, args.proto, args.ip, args.port):
                continue

            stats.update(parsed)
            exporter.record_packet(parsed)

            # IDS Anomaly check
            if detector:
                alerts = detector.analyze(parsed)
                for alert in alerts:
                    print_alert(alert)

            # Terminal Display
            if args.verbose:
                print_packet_detail(parsed, show_payload=args.show_payload)
            else:
                print_packet_line(parsed)

            if args.count > 0 and packet_counter >= args.count:
                console.print(f"\n[green][*] Reached target packet count of {args.count}.[/green]")
                break

    except KeyboardInterrupt:
        pass
    finally:
        engine.stop()
        print_statistics_dashboard(stats)
        exporter.finalize(stats)
        if args.write:
            console.print(f"[green][+] Saved capture to {args.write}[/green]")
        if args.export_json:
            console.print(f"[green][+] Exported analysis to {args.export_json}[/green]")
        if args.export_csv:
            console.print(f"[green][+] Exported CSV to {args.export_csv}[/green]")


if __name__ == "__main__":
    main()
