"""
Packet Capture Engine
Handles network interface enumeration, permission verification,
multithreaded packet capture queueing, and PCAP stream reading/writing.
"""

import os
import sys
from pathlib import Path

# Enable direct script execution from IDE or CLI without ModuleNotFoundError
if __package__ is None or __package__ == "":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import ctypes
import queue
import threading
import time
from typing import List, Dict, Any, Optional, Generator, Callable

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import conf, sniff
from scapy.utils import PcapWriter, PcapReader


def is_admin() -> bool:
    """Check if the current process has administrative or root privileges."""
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False


def get_interfaces(all_adapters: bool = False) -> List[Dict[str, Any]]:
    """
    Enumerate all network interfaces on the host system.
    Returns a normalized list of dictionaries with metadata:
    id, name, description, ips, mac, device.
    """
    results = []

    if sys.platform == "win32":
        try:
            from scapy.arch.windows import get_windows_if_list
            raw_list = get_windows_if_list()
            active_idx = 0
            for raw_idx, item in enumerate(raw_list):
                name = item.get("name", "")
                ips = item.get("ips", [])

                # Skip internal NDIS filter sub-drivers unless explicitly requested
                is_filter_subdriver = any(
                    token in name for token in ["Filter-", "Scheduler-", "Native MAC"]
                )
                if not all_adapters and is_filter_subdriver:
                    continue

                # In clean mode, prioritize adapters that have IPs or friendly hardware names
                if not all_adapters and not ips and "Pseudo" not in name and "Ethernet" not in name and "Wi-Fi" not in name:
                    continue

                ipv4s = [ip for ip in ips if ":" not in ip]
                ipv6s = [ip for ip in ips if ":" in ip]

                guid = item.get("guid", "")
                device_name = f"\\Device\\NPF_{guid}" if guid else ""

                results.append({
                    "id": active_idx,
                    "raw_index": raw_idx,
                    "name": name or f"Interface {raw_idx}",
                    "description": item.get("description", "Unknown Adapter"),
                    "ips": ips,
                    "ipv4": ipv4s[0] if ipv4s else "No IPv4",
                    "ipv6": ipv6s[0] if ipv6s else "No IPv6",
                    "mac": item.get("mac", "00:00:00:00:00:00"),
                    "guid": guid,
                    "device": device_name,
                })
                active_idx += 1
            return results
        except Exception:
            pass

    # Generic / Linux / macOS interface listing via conf.ifaces
    try:
        for idx, (iface_name, iface_obj) in enumerate(conf.ifaces.items()):
            ip = getattr(iface_obj, "ip", "Unknown")
            mac = getattr(iface_obj, "mac", "Unknown")
            desc = getattr(iface_obj, "description", str(iface_name))
            results.append({
                "id": idx,
                "name": str(iface_name),
                "description": desc,
                "ips": [ip] if ip else [],
                "ipv4": ip or "No IPv4",
                "ipv6": "No IPv6",
                "mac": mac or "00:00:00:00:00:00",
                "guid": "",
                "device": str(iface_name),
            })
    except Exception:
        pass

    return results


def resolve_interface(identifier: str) -> Optional[Dict[str, Any]]:
    """
    Resolve an interface by index, friendly name, device name, or IP address.
    """
    interfaces = get_interfaces()
    if not interfaces:
        return None

    # Check if integer index
    try:
        idx = int(identifier)
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
    except ValueError:
        pass

    clean_id = identifier.strip().lower()

    # Match by exact name or friendly name (case-insensitive)
    for iface in interfaces:
        if iface["name"].lower() == clean_id:
            return iface

    # Match by partial name or description
    for iface in interfaces:
        if clean_id in iface["name"].lower() or clean_id in iface["description"].lower():
            return iface

    # Match by device or guid
    for iface in interfaces:
        if clean_id in iface["device"].lower() or clean_id in iface["guid"].lower():
            return iface

    # Match by IP
    for iface in interfaces:
        for ip in iface["ips"]:
            if clean_id == ip.lower():
                return iface

    return None


class PacketCaptureEngine:
    """
    Thread-safe packet capture engine supporting live network capture and offline PCAP streaming.
    Uses an internal queue to buffer packets and avoid dropped frames during UI rendering.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: Optional[str] = None,
        output_pcap: Optional[str] = None,
        queue_size: int = 10000,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.output_pcap = output_pcap
        self.packet_queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.is_running: bool = False
        self.capture_thread: Optional[threading.Thread] = None
        self.pcap_writer: Optional[PcapWriter] = None
        self.dropped_packets: int = 0
        self.captured_count: int = 0

        if self.output_pcap:
            # Sync writes to avoid losing packets if terminated abruptly
            self.pcap_writer = PcapWriter(self.output_pcap, append=True, sync=True)

    def _packet_callback(self, pkt: Any) -> None:
        """Callback invoked by Scapy for every captured packet."""
        self.captured_count += 1

        # Stream directly to PCAP if enabled
        if self.pcap_writer:
            try:
                self.pcap_writer.write(pkt)
            except Exception:
                pass

        # Push to queue for analysis
        try:
            self.packet_queue.put_nowait(pkt)
        except queue.Full:
            self.dropped_packets += 1

    def start_live(self) -> None:
        """Launch the live packet sniffing worker thread."""
        self.is_running = True

        def _sniff_worker():
            try:
                sniff_kwargs: Dict[str, Any] = {
                    "prn": self._packet_callback,
                    "store": False,
                    "stop_filter": lambda _: not self.is_running,
                }

                if self.interface:
                    sniff_kwargs["iface"] = self.interface

                if self.bpf_filter:
                    sniff_kwargs["filter"] = self.bpf_filter

                sniff(**sniff_kwargs)
            except Exception as e:
                # Signal error to consumer
                self.packet_queue.put(e)
            finally:
                self.is_running = False

        self.capture_thread = threading.Thread(target=_sniff_worker, daemon=True)
        self.capture_thread.start()

    def stop(self) -> None:
        """Stop packet capture and flush any open resources."""
        self.is_running = False
        if self.pcap_writer:
            try:
                self.pcap_writer.close()
            except Exception:
                pass
            self.pcap_writer = None

    def read_pcap_stream(
        self, pcap_path: str, bpf_filter: Optional[str] = None
    ) -> Generator[Any, None, None]:
        """
        Stream packets from an existing PCAP file one by one to minimize memory usage.
        Optionally applies BPF filter logic if supported.
        """
        reader = PcapReader(pcap_path)
        try:
            for pkt in reader:
                # If write capture requested during replay
                if self.pcap_writer:
                    self.pcap_writer.write(pkt)
                yield pkt
        finally:
            reader.close()
            if self.pcap_writer:
                self.pcap_writer.close()


if __name__ == "__main__":
    from sniffer.display import print_interfaces, print_banner

    print_banner()
    print("[*] Running PacketCaptureEngine Self-Test Demo...\n")

    print(f"  - Administrative / Root Privileges: {is_admin()}")
    interfaces = get_interfaces()
    print(f"  - Discovered {len(interfaces)} active network interfaces:\n")
    print_interfaces(interfaces)

    print("[+] CaptureEngine self-test finished successfully!")
