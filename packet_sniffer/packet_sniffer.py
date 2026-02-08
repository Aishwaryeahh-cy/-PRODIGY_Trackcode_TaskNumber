import sys
import argparse
import logging
from datetime import datetime
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    from scapy.arch import get_if_list
except ImportError:
    print("Error: Scapy is not installed. Please install it using 'pip install scapy'.")
    sys.exit(1)

# --- Ethical Disclaimer ---
DISCLAIMER = """
==================================================
          NETWORK PACKET ANALYZER
==================================================
[!] ETHICAL USE ONLY:
This tool is designed for educational purposes and 
authorized security testing only. 
Unauthorized monitoring of network traffic is illegal
and unethical. Please use this tool responsibly.
==================================================
"""

class PacketAnalyzer:
    """
    A class to capture, analyze, and log network packets.
    """

    def __init__(self, interface=None, log_file=None, count=0):
        """
        Initialize the analyzer.
        :param interface: Network interface to sniff on.
        :param log_file: Path to the log file.
        :param count: Number of packets to capture (0 for infinite).
        """
        self.interface = interface
        self.log_file = log_file
        self.count = count
        self.packet_count = 0

        # Configure logging if requested
        if self.log_file:
            import os
            # Ensure the path is absolute and directory exists
            self.log_file = os.path.abspath(self.log_file)
            log_dir = os.path.dirname(self.log_file)
            if not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir)
                except Exception as e:
                    print(f"Error: Could not create directory for log file: {e}")
                    sys.exit(1)

            try:
                logging.basicConfig(
                    filename=self.log_file,
                    level=logging.INFO,
                    format='%(message)s'
                )
            except Exception as e:
                print(f"Error: Could not initialize log file: {e}")
                sys.exit(1)

    def process_packet(self, packet):
        """
        Callback function to process each captured packet.
        """
        if not packet.haslayer(IP):
            return

        self.packet_count += 1
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        length = len(packet)

        # Identify protocol name
        protocol = "Other"
        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
        else:
            # Fallback to protocol number if not one of the majors
            protocol = f"PROTO-{proto_num}"

        # Extract payload data
        payload = "None"
        if packet.haslayer(Raw):
            # Show a snippet of raw data, hex-encoded or string
            payload = packet[Raw].load.decode(errors='replace')[:100]
            if len(packet[Raw].load) > 100:
                payload += "..."

        # Format output
        output = f"""==================================================
Packet Captured (ID: {self.packet_count})
==================================================
Timestamp:      {timestamp}
Source IP:      {src_ip}
Destination IP: {dst_ip}
Protocol:       {protocol}
Packet Length:  {length} bytes
Payload:        {payload}
=================================================="""

        # Display to console
        print(output)

        # Log to file if configured
        if self.log_file:
            logging.info(output)

    def start(self, filter_str=""):
        """
        Start sniffing packets.
        :param filter_str: BPF filter string (e.g., 'tcp', 'udp', 'icmp').
        """
        print(f"[*] Starting capture on interface: {self.interface or 'Default'}")
        if filter_str:
            print(f"[*] Filter applied: {filter_str}")
        print("[*] Press Ctrl+C to stop.")

        try:
            # Note: sniff() requires administrator/root privileges
            sniff(
                iface=self.interface,
                filter=filter_str,
                prn=self.process_packet,
                count=self.count,
                store=0  # Don't store packets in memory to avoid memory leaks
            )
        except PermissionError:
            print("\n[!] ERROR: Permission Denied.")
            print("[!] Please run this script with administrative/root privileges.")
            sys.exit(1)
        except Exception as e:
            print(f"\n[!] ERROR: An unexpected error occurred: {e}")
            sys.exit(1)

def main():
    # Print disclaimer first
    print(DISCLAIMER)

    parser = argparse.ArgumentParser(description="Python Network Packet Analyzer (Scapy Based)")
    
    # Filtering options
    parser.add_argument("--tcp", action="store_true", help="Filter for TCP packets")
    parser.add_argument("--udp", action="store_true", help="Filter for UDP packets")
    parser.add_argument("--icmp", action="store_true", help="Filter for ICMP packets")
    
    # Capture settings
    parser.add_argument("--interface", type=str, help="Network interface to use (e.g., eth0, wlan0)")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture (default: unlimited)")
    parser.add_argument("--log", type=str, help="Save output to a log file")
    
    # Utility
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces and exit")

    args = parser.parse_args()

    # List interfaces if requested
    if args.list_interfaces:
        print("[*] Available Interfaces:")
        interfaces = get_if_list()
        for i, iface in enumerate(interfaces):
            print(f" {i+1}. {iface}")
        return

    # Construct BPF filter string
    filters = []
    if args.tcp: filters.append("tcp")
    if args.udp: filters.append("udp")
    if args.icmp: filters.append("icmp")
    
    filter_str = " or ".join(filters)

    # Initialize and start analyzer
    analyzer = PacketAnalyzer(
        interface=args.interface,
        log_file=args.log,
        count=args.count
    )

    try:
        analyzer.start(filter_str=filter_str)
    except KeyboardInterrupt:
        print("\n\n[*] Capture stopped by user. Exiting...")
        print(f"[*] Total packets captured: {analyzer.packet_count}")
        sys.exit(0)

if __name__ == "__main__":
    main()
