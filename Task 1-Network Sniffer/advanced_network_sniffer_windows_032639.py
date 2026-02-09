#!/usr/bin/env python3
try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
from datetime import datetime
import sys
import signal
import os
import ctypes

class TrafficAnalyzer:
    def __init__(self):
        self.packet_count = 0
        self.protocol_stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'HTTP': 0}
        self.start_time = datetime.now()

    def update_stats(self, packet):
# Updates protocol statistics
        self.packet_count += 1
                
        if packet.haslayer(TCP):
            self.protocol_stats['TCP'] += 1
        elif packet.haslayer(UDP):
            self.protocol_stats['UDP'] += 1
        elif packet.haslayer(ICMP):
            self.protocol_stats['ICMP'] += 1
        else:
            self.protocol_stats['HTTP'] += 1

def is_admin():
    # Check if running as administrator on Windows
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def signal_handler(sig, frame):
# Handles Ctrl+C gracefully with final statistics
    print("\n" + "="*60)
    print("[!] Sniffer interrupted by user")
    print("[*] Generating final report...")
    print("="*60)
    sys.exit(0)

def display_banner():
# Displays a clean banner    
    banner = """╔═══════════════════════════════════════════════════╗
            ║ NETWORK TRAFFIC ANALYZER - SECURITY EDITION       ║
            ║ Safe for Authorized Networks Only                 ║
            ╚═══════════════════════════════════════════════════╝"""
    print(banner)

def format_packet_info(packet):
# Formats packet information in a clean, readable way
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

# Basic packet info
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

# Protocol mapping
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        proto_name = proto_map.get(proto, f"Proto-{proto}")

# Gets port info for TCP/UDP
        port_info = ""
        if packet.haslayer(TCP):
            port_info = f":{packet[TCP].sport} → :{packet[TCP].dport}"
        elif packet.haslayer(UDP):
            port_info = f":{packet[UDP].sport} → :{packet[UDP].dport}"

# Formats output with color coding (optional)
        if packet.haslayer(TCP) and packet[TCP].dport == 80:
# Highlights HTTP traffic
            highlight = "[HTTP]"
        elif packet.haslayer(TCP) and packet[TCP].dport == 443:
            highlight = "[HTTPS]"
        elif packet.haslayer(DNS):
            highlight = "[DNS]"
        else:
            highlight = "[DATA]"

        return f"{timestamp} {highlight} {src_ip}{port_info} → {dst_ip} [{proto_name}]"

    elif packet.haslayer(ARP):
        return f"{timestamp} [ARP] {packet[ARP].psrc} is at {packet[ARP].hwsrc}"

    return f"{timestamp} [OTHER] {packet.summary()}"

def display_stats(analyzer, interval=10):
# This display statistics every N packets
    if analyzer.packet_count % interval == 0 and analyzer.packet_count > 0:
        elapsed = datetime.now() - analyzer.start_time
        packets_per_sec = analyzer.packet_count / max(elapsed.total_seconds(), 0.001)

        print("\n" + "-"*60)
        print(f"INTERIM STATISTICS (Packet {analyzer.packet_count})")
        print("-"*60)
        print(f"Duration: {elapsed.seconds} seconds")
        print(f"Packets/sec: {packets_per_sec:.2f}")
        print(f"Protocol Distribution:")
        for proto, count in analyzer.protocol_stats.items():
            if count > 0:
                percentage = (count / analyzer.packet_count) * 100
                print(f"  - {proto}: {count} packets ({percentage:.1f}%)")
        print("-"*60 + "\n")

def packet_callback(packet, analyzer, packets):
#Enhanced packet processing with analysis
    analyzer.update_stats(packet)
    packets.append(packet)

# Display formatted packet info
    packet_info = format_packet_info(packet)
    print(packet_info)

# Detailed inspection for interesting packets
    if packet.haslayer(TCP) and packet[TCP].flags == 2: # SYN flag
        print(f" [SYN] TCP SYN detected (new connection attempt)")

# Display statistics periodically
    display_stats(analyzer, interval=25)

# Save interesting packets to file
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].dport == 443):
        wrpcap("interesting_traffic.pcap", packet, append=True)

def main():
# Main function with clean setup
# Setups signal handler for graceful exit
    signal.signal(signal.SIGINT, signal_handler)

    if not SCAPY_AVAILABLE:
        print("[!] Error: Scapy is not installed. Please install it with 'pip install scapy' and ensure Npcap is installed on Windows.")
        sys.exit(1)

# Check for admin privileges on Windows
    if os.name == 'nt' and not is_admin():
        print("[!] This program requires administrator privileges to capture network traffic on Windows.")
        print("[*] Please run as administrator (Right-click > Run as administrator)")
        sys.exit(1)

# Displays banner
    display_banner()

# Initializes analyzer
    analyzer = TrafficAnalyzer()
    packets = []

    print("[*] Initializing packet capture...")
    print("[*] Interface: Default system interface")
    print("[*] Filter: TCP ports 80 and 443")
    print("[*] Note: Ensure Npcap is installed for Windows compatibility")
    print("[*] Press Ctrl+C to stop and generate report\n")
    print("-"*60)

    try:
        # Starts sniffing with enhanced parameters
        sniff(filter="tcp port 80 or tcp port 443", prn=lambda pkt: packet_callback(pkt, analyzer, packets), store=0, timeout=300, promisc=True)
    except Exception as e:
        print(f"\n[!] Error occurred: {e}")
        print("[*] Captured data will be saved upon exit...")

    finally:
        if packets:
            wrpcap("captured_traffic.pcap", packets)
            print(f"[*] Saved {len(packets)} packets to captured_traffic.pcap")

    print("\n" + "="*60)
    print("📋 FINAL CAPTURE REPORT")
    print("="*60)
    elapsed = datetime.now() - analyzer.start_time
    print(f"Total packets captured: {analyzer.packet_count}")
    print(f"Capture duration: {elapsed}")
    print(f"Average rate: {analyzer.packet_count / max(elapsed.total_seconds(), 0.001):.2f} pkt/sec")
    print("\nProtocol Breakdown:")
    for proto, count in analyzer.protocol_stats.items():
        if count > 0:
            print(f"  - {proto}: {count}")
    print("="*60)
    print("[*] Note: Always ensure proper authorization for network monitoring")
    print("[*] Captured data may be sensitive - handle with care")

if __name__ == "__main__": 
    main()