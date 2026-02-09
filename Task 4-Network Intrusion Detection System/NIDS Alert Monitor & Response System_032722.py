import json
import time
import subprocess
from datetime import datetime
import sys

class NIDSMonitor:
    def __init__(self, alert_file="/var/log/suricata/eve.json"):
        self.alert_file = alert_file
        self.alert_counts = {}
        self.blocked_ips = set()
        
    def follow_alerts(self):
        """Monitor Suricata's JSON alert log (like 'tail -f')"""
        print(f"[*] Starting NIDS Monitor - Watching {self.alert_file}")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            with open(self.alert_file, 'r') as f:
                f.seek(0, 2)  # Go to end of file
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    
                    try:
                        alert = json.loads(line)
                        self.process_alert(alert)
                    except json.JSONDecodeError:
                        continue
                        
        except KeyboardInterrupt:
            print("\n[*] Shutting down NIDS Monitor")
            self.generate_report()
        except FileNotFoundError:
            print(f"[!] Alert file not found: {self.alert_file}")
            print("[!] Start Suricata first: sudo suricata -c /etc/suricata/suricata.yaml -i eth0")
    
    def process_alert(self, alert):
        """Process and respond to alerts"""
        if alert.get('event_type') != 'alert':
            return
        
        # Extract alert details
        alert_data = alert.get('alert', {})
        src_ip = alert.get('src_ip', 'Unknown')
        dest_ip = alert.get('dest_ip', 'Unknown')
        signature = alert_data.get('signature', 'No signature')
        severity = alert_data.get('severity', 3)
        
        # Update counts
        self.alert_counts[signature] = self.alert_counts.get(signature, 0) + 1
        
        # Display alert
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"\n⚠️  [{timestamp}] ALERT: {signature}")
        print(f"   Source: {src_ip} → Destination: {dest_ip}")
        print(f"   Severity: {severity}/1 (1=highest)")
        
        # Implement response based on severity
        self.auto_respond(alert, severity, src_ip)
    
    def auto_respond(self, alert, severity, src_ip):
        """Automatic response mechanisms"""
        # Log all alerts
        self.log_alert(alert)
        
        # Level 1: High severity - aggressive response
        if severity == 1:
            print(f"   🚨 CRITICAL - Blocking source IP: {src_ip}")
            self.block_ip_iptables(src_ip, "Critical threat detected")
            
        # Level 2: Medium severity - log and alert
        elif severity == 2:
            print(f"   ⚠️  HIGH - Logging for analysis")
            # Could add email notification here
            
        # Level 3: Low severity - informational
        else:
            print(f"   ℹ️  INFO - Monitoring activity")
    
    def block_ip_iptables(self, ip, reason):
        """Block IP using iptables (Linux firewall)"""
        if ip in self.blocked_ips or ip == 'Unknown':
            return
        
        try:
            # Block IP with iptables
            subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], 
                          check=True)
            subprocess.run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                          check=True)
            
            self.blocked_ips.add(ip)
            print(f"   ✅ Successfully blocked {ip}")
            
            # Log the block
            with open('/tmp/nids_blocks.log', 'a') as f:
                f.write(f"{datetime.now()}: Blocked {ip} - {reason}\n")
                
        except subprocess.CalledProcessError as e:
            print(f"   ❌ Failed to block {ip}: {e}")
    
    def log_alert(self, alert):
        """Log alert to file"""
        with open('/tmp/nids_alerts.log', 'a') as f:
            f.write(json.dumps(alert) + '\n')
    
    def generate_report(self):
        """Generate summary report"""
        print("\n" + "="*60)
        print("NIDS MONITORING REPORT")
        print("="*60)
        print(f"Total unique alert types: {len(self.alert_counts)}")
        
        if self.alert_counts:
            print("\nTop 5 Alert Types:")
            for sig, count in sorted(self.alert_counts.items(), 
                                    key=lambda x: x[1], reverse=True)[:5]:
                print(f"  • {sig}: {count} times")
        
        print(f"\nIPs Blocked: {len(self.blocked_ips)}")
        if self.blocked_ips:
            for ip in self.blocked_ips:
                print(f"  • {ip}")
        
        print(f"\nFull logs: /tmp/nids_alerts.log")
        print("="*60)

def main():
    """Main function"""
    monitor = NIDSMonitor()
    
    # Check if running as root (needed for iptables)
    if subprocess.run(['id', '-u'], capture_output=True, text=True).stdout.strip() != '0':
        print("[!] Warning: Running without root privileges")
        print("[!] IP blocking features will be simulated")
    
    # Start monitoring
    monitor.follow_alerts()

if __name__ == "__main__":
    main()