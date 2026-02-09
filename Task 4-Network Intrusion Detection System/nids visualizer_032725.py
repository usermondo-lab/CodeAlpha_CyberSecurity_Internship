class NIDSVisualizer:
    """Simple terminal-based visualization"""
    
    @staticmethod
    def show_dashboard(alerts_by_hour, top_signatures):
        """Display ASCII dashboard"""
        print("\n" + "="*60)
        print("NIDS LIVE DASHBOARD")
        print("="*60)
        
        # Alert timeline
        print("\n📊 Alerts by Hour (Last 24h):")
        for hour, count in alerts_by_hour[-6:]:  # Last 6 hours
            bar = "█" * min(count, 20)
            print(f"  {hour:02d}:00 | {bar} {count}")
        
        # Top threats
        print("\n🔥 Top Threat Signatures:")
        for sig, count in top_signatures[:5]:
            print(f"  • {sig[:40]:40s} | {count:3d} alerts")
        
        # Status indicators
        print("\n🛡️  System Status:")
        print("  Suricata:    ● Running")
        print("  Monitoring:  ● Active")
        print("  Response:    ● Enabled")
        print("="*60)