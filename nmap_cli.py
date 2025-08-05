#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap Scanner CLI - Android/Termux Version
A command-line interface for the Nmap Scanner, optimized for Android/Termux usage.

Author: mdnoyon9758 (https://github.com/mdnoyon9758)
Version: 1.0.0
License: MIT
"""

import sys
import os
import argparse
from datetime import datetime
from scanner.nmap_wrapper import NmapScanner
from scanner.parser import NmapParser

def print_banner():
    """Print application banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║  🔍 Advanced Nmap Scanner CLI - Android/Termux Version   ║
║                                                          ║
║  Author: mdnoyon9758                                     ║
║  GitHub: https://github.com/mdnoyon9758/Nmap_Scaner     ║
╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_help():
    """Print detailed help information"""
    help_text = """
📖 USAGE EXAMPLES:

Basic scans:
  python3 nmap_cli.py 192.168.1.1
  python3 nmap_cli.py example.com
  python3 nmap_cli.py 192.168.1.0/24

Specific scan types:
  python3 nmap_cli.py 192.168.1.1 --scan-type "Quick Scan"
  python3 nmap_cli.py 192.168.1.1 --scan-type "Intense Scan"
  python3 nmap_cli.py 192.168.1.1 --scan-type "Ping Scan"
  python3 nmap_cli.py 192.168.1.1 --scan-type "Service Detection"

Port range scans:
  python3 nmap_cli.py 192.168.1.1 --ports "1-1000"
  python3 nmap_cli.py 192.168.1.1 --ports "22,80,443,8080"
  python3 nmap_cli.py 192.168.1.1 --scan-type "Port Scan" --ports "1-65535"

🎯 SCAN TYPES:
  • Quick Scan      - Fast scan of most common ports
  • Intense Scan    - Comprehensive scan with OS detection  
  • Ping Scan       - Host discovery scan
  • Port Scan       - Custom port range scanning
  • Service Detection - Identify services and versions

📱 ANDROID/TERMUX TIPS:
  • Use WiFi for better performance
  • Avoid intensive scans on mobile data
  • Consider battery usage for long scans
  • Some features require root access
  • Use screen/tmux for long-running scans

⚠️  LEGAL NOTICE:
Only scan networks and systems you own or have explicit permission to test.
    """
    print(help_text)

def validate_target(target):
    """Basic target validation"""
    if not target:
        return False, "Target cannot be empty"
    
    # Basic validation - more comprehensive validation is done by nmap
    if len(target.strip()) < 3:
        return False, "Target seems too short"
    
    return True, "Valid"

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='Advanced Nmap Scanner CLI - Android/Termux Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 nmap_cli.py 192.168.1.1
  python3 nmap_cli.py example.com --scan-type "Intense Scan"
  python3 nmap_cli.py 192.168.1.1 --ports "1-1000"

For more help: python3 nmap_cli.py --help-detailed
        """
    )
    
    parser.add_argument('target', 
                       help='Target IP address, hostname, or network range')
    parser.add_argument('--scan-type', '-s',
                       choices=['Quick Scan', 'Intense Scan', 'Ping Scan', 
                               'Port Scan', 'Service Detection'],
                       default='Quick Scan',
                       help='Type of scan to perform (default: Quick Scan)')
    parser.add_argument('--ports', '-p',
                       help='Port range (e.g., "1-1000" or "22,80,443")')
    parser.add_argument('--output', '-o',
                       help='Output file to save results')
    parser.add_argument('--verbose', '-v',
                       action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--banner',
                       action='store_true',
                       help='Show banner')
    parser.add_argument('--help-detailed',
                       action='store_true',
                       help='Show detailed help and examples')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Handle special arguments
    if args.help_detailed:
        print_banner()
        print_help()
        return
    
    if args.banner:
        print_banner()
    
    # Validate target
    is_valid, message = validate_target(args.target)
    if not is_valid:
        print(f"❌ Error: {message}")
        return 1
    
    # Initialize scanner components
    try:
        scanner = NmapScanner()
        parser_obj = NmapParser()
    except Exception as e:
        print(f"❌ Error initializing scanner: {e}")
        return 1
    
    # Print scan information
    print(f"\n🎯 Target: {args.target}")
    print(f"📊 Scan Type: {args.scan_type}")
    if args.ports:
        print(f"🔍 Port Range: {args.ports}")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Perform the scan
    try:
        if args.verbose:
            print(f"🔍 Starting {args.scan_type} of {args.target}...")
        
        results = scanner.scan(args.target, args.scan_type, args.ports)
        formatted_results = parser_obj.format_results(results, args.target, args.scan_type)
        
        # Display results
        print(formatted_results)
        
        # Save to file if requested
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(f"Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n")
                    f.write(f"Target: {args.target}\n")
                    f.write(f"Scan Type: {args.scan_type}\n")
                    if args.ports:
                        f.write(f"Port Range: {args.ports}\n")
                    f.write("\n" + formatted_results)
                
                print(f"\n💾 Results saved to: {args.output}")
            except Exception as e:
                print(f"❌ Error saving results: {e}")
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
