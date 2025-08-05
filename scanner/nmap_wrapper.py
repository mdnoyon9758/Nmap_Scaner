import subprocess
import sys
import os
from datetime import datetime

class NmapScanner:
    def __init__(self):
        self.nmap_path = None
        # Add nmap to PATH if it's in standard locations
        self.add_nmap_to_path()
        self.nmap_available = self.check_nmap_installation()
        if self.nmap_available:
            try:
                import nmap
                self.scanner = nmap.PortScanner()
            except Exception as e:
                self.nmap_available = False
                print(f"Error initializing nmap: {e}")
    
    def add_nmap_to_path(self):
        """Add nmap to PATH if it exists in standard locations"""
        nmap_dirs = [
            'C:\\Program Files (x86)\\Nmap',
            'C:\\Program Files\\Nmap',
            '/usr/bin',
            '/usr/local/bin'
        ]
        
        for nmap_dir in nmap_dirs:
            if os.path.exists(nmap_dir):
                if nmap_dir not in os.environ.get('PATH', ''):
                    os.environ['PATH'] += os.pathsep + nmap_dir
                    print(f"Added {nmap_dir} to PATH")
                break
    
    def check_nmap_installation(self):
        """Check if nmap is installed and available in PATH"""
        # Check common nmap locations
        nmap_paths = [
            'nmap',  # In PATH
            'C:\\Program Files (x86)\\Nmap\\nmap.exe',  # Default Windows install
            'C:\\Program Files\\Nmap\\nmap.exe',  # Alternative Windows install
            '/usr/bin/nmap',  # Linux
            '/usr/local/bin/nmap'  # macOS/Linux alternative
        ]
        
        for nmap_path in nmap_paths:
            try:
                result = subprocess.run([nmap_path, '--version'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    self.nmap_path = nmap_path
                    print(f"Found nmap at: {nmap_path}")
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        
        return False
    
    def get_scan_arguments(self, scan_type, port_range=None):
        """Get nmap arguments based on scan type"""
        args_map = {
            "Quick Scan": "-T4 -F",
            "Intense Scan": "-T4 -A -v",
            "Ping Scan": "-sn",
            "Port Scan": "-sS",
            "Service Detection": "-sV"
        }
        
        args = args_map.get(scan_type, "-T4 -F")
        
        if port_range and scan_type != "Ping Scan":
            args += f" -p {port_range}"
            
        return args
    
    def scan(self, target, scan_type="Quick Scan", port_range=None):
        """Perform nmap scan"""
        if not self.nmap_available:
            return self.simulate_scan(target, scan_type)
        
        try:
            import nmap
            args = self.get_scan_arguments(scan_type, port_range)
            print(f"Scanning {target} with arguments: {args}")
            
            self.scanner.scan(hosts=target, arguments=args)
            return {
                'hosts': self.scanner.all_hosts(),
                'scanner_info': self.scanner,
                'scan_type': scan_type,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        except Exception as e:
            return {
                'error': str(e),
                'hosts': [],
                'scan_type': scan_type,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def simulate_scan(self, target, scan_type):
        """Simulate scan results when nmap is not available"""
        return {
            'simulated': True,
            'message': 'Nmap not found. Install nmap to perform real scans.',
            'install_instructions': self.get_install_instructions(),
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'sample_results': {
                'host_up': True,
                'ports': [
                    {'port': 22, 'state': 'open', 'service': 'ssh'},
                    {'port': 80, 'state': 'open', 'service': 'http'},
                    {'port': 443, 'state': 'open', 'service': 'https'}
                ]
            }
        }
    
    def get_install_instructions(self):
        """Get nmap installation instructions for current OS"""
        if sys.platform.startswith('win'):
            return {
                'os': 'Windows',
                'steps': [
                    '1. Download Nmap from https://nmap.org/download.html',
                    '2. Run the installer (nmap-X.XX-setup.exe)',
                    '3. Follow the installation wizard',
                    '4. Restart this application'
                ],
                'alternative': 'Or use: winget install Nmap.Nmap'
            }
        elif sys.platform.startswith('darwin'):
            return {
                'os': 'macOS',
                'steps': [
                    '1. Install Homebrew if not installed',
                    '2. Run: brew install nmap',
                    '3. Restart this application'
                ],
                'alternative': 'Or download from https://nmap.org/download.html'
            }
        else:
            return {
                'os': 'Linux',
                'steps': [
                    '1. Ubuntu/Debian: sudo apt install nmap',
                    '2. CentOS/RHEL: sudo yum install nmap',
                    '3. Arch: sudo pacman -S nmap',
                    '4. Restart this application'
                ]
            }
