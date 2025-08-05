from datetime import datetime

class NmapParser:
    def format_results(self, results, target, scan_type):
        """Format scan results for display"""
        if 'simulated' in results:
            return self.format_simulation_results(results)
        elif 'error' in results:
            return self.format_error_results(results)
        else:
            return self.format_real_results(results, target)
    
    def format_simulation_results(self, results):
        """Format simulated results when nmap is not available"""
        output = []
        output.append("="*60)
        output.append("🚨 NMAP NOT INSTALLED - SHOWING DEMO RESULTS")
        output.append("="*60)
        output.append(f"\n📅 Scan Time: {results['timestamp']}")
        output.append(f"🎯 Target: {results['target']}")
        output.append(f"📊 Scan Type: {results['scan_type']}")
        output.append(f"\n{results['message']}")
        
        # Installation instructions
        instructions = results['install_instructions']
        output.append(f"\n📋 Installation Instructions for {instructions['os']}:")
        output.append("-" * 40)
        for step in instructions['steps']:
            output.append(f"   {step}")
        
        if 'alternative' in instructions:
            output.append(f"\n💡 Alternative: {instructions['alternative']}")
        
        # Sample results
        output.append("\n" + "="*60)
        output.append("📊 SAMPLE SCAN RESULTS (Demo)")
        output.append("="*60)
        sample = results['sample_results']
        output.append(f"\n🖥️  Host Status: {'UP' if sample['host_up'] else 'DOWN'}")
        output.append("\n🔍 Open Ports:")
        output.append("-" * 20)
        
        for port_info in sample['ports']:
            output.append(f"   Port {port_info['port']}/tcp - {port_info['state'].upper()} - {port_info['service']}")
        
        output.append("\n" + "="*60)
        output.append("ℹ️  Install nmap for real scanning capabilities!")
        output.append("="*60)
        
        return "\n".join(output)
    
    def format_error_results(self, results):
        """Format error results"""
        output = []
        output.append("="*60)
        output.append("❌ SCAN ERROR")
        output.append("="*60)
        output.append(f"\n📅 Time: {results['timestamp']}")
        output.append(f"📊 Scan Type: {results['scan_type']}")
        output.append(f"\n🚨 Error: {results['error']}")
        output.append("\n" + "="*60)
        
        return "\n".join(output)
    
    def format_real_results(self, results, target):
        """Format real nmap results"""
        output = []
        output.append("="*60)
        output.append("🔍 NMAP SCAN RESULTS")
        output.append("="*60)
        output.append(f"\n📅 Scan Time: {results['timestamp']}")
        output.append(f"🎯 Target: {target}")
        output.append(f"📊 Scan Type: {results['scan_type']}")
        
        scanner = results.get('scanner_info')
        hosts = results.get('hosts', [])
        
        if not hosts:
            output.append("\n❌ No hosts found or all hosts are down")
            return "\n".join(output)
        
        output.append(f"\n🖥️  Hosts Found: {len(hosts)}")
        output.append("\n" + "="*60)
        
        for host in hosts:
            output.append(f"\n🌐 Host: {host}")
            
            if scanner and host in scanner.all_hosts():
                # Host status
                state = scanner[host].state()
                output.append(f"   Status: {state.upper()}")
                
                # Hostname
                hostnames = scanner[host].hostnames()
                if hostnames:
                    output.append(f"   Hostname: {', '.join([h['name'] for h in hostnames])}")
                
                # Protocols
                for protocol in scanner[host].all_protocols():
                    output.append(f"\n   📡 Protocol: {protocol.upper()}")
                    
                    ports = scanner[host][protocol].keys()
                    if ports:
                        output.append("   🔍 Open Ports:")
                        output.append("   " + "-"*40)
                        
                        for port in sorted(ports):
                            port_info = scanner[host][protocol][port]
                            state = port_info['state']
                            name = port_info.get('name', 'unknown')
                            product = port_info.get('product', '')
                            version = port_info.get('version', '')
                            
                            service_info = f"{name}"
                            if product:
                                service_info += f" ({product}"
                                if version:
                                    service_info += f" {version}"
                                service_info += ")"
                            
                            output.append(f"      {port}/tcp - {state.upper()} - {service_info}")
                
                # OS detection if available
                if 'osmatch' in scanner[host] and scanner[host]['osmatch']:
                    output.append("\n   💻 OS Detection:")
                    for osmatch in scanner[host]['osmatch']:
                        accuracy = osmatch.get('accuracy', 'Unknown')
                        name = osmatch.get('name', 'Unknown OS')
                        output.append(f"      {name} (Accuracy: {accuracy}%)")
            
            output.append("\n" + "-"*60)
        
        output.append("\n✅ Scan completed successfully!")
        output.append("="*60)
        
        return "\n".join(output)
