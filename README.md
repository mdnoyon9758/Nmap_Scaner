# 🔍 Advanced Nmap Scanner GUI

[![GitHub stars](https://img.shields.io/github/stars/mdnoyon9758/Nmap_Scaner.svg)](https://github.com/mdnoyon9758/Nmap_Scaner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mdnoyon9758/Nmap_Scaner.svg)](https://github.com/mdnoyon9758/Nmap_Scaner/network)
[![GitHub license](https://img.shields.io/github/license/mdnoyon9758/Nmap_Scaner.svg)](https://github.com/mdnoyon9758/Nmap_Scaner/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/mdnoyon9758/Nmap_Scaner)

A **modern, beautiful, and user-friendly GUI application** for network scanning using Nmap. Perfect for penetration testers, network administrators, and cybersecurity professionals.

---

# 🛡️ ReconX — Combined Security Assessment Toolkit (v2.0)

This project now ships **ReconX**, a self-contained, cross-platform
reconnaissance and security-assessment toolkit built for authorized
penetration testing and **bug-bounty** work. It runs anywhere Python runs
— Windows, macOS, Linux, and Android/Termux — **with zero required
dependencies** (pure standard library) and **without needing a separate
Linux box or external binaries**. Nmap is used automatically when present,
but is optional.

> ⚠️ **Authorized use only.** ReconX will not run until you confirm you
> have permission to test the target scope (via `--i-am-authorized`, the
> `RECONX_AUTHORIZED=1` env var, or an interactive prompt). Every run is
> written to an audit log at `~/.reconx/audit.log`. Only scan systems you
> own or are explicitly authorized to test (a signed engagement or an
> in-scope bug-bounty program). See [SECURITY.md](SECURITY.md).

## What it does

One command consolidates the common recon/enumeration tasks:

| Module | What it gathers |
| ------ | --------------- |
| `portscan` | TCP connect port scan + banner grab (no nmap needed) |
| `nmap` | Deep service/version/OS scan **when nmap is installed** |
| `dns` | A/AAAA/NS/MX/TXT/CNAME/SOA records + SPF/DMARC posture |
| `subdomains` | Subdomain discovery via Certificate Transparency (crt.sh) + DNS wordlist |
| `whois` | Domain/IP registration data over the WHOIS protocol |
| `headers` | HTTP security-header analysis (HSTS, CSP, etc.) |
| `tls` | TLS certificate + protocol inspection (expiry, weak protocols) |
| `tech` | Passive web technology fingerprinting |
| `web` | robots/sitemap/security.txt + exposed sensitive-path checks (`.git`, `.env`, …) |

Findings are collected into one report you can export as **text**, **JSON**
(for pipelines/CI), or a self-contained **HTML** report to hand to a client.

## Quick start

```bash
# No install needed — run straight from the checkout:
python3 recon.py example.com --profile recon --i-am-authorized

# Port scan an IP (no nmap required):
python3 recon.py 203.0.113.10 --modules portscan --ports top --i-am-authorized

# Full assessment of a web app, HTML report, polite rate limit:
python3 recon.py https://example.com --profile full \
        --rate 5 --format html --output report.html --i-am-authorized

# List every module and profile:
python3 recon.py --list
```

Or install it as a `reconx` command:

```bash
pip install -e .
reconx example.com --profile recon --i-am-authorized
```

## Profiles

| Profile | Modules |
| ------- | ------- |
| `quick` | portscan, headers |
| `recon` | dns, subdomains, whois, headers, tech, tls |
| `web`   | headers, tech, tls, web |
| `full`  | dns, subdomains, whois, portscan, headers, tech, tls, web |

## Handy flags

- `--modules/-m` — pick specific modules or profiles (or `all`)
- `--ports` — `top` | `all` | `22,80,443` | `1-1024`
- `--rate N` — cap operations/sec (be a good citizen)
- `--threads/-t` — concurrency (default 50)
- `--wordlist FILE` — custom subdomain wordlist
- `--format text|json|html` and `--output FILE`
- CIDR ranges (e.g. `192.168.1.0/24`) are expanded automatically (capped at 65536 hosts)

## Design & safety notes

- **Pure stdlib core** — the toolkit works with no `pip install` at all.
- **Scoped by design** — no mass-targeting, DoS, or exploitation payloads;
  ReconX focuses on the reconnaissance and assessment that legitimate
  bug-bounty and pentest engagements rely on.
- **Graceful degradation** — a blocked host or missing nmap produces a
  clear finding, never a crash.
- Tests: `python3 -m unittest discover -s tests`

---

## 🌟 Why Choose This Nmap GUI?

- 🎨 **Beautiful Modern Interface** - Dark theme with smooth animations
- 🚀 **Multiple Scan Types** - Quick, Intense, Ping, Port, and Service Detection scans
- 📊 **Real-time Progress** - Live status updates and progress bars
- 💾 **Export Results** - Save scan results to files
- 🔧 **Easy to Use** - No command-line knowledge required
- 🖥️ **Cross-Platform** - Works on Windows, Linux, and macOS
- ⚡ **Fast & Efficient** - Built with Python and CustomTkinter

## 📸 Screenshots

### Main Interface
![Nmap Scanner GUI](https://via.placeholder.com/800x600/1a1a1a/ffffff?text=Nmap+Scanner+GUI+Interface)
*Modern dark theme interface with intuitive controls*

### Scan Results
![Scan Results](https://via.placeholder.com/800x400/2d2d2d/00ff00?text=Real-time+Scan+Results)
*Detailed scan results with color-coded output*

## 🚀 Quick Start

### Option 1: Download Executable (Recommended)
1. Go to [Releases](https://github.com/mdnoyon9758/Nmap_Scaner/releases)
2. Download `Nmap-Scanner-GUI.exe`
3. Run the executable (Windows only)

### Option 2: Run from Source
```bash
# Clone the repository
git clone https://github.com/mdnoyon9758/Nmap_Scaner.git
cd Nmap_Scaner

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## 📋 Prerequisites

### For Executable Version:
- ✅ Windows 10/11 (64-bit)
- ✅ Nmap installed ([Download here](https://nmap.org/download.html))

### For Source Code Version:
- ✅ Python 3.8 or higher
- ✅ Nmap installed
- ✅ Required Python packages (see requirements.txt)

## 🛠️ Installation Guide

### Step 1: Install Nmap

#### 🪟 Windows:
```powershell
# Method 1: Using winget (recommended)
winget install Insecure.Nmap

# Method 2: Using Chocolatey
choco install nmap

# Method 3: Manual download
# Download from https://nmap.org/download.html
```

#### 🐧 Linux:

##### Ubuntu/Debian:
```bash
sudo apt update
sudo apt install nmap python3 python3-pip
```

##### CentOS/RHEL/Fedora:
```bash
# CentOS/RHEL 7
sudo yum install nmap python3 python3-pip

# CentOS/RHEL 8+ and Fedora
sudo dnf install nmap python3 python3-pip
```

##### Arch Linux:
```bash
sudo pacman -S nmap python python-pip
```

##### Alpine Linux:
```bash
sudo apk add nmap python3 py3-pip
```

##### openSUSE:
```bash
sudo zypper install nmap python3 python3-pip
```

#### 🍎 macOS:
```bash
# Using Homebrew (recommended)
brew install nmap python3

# Using MacPorts
sudo port install nmap python39
```

#### 🤖 Android (via Termux):

**Note**: This runs in terminal mode only, no GUI support.

1. **Install Termux** from [F-Droid](https://f-droid.org/packages/com.termux/) or Google Play Store
2. **Setup Termux environment**:
```bash
# Update packages
pkg update && pkg upgrade

# Install required packages
pkg install nmap python git

# Install pip
pkg install python-pip
```

3. **Clone and setup the scanner**:
```bash
# Clone the repository
git clone https://github.com/mdnoyon9758/Nmap_Scaner.git
cd Nmap_Scaner

# Install Python dependencies (GUI components will be skipped)
pip install python-nmap
```

4. **Create a command-line version** (see Android Usage section below)

### Step 2: Install Dependencies (Source version only)
```bash
pip install customtkinter==5.2.2 pillow==10.0.1 python-nmap==0.7.1
```

## 🎯 Features Overview

### Scan Types Available:
- **🏃 Quick Scan** - Fast scan of most common ports
- **💪 Intense Scan** - Comprehensive scan with OS detection
- **📡 Ping Scan** - Host discovery scan
- **🔍 Port Scan** - Custom port range scanning
- **🔧 Service Detection** - Identify services and versions

### Interface Features:
- **🎨 Modern UI** - CustomTkinter-based beautiful interface
- **🌓 Theme Support** - Dark, Light, and System themes
- **📊 Progress Tracking** - Real-time scan progress
- **💾 Export Options** - Save results to text files
- **🚫 Scan Control** - Start, stop, and clear functions
- **📱 Responsive Design** - Resizable and user-friendly

## 📖 Usage Guide

### Basic Usage:
1. **Launch the application**
2. **Enter target**: IP address (e.g., `192.168.1.1`) or domain (e.g., `example.com`)
3. **Select scan type** from the dropdown menu
4. **Specify port range** (optional): `1-1000` or `22,80,443`
5. **Click "🚀 Start Scan"**
6. **View results** in the main panel
7. **Save results** using the "💾 Save Results" button

### Advanced Tips:
- Use **Quick Scan** for fast network discovery
- Use **Intense Scan** for detailed security assessment
- Use **Ping Scan** to check if hosts are alive
- Use **Service Detection** to identify running services
- Combine with port ranges for targeted scanning

## 🖥️ Platform-Specific Usage

### 🪟 Windows Usage

#### Running the GUI:
```cmd
# Method 1: Using the executable
Nmap-Scanner-GUI.exe

# Method 2: From source
cd Nmap_Scaner
python main.py
```

#### Windows-specific features:
- 📁 **Portable**: The executable runs without installation
- 🎨 **Native look**: Integrates with Windows themes
- 🔐 **UAC support**: Prompts for admin rights when needed

### 🐧 Linux Usage

#### GUI Version:
```bash
# Install display server (if using headless system)
sudo apt install xvfb  # Ubuntu/Debian

# Run with GUI
python3 main.py

# Run headless (X11 forwarding for SSH)
ssh -X user@server
python3 main.py
```

#### Command-line Version:
```bash
# Direct nmap usage (examples)
nmap -T4 -F 192.168.1.1              # Quick scan
nmap -T4 -A -v 192.168.1.1           # Intense scan
nmap -sn 192.168.1.0/24              # Ping scan
nmap -sS -p 1-1000 192.168.1.1       # Port scan
nmap -sV 192.168.1.1                 # Service detection
```

#### Linux-specific features:
- 🔒 **Sudo integration**: Automatic privilege escalation prompts
- 📊 **Performance**: Optimized for Linux networking stack
- 🔧 **Customization**: Easy to modify for specific distros

### 🍎 macOS Usage

#### GUI Version:
```bash
# Install using Homebrew
brew install python-tk  # For tkinter support

# Run the application
python3 main.py
```

#### macOS-specific considerations:
- 🔐 **Gatekeeper**: May need to allow app in Security & Privacy
- 🖥️ **Retina support**: GUI scales properly on high-DPI displays
- 🎨 **Native theming**: Adapts to macOS light/dark mode

### 🤖 Android Usage (Termux)

**Note**: Android version runs in command-line mode only.

#### Setup and Usage:
```bash
# After installing Termux and cloning the repo
cd Nmap_Scaner

# Create a simple CLI wrapper
cat > nmap_cli.py << 'EOF'
#!/usr/bin/env python3
import sys
from scanner.nmap_wrapper import NmapScanner
from scanner.parser import NmapParser

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_cli.py <target> [scan_type] [port_range]")
        print("Scan types: 'Quick Scan', 'Intense Scan', 'Ping Scan', 'Port Scan', 'Service Detection'")
        return
    
    target = sys.argv[1]
    scan_type = sys.argv[2] if len(sys.argv) > 2 else "Quick Scan"
    port_range = sys.argv[3] if len(sys.argv) > 3 else None
    
    scanner = NmapScanner()
    parser = NmapParser()
    
    print(f"\n🔍 Starting {scan_type} of {target}...")
    results = scanner.scan(target, scan_type, port_range)
    formatted_results = parser.format_results(results, target, scan_type)
    print(formatted_results)

if __name__ == "__main__":
    main()
EOF

# Make it executable
chmod +x nmap_cli.py

# Usage examples
python3 nmap_cli.py 192.168.1.1                    # Quick scan
python3 nmap_cli.py 192.168.1.1 "Intense Scan"      # Intensive scan
python3 nmap_cli.py 192.168.1.1 "Port Scan" "1-1000" # Port range scan
```

#### Android-specific features:
- 📱 **Mobile-optimized**: Designed for touch interfaces
- 🔋 **Battery-aware**: Efficient scanning to preserve battery
- 📶 **Network-aware**: Adapts to mobile vs WiFi connections
- 🔒 **Root detection**: Enhanced features when device is rooted

#### Android Limitations:
- ❌ **No GUI**: Terminal interface only
- ⚠️ **Limited permissions**: Some scan types require root
- 🔋 **Battery drain**: Intensive scans can drain battery quickly
- 📱 **Screen space**: Limited terminal real estate

## 🔧 Troubleshooting

### Common Issues:

#### "Nmap not found" error:
```bash
# Verify nmap installation
nmap --version

# Add to PATH if needed (Linux/macOS)
export PATH=$PATH:/usr/local/bin

# Windows: Add nmap directory to system PATH
```

#### Permission denied (Linux/macOS):
```bash
# Run with sudo for privileged scans
sudo python3 main.py

# Or add user to netdev group (Ubuntu)
sudo usermod -a -G netdev $USER
```

#### GUI not displaying (Linux):
```bash
# Install tkinter
sudo apt install python3-tk  # Ubuntu/Debian
sudo yum install tkinter      # CentOS/RHEL

# Set DISPLAY variable for SSH
export DISPLAY=:0.0
```

#### Dependencies issues:
```bash
# Upgrade pip and reinstall
pip install --upgrade pip
pip install --force-reinstall -r requirements.txt

# Virtual environment (recommended)
python3 -m venv nmap_env
source nmap_env/bin/activate  # Linux/macOS
nmap_env\Scripts\activate     # Windows
pip install -r requirements.txt
```

## ⚠️ Legal Disclaimer

**Important**: This tool is intended for **authorized testing only**. Users are responsible for complying with all applicable laws and regulations. Only scan networks and systems you own or have explicit permission to test.

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. 💻 Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. 📤 Push to the branch (`git push origin feature/AmazingFeature`)
5. 🔄 Open a Pull Request

## 🐛 Issue Reporting

Found a bug? Have a feature request? Please create an issue:
1. Go to [Issues](https://github.com/mdnoyon9758/Nmap_Scaner/issues)
2. Click "New Issue"
3. Provide detailed information

## 📝 Changelog

### Version 1.0.0 (Latest)
- ✅ Initial release
- ✅ Modern GUI interface
- ✅ Multiple scan types
- ✅ Real-time progress tracking
- ✅ Export functionality
- ✅ Cross-platform support

## 🏆 Support the Project

If you find this project helpful:
- ⭐ Star the repository
- 🍴 Fork and contribute
- 📢 Share with others
- 🐛 Report issues

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**GitHub**: [@mdnoyon9758](https://github.com/mdnoyon9758)

---

## 🔍 Keywords for Search Optimization

`nmap gui` `network scanner` `port scanner` `nmap frontend` `network security tools` `penetration testing` `cybersecurity tools` `network discovery` `vulnerability scanner` `nmap python gui` `ethical hacking tools` `network analysis` `security assessment` `nmap interface` `network mapping` `python network tools`

---

### 📊 Repository Stats

![GitHub repo size](https://img.shields.io/github/repo-size/mdnoyon9758/Nmap_Scaner)
![GitHub last commit](https://img.shields.io/github/last-commit/mdnoyon9758/Nmap_Scaner)
![GitHub issues](https://img.shields.io/github/issues/mdnoyon9758/Nmap_Scaner)
![GitHub pull requests](https://img.shields.io/github/issues-pr/mdnoyon9758/Nmap_Scaner)

**⭐ Star this repository if you find it useful!**


