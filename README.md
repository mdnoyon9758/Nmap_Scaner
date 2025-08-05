# 🔍 Advanced Nmap Scanner GUI

[![GitHub stars](https://img.shields.io/github/stars/mdnoyon9758/Nmap_Scaner.svg)](https://github.com/mdnoyon9758/Nmap_Scaner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mdnoyon9758/Nmap_Scaner.svg)](https://github.com/mdnoyon9758/Nmap_Scaner/network)
[![GitHub license](https://img.shields.io/github/license/mdnoyon9758/Nmap_Scaner.svg)](https://github.com/mdnoyon9758/Nmap_Scaner/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/mdnoyon9758/Nmap_Scaner)

A **modern, beautiful, and user-friendly GUI application** for network scanning using Nmap. Perfect for penetration testers, network administrators, and cybersecurity professionals.

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

#### Windows:
```powershell
# Using winget (recommended)
winget install Insecure.Nmap

# Or download from https://nmap.org/download.html
```

#### Linux (Ubuntu/Debian):
```bash
sudo apt update
sudo apt install nmap
```

#### macOS:
```bash
# Using Homebrew
brew install nmap
```

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


