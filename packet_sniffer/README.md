# Network Packet Analyzer

A professional, modular, and beginner-friendly Network Packet Analyzer (Packet Sniffer) built with Python and Scapy. This tool is designed for educational and ethical cybersecurity learning purposes.

## 🚀 Features

- **Real-time Capture**: Sniffs live network traffic using Scapy's powerful engine.
- **Protocol Identification**: Distinguishes between TCP, UDP, ICMP, and other protocols.
- **IP Analysis**: Displays precise Source and Destination IP addresses.
- **Payload Extraction**: Displays raw payload data (if available) for deep packet inspection.
- **Protocol Filtering**: Command-line flags to focus on specific traffic (`--tcp`, `--udp`, `--icmp`).
- **Interface Selection**: Choose specific network adapters for sniffing.
- **Logging**: Save captured packet details to a text file for later analysis.
- **Session Control**: Limit capture by packet count or stop safely with `Ctrl+C`.

## ⚠️ Ethical Disclaimer

**This tool is for educational purposes and authorized security testing ONLY.**
Unauthorized monitoring of network traffic is illegal and violates privacy policies. Use this tool only on networks you own or have explicit permission to test.

## 🛠️ Installation

### Prerequisites

1.  **Python 3.x**: Ensure you have Python 3 installed.
2.  **Windows Users (Npcap)**: Packet sniffing on Windows requires **Npcap**. Download it from [nmap.org/npcap/](https://nmap.org/npcap/). During installation, ensure "Install Npcap in WinPcap API-compatible Mode" is checked.
3.  **Linux/macOS Users**: You may need to install `libpcap` (usually pre-installed).

### Setup

1.  Clone or download the project.
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## 📝 Usage

The tool requires **Administrator** (Windows) or **Root** (Linux/macOS) privileges to access the network hardware.

### List Available Interfaces
```bash
python packet_sniffer.py --list-interfaces
```

### Windows Execution (PowerShell/CMD)
Always use double quotes if your path contains spaces.

```powershell
# Navigate to the project folder
cd "C:\Users\91961\OneDrive\Desktop\Network Packet Analyzer\packet_sniffer"

# Run with Administrator privileges
python packet_sniffer.py --tcp
```

### Linux/macOS
```bash
sudo python3 packet_sniffer.py
```

### Advanced Usage Examples
- **Log to a specific path**:
  ```powershell
  python packet_sniffer.py --log "C:\Users\91961\OneDrive\Desktop\Network Packet Analyzer\packet_sniffer\capture.log"
  ```
- **Filter for UDP**:
  ```bash
  python packet_sniffer.py --udp
  ```

## 🛠️ Troubleshooting (Windows)

### 1. "No loopback interface found" or "No interfaces found"
This usually means **Npcap** is missing or not installed in WinPcap compatibility mode.
- **Fix**: Reinstall Npcap and check "Install Npcap in WinPcap API-compatible Mode".

### 2. "Permission Denied"
You must run your terminal (PowerShell, CMD, or VS Code) as **Administrator**.

### 3. File Path Errors
Ensure you use quotes around paths: `cd "C:\Path With Spaces"`.

## ⚙️ How It Works
The packet sniffer acts as a digital "wiretap" on your network card, intercepting binary data as it arrives, peeling back layers of the network stack (IP -> TCP/UDP), and presenting the data in a human-readable format.

1.  **Scanner Initialization**: The tool uses the `argparse` library to parse user-defined filters and settings.
2.  **Scapy Engine**: It leverages the `sniff()` function from Scapy to hook into the network interface.
3.  **Layer Analysis**: For every captured packet, the tool verifies if it contains an IP layer.
4.  **Protocol Parsing**: It inspects the IP header to determine if the packet is TCP, UDP, or ICMP.
5.  **Data Extraction**: It pulls the source/destination IPs, packet length, and raw payload data.
6.  **Human-Readable Output**: The `PacketAnalyzer` class formats these technical details into the structured layout seen in your console.

## 🔮 Future Improvements

- Add support for deeper analysis of HTTP/DNS layers.
- Implement a graphical user interface (GUI) using Tkinter or PyQT.
- Add real-time traffic visualization (graphs/charts).
- Implement geolocation lookup for IP addresses.

## 📄 License
This project is licensed under the MIT License - see the `LICENSE` file for details.
