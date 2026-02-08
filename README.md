🌐 Network Packet Analyzer

🚀 A beginner-friendly packet sniffer built using Python + Scapy to understand how data travels across the internet in real time.

🧠 Why I Built This

I wanted to learn how devices actually communicate over a network. Instead of just studying theory, I built this tool to see real network traffic live and understand how packets move between systems.

⚙️ What This Tool Can Do

✨ Capture live network packets
🌍 Show Source & Destination IP addresses
📡 Detect protocols like TCP, UDP & ICMP
📦 Display packet size and payload data
📁 Save captured packets into log files
🔍 List available network interfaces

🛠 Tech Stack

🐍 Python
📡 Scapy (Packet Manipulation Library)

🚀 How To Run
Clone Repository
git clone https://github.com/Aishwaryeahh-cy/-PRODIGY_Trackcode_TaskNumber.git

Move Into Folder
cd PRODIGY_Trackcode_TaskNumber

Install Requirements
pip install -r requirements.txt

Start Sniffer
python packet_sniffer.py

🎯 Useful Commands

👉 Capture limited packets

python packet_sniffer.py --count 5


👉 Capture only TCP traffic

python packet_sniffer.py --tcp


👉 Capture only UDP traffic

python packet_sniffer.py --udp


👉 Save packets to file

python packet_sniffer.py --log packets.txt


👉 Show network interfaces

python packet_sniffer.py --list-interfaces

⚠️ Important Note

🔐 Run the tool with Administrator / Root privileges

🪟 Windows users must install Npcap
👉 https://npcap.com

📚 What I Learned From This Project

✔ How packets travel across networks
✔ Difference between TCP, UDP, and ICMP
✔ Real-time traffic monitoring
✔ Using Scapy for packet analysis
✔ Git & GitHub workflow

🛡 Ethical Disclaimer

This tool is built strictly for learning and authorized testing.
Please don’t use it to monitor networks without permission.
