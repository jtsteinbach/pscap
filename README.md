# PScap: Process-Specific Network Capture

**Version**: 1.4.0
**License**: [LICENSE](https://r2.jts.gg/license)
**Developer**: [jts.gg/](https://jts.gg/)

---

PScap is a Python-based network packet capture tool designed to capture network traffic specifically associated with selected processes (by PID or process name). It leverages:

* **Scapy** for efficient packet capture
* **Psutil** for precise process management and port identification
* **Flexible filtering options** including blacklist ports and custom interfaces
* **Direct output to PCAP files** for easy analysis with tools like Wireshark

Ideal for IT security analysts, cybersecurity researchers, and system administrators needing targeted packet captures for security analysis or troubleshooting.

## Installation

Ensure you have Python 3 and necessary privileges:

```bash
# install dependencies
pip3 install psutil scapy
```

## Quick Start

List running processes:

```bash
sudo python3 pscap.py -l
```

Capture network traffic for specific PIDs or process names:

```bash
sudo python3 pscap.py -p 1234,chrome.exe -o capture.pcap
```

Capture traffic excluding specific ports:

```bash
sudo python3 pscap.py -p 1234 -b 80,443
```

Specify a network interface:

```bash
sudo python3 pscap.py -p chrome.exe -i eth0
```

Captured packets are saved as standard `.pcap` files for analysis.
