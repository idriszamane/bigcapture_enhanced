# BIG CAPTURE – Network Packet Analyzer

BIG CAPTURE is a Bash-based **network packet analysis and SOC investigation tool** designed to help security analysts inspect PCAP files, detect suspicious network activity, and generate structured investigation reports.

The tool organizes findings into logs and exportable artifacts, making it useful for **incident response, traffic investigation, and cybersecurity learning labs**.

---

## Author

**Idris Yahaya**

---

# Features

* PCAP file inspection
* Real-time attack alert display
* Color-coded terminal output
* Automatic investigation case ID generation
* Structured report directory creation
* Log collection for forensic review
* Exportable investigation artifacts
* Organized SOC-style case folders
* Automated cleanup option for generated files

---

# Report Structure

When the tool runs, it automatically creates a case directory:

```
bigcapture_reports_TIMESTAMP/
│
├── logs/
│
├── exports/
│
└── analysis reports
```

Each run generates a unique **Case ID** for investigation tracking.

Example:

```
CASE_20260305_083201
```

---

# Requirements

The script is designed for **Linux environments** and requires common packet analysis utilities.

Typical tools used in SOC environments:

* tcpdump
* tshark
* awk
* grep
* sed

Most of these are already available on **Kali Linux, Ubuntu, and other security distributions**.

---

# Installation

Clone the repository:

```
git clone git@github.com:idriszamane/Packet-analyzer-SOC-tools.git
```

Move into the directory:

```
cd Packet-analyzer-SOC-tools
```

Make the script executable:

```
chmod +x Bigcaptureprov2.sh
```

---

# Usage

Run the tool:

```
./Bigcaptureprov2.sh
```

The tool will:

1. Search for available PCAP files
2. Analyze network packets
3. Display possible attack indicators
4. Generate investigation reports
5. Store artifacts in a case directory

---

# Example Use Cases

This tool can be used for:

* Security Operations Center (SOC) practice
* Network traffic investigation
* Incident response exercises
* Cybersecurity learning labs
* Packet analysis training

---

# Disclaimer

This tool is intended for **educational and defensive cybersecurity purposes only**.
Use only on networks and data you are authorized to analyze.

---

# License

This project is licensed under the MIT License.
