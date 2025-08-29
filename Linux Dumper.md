# Linux DFIR Evidence Collection Tool

A Python-based digital forensics and incident response script specifically designed for Linux systems to collect evidence during cybersecurity investigations.

<p align="center">
  <img src="https://github.com/user-attachments/assets/30ccdf1b-04ad-4abf-a171-0bc6c56b6791" />
</p>

## Features

- **System Information Collection**: Gathers comprehensive Linux system data (OS version, kernel, users, mounts, etc.)
- **Volatile Data Capture**: Collects running processes, network connections, open files, and other volatile data
- **Process Memory Dumping**: Captures memory from specified processes using gcore
- **Network Evidence Collection**: 
  - Captures active network connections with ss
  - Records routing tables and iptables rules
  - Captures live network traffic to PCAP files using tcpdump
- **Disk Imaging**: Creates forensic images of specified directories using tar with metadata preservation
- **Log Collection**: Gathers important system and application log files
- **Integrity Verification**: Calculates multiple hash values (MD5, SHA1, SHA256) for all collected evidence
- **Progress Tracking**: Shows progress bars for each collection task
- **Comprehensive Reporting**: Generates detailed JSON and text reports of all collected evidence
- **Error Handling**: Robust exception handling with detailed error logging

## Requirements

- Python 3.6+
- Root privileges (required for most operations)
- Linux system tools:
  - `gcore` for process memory dumping (part of gdb package)
  - `tcpdump` for network traffic capture
  - `tar` for disk imaging
  - `ss`, `ip`, `route` for network information
  - `ps`, `lsof`, `lsmod` for system state information

## Installation

1. Clone the repository:
```bash
git clone https://github.com/D3One/Linux-DFIR-Evidence-Collection-Tool.git
cd Linux-DFIR-Evidence-Collection-Tool
```

2. Install Python dependencies:
```bash
pip install progress
```

3. Install required system tools on Ubuntu/Debian:
```bash
sudo apt-get update
sudo apt-get install gdb tcpdump tar coreutils
```

4. Make the script executable:
```bash
chmod +x linuxdumper.py
```

## Usage

1. Run with root privileges:
```bash
sudo python3 linuxdumper.py
```

2. Or use command line arguments to customize the collection:
```bash
sudo python3 linuxdumper.py \
  -o /opt/evidence \
  -p sshd apache2 mysql \
  -d /etc /var/www /home \
  -t 120
```

3. The script will:
   - Create an output directory with timestamp
   - Collect system information and volatile data
   - Dump specified processes from memory
   - Capture network data and traffic
   - Create disk images of specified directories
   - Collect log files
   - Generate comprehensive reports with integrity hashes

4. Customize the default configuration in the script if needed:
```python
CONFIG = {
    "processes_to_dump": ["sshd", "bash", "systemd", "nginx", "apache2", "mysql"],
    "directories_to_image": ["/etc", "/var/log", "/tmp", "/home"],
    "output_directory": "./linux_dfir_collection",
    "network_capture_duration": 60,
    "max_file_size_mb": 500,
    "hash_algorithms": ["md5", "sha1", "sha256"]
}
```

## Output

The script creates the following structure in the output directory:
```
linux_dfir_collection/
├── collection_report.json     # Comprehensive JSON report with integrity hashes
├── collection_summary.txt     # Human-readable summary
├── memory/                    # Process memory dumps (.core files)
├── disk_images/              # Directory images (.tar.gz files)
├── network/                  # Network data (PCAP, connections, routing)
├── system_info/              # System information
├── volatile_data/            # Volatile system state
└── logs/                     # Copied log files
```

## Linux-Specific Features

- Uses Linux-specific tools and commands (`ss` instead of `netstat`, `ip` instead of `ifconfig`)
- Collects Linux-specific artifacts (kernel modules, systemd services, etc.)
- Handles Linux filesystem structure and important directories
- Uses `gcore` for process memory dumping (more reliable on Linux)
- Captures iptables/nftables firewall rules
- Gathers system log files from standard Linux locations

## Disclaimer

This tool is designed for educational purposes and authorized digital forensics and incident response activities on Linux systems only. 

**Important:**
- Only use on systems you own or have explicit permission to investigate
- The author is not responsible for misuse of this tool
- Ensure compliance with local laws and regulations
- Some features require specific Linux tools to be installed

## Legal and Ethical Considerations

Always follow proper legal procedures when conducting digital forensics on Linux systems:
1. Obtain proper authorization before investigating any system
2. Follow chain of custody procedures for evidence preservation
3. Document all actions taken during the investigation
4. Ensure evidence is stored securely and not tampered with
5. Be aware that collecting certain data (like process memory) may affect system stability

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- New Linux-specific evidence collection modules
- Support for additional Linux distributions
- Documentation improvements

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

D3One - [GitHub Profile](https://github.com/D3One)

## Acknowledgments

- Inspired by various Linux digital forensics and incident response methodologies
- Uses concepts from SANS FOR508 Advanced Digital Forensics and Incident Response
- Incorporates best practices from NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response
- Based on Linux-specific forensic techniques and tools
```

This Linux-specific DFIR script includes all the requested features with detailed comments and a comprehensive README. It's specifically designed for Linux systems with appropriate tools and commands for that environment. The script includes progress indicators, error handling, integrity verification, and detailed reporting as requested.

