
# DFIR Evidence Collection Tool - Windows Dumper

A Python-based digital forensics and incident response script for collecting evidence from compromised systems during cybersecurity investigations.

## Features

- **System Information Collection**: Gathers comprehensive system data (OS version, users, network config, etc.)
- **Process Memory Dumping**: Captures memory from specified processes for later analysis
- **Network Evidence Collection**: 
  - Captures active network connections
  - Records routing tables
  - Captures live network traffic to PCAP files
- **Disk Imaging**: Creates forensic images of specified directories
- **Progress Tracking**: Shows progress bars for each collection task
- **Comprehensive Reporting**: Generates detailed JSON and text reports of all collected evidence
- **Error Handling**: Robust exception handling with detailed error logging

## Requirements

- Python 3.6+
- Administrative/root privileges
- Additional tools (will be checked during execution):
  - `procdump` (Sysinternals) for process memory dumping
  - `tcpdump` for network traffic capture
  - `dd` for disk imaging
  - `gzip` for compression of large files

## Installation

1. Clone the repository:
```bash
git clone https://github.com/D3One/DFIR-Evidence-Collection-Tool.git
cd DFIR-Evidence-Collection-Tool
```

2. Install Python dependencies:
```bash
pip install progress
```

3. Ensure required tools are installed on the system:
   - On Windows: Download Sysinternals Suite and add to PATH
   - On Linux: Install using package manager:
   ```bash
   sudo apt-get install tcpdump dd gzip
   ```

## Usage

1. Run with administrative privileges:
```bash
# On Windows
runas /user:Administrator python dfir_collector.py

# On Linux
sudo python dfir_collector.py
```

2. The script will:
   - Create an output directory with timestamp
   - Collect system information
   - Dump specified processes from memory
   - Capture network data
   - Create disk images of specified directories
   - Generate comprehensive reports

3. Customize the configuration in the script:
```python
CONFIG = {
    "processes_to_dump": ["lsass.exe", "svchost.exe", "explorer.exe"],
    "directories_to_image": ["C:\\Windows\\System32\\config", "C:\\Users"],
    "output_directory": "./dfir_collection",
    "network_capture_duration": 60,
    "max_file_size_mb": 500
}
```

## Output

The script creates the following structure in the output directory:
```
dfir_collection/
├── collection_report.json     # Comprehensive JSON report
├── collection_summary.txt     # Human-readable summary
├── memory/                    # Process memory dumps
├── disk_images/              # Directory images
├── network/                  # Network data (PCAP, connections)
└── system_info/              # System information
```

## Disclaimer

This tool is designed for educational purposes and authorized digital forensics and incident response activities only. 

**Important:**
- Only use on systems you own or have explicit permission to investigate
- The author is not responsible for misuse of this tool
- Ensure compliance with local laws and regulations
- Some features may require additional tools to be installed

## Legal and Ethical Considerations

Always follow proper legal procedures when conducting digital forensics:
1. Obtain proper authorization before investigating any system
2. Follow chain of custody procedures for evidence preservation
3. Document all actions taken during the investigation
4. Ensure evidence is stored securely and not tampered with

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:
- Bug fixes
- New features
- Documentation improvements
- Additional evidence collection modules

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

D3One - [GitHub Profile](https://github.com/D3One)

## Acknowledgments

- Inspired by various digital forensics and incident response methodologies
- Uses concepts from SANS FOR508 Advanced Digital Forensics and Incident Response
- Incorporates best practices from NIST SP 800-86 Guide to Integrating Forensic Techniques into Incident Response
```

This script provides a comprehensive approach to digital evidence collection with proper error handling, progress tracking, and reporting features. The README includes all necessary information for users to understand, install, and use the tool effectively while emphasizing the legal and ethical considerations of digital forensics work.
