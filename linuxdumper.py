#!/usr/bin/env python3
"""
Linux DFIR Evidence Collection Tool
Version: 1.1
Author: D3One | Ivan Piskunov 
Description: A Linux-specific script for collecting digital evidence during incident response investigations.
Disclaimer: This tool is for educational and authorized forensic purposes only. 
            The author is not responsible for misuse or damage caused by this tool.
"""

import os
import sys
import time
import json
import shutil
import subprocess
import platform
import argparse
from datetime import datetime
from pathlib import Path

try:
    from progress.bar import Bar
    HAS_PROGRESS = True
except ImportError:
    HAS_PROGRESS = False
    print("Progress library not found. Install with: pip install progress")

# Configuration for Linux systems
CONFIG = {
    "processes_to_dump": ["sshd", "bash", "systemd", "nginx", "apache2", "mysql"],
    "directories_to_image": ["/etc", "/var/log", "/tmp", "/home"],
    "output_directory": "./linux_dfir_collection",
    "network_capture_duration": 60,  # seconds
    "max_file_size_mb": 500,  # Maximum size for disk images
    "hash_algorithms": ["md5", "sha1", "sha256"]  # For evidence integrity
}

class LinuxDFIRCollector:
    def __init__(self, config):
        self.config = config
        self.start_time = time.time()
        self.results = {
            "collection_time": datetime.now().isoformat(),
            "system_info": {},
            "collected_evidence": {},
            "errors": [],
            "status": {},
            "integrity_hashes": {}
        }
        
        # Create output directory
        self.output_dir = Path(config["output_directory"])
        self.output_dir.mkdir(exist_ok=True)
        
        # Subdirectories for different evidence types
        self.memory_dir = self.output_dir / "memory"
        self.disk_dir = self.output_dir / "disk_images"
        self.network_dir = self.output_dir / "network"
        self.system_dir = self.output_dir / "system_info"
        self.volatile_dir = self.output_dir / "volatile_data"
        
        for directory in [self.memory_dir, self.disk_dir, self.network_dir, 
                          self.system_dir, self.volatile_dir]:
            directory.mkdir(exist_ok=True)
    
    def log_error(self, error_msg):
        """Log errors during evidence collection"""
        print(f"ERROR: {error_msg}")
        self.results["errors"].append(error_msg)
    
    def run_command(self, command, description, timeout=300):
        """Execute system command and handle errors"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, 
                                   text=True, timeout=timeout)
            if result.returncode != 0:
                self.log_error(f"{description} failed: {result.stderr}")
                return None
            return result.stdout
        except subprocess.TimeoutExpired:
            self.log_error(f"{description} timed out")
            return None
        except Exception as e:
            self.log_error(f"{description} exception: {str(e)}")
            return None
    
    def calculate_hashes(self, file_path):
        """Calculate hash values for file integrity verification"""
        hashes = {}
        for algorithm in self.config["hash_algorithms"]:
            try:
                hash_result = subprocess.run(
                    f"{algorithm}sum {file_path}", 
                    shell=True, capture_output=True, text=True
                )
                if hash_result.returncode == 0:
                    hashes[algorithm] = hash_result.stdout.split()[0]
            except Exception as e:
                self.log_error(f"Hash calculation failed for {algorithm}: {str(e)}")
        return hashes
    
    def show_progress(self, message, max_value=100):
        """Display progress bar if available, otherwise simple message"""
        if HAS_PROGRESS:
            return Bar(message, max=max_value)
        else:
            print(f"{message}...")
            return None
    
    def update_progress(self, bar, value=None):
        """Update progress bar if available"""
        if bar and HAS_PROGRESS:
            if value:
                bar.goto(value)
            else:
                bar.next()
    
    def collect_system_info(self):
        """Collect basic Linux system information"""
        bar = self.show_progress("Collecting system information", 15)
        
        try:
            # System information
            system_info = {
                "hostname": self.run_command("hostname", "Get hostname"),
                "os_version": self.run_command("cat /etc/os-release", "Get OS version"),
                "kernel_version": self.run_command("uname -a", "Get kernel version"),
                "architecture": platform.machine(),
                "boot_time": self.run_command("who -b", "Get boot time"),
                "current_user": os.getlogin(),
                "timezone": self.run_command("cat /etc/timezone", "Get timezone"),
                "uptime": self.run_command("uptime", "Get uptime"),
                "mounts": self.run_command("mount", "Get mount points"),
                "disk_usage": self.run_command("df -h", "Get disk usage"),
                "memory_usage": self.run_command("free -h", "Get memory usage")
            }
            
            # User accounts
            system_info["users"] = self.run_command("cat /etc/passwd", "Get user accounts")
            system_info["shadow"] = self.run_command("cat /etc/shadow", "Get shadow file", timeout=10)
            system_info["sudoers"] = self.run_command("cat /etc/sudoers", "Get sudoers", timeout=10)
            
            # Network configuration
            system_info["network_interfaces"] = self.run_command("ip addr show", "Get network interfaces")
            system_info["dns_config"] = self.run_command("cat /etc/resolv.conf", "Get DNS config")
            
            # Running services
            system_info["services"] = self.run_command("systemctl list-units --type=service", "Get services")
            
            # Cron jobs
            system_info["cron_jobs"] = self.run_command("ls /etc/cron.*", "Get cron jobs")
            
            self.results["system_info"] = system_info
            
            # Save to file
            with open(self.system_dir / "system_info.json", "w") as f:
                json.dump(system_info, f, indent=4)
                
            self.update_progress(bar, 15)
            if bar: bar.finish()
            self.results["status"]["system_info"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"System info collection failed: {str(e)}")
            self.results["status"]["system_info"] = "Failed"
            return False
    
    def collect_volatile_data(self):
        """Collect volatile data that might change quickly"""
        bar = self.show_progress("Collecting volatile data", 10)
        
        try:
            volatile_data = {
                "processes": self.run_command("ps aux", "Get running processes"),
                "network_connections": self.run_command("netstat -tunap", "Get network connections"),
                "open_files": self.run_command("lsof", "Get open files", timeout=60),
                "loaded_modules": self.run_command("lsmod", "Get loaded kernel modules"),
                "arp_table": self.run_command("arp -a", "Get ARP table"),
                "routing_table": self.run_command("route -n", "Get routing table"),
                "logged_in_users": self.run_command("who", "Get logged in users"),
                "history": self.run_command("history", "Get command history", timeout=10),
                "environment_variables": self.run_command("env", "Get environment variables")
            }
            
            # Save each volatile data to separate files
            for key, value in volatile_data.items():
                if value:
                    with open(self.volatile_dir / f"{key}.txt", "w") as f:
                        f.write(value)
            
            self.update_progress(bar, 10)
            if bar: bar.finish()
            self.results["status"]["volatile_data"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"Volatile data collection failed: {str(e)}")
            self.results["status"]["volatile_data"] = "Failed"
            return False
    
    def dump_process_memory(self):
        """Dump specific processes from memory using gcore"""
        bar = self.show_progress("Dumping process memory", len(self.config["processes_to_dump"]))
        
        try:
            # Get list of running processes
            processes_output = self.run_command("ps aux", "Get process list")
            if not processes_output:
                self.log_error("Could not retrieve process list")
                return False
            
            dumped_processes = []
            
            for process_name in self.config["processes_to_dump"]:
                # Find PIDs for the process name
                pids = []
                for line in processes_output.split('\n'):
                    if process_name in line and not line.startswith('awk') and not 'grep' in line:
                        try:
                            pid = line.split()[1]
                            pids.append(pid)
                        except:
                            continue
                
                for pid in pids:
                    # Use gcore to dump process memory
                    dump_file = self.memory_dir / f"{process_name}_{pid}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.core"
                    result = self.run_command(
                        f"gcore -o {dump_file} {pid}", 
                        f"Dump {process_name} (PID: {pid}) memory"
                    )
                    
                    if result and dump_file.exists():
                        # Calculate hashes for integrity verification
                        hashes = self.calculate_hashes(dump_file)
                        dumped_processes.append({
                            "process_name": process_name,
                            "pid": pid,
                            "dump_file": str(dump_file),
                            "size_mb": os.path.getsize(dump_file) / (1024 * 1024),
                            "hashes": hashes
                        })
                
                self.update_progress(bar)
            
            self.results["collected_evidence"]["memory_dumps"] = dumped_processes
            if bar: bar.finish()
            self.results["status"]["memory_dumps"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"Process memory dump failed: {str(e)}")
            self.results["status"]["memory_dumps"] = "Failed"
            return False
    
    def capture_network_data(self):
        """Capture network connections and traffic"""
        bar = self.show_progress("Capturing network data", 4)
        
        try:
            # Get network connections
            connections = self.run_command("ss -tunap", "Get network connections")
            if connections:
                with open(self.network_dir / "network_connections.txt", "w") as f:
                    f.write(connections)
            
            self.update_progress(bar)
            
            # Get routing table
            routing_table = self.run_command("ip route show", "Get routing table")
            if routing_table:
                with open(self.network_dir / "routing_table.txt", "w") as f:
                    f.write(routing_table)
            
            self.update_progress(bar)
            
            # Get iptables rules
            iptables = self.run_command("iptables -L -n -v", "Get iptables rules")
            if iptables:
                with open(self.network_dir / "iptables_rules.txt", "w") as f:
                    f.write(iptables)
            
            self.update_progress(bar)
            
            # Capture network traffic with tcpdump
            pcap_file = self.network_dir / f"network_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            tcpdump_cmd = f"timeout {self.config['network_capture_duration']} tcpdump -i any -w {pcap_file}"
            self.run_command(tcpdump_cmd, "Capture network traffic")
            
            if pcap_file.exists():
                # Calculate hashes for integrity verification
                hashes = self.calculate_hashes(pcap_file)
                self.results["collected_evidence"]["pcap_file"] = {
                    "path": str(pcap_file),
                    "size_mb": os.path.getsize(pcap_file) / (1024 * 1024),
                    "hashes": hashes
                }
            
            self.update_progress(bar, 4)
            if bar: bar.finish()
            self.results["status"]["network_capture"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"Network data capture failed: {str(e)}")
            self.results["status"]["network_capture"] = "Failed"
            return False
    
    def create_disk_images(self):
        """Create disk images of specified directories using tar for preservation"""
        bar = self.show_progress("Creating disk images", len(self.config["directories_to_image"]))
        
        try:
            disk_images = []
            
            for directory in self.config["directories_to_image"]:
                if os.path.exists(directory):
                    dir_name = directory.replace("/", "_")
                    image_file = self.disk_dir / f"{dir_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.tar.gz"
                    
                    # Use tar to create a compressed archive with preservation of permissions and metadata
                    tar_cmd = f"tar -czf {image_file} {directory}"
                    result = self.run_command(tar_cmd, f"Create disk image of {directory}", timeout=600)
                    
                    if result and image_file.exists():
                        # Calculate hashes for integrity verification
                        hashes = self.calculate_hashes(image_file)
                        size_mb = os.path.getsize(image_file) / (1024 * 1024)
                        
                        disk_images.append({
                            "directory": directory,
                            "image_file": str(image_file),
                            "size_mb": size_mb,
                            "hashes": hashes
                        })
                
                self.update_progress(bar)
            
            self.results["collected_evidence"]["disk_images"] = disk_images
            if bar: bar.finish()
            self.results["status"]["disk_images"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"Disk image creation failed: {str(e)}")
            self.results["status"]["disk_images"] = "Failed"
            return False
    
    def collect_log_files(self):
        """Collect important log files from the system"""
        bar = self.show_progress("Collecting log files", 5)
        
        try:
            log_files = []
            important_logs = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/secure",
                "/var/log/messages",
                "/var/log/kern.log",
                "/var/log/dmesg",
                "/var/log/audit/audit.log",
                "/var/log/nginx/access.log",
                "/var/log/nginx/error.log",
                "/var/log/apache2/access.log",
                "/var/log/apache2/error.log"
            ]
            
            log_dir = self.output_dir / "logs"
            log_dir.mkdir(exist_ok=True)
            
            for log_path in important_logs:
                if os.path.exists(log_path):
                    log_name = log_path.replace("/", "_")
                    copy_path = log_dir / log_name
                    
                    try:
                        shutil.copy2(log_path, copy_path)
                        # Calculate hashes for integrity verification
                        hashes = self.calculate_hashes(copy_path)
                        log_files.append({
                            "original_path": log_path,
                            "copied_path": str(copy_path),
                            "size_mb": os.path.getsize(copy_path) / (1024 * 1024),
                            "hashes": hashes
                        })
                    except Exception as e:
                        self.log_error(f"Failed to copy log file {log_path}: {str(e)}")
                
                self.update_progress(bar)
            
            self.results["collected_evidence"]["log_files"] = log_files
            if bar: bar.finish()
            self.results["status"]["log_files"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"Log file collection failed: {str(e)}")
            self.results["status"]["log_files"] = "Failed"
            return False
    
    def generate_report(self):
        """Generate a summary report of the collection process"""
        bar = self.show_progress("Generating report", 1)
        
        try:
            # Calculate collection duration
            duration = time.time() - self.start_time
            
            # Add summary information
            self.results["summary"] = {
                "collection_duration_seconds": round(duration, 2),
                "investigator": os.getlogin(),
                "hostname": platform.node(),
                "collection_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_evidence_size_mb": sum(
                    item["size_mb"] for evidence_type in self.results["collected_evidence"].values() 
                    for item in (evidence_type if isinstance(evidence_type, list) else [evidence_type])
                )
            }
            
            # Save comprehensive report
            report_file = self.output_dir / "collection_report.json"
            with open(report_file, "w") as f:
                json.dump(self.results, f, indent=4)
            
            # Calculate hash for the report itself
            self.results["integrity_hashes"]["collection_report"] = self.calculate_hashes(report_file)
            
            # Save human-readable summary
            summary_file = self.output_dir / "collection_summary.txt"
            with open(summary_file, "w") as f:
                f.write("LINUX DFIR EVIDENCE COLLECTION SUMMARY\n")
                f.write("======================================\n\n")
                f.write(f"Investigator: {os.getlogin()}\n")
                f.write(f"Host: {platform.node()}\n")
                f.write(f"Collection date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Collection duration: {round(duration, 2)} seconds\n\n")
                
                f.write("EVIDENCE COLLECTED:\n")
                f.write("------------------\n")
                
                for evidence_type, evidence_data in self.results["collected_evidence"].items():
                    f.write(f"\n{evidence_type.upper()}:\n")
                    if isinstance(evidence_data, list):
                        for item in evidence_data:
                            for key, value in item.items():
                                if key != "hashes":  # Don't print hashes in summary
                                    f.write(f"  {key}: {value}\n")
                            f.write("\n")
                    else:
                        for key, value in evidence_data.items():
                            if key != "hashes":  # Don't print hashes in summary
                                f.write(f"  {key}: {value}\n")
                
                f.write("\nSTATUS:\n")
                f.write("------\n")
                for task, status in self.results["status"].items():
                    f.write(f"  {task}: {status}\n")
                
                if self.results["errors"]:
                    f.write("\nERRORS ENCOUNTERED:\n")
                    f.write("------------------\n")
                    for error in self.results["errors"]:
                        f.write(f"  {error}\n")
            
            self.update_progress(bar, 1)
            if bar: bar.finish()
            return True
            
        except Exception as e:
            self.log_error(f"Report generation failed: {str(e)}")
            return False
    
    def run_collection(self):
        """Execute all evidence collection steps"""
        print("Starting Linux DFIR evidence collection...")
        print(f"Output directory: {self.output_dir}")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run collection steps
        steps = [
            ("System Information Collection", self.collect_system_info),
            ("Volatile Data Collection", self.collect_volatile_data),
            ("Process Memory Dumping", self.dump_process_memory),
            ("Network Data Capture", self.capture_network_data),
            ("Disk Imaging", self.create_disk_images),
            ("Log File Collection", self.collect_log_files)
        ]
        
        for step_name, step_func in steps:
            print(f"\n{step_name}:")
            print("-" * len(step_name))
            success = step_func()
            status = "COMPLETED" if success else "FAILED"
            print(f"Status: {status}")
        
        # Generate final report
        print("\nGenerating final report...")
        self.generate_report()
        
        # Print summary
        print("\n" + "=" * 60)
        print("LINUX DFIR EVIDENCE COLLECTION COMPLETE")
        print("=" * 60)
        print(f"Investigator: {os.getlogin()}")
        print(f"Host: {platform.node()}")
        print(f"Collection date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration: {round(time.time() - self.start_time, 2)} seconds")
        
        print("\nEvidence collected:")
        for evidence_type, evidence_data in self.results["collected_evidence"].items():
            if isinstance(evidence_data, list):
                print(f"  {evidence_type}: {len(evidence_data)} items")
            else:
                print(f"  {evidence_type}: 1 item")
        
        if self.results["errors"]:
            print(f"\nErrors encountered: {len(self.results['errors'])}")
            for error in self.results["errors"]:
                print(f"  - {error}")
        
        print(f"\nFull report available at: {self.output_dir / 'collection_report.json'}")
        print(f"Summary available at: {self.output_dir / 'collection_summary.txt'}")

def main():
    """Main function"""
    # Check if running with root privileges
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        print("Please run with sudo.")
        sys.exit(1)
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Linux DFIR Evidence Collection Tool')
    parser.add_argument('-o', '--output', help='Output directory', default=CONFIG['output_directory'])
    parser.add_argument('-p', '--processes', nargs='+', help='Processes to dump', default=CONFIG['processes_to_dump'])
    parser.add_argument('-d', '--directories', nargs='+', help='Directories to image', default=CONFIG['directories_to_image'])
    parser.add_argument('-t', '--timeout', type=int, help='Network capture duration', default=CONFIG['network_capture_duration'])
    
    args = parser.parse_args()
    
    # Update config with command line arguments
    CONFIG['output_directory'] = args.output
    CONFIG['processes_to_dump'] = args.processes
    CONFIG['directories_to_image'] = args.directories
    CONFIG['network_capture_duration'] = args.timeout
    
    # Initialize collector
    collector = LinuxDFIRCollector(CONFIG)
    
    # Run evidence collection
    collector.run_collection()

if __name__ == "__main__":
    main()
