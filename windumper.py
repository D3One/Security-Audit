#!/usr/bin/env python3
"""
DFIR Evidence Collection Tool
Version: 1.0
Author: D3One | Ivan Piskunov
Description: A script for collecting digital evidence during incident response investigations for MS WINDOWS platform.
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
from datetime import datetime
from pathlib import Path

try:
    from progress.bar import Bar
    HAS_PROGRESS = True
except ImportError:
    HAS_PROGRESS = False
    print("Progress library not found. Install with: pip install progress")

# Configuration
CONFIG = {
    "processes_to_dump": ["lsass.exe", "svchost.exe", "explorer.exe", "winlogon.exe"],
    "directories_to_image": ["C:\\Windows\\System32\\config", "C:\\Windows\\Temp", "C:\\Users"],
    "output_directory": "./dfir_collection",
    "network_capture_duration": 60,  # seconds
    "max_file_size_mb": 500  # Maximum size for disk images
}

class DFIRCollector:
    def __init__(self, config):
        self.config = config
        self.start_time = time.time()
        self.results = {
            "collection_time": datetime.now().isoformat(),
            "system_info": {},
            "collected_evidence": {},
            "errors": [],
            "status": {}
        }
        
        # Create output directory
        self.output_dir = Path(config["output_directory"])
        self.output_dir.mkdir(exist_ok=True)
        
        # Subdirectories for different evidence types
        self.memory_dir = self.output_dir / "memory"
        self.disk_dir = self.output_dir / "disk_images"
        self.network_dir = self.output_dir / "network"
        self.system_dir = self.output_dir / "system_info"
        
        for directory in [self.memory_dir, self.disk_dir, self.network_dir, self.system_dir]:
            directory.mkdir(exist_ok=True)
    
    def log_error(self, error_msg):
        """Log errors during evidence collection"""
        print(f"ERROR: {error_msg}")
        self.results["errors"].append(error_msg)
    
    def run_command(self, command, description):
        """Execute system command and handle errors"""
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=300)
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
        """Collect basic system information"""
        bar = self.show_progress("Collecting system information", 10)
        
        try:
            # System information
            system_info = {
                "hostname": platform.node(),
                "os_version": platform.platform(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "boot_time": self.run_command("systeminfo | find \"System Boot Time\"", "Get boot time"),
                "current_user": os.getlogin(),
                "timezone": time.tzname,
                "network_interfaces": self.run_command("ipconfig /all", "Get network configuration")
            }
            
            # User accounts
            system_info["users"] = self.run_command("net user", "Get user accounts")
            
            # Running services
            system_info["services"] = self.run_command("sc query", "Get services")
            
            # Scheduled tasks
            system_info["scheduled_tasks"] = self.run_command("schtasks /query /fo LIST", "Get scheduled tasks")
            
            # Installled programs
            system_info["installed_programs"] = self.run_command("wmic product get name,version", "Get installed programs")
            
            self.results["system_info"] = system_info
            
            # Save to file
            with open(self.system_dir / "system_info.json", "w") as f:
                json.dump(system_info, f, indent=4)
                
            self.update_progress(bar, 10)
            if bar: bar.finish()
            self.results["status"]["system_info"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"System info collection failed: {str(e)}")
            self.results["status"]["system_info"] = "Failed"
            return False
    
    def dump_process_memory(self):
        """Dump specific processes from memory"""
        bar = self.show_progress("Dumping process memory", len(self.config["processes_to_dump"]))
        
        try:
            # Get list of running processes
            processes_output = self.run_command("tasklist", "Get process list")
            if not processes_output:
                self.log_error("Could not retrieve process list")
                return False
            
            dumped_processes = []
            
            for process_name in self.config["processes_to_dump"]:
                # Check if process is running
                if process_name in processes_output:
                    # Use procdump from Sysinternals to dump process memory
                    dump_file = self.memory_dir / f"{process_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.dmp"
                    result = self.run_command(
                        f"procdump -ma {process_name} {dump_file}", 
                        f"Dump {process_name} memory"
                    )
                    
                    if result and dump_file.exists():
                        dumped_processes.append({
                            "process_name": process_name,
                            "dump_file": str(dump_file),
                            "size_mb": os.path.getsize(dump_file) / (1024 * 1024)
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
        bar = self.show_progress("Capturing network data", 3)
        
        try:
            # Get network connections
            connections = self.run_command("netstat -ano", "Get network connections")
            if connections:
                with open(self.network_dir / "network_connections.txt", "w") as f:
                    f.write(connections)
            
            self.update_progress(bar)
            
            # Get routing table
            routing_table = self.run_command("route print", "Get routing table")
            if routing_table:
                with open(self.network_dir / "routing_table.txt", "w") as f:
                    f.write(routing_table)
            
            self.update_progress(bar)
            
            # Capture network traffic with tcpdump (if available)
            pcap_file = self.network_dir / f"network_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
            tcpdump_cmd = f"tcpdump -i any -w {pcap_file} -G {self.config['network_capture_duration']} -W 1"
            self.run_command(tcpdump_cmd, "Capture network traffic")
            
            if pcap_file.exists():
                self.results["collected_evidence"]["pcap_file"] = str(pcap_file)
            
            self.update_progress(bar, 3)
            if bar: bar.finish()
            self.results["status"]["network_capture"] = "Success"
            return True
            
        except Exception as e:
            self.log_error(f"Network data capture failed: {str(e)}")
            self.results["status"]["network_capture"] = "Failed"
            return False
    
    def create_disk_images(self):
        """Create disk images of specified directories"""
        bar = self.show_progress("Creating disk images", len(self.config["directories_to_image"]))
        
        try:
            disk_images = []
            
            for directory in self.config["directories_to_image"]:
                if os.path.exists(directory):
                    dir_name = directory.replace(":", "").replace("\\", "_")
                    image_file = self.disk_dir / f"{dir_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.img"
                    
                    # Use dd to create a raw image of the directory
                    # Note: This is a simplified approach. In real forensics, you might use more specialized tools
                    dd_cmd = f"dd if={directory} of={image_file} bs=4M status=progress"
                    result = self.run_command(dd_cmd, f"Create disk image of {directory}")
                    
                    if result and image_file.exists():
                        size_mb = os.path.getsize(image_file) / (1024 * 1024)
                        
                        # Check if image is too large and compress if needed
                        if size_mb > self.config["max_file_size_mb"]:
                            compressed_file = f"{image_file}.gz"
                            self.run_command(f"gzip {image_file}", f"Compress {image_file}")
                            image_file = Path(compressed_file)
                        
                        disk_images.append({
                            "directory": directory,
                            "image_file": str(image_file),
                            "size_mb": size_mb
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
                    os.path.getsize(Path(file_path)) / (1024 * 1024) 
                    for evidence_type in self.results["collected_evidence"].values() 
                    for item in (evidence_type if isinstance(evidence_type, list) else [evidence_type])
                    for file_path in [item["image_file"] if "image_file" in item else item] 
                    if isinstance(item, dict) and "image_file" in item
                )
            }
            
            # Save comprehensive report
            report_file = self.output_dir / "collection_report.json"
            with open(report_file, "w") as f:
                json.dump(self.results, f, indent=4)
            
            # Save human-readable summary
            summary_file = self.output_dir / "collection_summary.txt"
            with open(summary_file, "w") as f:
                f.write("DFIR EVIDENCE COLLECTION SUMMARY\n")
                f.write("================================\n\n")
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
                                f.write(f"  {key}: {value}\n")
                            f.write("\n")
                    else:
                        f.write(f"  {evidence_data}\n")
                
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
        print("Starting DFIR evidence collection...")
        print(f"Output directory: {self.output_dir}")
        print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)
        
        # Run collection steps
        steps = [
            ("System Information Collection", self.collect_system_info),
            ("Process Memory Dumping", self.dump_process_memory),
            ("Network Data Capture", self.capture_network_data),
            ("Disk Imaging", self.create_disk_images)
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
        print("\n" + "=" * 50)
        print("DFIR EVIDENCE COLLECTION COMPLETE")
        print("=" * 50)
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
    # Check if running with administrative privileges
    if os.name == 'nt' and not os.getuid() == 0:
        try:
            # Try to relaunch with admin rights on Windows
            if not subprocess.run(["net", "session"], capture_output=True).returncode == 0:
                print("This script requires administrative privileges.")
                print("Please run as Administrator.")
                return
        except:
            print("This script requires administrative privileges.")
            print("Please run as Administrator.")
            return
    elif not os.geteuid() == 0:
        print("This script requires root privileges.")
        print("Please run with sudo.")
        return
    
    # Initialize collector
    collector = DFIRCollector(CONFIG)
    
    # Run evidence collection
    collector.run_collection()

if __name__ == "__main__":
    main()
