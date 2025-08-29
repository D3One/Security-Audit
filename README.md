
# Security Audit Toolkit

![GitHub](https://img.shields.io/github/license/D3One/Security-Audit)
![GitHub last commit](https://img.shields.io/github/last-commit/D3One/Security-Audit)
![Maintenance](https://img.shields.io/maintenance/yes/2024)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

A curated collection of personal scripts, code samples, templates, and tools developed and used for conducting security audits across diverse enterprise environments.

<img width="1472" height="1104" alt="image" src="https://github.com/user-attachments/assets/772a5e32-ad18-4066-bf77-b0387f438385" />

## 📖 Overview

This repository serves as my personal knowledge base and toolkit, accumulated through hands-on experience in infrastructure security auditing. It contains custom scripts, configuration templates, and checklists designed to assess the security posture of various technologies, including:

*   **Operating Systems:** Windows Server, Linux distributions
*   **Databases:** Microsoft SQL Server, SAP HANA/ASE
*   **Web Servers:** Apache HTTP Server, Nginx, IIS
*   **Network Services:** Active Directory, DNS, DHCP
*   **Middleware and Applications**

_The tools here are provided as-is to help security professionals, students, and enthusiasts understand common audit procedures and learn how to build their own automation._

- - - 

## [DFIR Evidence Collection Tool - Windows Dumper](https://github.com/D3One/Security-Audit/blob/main/Windows%20Dumper.md)
## [Linux DFIR Evidence Collection Tool](https://github.com/D3One/Security-Audit/blob/main/Linux%20Dumper.md)
## [PowerShell Script: Windows Server Security Express Audit Tool](https://github.com/D3One/Security-Audit/blob/main/MS%20AD%20express%20audit.md)

- - - 

## ⚠️ Important Disclaimer & Warning

**PLEASE READ THIS CAREFULLY BEFORE USING ANY MATERIAL FROM THIS REPOSITORY.**

*   **Educational Purpose Only:** This repository and all its contents are provided **strictly for educational and research purposes**. They are intended to be used in authorized lab environments for learning about security principles and audit techniques.
*   **No Warranty:** All scripts, code, and templates are offered **"AS IS" without any warranty**, express or implied. The author (**D3One**) assumes **no responsibility** for any damage, loss of data, or system instability caused by the use or misuse of these tools.
*   **Use at Your Own Risk:** You are solely responsible for any consequences resulting from the application of these scripts. **Always ensure you have explicit, written permission** to scan, test, or audit any system that you do not own.
*   **Outdated Code:** Technology evolves rapidly. These scripts might be **outdated** and not fully compatible with the latest software versions (e.g., newer Windows Server releases, updated SAP kernels, modern Apache versions). It is **YOUR responsibility** to review, test, and adapt any script to your specific environment and the target software version before running it.
*   **Not for Malicious Use:** This toolkit is designed for defensive security and improving infrastructure resilience. **Do not use it for any malicious or unauthorized activities.**

## 🛠️ What's Inside?

The repository is organized into directories for different technologies:

*   `/windows-audit/`
    *   PowerShell scripts for auditing Active Directory, Group Policy, OS hardening, and service configurations.
    *   Example: `Invoke-WindowsBaselineAudit.ps1` - A comprehensive check for common misconfigurations.
*   `/linux-audit/`
    *   Bash scripts and configuration checkers for common Linux security benchmarks (inspired by CIS).
*   `/sap-audit/`
    *   SQL scripts and notes for reviewing SAP security parameters, user authorizations, and system configurations.
*   `/mssql-audit/`
    *   T-SQL scripts to check for weak SQL Server settings, excessive permissions, and trace flags.
*   `/web-server-audit/`
    *   Templates and scripts for reviewing Apache/HTTPD and IIS configuration files for security issues.
*   `/templates/`
    *   Custom templates for audit reports, findings databases, and checklists.

## 🚀 Getting Started

### Prerequisites

*   A test/lab environment. **DO NOT RUN THESE SCRIPTS ON PRODUCTION SYSTEMS WITHOUT PROPER APPROVAL AND TESTING.**
*   Appropriate permissions on the target systems you are authorized to audit.
*   Basic knowledge of:
    *   PowerShell (for Windows scripts)
    *   Bash (for Linux scripts)
    *   SQL (for database scripts)
*   A text editor or IDE to review and modify the code before execution.

### Installation

1.  Clone the repository to your local machine:
    ```bash
    git clone https://github.com/D3One/Security-Audit.git
    ```
2.  Navigate to the directory of the tool you wish to use.
3.  **CRITICAL:** Open the script in a text editor. Carefully review the code.
    *   Understand what it does.
    *   Change any hard-coded variables (like usernames, IP addresses, paths) to match your test environment.
    *   Check for compatibility with your target's software version.

### Basic Usage

1.  **Adapt:** Modify the script for your specific environment and the version of the software you are auditing.
2.  **Test:** Run the script in a safe, isolated lab environment first to verify its functionality and output.
3.  **Execute:** Run the script on your authorized target system. Most scripts will output results to the console or a log file.
    *   **Example for a PowerShell script:**
        ```powershell
        # Review and adapt the script first!
        .\Invoke-WindowsBaselineAudit.ps1 -ComputerName "LAB-SERVER01" -OutputFormat CSV
        ```

## 📝 Contributing

Contributions are welcome! If you have a script, template, or improvement that aligns with the repository's goal, please feel free to:
1.  Fork the repo.
2.  Create a feature branch (`git checkout -b feature/AmazingScript`).
3.  Commit your changes (`git commit -m 'Add some AmazingScript'`).
4.  Push to the branch (`git push origin feature/AmazingScript`).
5.  Open a Pull Request.

Please ensure your contributions come with clear comments and a description of their purpose.

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details. This permissive license allows for reuse but comes with no liability.

## 🤝 Contact & Acknowledgement

*   **Maintainer:** D3One
*   **GitHub:** [https://github.com/D3One](https://github.com/D3One)

This repository is a compilation of personal work and community knowledge. Special thanks to the wider infosec community for its shared wisdom and resources that inspired many of these tools.

---

**Remember: Always Ethically Hack, Always Get Permission.**
