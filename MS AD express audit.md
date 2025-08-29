

# Windows Server Security Express Audit Tool

### PowerShell Script: Windows Server Security Express Audit Tool

## Description

A PowerShell script designed to perform basic express security audits on Windows Servers with roles like Active Directory Domain Controller, DNS, DHCP, and others. The script checks essential security configurations and generates a structured report with remediation recommendations for identified issues.

<img width="1472" height="1104" alt="image" src="https://github.com/user-attachments/assets/a54cb439-0e45-46cb-8a5a-d1a998e9e49c" />

## Features

- Password and account lockout policy analysis
- Service and firewall configuration checks
- System update status verification
- RDP, UAC, and SMB settings audit
- Remote scanning capability
- Multiple output formats (TXT, CSV, HTML)
- Progress indicator during execution

## Requirements

- Windows PowerShell 5.0 or later
- Administrative privileges for full functionality
- Active Directory module (for AD-related checks)
- Network access to target servers (for remote scanning)

## Installation

1. Copy the script to the server where the audit will be performed
2. Enable PowerShell script execution if needed:
   ```powershell
   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```
3. Ensure required modules are installed:
   ```powershell
   Install-WindowsFeature -Name RSAT-AD-PowerShell
   ```

## Usage

### Local audit:
```powershell
.\SecurityAudit.ps1
```

### Remote server audit:
```powershell
.\SecurityAudit.ps1 -ComputerName "SERVER01" -RemoteScan
```

### Generate report in specific format:
```powershell
.\SecurityAudit.ps1 -Format CSV -OutputPath "C:\AuditReports"
```

### Available parameters:
- `-ComputerName`: Target server name (default: local computer)
- `-OutputPath`: Report output directory (default: current directory)
- `-Format`: Report format (TXT, CSV, HTML; default: TXT)
- `-RemoteScan`: Flag for remote scanning
- `-Credential`: Credentials for remote access (optional)

## Sample Output

```
Security Audit Results:
================================================
Category          Check                       Status RiskLevel
--------          -----                       ------ ---------
Password Policy   Minimum Password Length     FAIL   High
Account Lockout   Account Lockout Threshold   PASS   Low
Password Policy   Never Expiring Passwords    FAIL   High
Services          Insecure Services           PASS   Low
```

## Report Structure

The report includes the following fields for each security check:
- **Category**: Check category
- **Check**: Specific check name
- **Status**: Result (PASS/FAIL/WARNING)
- **RiskLevel**: Risk level (High/Medium/Low)
- **Description**: Problem description
- **Remediation**: Fix recommendations
- **Reference**: Additional resources (MITRE, CVE, MSFT)
- **Timestamp**: Check execution time
- **Computer**: Target server name

## Important Notes

- This script is for educational and research purposes only
- Ensure you have proper authorization before scanning any systems
- The author is not responsible for any damage or misuse of this script
- Test in an isolated environment before using in production

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support and Contribution

For feature requests or bug reports, please create an issue in the project repository.

## Acknowledgments

- Microsoft for security documentation
- MITRE for CVE and CWE knowledge bases
- Security community for best practices
```
