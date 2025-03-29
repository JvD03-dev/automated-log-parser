# Automated Log Parser

A Python-based log parser for cybersecurity analysis. This tool helps analyze various types of log files to identify potential security threats and suspicious activities.

## Features

- Parse different types of log files (Apache, system logs, security logs)
- Identify suspicious IP addresses and patterns
- Generate statistical reports
- Support for custom log formats

## Requirements

- Python 3.8 or higher
- Required packages listed in requirements.txt

## Installation

1. Clone this repository
2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

Run the log parser:
```bash
python log_parser.py --file path/to/your/logfile.log
```

## Sample Log Files

The `sample_logs` directory contains example log files for testing:
- apache_access.log: Sample Apache web server access logs
- system.log: Sample system logs
- security.log: Sample security logs

## Output

The parser generates:
- Statistical analysis of log entries
- List of suspicious activities
- Summary report in both console and file format

## How We Detect Suspicious Activities

### 1. Failed Login Attempts
- We track multiple failed login attempts from the same IP address
- Example: If an IP tries to login more than 3 times in a short period
- Found in: Apache logs (401 status codes) and system logs (SSH failures)

### 2. Brute Force Attacks
- Detected by analyzing patterns of rapid login attempts
- Looks for multiple failed authentication attempts in quick succession
- Example: 5+ failed login attempts within 1 minute
- Found in: All log types (Apache, system, security)

### 3. Port Scanning
- Identifies multiple connection attempts to different ports
- Looks for rapid-fire connection attempts from single IP
- Example: Multiple "Dropped packet" messages from same IP
- Found in: System logs (firewall messages)

### 4. Suspicious IP Addresses
- Checks if IPs are from private ranges (192.168.x.x, 10.x.x.x)
- Identifies IPs making multiple failed requests
- Example: IP with high number of 401/403 responses
- Found in: All log types

### 5. Web-Based Attacks
- SQL Injection attempts (looks for SQL-like patterns in URLs)
- XSS attempts (looks for script tags and JavaScript code)
- Directory traversal attempts (looks for ../ patterns)
- Example: URLs containing ' OR '1'='1 or <script> tags
- Found in: Apache logs

### 6. Denial of Service (DoS) Attempts
- Detects rapid-fire requests from single IP
- Looks for unusual request patterns
- Example: 10+ requests per second from same IP
- Found in: Apache logs

### 7. Unauthorized Access Attempts
- Tracks attempts to access restricted areas
- Monitors admin panel access attempts
- Example: Multiple 403 Forbidden responses
- Found in: Apache logs and security logs

### 8. System-Level Suspicious Activities
- Failed sudo attempts
- Multiple failed SSH connections
- System service restarts
- Example: Multiple "authentication failure" messages
- Found in: System logs and security logs

## Common Attack Patterns We Detect

1. **Authentication Attacks**
   - Multiple failed login attempts
   - Brute force attempts
   - Password spraying

2. **Web Application Attacks**
   - SQL Injection
   - Cross-Site Scripting (XSS)
   - Directory Traversal
   - File Inclusion Attempts

3. **Network Attacks**
   - Port Scanning
   - Denial of Service
   - Suspicious IP ranges

4. **System Attacks**
   - Privilege Escalation Attempts
   - Service Manipulation
   - Unauthorized Access Attempts

## Understanding the Output

The parser provides colored output for better visibility:
- 🔴 Red: Critical security issues
- 🟡 Yellow: Warnings and suspicious activities
- 🟢 Green: Normal activities
- 🔵 Blue: Information and statistics

Each suspicious activity is tagged with:
- Timestamp
- IP Address
- Type of attack
- Severity level
- Additional context 