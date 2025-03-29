#!/usr/bin/env python3
import argparse
import re
from datetime import datetime
import pandas as pd
import numpy as np
from collections import defaultdict
import ipaddress
from colorama import init, Fore, Style
import os

init()

class LogParser:
    def __init__(self):
        self.suspicious_ips = set()
        self.suspicious_patterns = [
            r'failed login',
            r'authentication failure',
            r'permission denied',
            r'access denied',
            r'brute force',
            r'port scan',
            r'denial of service'
        ]
        
    def parse_apache_log(self, line):
        pattern = r'(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)'
        match = re.match(pattern, line)
        if match:
            ip, timestamp, request, status, size = match.groups()
            return {
                'ip': ip,
                'timestamp': datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z'),
                'request': request,
                'status': int(status),
                'size': int(size)
            }
        return None

    def parse_system_log(self, line):
        pattern = r'(\w+ \d+ \d+:\d+:\d+) (\S+) (.*)'
        match = re.match(pattern, line)
        if match:
            timestamp, host, message = match.groups()
            return {
                'timestamp': datetime.strptime(timestamp, '%b %d %H:%M:%S'),
                'host': host,
                'message': message
            }
        return None

    def is_suspicious_ip(self, ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return False
            return False
        except ValueError:
            return False

    def analyze_log(self, log_file):
        print(f"{Fore.CYAN}Analyzing log file: {log_file}{Style.RESET_ALL}")
        
        stats = defaultdict(int)
        ip_counts = defaultdict(int)
        suspicious_activities = []
        
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    entry = self.parse_apache_log(line) or self.parse_system_log(line)
                    
                    if entry:
                        if 'ip' in entry:
                            ip_counts[entry['ip']] += 1
                            if self.is_suspicious_ip(entry['ip']):
                                self.suspicious_ips.add(entry['ip'])
                        
                        for pattern in self.suspicious_patterns:
                            if re.search(pattern, str(entry).lower()):
                                suspicious_activities.append({
                                    'timestamp': entry.get('timestamp', 'N/A'),
                                    'message': str(entry)
                                })
                        
                        if 'status' in entry:
                            stats[f'status_{entry["status"]}'] += 1
                        
                        stats['total_entries'] += 1
        
        except FileNotFoundError:
            print(f"{Fore.RED}Error: Log file not found{Style.RESET_ALL}")
            return
        
        self.generate_report(stats, ip_counts, suspicious_activities)

    def generate_report(self, stats, ip_counts, suspicious_activities):
        print(f"\n{Fore.GREEN}=== Log Analysis Report ==={Style.RESET_ALL}")
        print(f"\nTotal log entries analyzed: {stats['total_entries']}")
        
        print(f"\n{Fore.YELLOW}Top IP Addresses:{Style.RESET_ALL}")
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            status = f"{Fore.RED}(SUSPICIOUS){Style.RESET_ALL}" if ip in self.suspicious_ips else ""
            print(f"IP: {ip} - Count: {count} {status}")
        
        print(f"\n{Fore.YELLOW}Suspicious Activities:{Style.RESET_ALL}")
        for activity in suspicious_activities[:10]:
            print(f"Time: {activity['timestamp']}")
            print(f"Activity: {activity['message']}\n")
        
        print(f"\n{Fore.YELLOW}Status Code Distribution:{Style.RESET_ALL}")
        for key, value in stats.items():
            if key.startswith('status_'):
                print(f"Status {key.split('_')[1]}: {value}")

def main():
    parser = argparse.ArgumentParser(description='Log Parser for Security Analysis')
    parser.add_argument('--file', required=True, help='Path to the log file to analyze')
    args = parser.parse_args()
    
    log_parser = LogParser()
    log_parser.analyze_log(args.file)

if __name__ == '__main__':
    main()