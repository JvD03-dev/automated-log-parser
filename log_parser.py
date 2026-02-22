from __future__ import annotations
import argparse
import ipaddress
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union
from colorama import Fore, Style, init

init(autoreset=True)

ApacheEntry = Dict[str, Any]
SystemEntry = Dict[str, Any]
LogEntry = Union[ApacheEntry, SystemEntry]

@dataclass(frozen=True)
class SuspiciousActivity:
    timestamp: Any
    message: str


class LogParser:
    def __init__(self) -> None:
        self.suspicious_ips: set[str] = set()
        self.suspicious_patterns: List[str] = [
            r"failed login",
            r"authentication failure",
            r"permission denied",
            r"access denied",
            r"brute force",
            r"port scan",
            r"denial of service",
        ]
        self._compiled_suspicious = [re.compile(p, re.IGNORECASE) for p in self.suspicious_patterns]
        self._apache_re = re.compile(r'(\S+)\s+-\s+-\s+\[(.*?)\]\s+"(.*?)"\s+(\d{3})\s+(\S+)')
        self._syslog_re = re.compile(r"(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)")

    
    def parse_apache_log(self, line: str) -> Optional[ApacheEntry]:
        match = self._apache_re.match(line)
        if not match:
            return None
        ip, timestamp, request, status, size = match.groups()
        try:
            ts = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            return None
        try:
            size_int = int(size) if size != "-" else 0
        except ValueError:
            size_int = 0
        return {"ip": ip,"timestamp": ts,"request": request,"status": int(status),"size": size_int,}

    
    def parse_system_log(self, line: str) -> Optional[SystemEntry]:
        match = self._syslog_re.match(line)
        if not match: return None
        timestamp, host, message = match.groups()
        try:
            ts = datetime.strptime(timestamp, "%b %d %H:%M:%S")
        except ValueError:
            return None
        return {"timestamp": ts,"host": host,"message": message,}

    
    def is_suspicious_ip(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False

        if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved): return False
        return False

    
    def analyze_log(self, log_file: str) -> None:
        print(f"{Fore.CYAN}Analyzing log file: {log_file}{Style.RESET_ALL}")
        stats: defaultdict[str, int] = defaultdict(int)
        ip_counts: defaultdict[str, int] = defaultdict(int)
        suspicious_activities: List[SuspiciousActivity] = []
        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if not line:
                        continue

                    entry = self.parse_apache_log(line) or self.parse_system_log(line)
                    if not entry:
                        continue

                    if "ip" in entry:
                        ip = str(entry["ip"])
                        ip_counts[ip] += 1
                        if self.is_suspicious_ip(ip):
                            self.suspicious_ips.add(ip)
                    entry_text = str(entry)
                    for rx in self._compiled_suspicious:
                        if rx.search(entry_text):
                            suspicious_activities.append(SuspiciousActivity(timestamp=entry.get("timestamp", "N/A"),message=entry_text,))
                            break
                    if "status" in entry: stats[f"status_{entry['status']}"] += 1
                    stats["total_entries"] += 1

        except FileNotFoundError:
            print(f"{Fore.RED}Error: Log file not found{Style.RESET_ALL}")
            return
        except OSError as e:
            print(f"{Fore.RED}Error reading file: {e}{Style.RESET_ALL}")
            return
        self.generate_report(stats, ip_counts, suspicious_activities)

    
    def generate_report(self, stats: defaultdict[str, int], ip_counts: defaultdict[str, int], suspicious_activities: List[SuspiciousActivity]):
        print(f"\n{Fore.GREEN}=== Log Analysis Report ==={Style.RESET_ALL}")
        print(f"\nTotal log entries analyzed: {stats['total_entries']}")

        if ip_counts:
            print(f"\n{Fore.YELLOW}Top IP Addresses:{Style.RESET_ALL}")
            for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                tag = f"{Fore.RED}(SUSPICIOUS){Style.RESET_ALL}" if ip in self.suspicious_ips else ""
                print(f"IP: {ip} - Count: {count} {tag}")
        else:
            print(f"\n{Fore.YELLOW}Top IP Addresses:{Style.RESET_ALL}")
            print("No IP data found (likely not an Apache access log).")

        print(f"\n{Fore.YELLOW}Suspicious Activities:{Style.RESET_ALL}")
        if suspicious_activities:
            for activity in suspicious_activities[:10]:
                print(f"Time: {activity.timestamp}")
                print(f"Activity: {activity.message}\n")
        else:
            print("No suspicious activity keywords matched.")

        print(f"\n{Fore.YELLOW}Status Code Distribution:{Style.RESET_ALL}")
        status_keys = sorted(k for k in stats.keys() if k.startswith("status_"))
        if status_keys:
            for key in status_keys:
                print(f"Status {key.split('_', 1)[1]}: {stats[key]}")
        else:
            print("No HTTP status data found.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Log Parser for basic security-oriented analysis")
    parser.add_argument("--file", required=True, help="Path to the log file to analyze")
    args = parser.parse_args()
    LogParser().analyze_log(args.file)

if __name__ == "__main__":
    main()
