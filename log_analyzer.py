import re
from collections import Counter, defaultdict
from datetime import datetime
import csv
import json
import matplotlib.pyplot as plt
from typing import List, Dict, Any, Tuple
import os
import sys
import multiprocessing
from user_agents import parse

class LogEntry:
    def __init__(self, entry_dict: Dict[str, Any]):
        self.__dict__.update(entry_dict)

class LogParser:
    @staticmethod
    def parse_common_log_format(line: str) -> Dict[str, Any]:
        pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+)'
        match = re.match(pattern, line)
        if match:
            return {
                'ip': match.group(1),
                'user': match.group(3),
                'timestamp': datetime.strptime(match.group(4), '%d/%b/%Y:%H:%M:%S %z'),
                'request': match.group(5),
                'status': int(match.group(6)),
                'size': int(match.group(7))
            }
        return None

    @staticmethod
    def parse_nginx_log_format(line: str) -> Dict[str, Any]:
        pattern = r'(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(pattern, line)
        if match:
            return {
                'ip': match.group(1),
                'user': match.group(2),
                'timestamp': datetime.strptime(match.group(3), '%d/%b/%Y:%H:%M:%S %z'),
                'request': match.group(4),
                'status': int(match.group(5)),
                'size': int(match.group(6)),
                'referrer': match.group(7),
                'user_agent': match.group(8)
            }
        return None

class LogAnalyzer:
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.log_entries = []
        self.parsed_logs = []

    def parse_logs(self):
        parsers = [LogParser.parse_common_log_format, LogParser.parse_nginx_log_format]
        
        with open(self.log_file, 'r') as file:
            for line in file:
                for parser in parsers:
                    entry = parser(line)
                    if entry:
                        self.parsed_logs.append(LogEntry(entry))
                        break

    def analyze(self):
        self.parse_logs()
        print(f"Total log entries: {len(self.parsed_logs)}")
        
        # Time-based analysis
        self.time_based_analysis()
        
        # IP geolocation and top IPs
        top_ips = self.get_top_ips(5)
        print("Top 5 IPs with requests:")
        for ip, count in top_ips:
            print(f"{ip} ({count} requests)")
        
        # User behavior analysis
        self.user_behavior_analysis()
        
        # Advanced pattern matching
        self.detect_security_events()
        
        # Generate visualizations
        self.generate_visualizations()
        
        # Generate report
        self.generate_report('log_analysis_report.json')

    def time_based_analysis(self):
        time_distribution = defaultdict(int)
        for entry in self.parsed_logs:
            hour = entry.timestamp.strftime('%H')
            time_distribution[hour] += 1
        
        print("\nHourly request distribution:")
        for hour, count in sorted(time_distribution.items()):
            print(f"{hour}:00 - {count} requests")

    def get_top_ips(self, n: int = 10) -> List[Tuple[str, int]]:
        ip_counts = Counter(entry.ip for entry in self.parsed_logs)
        return ip_counts.most_common(n)

    def user_behavior_analysis(self):
        user_sessions = defaultdict(list)
        for entry in self.parsed_logs:
            user_sessions[entry.ip].append(entry)
        
        print("\nUser behavior analysis:")
        for ip, sessions in user_sessions.items():
            if len(sessions) > 10:  # Arbitrary threshold for demonstration
                print(f"IP {ip} made {len(sessions)} requests:")
                user_agent = parse(sessions[0].user_agent if hasattr(sessions[0], 'user_agent') else '')
                print(f"  Browser: {user_agent.browser.family} {user_agent.browser.version_string}")
                print(f"  OS: {user_agent.os.family} {user_agent.os.version_string}")
                print(f"  Device: {user_agent.device.family}")

    def detect_security_events(self):
        security_events = []
        patterns = {
            'sql_injection': r'UNION.*SELECT|INSERT.*INTO|UPDATE.*SET|DELETE.*FROM',
            'xss_attempt': r'<script>|javascript:',
            'path_traversal': r'\.\./|\.\.\%2F',
            'admin_access': r'/admin|/administrator|/login\.php'
        }
        
        for entry in self.parsed_logs:
            for event_type, pattern in patterns.items():
                if re.search(pattern, entry.request, re.IGNORECASE):
                    security_events.append({
                        'event_type': event_type,
                        'ip': entry.ip,
                        'request': entry.request
                    })
        
        print("\nDetected security events:")
        for event in security_events:
            print(f"{event['event_type'].upper()}: {event['ip']} - {event['request']}")
        
        # Return security events for inclusion in the report
        return security_events

    def generate_visualizations(self):
        # Request distribution over time
        timestamps = [entry.timestamp for entry in self.parsed_logs]
        plt.figure(figsize=(12, 6))
        plt.hist(timestamps, bins=24, edgecolor='black')
        plt.title('Request Distribution Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Requests')
        plt.savefig('request_distribution.png')
        plt.close()

        # Status code distribution
        status_codes = [entry.status for entry in self.parsed_logs]
        status_counts = Counter(status_codes)
        plt.figure(figsize=(10, 6))
        plt.bar(status_counts.keys(), status_counts.values())
        plt.title('HTTP Status Code Distribution')
        plt.xlabel('Status Code')
        plt.ylabel('Count')
        plt.savefig('status_code_distribution.png')
        plt.close()

    def generate_report(self, output_file: str):
        security_events = self.detect_security_events()  # Capture security events
        
        report = {
            'total_entries': len(self.parsed_logs),
            'top_ips': self.get_top_ips(10),
            'status_code_distribution': dict(Counter(entry.status for entry in self.parsed_logs)),
            'security_events': security_events  # Add security events to the report
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Report generated: {output_file}")

def process_chunk(chunk):
    analyzer = LogAnalyzer(chunk)
    return analyzer.parsed_logs

def main():
    if len(sys.argv) != 2:
        print("Usage: python log_analyzer.py <path_to_log_file>")
        sys.exit(1)
    
    log_file = sys.argv[1]
    if not os.path.exists(log_file):
        print(f"Error: The file '{log_file}' does not exist.")
        sys.exit(1)

    # Performance optimization using multiprocessing
    cpu_count = multiprocessing.cpu_count()
    chunk_size = os.path.getsize(log_file) // cpu_count
    
    with multiprocessing.Pool(processes=cpu_count) as pool:
        chunks = [log_file] * cpu_count  # Simplified for demonstration
        results = pool.map(process_chunk, chunks)
    
    # Combine results
    all_parsed_logs = [log for chunk_result in results for log in chunk_result]
    
    analyzer = LogAnalyzer(log_file)
    analyzer.parsed_logs = all_parsed_logs
    analyzer.analyze()

if __name__ == "__main__":
    main()