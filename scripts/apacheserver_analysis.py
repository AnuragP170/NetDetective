import re
import os
import gzip
import csv
import html
import sys

def extract_log_details(log_line, log_type):
    if log_type == "access":
        match = re.search(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - .+? \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)"', log_line)
        if match:
            ip = match.group('ip')
            time = match.group('time')
            request = match.group('request')
            request_parts = request.split()
            uri = request_parts[1] if len(request_parts) > 1 else "-"
            return [time, uri, ip, "-"]
        else:
            return ["-", "-", "-", "-"]


    elif log_type == "error":
        timestamp_match = re.search(r'\[(.*?)\]', log_line)
        timestamp = timestamp_match.group(1) if timestamp_match else "-"
        client_ip_match = re.search(r'\[client (\d+\.\d+\.\d+\.\d+)\]', log_line)
        client_ip = client_ip_match.group(1) if client_ip_match else "-"
        pid_match = re.search(r'\[pid (\d+)\]', log_line)
        pid = pid_match.group(1) if pid_match else "-"
        uri_match = re.search(r'\[uri "(.*?)"\]', log_line)
        uri = uri_match.group(1) if uri_match else "-"
        referer_match = re.search(r'\[referer "(.*?)"\]', log_line)
        referer = referer_match.group(1) if referer_match else "-"
        return [timestamp, uri, client_ip, pid, referer]
    elif log_type == "system":
        parts = log_line.split(']', 1)
        if len(parts) > 1:
            time = parts[0].strip('[')
            details = parts[1].strip()
            return [time, details]
    return ["-", "-", "-", "-", "-"]

def process_and_write_to_csv(log_file_path, patterns, csv_writer, log_type):
    try:
        open_func = gzip.open if log_file_path.endswith('.gz') else open
        with open_func(log_file_path, 'rt', errors='ignore') as file:
            for line in file:
                for attack, pattern in patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        details = extract_log_details(line, log_type)
                        details = [html.escape(detail) for detail in details]
                        if log_type == "access":
                            csv_writer.writerow([os.path.basename(log_file_path), attack] + details)
                        elif log_type == "error":
                            formatted_details = [f"timestamp:{details[0]}", f"uri:{details[1]}", f"client:{details[2]}", f"pid:{details[3]}", f"referer:{details[4]}"]
                            csv_writer.writerow([os.path.basename(log_file_path), attack] + formatted_details)
                        else:
                            csv_writer.writerow([os.path.basename(log_file_path), attack] + details)
    except Exception as e:
        print(f"Error processing log file {log_file_path}: {e}")

def analyze_logs_and_write_csv(log_dir, file_prefixes, patterns, csv_filename, log_type):
    with open(csv_filename, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        for file_prefix in file_prefixes:
            for log_file_name in os.listdir(log_dir):
                if log_file_name.startswith(file_prefix):
                    log_file_path = os.path.join(log_dir, log_file_name)
                    process_and_write_to_csv(log_file_path, patterns, csv_writer, log_type)

def main(nginx_dir, system_log_dir, output_dir):
    nginx_log_dir = nginx_dir
    system_log_dir = system_log_dir
    output_dir = output_dir
    log_patterns = {
        'access': {
            'SQL Injection': r'(union\s+select|select\s+\*|insert\s+into|values\s*\(|update\s+.*\s+set|delete\s+from|drop\s+table|where\s+.+=.+)',
            'XSS': r'(<script|<svg/onload=|javascript:|%3Cscript|%3Csvg%2Fonload=)',
            'Directory Traversal': r'(\.\./|\.\.%2f|\%2e%2e\%2f|\%2e%2e/)',
            'RFI/LFI': r'(include=|require=|path=|filepath=|file=|document=|root=|pages=)',
            'Unusual Request Methods': r'(PUT|DELETE|TRACE|CONNECT)',
            'Error Codes': r'HTTP/[0-9\.]+"\s(4\d\d|5\d\d)\s',
            'Unusual File Types and Paths': r'(\.bak|\.config|\.db|\.sql|/etc/passwd|/etc/shadow)',
            'Command Injection': r'(;|\||`|&|\$|\*|\{|\}|\[|\]|\^|\!)',
            'Referer Header Anomalies': r'(Referer:\s*[^http]|Referer:\s*http[^s]|Referer:\s*https[^:])',
            'Uncommon User Agents': r'(User-Agent:\s*[^Mozilla]|User-Agent:\s*[^Chrome]|User-Agent:\s*[^Safari])',
            'Suspicious Parameters': r'(\?|\&)(cmd=|exec=|command=|execute=|shell=)',
            'Malformed Requests': r'(HTTP/1\.1" 400|HTTP/1\.0" 400)'
        },
        'error': {
            'File Not Found': r'File not found',
            'Permission Denied': r'Permission denied',
            'Connection Refused': r'Connection refused',
            'SSL Handshake Failed': r'handshake failed',
            'MySQL Access Denied': r'mysqli_sql_exception: Access denied for user',
            'SQL Injection': r'SQLI=[1-9]\d*',
            'XSS': r'XSS=[1-9]\d*',
            'Remote File Inclusion': r'RFI=[1-9]\d*',
            'Local File Inclusion': r'LFI=[1-9]\d*',
            'Remote Code Execution': r'RCE=[1-9]\d*',
            'PHP Code Injection': r'PHPI=[1-9]\d*',
            'HTTP Header Injection': r'HTTP=[1-9]\d*',
            'Session Fixation': r'SESS=[1-9]\d*'
        },
        'system': {
            'Nginx Error': r'nginx.*error',
            'Nginx Restart': r'restarting nginx',
            'Authentication Failure': r'authentication failure'
        }
    }
    print("Writing Nginx access logs to CSV...")
    analyze_logs_and_write_csv(nginx_log_dir, ['access.log'], log_patterns['access'], os.path.join(output_dir, 'access_logs.csv'), 'access')
    print("Writing Nginx error logs to CSV...")
    analyze_logs_and_write_csv(nginx_log_dir, ['error.log'], log_patterns['error'], os.path.join(output_dir, 'error_logs.csv'), 'error')

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python log_analysis.py <nginx_dir> <system_log_dir> <output_dir>")
        sys.exit(1)
    nginx_dir = sys.argv[1]
    system_log_dir = sys.argv[2]
    output_dir = sys.argv[3]
    main(nginx_dir, system_log_dir, output_dir)

