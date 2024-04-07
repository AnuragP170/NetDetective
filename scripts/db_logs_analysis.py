import re
import sys
import glob
import os
import gzip

def filter_queries(log_file):
    with open(log_file, 'r') as file:
        lines = file.readlines()

    filtered_queries = []
    current_date = None
    current_time = None
    sql_injection_regex = r'(union\s+select|select\s+\*|insert\s+into|values\s*\(|update\s+.*\s+set|delete\s+from|drop\s+table|where\s+.+=.+)'
    for line in lines:
        match = re.match(r'(\d{6})\s+(\d{1,2}:\d{2}:\d{2})\s+(\d+)\s+(\w+)\s+(.*)', line)
        if match:
            current_date = match.group(1)[:2] + '/' + match.group(1)[2:4] + '/' + match.group(1)[4:]
            current_time = match.group(2)
        elif 'Query' in line:
            query = line.split('Query', 1)[1].strip()
            if re.search(sql_injection_regex, query, re.IGNORECASE):
                filtered_queries.append({
                    'date': current_date,
                    'time': current_time,
                    'query': query
                })

    return filtered_queries

def process_log_files(log_directory):
    log_files = glob.glob(os.path.join(log_directory, 'mysql.log*'))
    gz_files = glob.glob(os.path.join(log_directory, '*.gz'))

    if not log_files:
        return ["No log files found in the directory."]
    
    output = []
    for log_file in log_files:
        output.append(f"Processing log file: {log_file}")
        filtered_queries = filter_queries(log_file)
        
        if filtered_queries:
            output.append("\nPossible SQL Injection Queries:\n")
            for query in filtered_queries:
                output.append(f"Date: {query['date']}")
                output.append(f"Time: {query['time']}")
                output.append(f"Query: {query['query']}\n")
        else:
            output.append("No possible SQL injection queries found in this file.")
    
    for gz_file in gz_files:
        with gzip.open(gz_file, 'rt') as f:
            for line in f:
                if line.startswith('mysql.log'):
                    output.extend(process_log_files_from_text(line))
                    break
    
    return "\n".join(output)

def process_log_files_from_text(text):
    filtered_queries = []
    lines = text.split('\n')
    current_date = None
    current_time = None
    sql_injection_regex = r'(union\s+select|select\s+\*|insert\s+into|values\s*\(|update\s+.*\s+set|delete\s+from|drop\s+table|where\s+.+=.+)'
    for line in lines:
        match = re.match(r'(\d{6})\s+(\d{1,2}:\d{2}:\d{2})\s+(\d+)\s+(\w+)\s+(.*)', line)
        if match:
            current_date = match.group(1)[:2] + '/' + match.group(1)[2:4] + '/' + match.group(1)[4:]
            current_time = match.group(2)
        elif 'Query' in line:
            query = line.split('Query', 1)[1].strip()
            if re.search(sql_injection_regex, query, re.IGNORECASE):
                filtered_queries.append({
                    'date': current_date,
                    'time': current_time,
                    'query': query
                })

    return filtered_queries

def main():
    if len(sys.argv) != 2:
        print("Usage: python script.py /path/to/log/directory")
        sys.exit(1)

    log_directory = sys.argv[1]
    output = process_log_files(log_directory)
    print(output)

if __name__ == "__main__":
    main()

