import re
import csv
import sys
import os
import gzip

def parse_log_entry(entry):
    # Define the dictionary to store the extracted information
    details = {
        'Attack Type': '',
        'URL Used': '',
        'Payload Used': '',
        'Severity': '',
    }

    # Define regex patterns to extract information
    attack_type_pattern = re.compile(r'\[msg "([^"]+)"\]')
    url_pattern = re.compile(r'REQUEST_HEADERS:Referer: ([^\s]+)')
    payload_pattern = re.compile(r'\[data "Matched Data: ([^"]+)"\]')
    severity_pattern = re.compile(r'\[severity "([^"]+)"\]')

    # Search for Attack Type
    attack_type_match = attack_type_pattern.search(entry)
    if attack_type_match:
        details['Attack Type'] = attack_type_match.group(1)

    # Search for URL used
    url_match = url_pattern.search(entry)
    if url_match:
        details['URL Used'] = url_match.group(1)

    # Search for Payload used
    payload_match = payload_pattern.search(entry)
    if payload_match:
        details['Payload Used'] = payload_match.group(1)

    # Search for Severity
    severity_match = severity_pattern.search(entry)
    if severity_match:
        details['Severity'] = severity_match.group(1)

    # If all components are found, return the details dictionary
    if all(value for key, value in details.items() if key != 'URL Used'):  # URL might not always be present
        return details
    else:
        return None

def logs_to_csv(log_entries, output_csv_path):
    with open(output_csv_path, mode='w', newline='') as csvfile:
        fieldnames = ['Attack Type', 'URL Used', 'Payload Used', 'Severity']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for entry in log_entries:
            parsed_entry = parse_log_entry(entry)
            if parsed_entry:  # If parsing was successful
                writer.writerow(parsed_entry)


def read_log_file(log_file_path):
    log_entries = []
    if os.path.isdir(log_file_path):  # If the provided path is a directory
        for file_name in os.listdir(log_file_path):
            if file_name.startswith("modsec_audit.log"):  # Filter log files
                full_path = os.path.join(log_file_path, file_name)
                log_entries.extend(read_log_file(full_path))  # Recursively read log files
    else:  # If the provided path is a file
        if log_file_path.endswith(".gz"):  # If the file is compressed
            with gzip.open(log_file_path, 'rt') as file:
                log_entries.extend(file.readlines())
        else:  # If the file is not compressed
            with open(log_file_path, 'r') as file:
                log_entries.extend(file.readlines())
    return log_entries

def main(log_file_path, output_csv_path):
    # Read the log entries from file
    log_entries = read_log_file(log_file_path)

    # Process the log entries and save to CSV
    logs_to_csv(log_entries, output_csv_path)


if __name__ == "__main__":
    log_file_path = sys.argv[1]  # Replace with the path to your ModSecurity log file
    output_csv_path = sys.argv[2]  # Replace with the path where you want to save the CSV output
    main(log_file_path, output_csv_path)
