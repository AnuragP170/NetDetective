import subprocess
from jinja2 import Environment, FileSystemLoader
from collections import defaultdict
from datetime import datetime
import csv
import bleach

# import log analysis scripts from scripts/
from scripts import apacheserver_analysis
from scripts import check_db_privileges
from scripts import db_logs_analysis
from scripts import db_binary_analysis
from scripts import virusTotalScan
from scripts import error_logs_graph
from scripts import check_waf
from scripts import modsec_logs_analysis

def read_file_content(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
        sanitized_content = bleach.clean(content, strip=True, tags=[], attributes={}, protocols=[])
        return sanitized_content


def summarize_modsec_logs(csv_file_path):
    summary = {}
    with open(csv_file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            if row:  # Check if the row is not empty
                attack_type = bleach.clean(row[0], tags=[], strip=True).strip()
                if attack_type in summary:
                    summary[attack_type] += 1
                else:
                    summary[attack_type] = 1

    # Format the summary as a multi-line string
    formatted_summary = "\n".join(f"{attack_type}: {count}" for attack_type, count in summary.items())
    return formatted_summary

def summarize_access_logs(csv_file_path):
    summary = defaultdict(lambda: defaultdict(lambda: {'start': None, 'end': None}))
    with open(csv_file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            _, attack_type, timestamp, _, _, _ = row
            date_time = datetime.strptime(timestamp.split(' ')[0], "%d/%b/%Y:%H:%M:%S")
            date = date_time.strftime("%Y-%m-%d")

            if not summary[date][attack_type]['start'] or date_time < summary[date][attack_type]['start']:
                summary[date][attack_type]['start'] = date_time

            if not summary[date][attack_type]['end'] or date_time > summary[date][attack_type]['end']:
                summary[date][attack_type]['end'] = date_time

    # Convert datetime objects to string for easy handling in the template
    for date, attacks in summary.items():
        for attack_type, times in attacks.items():
            times['start'] = times['start'].strftime("%Y-%m-%d %H:%M:%S") if times['start'] else None
            times['end'] = times['end'].strftime("%Y-%m-%d %H:%M:%S") if times['end'] else None

    return summary


def summarize_error_logs(csv_file_path):
    summary = defaultdict(lambda: defaultdict(int))
    with open(csv_file_path, 'r') as file:
        reader = csv.reader(file)
        for row in reader:
            log_file, attack_type, timestamp, *_ = row
            if timestamp.strip() == '-' or 'timestamp:' not in timestamp:
                # Skip rows with invalid timestamps
                continue

            # Extracting the datetime object from the timestamp string
            timestamp = timestamp.split('timestamp:')[1].strip()
            try:
                date_time = datetime.strptime(timestamp, "%a %b %d %H:%M:%S.%f %Y")
            except ValueError:
                # Skip rows where the timestamp does not match the expected format
                continue

            date = date_time.strftime("%Y-%m-%d")
            summary[date][attack_type] += 1
    return summary

# Load the template
env = Environment(loader=FileSystemLoader('.'))
template = env.get_template('report_template.html')

input_dir = input("Enter directory name for analysis (eg. backup) : ")

apacheserver_analysis.main(input_dir + "/apache2/", input_dir +"/", "output/")
mariadb_logs = db_logs_analysis.process_log_files(input_dir + "/mysql/")
mariadb_priv_logs = check_db_privileges.main()
mariadb_binary_logs = db_binary_analysis.main()
waf_status = check_waf.main(input_dir + "/modsecurity/")
virustotalscan_logs = virusTotalScan.run_scan(input_dir + "/html/")
modsec_logs_analysis = modsec_logs_analysis.main(input_dir + "/apache2/", "output/modsec_logs.csv")

apache_access_logs = read_file_content('output/access_logs.csv')
access_logs_summary = summarize_access_logs('output/access_logs.csv')
apache_error_logs = read_file_content('output/error_logs.csv')
error_logs_summary = summarize_error_logs('output/error_logs.csv')
#system_logs = read_file_content('output/system_logs.csv')
error_logs_graph.main('output/error_logs.csv')
modsec_logs = read_file_content("output/modsec_logs.csv")
modsec_logs_summary=summarize_modsec_logs("output/modsec_logs.csv")

# Render the template with the log contents
output_from_parsed_template = template.render(
    mariadb_logs=mariadb_logs,
    apache_access_logs=apache_access_logs,
    access_logs_summary=access_logs_summary,
    apache_error_logs=apache_error_logs,
    error_logs_summary=error_logs_summary,
#    system_logs=system_logs,
    mariadb_binary_logs=mariadb_binary_logs,
    mariadb_priv_logs=mariadb_priv_logs,
    virustotalscan_logs=virustotalscan_logs,
    modsec_logs=modsec_logs,
    waf_status=waf_status,
    modsec_logs_summary=modsec_logs_summary
)

# Write the rendered HTML to a file
with open("log_analysis_report.html", "w") as fh:
    fh.write(output_from_parsed_template)

print("Report generated: log_analysis_report.html")


# def run_command(command, output_file=None):
#     with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True, executable='/bin/bash') as process:
#         stdout, stderr = process.communicate()
#         if output_file:
#             with open(output_file, 'wb') as file:
#                 file.write(stdout)
#
# # Function to read file content
# def read_file_content(file_path):
#     with open(file_path, 'r') as file:
#         return file.read()
#
