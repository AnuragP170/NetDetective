import os
import sys
import hashlib
import requests
import datetime
import pwd
import io

VT_API_URL = "https://www.virustotal.com/api/v3/files/"
API_KEY = "d240798afdc5990062b5ef92d4f4afa799251ece4613e6c8c604f6988c68938f"

def get_md5_hash(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    return hasher.hexdigest()

def get_file_metadata(file_path):
    try:
        stats = os.stat(file_path)
        creation_time = datetime.datetime.fromtimestamp(stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        modification_time = datetime.datetime.fromtimestamp(stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        owner = pwd.getpwuid(stats.st_uid).pw_name
        return creation_time, modification_time, owner
    except Exception as e:
        return f"Error retrieving metadata for {file_path}: {e}", None, None, None

def list_files(directory):
    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    return files

def upload_hash(file_hash):
    headers = {
        "x-apikey": API_KEY,
    }
    response = requests.get(VT_API_URL + file_hash, headers=headers)
    return response.json()

def display_analysis_details(analysis_result):
    if analysis_result.get("data"):
        attributes = analysis_result.get("data").get("attributes")
        last_analysis_stats = attributes.get("last_analysis_stats")
        malicious = last_analysis_stats.get('malicious', 0)
        return 'malicious' if malicious > 0 else 'non-malicious'
    else:
        return 'non-malicious'

def run_scan(directory):
    # Redirect stdout to a StringIO buffer
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()

    files = list_files(directory)

    for file_path in files:
        file_hash = get_md5_hash(file_path)
        analysis_result = upload_hash(file_hash)
        result = display_analysis_details(analysis_result)
        if result == 'malicious':
            creation_time, modification_time, owner = get_file_metadata(file_path)
            print(f"\nFile: {os.path.basename(file_path)}")
            print(f"    Hash: {file_hash}")
            print(f"    Created: {creation_time}")
            print(f"    Modified: {modification_time}")
            print(f"    Owner: {owner}")

    # Restore stdout and return buffer contents
    sys.stdout = old_stdout
    return buffer.getvalue()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script_name.py <target directory>")
        sys.exit(1)

    directory = sys.argv[1]
    output = run_scan(directory)
    print(output)
