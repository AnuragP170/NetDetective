import os
import re
import sys

def check_modsec_mode(config_path):
    mode = "Not set"
    try:
        with open(config_path, 'r') as file:
            for line in file:
                # Looking for SecRuleEngine directive
                if 'SecRuleEngine' in line and not line.strip().startswith('#'):
                    mode_match = re.search(r'SecRuleEngine\s+(\S+)', line)
                    if mode_match:
                        mode = mode_match.group(1)
                        break  # No need to continue once we've found the mode
    except FileNotFoundError:
        return "ModSecurity configuration file not found.", []
    except Exception as e:
        return f"An error occurred: {e}", []

    return mode, list_crs_rule_sets(os.path.join(os.path.dirname(config_path), 'crs'))

def list_crs_rule_sets(crs_dir):
    rule_sets = []
    try:
        # Check if the CRS directory exists and is a directory
        if os.path.exists(crs_dir) and os.path.isdir(crs_dir):
            # List all .conf files in the CRS directory
            for item in os.listdir(crs_dir):
                if item.endswith('.conf'):
                    rule_sets.append(item)
    except Exception as e:
        return [f"An error occurred while listing CRS rule sets: {e}"]

    return rule_sets

def main(input_dir):
    output = []
    modsec_conf_path = os.path.join(input_dir, 'modsecurity.conf')
    mode, crs_rule_sets = check_modsec_mode(modsec_conf_path)
    output.append(f'ModSecurity Rule Engine is set to: {mode}')
    if crs_rule_sets:
        output.append("CRS rule sets found:")
        for rule_set in crs_rule_sets:
            output.append(f" - {rule_set}")
    else:
        output.append("No CRS rule sets found or unable to list them.")
    final_output = '\n'.join(output)
    return final_output

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <input_directory>")
        sys.exit(1)

    input_directory = sys.argv[1]
    outputs = main(input_directory)
    print(outputs)
