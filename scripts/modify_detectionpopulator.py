import fileinput
import re

# Define the target string
target = "vuln_results_field = re.sub('\\s+', ' ', val).strip(' ')"

# Define the replacement lines
new_lines = [
    "vuln_results_field = re.sub('\\n', 'NEW_LINE_CHAR', val)\n",
    "vuln_results_field = re.sub('\\t', 'TAB_CHAR', vuln_results_field)\n",
    "vuln_results_field = re.sub('\\s+', ' ', vuln_results_field).strip(' ')\n"
]

# Loop through the file and replace the target line with the new lines
found_target = False
for line in fileinput.input('./TA-QualysCloudPlatform/bin/qualysModule/splunkpopulator/detectionpopulator.py', inplace=True):
    # Check if the target line is found
    if line.strip() == target:
        # Print the original line as a commented-out line
        print("# " + line.strip())
        # Print the new lines with the same indentation as the original line
        indentation = re.match(r"^\s*", line).group(0)
        for new_line in new_lines:
            print(indentation + new_line, end="")
        found_target = True
    else:
        print(line, end="")

# If the target line was not found, print an error message
if not found_target:
    print("Error: target string not found in file")
