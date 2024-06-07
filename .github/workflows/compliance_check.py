import json
import csv
import subprocess
import sys
import os
import tempfile
import shutil

def run_bandit(target_path, output_dir):
    # Step 1: Clone the GitHub repository to a temporary directory
    temp_dir = tempfile.mkdtemp()
    subprocess.run(['git', 'clone', target_path, temp_dir])

    # Step 2: Run Bandit and generate JSON output
    result = subprocess.run(['bandit', '-r', temp_dir, '-f', 'json'], capture_output=True, text=True)
    bandit_output = result.stdout

    # Step 3: Parse the JSON output
    bandit_data = json.loads(bandit_output)

    # Step 4: Convert parsed data into CSV format
    csv_data = []
    headers = ['Filename', 'Line Number', 'Issue Severity', 'Issue Confidence', 'Issue Text', 'More Info']

    for result in bandit_data['results']:
        csv_data.append([
            result['filename'],
            result['line_number'],
            result['issue_severity'],
            result['issue_confidence'],
            result['issue_text'],
            result['more_info']
        ])

    # Step 5: Write the CSV data to a file in the specified output directory
    csv_filename = os.path.join(output_dir, 'compliance_report.csv')
    with open(csv_filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(headers)  # Write the header
        csvwriter.writerows(csv_data)  # Write the data

    print(f"CSV file '{csv_filename}' has been created successfully.")

    # Step 6: Clean up the temporary directory
    shutil.rmtree(temp_dir)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {os.path.basename(__file__)} <github_repository> <output_directory>")
        sys.exit(1)
    
    github_repo = sys.argv[1]
    output_dir = sys.argv[2]
    
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    run_bandit(github_repo, output_dir)
