import os
import sys
import pandas as pd
import requests
from bandit.core import manager, config

def get_file_list_recursive(url, file_list = []):
    """
    Recursively fetches all file URLs from a GitHub repository directory.

    Arguments:
        url (str): API-URL to the directory on github repository.
        file_list: A list to store the file URLs

    Returns:
        list: A list of file URLs in the repository directory.
    """
    
    response = requests.get(url)
    assert response.status_code == '200', response.text
    js_res = response.json()
    for item in js_res:
        if item['type'] == "file":
            print(item['download_url'])
            file_list.append(item['download_url'])
        elif item['type'] == "dir":
            file_list.extend(get_all_nested_files(item['url'])) 
        
    return file_list

def get_first_level_files(url):

    """
    Gets the URLs of all files in the top level of a GitHub repository directory.

    Arguments:
        url (str): The API URL of a directory in the GitHub repository.

    Returns:
        list: A list of file URLs in the top level of the repository directory.
    """

    response = requests.get(url)
    assert response.status_code == '200', response.text
    files = response.json()
    file_list = [file['download_url'] for file in files if file['type'] == "file"]
    return file_list


def download_files(repo_url, local_dir):

    """
    Downloads Python files to local directory from a GitHub repository .

    Args:
        repo_url (str): The API URL of the GitHub repository.
        local_dir (str): The local directory to save the downloaded files.
    """

    response = requests.get(repo_url)
    files = response.json()
    if not os.path.exists(local_dir):
        os.makedirs(local_dir)
    for file in files:
        download_url = file['download_url']
        file_name = os.path.join(local_dir, file['name'])
        if not file_name.lower().endswith(".py"):
            print(f"Skipping file '{file_name}' as it is not a python file");
            continue
        print(f"Downloading to path '{file_name}'")
        file_content = requests.get(download_url).text
        with open(file_name, 'w') as f:
            f.write(file_content)



def run_bandit_on_file(b_mgr, file_path):
    """
     This function runs Bandit security analysis on a Python file.

    Args:
        b_mgr (BanditManager): The Bandit manager instance.
        file_path (str): Path to the Python file for Analysis.

    Returns:
        list: A list of issues detected in the file.
    """
    try:
        b_mgr.discover_files([file_path])
        b_mgr.run_tests()
        return b_mgr.results
    except Exception as e:
        print(f"Error running bandit on {file_path}: {e}")
        return []

def scan_directory(directory):

    """
    Scans all Python files in a directory using Bandit for security issues.

    Args:
        directory (str): The directory containing Python files to scan.

    Returns:
        list: A list of issues found in the directory.
    """
    
    conf = config.BanditConfig()
    b_mgr = manager.BanditManager(conf, "file")
    
    issues = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                print(f"Scanning {file_path}...")
                results = run_bandit_on_file(b_mgr, file_path)
                issues.extend(results)
    
    return issues

def format_issue(issue):
    """
    This function formats a Bandit issue into a dictionary for CSV output.

    Args:
        issue (Issue): A Bandit issue instance.

    Returns:
        dict: A dictionary containing formatted issue information like Filename, Line Number, Severity, Confidence and Issue Text.
    """
    return {
        "File": os.path.basename(issue.fname),
        "Line": issue.lineno,
        "Severity": issue.severity,
        "Confidence": issue.confidence,
        "Issue": issue.text
    }

def save_compliance_report(issues, output_file):
    """
    Saves the unique issues to a CSV file using pandas.

    Args:
        issues (list): A list of Bandit issues.
        output_file (str): The path to the output CSV file.
    """

    unique_issues = set(issues)  # Converts list to set to remove duplicates
    issues_data = [format_issue(issue) for issue in unique_issues]
    df = pd.DataFrame(issues_data)
    df.to_csv(output_file, index=False)
    print(f"Issues saved to '{output_file}'")

def convert_github_url_to_api(url):

    """
    Converts a GitHub repository URL to the corresponding API URL.

    Args:
        url (str): The GitHub repository URL.

    Returns:
        str: The GitHub API URL.
    
    Raises:
        ValueError: If the provided URL is not a valid GitHub URL.
    """

    if not url.startswith("https://github.com/"):
        raise ValueError("Invalid GitHub URL")
    repo_path = url[len("https://github.com/"):].split('/')
    assert len(repo_path) >= 2, "Looks like an invalid('/')"

    return f"https://api.github.com/repos/{repo_path[0]}/{repo_path[1]}/contents/"

def main(repo_url, directory="temp"):

    """
    Main function to download files, scan for vulnerabilities, and save the report.

    Args:
        repo_url (str): The GitHub repository API URL.
        directory (str): The local directory to save the downloaded files.
    """

    
    download_files(repo_url, directory)
    issues = scan_directory(directory)
    print("====================ISSUE_LIST====================")
    for issue in issues:
        print(f"{issue.text} '{issue.fname}'")
    print("====================XXXXXXXXXX====================")
    if issues:
        save_compliance_report(issues, "compliance_report.csv")
    else:
        print("No issues found.")

if __name__ == "__main__":
    api_url = None
    if len(sys.argv) != 2:
        print("Usage: python <file_name> <repo_url>")
    else:
        repo_url = sys.argv[1]
        try:
            api_url = convert_github_url_to_api(repo_url)
            print(api_url)
        except ValueError as e:
            print(e)
            
    main(api_url)
