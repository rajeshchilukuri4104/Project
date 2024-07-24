# !/usr/bin/env python3
# -*- coding: utf-8 -*-
                        
#  ____            _          _____        __        __   _     
# |  _ \ _ __ ___ | |__   ___|  ___|__  _ _\ \      / /__| |__  
# | |_) | '__/ _ \| '_ \ / _ \ |_ / _ \| '__\ \ /\ / / _ \ '_ \ 
# |  __/| | | (_) | |_) |  __/  _| (_) | |   \ V  V /  __/ |_) |
# |_|   |_|  \___/|_.__/ \___|_|  \___/|_|    \_/\_/ \___|_.__/ 

# Author     : Bhanu
# Tool       : Probeforweb v1.0
# Usage      : python3 probefortheweb.py example.com
# Description: This scanner automates the process of security scanning by using a
#              multitude of available linux security tools and some custom scripts.
# Importing the libraries
# Import necessary libraries
import argparse
import subprocess
import time
import os
import sys
import json
import logging
from typing import List, Dict

# Define color class for terminal output
class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

# Argument parser setup
def get_parser() -> argparse.ArgumentParser:
    """
    Set up the argument parser for command-line arguments.

    Returns:
        argparse.ArgumentParser: Configured argument parser instance.
    """
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true', help='Update Probeforweb.')
    parser.add_argument('-s', '--skip', action='append', default=[], help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', help='Disable the idle loader/spinner.')
    parser.add_argument('-c', '--config', metavar='CONFIG_FILE', type=str, help='Path to configuration file.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser

# Function to check internet connectivity
def check_internet() -> bool:
    """
    Check if the system has internet connectivity.

    Returns:
        bool: True if internet is available, False otherwise.
    """
    try:
        subprocess.check_output(['ping', '-c', '1', '8.8.8.8'])
        return True
    except subprocess.CalledProcessError:
        return False

# Function to format URL
def url_maker(url: str) -> str:
    """
    Ensure the URL starts with 'http://' or 'https://'.

    Args:
        url (str): The URL to format.

    Returns:
        str: The formatted URL.
    """
    if not url.startswith('http://') and not url.startswith('https://'):
        return 'http://' + url
    return url

# Function to display time in H:M:S format
def display_time(seconds: int) -> str:
    """
    Convert seconds to H:M:S format.

    Args:
        seconds (int): Number of seconds.

    Returns:
        str: Time in H:M:S format.
    """
    return time.strftime("%H:%M:%S", time.gmtime(seconds))

# Function to display logo
def logo():
    """
    Display the logo of the tool.
    """
    print("Probeforweb - Security Scanner")

# Function to display helper message
def helper():
    """
    Display usage information and options for the tool.
    """
    print("Usage: python probeforweb.py [options] [URL]")

# Function to set up logging
def setup_logging(log_file: str):
    """
    Set up logging configuration.

    Args:
        log_file (str): Path to the log file.
    """
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logging.info("Logging setup complete.")

# Function to generate HTML report for vulnerabilities
def generate_vulnerability_html(vulnerability_info: List[str], temp_report_name: str) -> str:
    """
    Generate HTML for a single vulnerability report.

    Args:
        vulnerability_info (List[str]): Information about the vulnerability.
        temp_report_name (str): Path to the temporary report file.

    Returns:
        str: HTML string for the vulnerability report.
    """
    html = f"<h2>{vulnerability_info[1]}</h2>\n"
    html += "<pre>\n"
    with open(temp_report_name, 'r') as temp_report:
        data = temp_report.read()
        html += data
    html += "</pre>\n"
    return html

# Function to generate complete HTML report
def generate_html_report(target: str, rs_vul_list: List[str], tool_names: List[str], rs_skipped_checks: int, rs_total_elapsed: float):
    """
    Generate an HTML report for all vulnerabilities detected.

    Args:
        target (str): Target URL.
        rs_vul_list (List[str]): List of detected vulnerabilities.
        tool_names (List[str]): List of tool names used.
        rs_skipped_checks (int): Number of checks skipped.
        rs_total_elapsed (float): Total time elapsed for the scan.
    """
    date = subprocess.Popen(["date", "+%Y-%m-%d"], stdout=subprocess.PIPE).stdout.read()[:-1].decode("utf-8")
    debuglog = f"rs.dbg.{target}.{date}"
    vulreport = f"rs.vul.{target}.{date}"

    html_report = f"<html>\n<head>\n<title>Vulnerability Report</title>\n</head>\n<body>\n"
    html_report += f"<h1>Report for {target}</h1>\n"
    html_report += "<h2>Vulnerabilities</h2>\n"

    if len(rs_vul_list) == 0:
        html_report += "<p>No Vulnerabilities Detected.</p>\n"
    else:
        html_report += "<ul>\n"
        for vuln in rs_vul_list:
            vuln_info = vuln.split('*')
            temp_report_name = f"/tmp/probeforweb_temp_{vuln_info[0]}"
            html_report += "<li>\n"
            html_report += generate_vulnerability_html(vuln_info, temp_report_name)
            html_report += "</li>\n"
        html_report += "</ul>\n"

    html_report += "<h2>Debugging Information</h2>\n"
    html_report += f"<p>Total Number of Vulnerability Checks: <strong>{len(tool_names)}</strong></p>\n"
    html_report += f"<p>Total Number of Vulnerability Checks Skipped: <strong>{rs_skipped_checks}</strong></p>\n"
    html_report += f"<p>Total Number of Vulnerabilities Detected: <strong>{len(rs_vul_list)}</strong></p>\n"
    html_report += f"<p>Total Time Elapsed for the Scan: <strong>{display_time(int(rs_total_elapsed))}</strong></p>\n"
    html_report += f"<p>For Debugging Purposes, You can view the complete output generated by all the tools <a href='{debuglog}'>{debuglog}</a> under the same directory.</p>\n"

    html_report += "</body>\n</html>"

    with open("rs.html", "w") as report_file:
        report_file.write(html_report)

    print("[ Report Generation Completed. Report saved as rs.html ]")

# Function to run a specific tool
def run_tool(tool_cmd: str, tool_name: str, target_url: str, rs_vul_list: List[str]):
    """
    Execute a specific security tool and process its results.

    Args:
        tool_cmd (str): Command to run the tool.
        tool_name (str): Name of the tool.
        target_url (str): Target URL.
        rs_vul_list (List[str]): List to append detected vulnerabilities.
    """
    logging.info(f"Running tool: {tool_name}")
    try:
        result = subprocess.check_output(f"{tool_cmd} {target_url}", shell=True, stderr=subprocess.STDOUT).decode()
        temp_report_name = f"/tmp/probeforweb_temp_{tool_name}"
        with open(temp_report_name, 'w') as temp_report:
            temp_report.write(result)

        # Process result and extract vulnerabilities
        if "vulnerability" in result.lower():
            rs_vul_list.append(f"{tool_name}*{tool_name} Vulnerabilities Found")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running {tool_name}: {e}")
        print(f"[ {bcolors.FAIL}Error running {tool_name}: {e}{bcolors.ENDC}")

# Function to load configuration from a file
def load_config(config_file: str) -> Dict:
    """
    Load configuration from a JSON file.

    Args:
        config_file (str): Path to the configuration file.

    Returns:
        Dict: Configuration data.
    """
    if not os.path.isfile(config_file):
        print(f"[ {bcolors.FAIL}Error: Configuration file '{config_file}' does not exist.{bcolors.ENDC}")
        sys.exit(1)
    with open(config_file, 'r') as file:
        return json.load(file)

# Function to apply configuration settings
def apply_config(config: Dict):
    """
    Apply configuration settings from a dictionary.

    Args:
        config (Dict): Configuration data.
    """
    global tools_precheck
    tools_precheck = config.get('tools', tools_precheck)

# List of security tools and their configurations
tools_precheck = [
    ["nmap", "nmap -sS -p 80,443", "Nmap Scan", 1],
    ["nikto", "nikto -h", "Nikto Scan", 1],
    ["wapiti", "wapiti -u", "Wapiti Scan", 1],
    ["dirb", "dirb", "Dirb Scan", 1],
    ["gobuster", "gobuster dir", "Gobuster Scan", 1],
    ["sqlmap", "sqlmap -u", "SQLMap Scan", 1],
    ["wpscan", "wpscan --url", "WPScan", 1],
    ["owasp-zap", "zap-cli quick-scan", "OWASP ZAP Scan", 1],
    ["arachni", "arachni", "Arachni Scan", 1],
]

# Main function to execute the tool
def main():
    """
    Main function to execute the security scanning tool.
    """
    parser = get_parser()
    args_namespace = parser.parse_args()
    if args_namespace.help:
        helper()
        sys.exit(0)

    if not check_internet():
        print(f"[ {bcolors.FAIL}No internet connection detected.{bcolors.ENDC}")
        sys.exit(1)

    if args_namespace.update:
        # Update logic here
        print("[ Update Complete ]")
        sys.exit(0)

    if args_namespace.config:
        apply_config(load_config(args_namespace.config))

    if not args_namespace.target:
        print("[ Error ] No URL provided.")
        sys.exit(1)

    target_url = url_maker(args_namespace.target)
    rs_vul_list = []

    start_time = time.time()
    rs_skipped_checks = 0

    for tool_index, tool_name in enumerate([t[0] for t in tools_precheck]):
        if tool_name in args_namespace.skip:
            rs_skipped_checks += 1
            continue

        tool_cmd = next(t[1] for t in tools_precheck if t[0] == tool_name)
        run_tool(tool_cmd, tool_name, target_url, rs_vul_list)

    end_time = time.time()
    rs_total_elapsed = end_time - start_time

    generate_html_report(target_url, rs_vul_list, [t[2] for t in tools_precheck], rs_skipped_checks, rs_total_elapsed)

if __name__ == "__main__":
    main()
