import subprocess
import re
import shutil
import os
import requests

# Replace 'YOUR_API_KEY' with your VulDB API key
VULDB_API_KEY = 'YOUR_API_KEY'

# Function to run a shell command and capture its output
def run_command(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=True,
            universal_newlines=True,
        )
        return result.stdout
    except Exception as e:
        return str(e)

# Function to create a backup of a file
def backup_file(file_path):
    backup_path = file_path + ".bak"
    shutil.copy2(file_path, backup_path)
    return backup_path

# Function to notify the admin to restart Apache
def notify_restart_apache():
    print("\n*** Please restart Apache for the changes to take effect. ***\n")

# Function to query VulDB API for Apache vulnerabilities
def query_vuldb_apache_vulnerabilities():
    url = "https://vuldb.com/api/v1/apache/search"

    headers = {
        "X-VulDB-ApiKey": VULDB_API_KEY,
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return None

# Function to check SSL configuration best practices
def check_ssl_config(config_file):
    ssl_directives = [
        "SSLProtocol",
        "SSLCipherSuite",
        "SSLCertificateFile",
        "SSLCertificateKeyFile",
        "SSLCACertificateFile",
    ]

    with open(config_file, "r") as f:
        config_content = f.read()

    issues = []

    for directive in ssl_directives:
        if re.search(rf"{directive}\s+", config_content):
            issues.append(f"{directive} is configured")

    return issues

# Function to fix SSL configuration issues
def fix_ssl_config(config_file):
    ssl_directives = [
        "SSLProtocol",
        "SSLCipherSuite",
        "SSLCertificateFile",
        "SSLCertificateKeyFile",
        "SSLCACertificateFile",
    ]

    with open(config_file, "r") as f:
        config_lines = f.readlines()

    for i, line in enumerate(config_lines):
        for directive in ssl_directives:
            if re.search(rf"{directive}\s+", line):
                # Replace the directive with a recommended value
                config_lines[i] = f"{directive} recommended_value\n"

    # Write the modified configuration back to the file
    with open(config_file, "w") as f:
        f.writelines(config_lines)

# Function to check and optionally fix Apache configurations
def check_and_fix_apache_configurations(fix=False):
    apache_config_files = [
        "/etc/apache2/apache2.conf",  # Adjust the paths as per your system
        "/etc/apache2/sites-available/*",  # Adjust for your site configuration files
    ]

    security_issues = []
    ssl_issues = []

    for config_file in apache_config_files:
        backup_path = None

        if fix:
            # Create a backup of the original configuration file
            backup_path = backup_file(config_file)

        output = run_command(f"cat {config_file}")
        if "Options -Indexes" not in output:
            security_issues.append(f"Directory listing is enabled in {config_file}")
            if fix:
                # Disable directory listing
                with open(config_file, "a") as f:
                    f.write("\nOptions -Indexes\n")
                security_issues.remove(f"Directory listing is enabled in {config_file}")

        if "ServerSignature Off" not in output:
            security_issues.append(f"ServerSignature is not turned off in {config_file}")
            if fix:
                # Turn off ServerSignature
                with open(config_file, "a") as f:
                    f.write("\nServerSignature Off\n")
                security_issues.remove(f"ServerSignature is not turned off in {config_file}")

        ssl_issues.extend(check_ssl_config(config_file))
        if fix:
            fix_ssl_config(config_file)

        if backup_path:
            print(f"Backup of {config_file} created at {backup_path}")

    if security_issues:
        print("Security Issues:")
        for issue in security_issues:
            print(f"- {issue}")

    if ssl_issues:
        print("SSL Configuration Issues:")
        for issue in ssl_issues:
            print(f"- {issue}")

    if fix:
        notify_restart_apache()

    # Query VulDB for Apache vulnerabilities
    vuldb_data = query_vuldb_apache_vulnerabilities()
    if vuldb_data:
        print("\nVulDB Apache Vulnerabilities:")
        for vuln in vuldb_data["data"]:
            print(f"- {vuln['title']} (CVE: {vuln['cve']})")
    else:
        print("\nFailed to fetch VulDB Apache vulnerabilities. Check your API key or network connection.")

if __name__ == "__main__":
    # Before enabling the fix option, make sure to back up your configuration files.
    # Uncomment the line below to enable automatic fixing.
    # check_and_fix_apache_configurations(fix=True)
    check_and_fix_apache_configurations()

