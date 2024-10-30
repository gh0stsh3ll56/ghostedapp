import os
import socket
import subprocess
import requests
import psutil
from datetime import datetime

def get_hostname_ip():
    """Retrieve hostname and IP of the client machine."""
    hostname = socket.gethostname()
    ip_address = socket.gethostbyname(hostname)
    return hostname, ip_address

def scan_ports():
    """Check open ports on Windows using netstat."""
    try:
        result = subprocess.run(['netstat', '-an'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error running netstat: {result.stderr}"
    except FileNotFoundError:
        return "[ERROR] netstat command not found. Ensure it is available on your system."

def scan_filesystem(start_dir, extensions, keyword):
    """Recursively scan the filesystem for files with specific extensions and the keyword."""
    found_files = []
    for root, dirs, files in os.walk(start_dir):
        for file in files:
            if file.endswith(extensions) and keyword.lower() in file.lower():
                found_files.append(os.path.join(root, file))
    return found_files

def fetch_web_content(url):
    """Fetch content from a URL to check if the endpoint is accessible."""
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text, url, response.status_code
        else:
            return None, url, response.status_code
    except requests.RequestException as e:
        return None, f"Error accessing {url}: {str(e)}", None

def check_hosted_files(host_ip, found_files, report_lines):
    """Attempt to connect to each file's endpoint and check if it is hosted."""
    active_endpoints = []
    base_urls = [f"http://{host_ip}", "http://127.0.0.1", "http://localhost"]

    for file_path in found_files:
        # Construct the possible endpoint URLs from the file path
        endpoint_path = file_path.replace('\\', '/').split('wwwroot', 1)[-1]  # Adjust as needed for different paths
        for base_url in base_urls:
            full_url = f"{base_url}{endpoint_path}"
            content, url_checked, status_code = fetch_web_content(full_url)
            if status_code == 200:
                active_endpoints.append(url_checked)
                print(f"[INFO] Hosted file running at {url_checked} (HTTP 200 OK)")
                report_lines.append(f"[INFO] Hosted file running at {url_checked} (HTTP 200 OK)")
            else:
                print(f"[WARN] File {url_checked} is not actively hosted (Status Code: {status_code})")
                report_lines.append(f"[WARN] File {url_checked} is not actively hosted (Status Code: {status_code})")
    return active_endpoints

def prompt_directories():
    """Prompt user for additional directories to scan for web files."""
    print("\n[INFO] Please provide the root directory to scan (e.g., C:\\inetpub\\wwwroot, C:\\MyWebApp):")
    user_input = input("Directory to scan: ")
    return user_input.strip()

def prompt_keyword():
    """Prompt the user for a keyword to filter possible endpoints."""
    print("\n[INFO] Please provide a keyword to filter endpoints (e.g., 'api', 'auth', 'service'):")
    keyword = input("Keyword: ")
    return keyword.strip()

def create_hostedloot_folder():
    """Create the hostedloot folder in the current directory to store the report."""
    current_dir = os.getcwd()
    hostedloot_path = os.path.join(current_dir, "hostedloot")
    
    if not os.path.exists(hostedloot_path):
        os.makedirs(hostedloot_path)
        print(f"[INFO] Created folder: {hostedloot_path}")
    else:
        print(f"[INFO] Folder already exists: {hostedloot_path}")
    
    return hostedloot_path

def write_report(report_lines, hostedloot_path):
    """Write the detailed report of found files and endpoints to hostedloot folder."""
    report_file = os.path.join(hostedloot_path, f"hosted_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    
    with open(report_file, 'w') as report:
        report.write("Hosted Loot Detailed Report\n")
        report.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for line in report_lines:
            report.write(f"{line}\n")
    
    print(f"\n[INFO] Report saved as: {report_file}")

def main():
    """Main execution function to gather and display verbose output."""

    # Step 1: Get Hostname and IP
    hostname, ip = get_hostname_ip()
    print(f"[INFO] Hostname: {hostname}\n[INFO] IP Address: {ip}")
    
    # List to store all report lines
    report_lines = [f"[INFO] Hostname: {hostname}", f"[INFO] IP Address: {ip}\n"]

    # Step 2: Scan Ports for Open Web Servers
    print("\n[INFO] Scanning open ports...")
    port_scan_result = scan_ports()
    print(port_scan_result)
    report_lines.append(f"[INFO] Open Ports:\n{port_scan_result}")

    # Step 3: Prompt user for a keyword
    keyword = prompt_keyword()

    # Step 4: Define file types to search for in user-provided directories
    file_extensions = ('.xml', '.asmx')

    # Step 5: Prompt user for a directory to crawl
    user_directory = prompt_directories()

    # Step 6: Crawl the provided directory recursively for .xml and .asmx files containing the keyword
    print(f"\n[INFO] Scanning directory: {user_directory} and its subdirectories for .xml and .asmx files...")
    found_local_files = scan_filesystem(user_directory, file_extensions, keyword)

    if found_local_files:
        print("\n[INFO] Found files matching the keyword in the directory and subdirectories:")
        report_lines.append("\n[INFO] Found files matching the keyword in the directory and subdirectories:")
        for file_path in found_local_files:
            print(f" - {file_path}")
            report_lines.append(f" - {file_path}")
    else:
        print(f"\n[INFO] No .xml or .asmx files containing the keyword '{keyword}' were found in the provided directory.")
        report_lines.append(f"\n[INFO] No .xml or .asmx files containing the keyword '{keyword}' were found in the provided directory.")

    # Step 7: Check if discovered files are actively hosted on localhost or IP
    print("\n[INFO] Checking if discovered files are hosted and running...")
    report_lines.append("\n[INFO] Checking if discovered files are hosted and running...")
    active_endpoints = check_hosted_files(ip, found_local_files, report_lines)

    if active_endpoints:
        print(f"\n[INFO] Active hosted endpoints found:")
        report_lines.append(f"\n[INFO] Active hosted endpoints found:")
        for endpoint in active_endpoints:
            print(f" - {endpoint}")
            report_lines.append(f" - {endpoint}")
    else:
        print("[INFO] No active endpoints detected from discovered files.")
        report_lines.append("[INFO] No active endpoints detected from discovered files.")

    # Step 8: Create hostedloot folder and write the report
    hostedloot_path = create_hostedloot_folder()
    write_report(report_lines, hostedloot_path)

if __name__ == "__main__":
    main()
