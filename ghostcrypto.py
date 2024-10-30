import os
import re
import hashlib
import threading
import subprocess
from itertools import product
from string import ascii_letters, digits
from scapy.all import sniff, IP, TCP, UDP
from scapy.packet import Raw
from Crypto.Cipher import ARC2, ARC4
from datetime import datetime
import signal
import sys

# Dictionary to map vulnerable algorithms, modes, and hash functions with details
vulnerable_algorithms = {
    'DES': 'Weak due to short key length (56-bit) and vulnerability to brute-force attacks.',
    'TripleDES': 'Weak due to its small block size (64-bit) and deprecated status.',
    'MD5': 'Vulnerable to hash collisions, making it unsuitable for cryptographic security.',
    'SHA-1': 'Vulnerable to collision attacks. Deprecated by most modern systems.',
    'SHA-256': 'Considered secure but check usage carefully.',
    'RC2': 'RC2 is vulnerable due to its small key sizes. Considered outdated.',
    'RC4': 'RC4 is broken due to known key biases and vulnerabilities. Avoid using it.',
    'XOR': 'XOR is not secure for encryption, especially with static keys. Vulnerable to known-plaintext attacks.'
}

# Sample dictionary words for cracking hashes and XOR (you can replace this with an actual wordlist file)
sample_wordlist = ["password", "123456", "admin", "qwerty", "letmein", "welcome"]

# Global variables for controlling brute-force and traffic capture
stop_bruteforce = threading.Event()
stop_capture = threading.Event()

# Create a global lock for thread-safe printing
print_lock = threading.Lock()

# Thread-safe print function
def thread_safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

# Function to handle signals like Ctrl+C for graceful exiting of brute-force
def signal_handler(sig, frame):
    global stop_bruteforce
    thread_safe_print("\nOperation interrupted by user! Skipping brute-force...")
    stop_bruteforce.set()

# Register the signal handler for Ctrl+C
signal.signal(signal.SIGINT, signal_handler)

# Function to identify cryptographic algorithms and hashes in file content
def identify_crypto_and_hashes_in_file(content):
    """
    Inspects the content of a file to detect cryptographic algorithms or hashes.
    This function looks for common cryptography algorithms and common hash types (MD5, SHA-1, etc.).
    """
    patterns = {
        'AES': r'\bAES(?:[-\s](128|192|256))?\b',
        'RSA': r'\bRSA(?:[-\s](1024|2048|4096))?\b',
        'DES': r'\bDES\b',
        '3DES': r'\b(3DES|TripleDES)\b',
        'RC4': r'\bRC4\b',
        'RC2': r'\bRC2\b',
        'Blowfish': r'\bBlowfish\b',
        'MD5': r'\b([a-fA-F0-9]{32})\b',  # MD5 hash pattern (32 hexadecimal characters)
        'SHA-1': r'\b([a-fA-F0-9]{40})\b',  # SHA-1 hash pattern (40 hexadecimal characters)
        'SHA-256': r'\b([A-Fa-f0-9]{64})\b',  # SHA-256 hash pattern (64 hexadecimal characters)
        'SHA-512': r'\b([A-Fa-f0-9]{128})\b',  # SHA-512 hash pattern (128 hexadecimal characters)
        'XOR': r'\bXOR\b',
        'UTF-8': r'\bUTF[-\s]?8\b'
    }

    detected_algorithms = []
    matched_strings = []

    for algo, pattern in patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            detected_algorithms.append(algo)
            matched_strings.append(matches)

    return detected_algorithms, matched_strings

# Function to crack MD5/SHA1 using a larger wordlist or brute-force attack
def crack_hash(hash_value, hash_type='MD5', brute_force=False):
    """
    Cracks an MD5 or SHA-1 hash using either a wordlist or brute-force.
    """
    if brute_force:
        return brute_force_crack(hash_value, hash_type)

    # First attempt wordlist-based cracking
    for word in sample_wordlist:
        if hash_type == 'MD5':
            hashed_word = hashlib.md5(word.encode()).hexdigest()
        elif hash_type == 'SHA-1':
            hashed_word = hashlib.sha1(word.encode()).hexdigest()
        if hashed_word == hash_value:
            return word
    return None

# Brute-force MD5 or SHA-1 hash cracker (limited to short lengths for feasibility)
def brute_force_crack(hash_value, hash_type, max_len=6, progress_update_interval=1000):
    """
    Tries to brute-force the given hash value by generating all possible combinations
    of letters and digits up to `max_len`.
    Provides progress updates after every `progress_update_interval` iterations.
    Allows the user to stop the brute-force using Ctrl+C.
    """
    global stop_bruteforce
    stop_bruteforce.clear()
    charset = ascii_letters + digits
    iteration_count = 0

    for length in range(1, max_len + 1):
        for guess in product(charset, repeat=length):
            if stop_bruteforce.is_set():
                thread_safe_print("Brute-force stopped by user.")
                return None  # Stop brute-force attempt gracefully

            guess_str = ''.join(guess)
            if hash_type == 'MD5':
                hashed_guess = hashlib.md5(guess_str.encode()).hexdigest()
            elif hash_type == 'SHA-1':
                hashed_guess = hashlib.sha1(guess_str.encode()).hexdigest()

            iteration_count += 1
            if iteration_count % progress_update_interval == 0:
                thread_safe_print(f"Brute-forcing {hash_type}: {iteration_count} attempts so far...")

            if hashed_guess == hash_value:
                return guess_str
    return None

# RC4 decryption using a key
def rc4_decrypt(ciphertext, key):
    cipher = ARC4.new(key)
    try:
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8', errors='ignore')
    except Exception:
        return None

# RC2 decryption using a key
def rc2_decrypt(ciphertext, key):
    try:
        cipher = ARC2.new(key, ARC2.MODE_ECB)  # Assuming ECB mode for simplicity
        plaintext = cipher.decrypt(ciphertext)
        return plaintext.decode('utf-8', errors='ignore')
    except Exception:
        return None

# XOR decryption (single-byte key brute-force)
def xor_decrypt(ciphertext):
    results = []
    for key in range(256):  # Try all possible single-byte keys (0-255)
        plaintext = ''.join(chr(c ^ key) for c in ciphertext)
        if is_printable(plaintext):
            results.append((key, plaintext))
    return results

# Helper function to check if text is printable
def is_printable(text):
    return all(32 <= ord(c) <= 126 for c in text)

# Function to handle timeouts and log verbose messages
def run_with_timeout(function, args=(), kwargs={}, timeout=10, operation_desc=""):
    """
    Runs the specified function with a timeout and provides verbose logging.
    If the function hangs, it will notify the user and log the operation description.
    """
    result = None
    try:
        result = function(*args, **kwargs)
    except Exception as e:
        thread_safe_print(f"WARNING: {operation_desc} failed: {e}")
    return result

# Function to recursively crawl directories and analyze files for cryptography and hashes
def crawl_directories_and_identify_crypto_and_hashes(directory, report_data, hash_summary, crypto_summary):
    """
    Recursively crawls through directories and files, analyzing each file for cryptographic patterns and hashes.
    """
    for root, dirs, files in os.walk(directory):
        thread_safe_print(f"Entering directory: {root}")  # Verbose output: show current directory
        for file in files:
            file_path = os.path.join(root, file)
            thread_safe_print(f"Processing file: {file_path}")  # Verbose output: show file being processed
            try:
                # Open each file and analyze its content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    algorithms, matched_strings = identify_crypto_and_hashes_in_file(content)

                    if algorithms:
                        for algo, matched in zip(algorithms, matched_strings):
                            vulnerability = vulnerable_algorithms.get(algo, "No known vulnerabilities")
                            cracked_info = ""

                            # Update summary counts
                            if algo in hash_summary:
                                hash_summary[algo] += len(matched)
                            elif algo in crypto_summary:
                                crypto_summary[algo] += len(matched)
                            else:
                                # First time detection
                                if algo in vulnerable_algorithms:
                                    crypto_summary[algo] = len(matched)
                                else:
                                    hash_summary[algo] = len(matched)

                            # Try to crack MD5 or SHA-1 if found with timeout protection
                            if algo in ['MD5', 'SHA-1', 'SHA-256', 'SHA-512']:
                                for hash_val in matched:
                                    thread_safe_print(f"Attempting to crack {algo} hash: {hash_val}")
                                    if algo in ['MD5', 'SHA-1']:  # Only try cracking MD5/SHA-1 (not feasible for SHA-256, etc.)
                                        try:
                                            cracked = run_with_timeout(crack_hash, args=(hash_val, algo), timeout=10, operation_desc=f"Cracking {algo} hash")
                                            if not cracked:
                                                thread_safe_print(f"Attempting brute-force for {algo} hash...")
                                                cracked = run_with_timeout(crack_hash, args=(hash_val, algo, True), timeout=20, operation_desc=f"Brute-forcing {algo} hash")
                                        except KeyboardInterrupt:
                                            thread_safe_print(f"Brute-forcing interrupted for {algo}. Skipping...")
                                            cracked = "Skipped by user"
                                        if cracked:
                                            cracked_info = f"Cracked Value: {cracked}"
                                    else:
                                        cracked_info = f"Found {algo} hash, no cracking attempted."

                            # Try to decrypt RC4, RC2, or XOR if found with timeout protection
                            if algo == 'RC4' and len(matched) > 0:
                                thread_safe_print(f"Attempting to decrypt RC4...")
                                for key in sample_wordlist:
                                    decrypted_text = run_with_timeout(rc4_decrypt, args=(bytes(matched[0], 'utf-8'), key.encode()), timeout=10, operation_desc="Decrypting RC4")
                                    if decrypted_text:
                                        cracked_info = f"Decrypted RC4 with key '{key}': {decrypted_text}"

                            if algo == 'RC2' and len(matched) > 0:
                                thread_safe_print(f"Attempting to decrypt RC2...")
                                for key in sample_wordlist:
                                    decrypted_text = run_with_timeout(rc2_decrypt, args=(bytes(matched[0], 'utf-8'), key.encode()), timeout=10, operation_desc="Decrypting RC2")
                                    if decrypted_text:
                                        cracked_info = f"Decrypted RC2 with key '{key}': {decrypted_text}"

                            if algo == 'XOR':
                                thread_safe_print(f"Attempting to decrypt XOR...")
                                ciphertext = bytes(matched[0], 'utf-8')
                                xor_results = run_with_timeout(xor_decrypt, args=(ciphertext,), timeout=10, operation_desc="Decrypting XOR")
                                if xor_results:
                                    cracked_info = f"Decrypted XOR with key {xor_results[0][0]}: {xor_results[0][1]}"

                            report_data.append({
                                'file_path': file_path,
                                'algorithm': algo,
                                'matched_string': matched,
                                'vulnerability': vulnerability,
                                'cracked_info': cracked_info
                            })

            except Exception as e:
                thread_safe_print(f"Error processing file {file_path}: {str(e)}")

# Function to generate a report based on findings
def generate_report(report_data, hash_summary, crypto_summary, traffic_data, report_name):
    """
    Generates a report after any operation.
    Includes summary of hashes and vulnerable cryptography algorithms.
    """
    report_file = os.path.join(os.getcwd(), report_name)
    with open(report_file, 'w', encoding='utf-8') as report:
        report.write(f"Encryption Vulnerability Report\n")
        report.write(f"Date: {datetime.now()}\n")
        report.write("=================================================\n")

        # Summary Section
        report.write("Summary of Detected Hashes and Cryptography\n")
        report.write("-------------------------------------------------\n")
        report.write("Detected Hashes:\n")
        for hash_type, count in hash_summary.items():
            report.write(f"- {hash_type}: {count} occurrences\n")

        report.write("\nVulnerable Cryptography Algorithms:\n")
        for crypto_type, count in crypto_summary.items():
            report.write(f"- {crypto_type}: {count} occurrences\n")

        report.write("\nDetailed Report:\n")
        report.write("=================================================\n")
        
        # Detailed Report
        for entry in report_data:
            report.write(f"File: {entry['file_path']}\n")
            report.write(f"Algorithm/Hash: {entry['algorithm']}\n")
            report.write(f"Matched String: {entry['matched_string']}\n")
            report.write(f"Vulnerability: {entry['vulnerability']}\n")
            report.write(f"Cracked Info: {entry['cracked_info'] if entry['cracked_info'] else 'N/A'}\n")
            report.write("-------------------------------------------------\n")

        # Add network traffic details to the report
        if traffic_data:
            report.write("\nNetwork Traffic Information:\n")
            report.write("-------------------------------------------------\n")
            for traffic in traffic_data:
                report.write(f"Endpoint: {traffic['ip']} Port: {traffic['port']} Cryptography: {traffic['crypto']}\n")

    thread_safe_print(f"Report generated at: {report_file}")

# Network traffic packet handler to inspect packet content for cryptographic patterns
def packet_handler(packet, traffic_data):
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        # Inspect packet content for cryptographic patterns
        if packet.haslayer(Raw):
            payload = str(packet[Raw].load)
            if 'rc4' in payload.lower() or 'md5' in payload.lower():
                traffic_info = {
                    'ip': packet[IP].dst,
                    'port': packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport,
                    'crypto': 'Detected cryptography: RC4/MD5 in payload'
                }
                traffic_data.append(traffic_info)
                thread_safe_print(f"Detected cryptographic data in traffic: {traffic_info}")

# Function to monitor network traffic while an application is running
def monitor_application(app_command, interface="Ethernet", capture_duration=60):
    """
    Starts the specified application and monitors network traffic for cryptographic patterns.
    Args:
        app_command (str): The application command to run.
        interface (str): The network interface to capture traffic on.
        capture_duration (int): How long to capture traffic (in seconds).
    """
    global stop_capture
    stop_capture.clear()

    traffic_data = []

    # Start the application using subprocess
    try:
        thread_safe_print(f"Starting application: {app_command}")
        process = subprocess.Popen(app_command, shell=True)

        # Start sniffing network traffic in a separate thread
        def capture_traffic():
            sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, traffic_data), stop_filter=lambda x: stop_capture.is_set(), timeout=capture_duration)

        thread_safe_print(f"Capturing network traffic on interface: {interface} for {capture_duration} seconds...")
        capture_thread = threading.Thread(target=capture_traffic)
        capture_thread.start()

        # Wait for the traffic capture to complete
        capture_thread.join()

        # Once the capture is complete, terminate the application
        thread_safe_print("Stopping the application and traffic capture...")
        process.terminate()

    except Exception as e:
        thread_safe_print(f"Error while running application or capturing traffic: {str(e)}")

    return traffic_data

# Function to start all .exe applications in a directory and capture network traffic
def start_and_monitor_exe_apps(exe_dir, interface="Ethernet", capture_duration=60):
    """
    Starts all .exe files found in the specified directory and subdirectories, monitors network traffic, and identifies cryptography.
    Args:
        exe_dir (str): The directory where .exe files are located.
        interface (str): The network interface to capture traffic on.
        capture_duration (int): How long to capture traffic (in seconds).
    """
    global stop_capture
    stop_capture.clear()

    # Recursively find all .exe files in the specified directory and subdirectories
    exe_files = []
    for root, dirs, files in os.walk(exe_dir):
        for file in files:
            if file.endswith('.exe'):
                exe_files.append(os.path.join(root, file))

    if not exe_files:
        thread_safe_print(f"No .exe files found in directory: {exe_dir}")
        return

    traffic_data = []
    try:
        for exe_file in exe_files:
            thread_safe_print(f"Starting application: {exe_file}")
            process = subprocess.Popen(exe_file)

            # Start sniffing network traffic in a separate thread
            def capture_traffic():
                sniff(iface=interface, prn=lambda pkt: packet_handler(pkt, traffic_data), stop_filter=lambda x: stop_capture.is_set(), timeout=capture_duration)

            thread_safe_print(f"Capturing network traffic for {exe_file} on interface: {interface} for {capture_duration} seconds...")
            capture_thread = threading.Thread(target=capture_traffic)
            capture_thread.start()

            # Wait for the traffic capture to complete
            capture_thread.join()

            # Stop the application once traffic capture is done
            thread_safe_print(f"Stopping application: {exe_file}")
            process.terminate()

    except Exception as e:
        thread_safe_print(f"Error while running applications or capturing traffic: {str(e)}")

    return traffic_data

# Main function with menu
def main():
    while True:
        print("\nMenu:")
        thread_safe_print("1. Run normal search through directories")
        thread_safe_print("2. Start an application, capture traffic, and identify cryptography")
        thread_safe_print("3. Start all .exe applications, capture traffic, and identify cryptography")
        thread_safe_print("4. Exit")
        
        try:
            choice = input("Select an option: ")

            if choice == "1":
                user_input_dir = input("Enter the directory to scan: ")
                if not os.path.exists(user_input_dir):
                    thread_safe_print("Invalid directory path. Please check the path and try again.")
                    continue

                # Initialize an empty list to collect the findings
                report_data = []
                hash_summary = {}
                crypto_summary = {}

                # Perform the directory crawl and cryptography identification
                crawl_directories_and_identify_crypto_and_hashes(user_input_dir, report_data, hash_summary, crypto_summary)

                # Generate a report from the findings
                report_name = f"directory_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                generate_report(report_data, hash_summary, crypto_summary, [], report_name)

            elif choice == "2":
                app_command = input("Enter the application command to start: ")
                network_interface = "Ethernet"  # Automatically using Ethernet, adjust if needed
                traffic_data = monitor_application(app_command, interface=network_interface)

                # Generate a simple report about traffic capture
                report_name = f"application_traffic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                generate_report([], {}, {}, traffic_data, report_name)

            elif choice == "3":
                exe_dir = input("Enter the directory with .exe files: ")
                if not os.path.exists(exe_dir):
                    thread_safe_print("Invalid directory path. Please check the path and try again.")
                    continue
                network_interface = "Ethernet"  # Automatically using Ethernet, adjust if needed
                traffic_data = start_and_monitor_exe_apps(exe_dir, interface=network_interface)

                # Generate a simple report about .exe monitoring
                report_name = f"exe_monitoring_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                generate_report([], {}, {}, traffic_data, report_name)

            elif choice == "4":
                thread_safe_print("Exiting...")
                break

            else:
                thread_safe_print("Invalid choice. Please select again.")
        except KeyboardInterrupt:
            thread_safe_print("User interrupted the program. Exiting now...")
            sys.exit(0)

if __name__ == "__main__":
    main()
