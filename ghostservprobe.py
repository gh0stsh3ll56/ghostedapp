import psutil
import socket
import time

# Function to attempt a connection and read banner
def probe_port(ip, port):
    print(f"[INFO] Attempting to connect to {ip}:{port}...")  # Verbose output
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)  # Timeout if the connection takes too long
        sock.connect((ip, port))
        
        # Try to read banner (first few bytes)
        banner = sock.recv(1024).decode().strip()
        sock.close()
        print(f"[SUCCESS] Connected to {ip}:{port}, Banner: {banner}")  # Verbose output
        return banner
    except socket.timeout:
        print(f"[TIMEOUT] Connection to {ip}:{port} timed out.")  # Verbose output
        return None
    except ConnectionRefusedError:
        print(f"[REFUSED] Connection to {ip}:{port} was refused.")  # Verbose output
        return None
    except Exception as e:
        print(f"[ERROR] Error connecting to {ip}:{port}: {e}")  # Verbose output
        return None

# Function to get server details and attempt connections
def get_server_details():
    print("[INFO] Gathering all open network connections...")  # Verbose output
    connections = psutil.net_connections(kind='inet')
    server_list = []

    if not connections:
        print("[WARNING] No active network connections found.")  # Verbose output
        return server_list

    for conn in connections:
        if conn.status == psutil.CONN_LISTEN:
            ip, port = conn.laddr
            print(f"[INFO] Detected listening service on {ip}:{port}.")  # Verbose output
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name()
                print(f"[INFO] Associated process: {process_name} (PID: {conn.pid}).")  # Verbose output
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = "Unknown Process"
                print(f"[WARNING] Could not retrieve process info for {ip}:{port}.")  # Verbose output
            
            # Try to connect and get a banner or response
            banner = probe_port(ip, port)
            if banner:
                server_type = identify_server_from_banner(banner)
            else:
                server_type = "Unknown (No Banner)"
                print(f"[INFO] No banner received for {ip}:{port}. Fallback to process name or manual identification.")  # Verbose output
            
            server_info = {
                "ip": ip,
                "port": port,
                "process_name": process_name,
                "server_type": server_type,
                "banner": banner,
                "pid": conn.pid
            }
            server_list.append(server_info)
    
    return server_list

# Function to identify server based on banner response
def identify_server_from_banner(banner):
    # Verbose banner inspection
    print(f"[INFO] Inspecting banner for server identification... Banner: {banner}")

    # Simple checks based on common database/server responses
    if "MySQL" in banner:
        print("[IDENTIFIED] MySQL Server detected.")  # Verbose output
        return "MySQL Server"
    elif "PostgreSQL" in banner:
        print("[IDENTIFIED] PostgreSQL Server detected.")  # Verbose output
        return "PostgreSQL Server"
    elif "Redis" in banner:
        print("[IDENTIFIED] Redis Server detected.")  # Verbose output
        return "Redis Server"
    elif "MongoDB" in banner:
        print("[IDENTIFIED] MongoDB Server detected.")  # Verbose output
        return "MongoDB Server"
    elif "SQL Server" in banner:
        print("[IDENTIFIED] Microsoft SQL Server detected.")  # Verbose output
        return "Microsoft SQL Server"
    elif "HTTP" in banner or "Apache" in banner or "nginx" in banner:
        print("[IDENTIFIED] Web Server (HTTP/HTTPS) detected.")  # Verbose output
        return "Web Server (HTTP/HTTPS)"
    elif "SSH" in banner:
        print("[IDENTIFIED] SSH Server detected.")  # Verbose output
        return "SSH Server"
    elif "FTP" in banner:
        print("[IDENTIFIED] FTP Server detected.")  # Verbose output
        return "FTP Server"
    else:
        print("[UNKNOWN] Could not identify server from banner.")  # Verbose output
        return "Unknown Server"

# Function to print server details in verbose format
def print_server_details(servers):
    if not servers:
        print("[INFO] No servers detected.")
        return

    print("[INFO] Printing detected server details:")
    for server in servers:
        print(f"----------------------------")
        print(f"Server Detected: {server['server_type']}")
        print(f"Process: {server['process_name']} (PID: {server['pid']})")
        print(f"Endpoint: {server['ip']}:{server['port']}")
        print(f"Banner: {server['banner']}")
        print(f"----------------------------")

if __name__ == "__main__":
    print("[START] Starting server identification script...")
    servers = get_server_details()
    print_server_details(servers)
    print("[COMPLETE] Server identification completed.")
