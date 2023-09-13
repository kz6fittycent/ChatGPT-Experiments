import socket
import ipaddress
import threading

# Define the target subnet (change this to your home network)
subnet = "10.0.0.0/24"

# Function to perform host enumeration
def enumerate_hosts(subnet):
    try:
        # Parse the subnet
        network = ipaddress.IPv4Network(subnet, strict=False)
        
        # Iterate through hosts in the subnet
        for host in network.hosts():
            host_ip = str(host)
            
            # Check if the host is reachable
            if is_host_reachable(host_ip):
                print(f"Host {host_ip} is up.")
                
                # Perform port scanning
                open_ports = scan_ports(host_ip)
                
                if open_ports:
                    print(f"Open ports on {host_ip}: {', '.join(map(str, open_ports))}")
                else:
                    print(f"No open ports found on {host_ip}")

    except Exception as e:
        print(f"Error: {e}")

# Function to check if a host is reachable
def is_host_reachable(host_ip):
    try:
        # Create a socket and set a timeout
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        # Attempt to connect to a common port (e.g., 80 for HTTP)
        result = sock.connect_ex((host_ip, 80))
        
        # If the connection was successful, the host is reachable
        return result == 0
    except socket.error:
        return False
    finally:
        sock.close()

# Function to scan ports on a host
def scan_ports(host_ip, start_port=1, end_port=1024, timeout=1):
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((host_ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            pass
    return open_ports

if __name__ == "__main__":
    enumerate_hosts(subnet)

