#!/usr/bin/env python3
import socket
import sys
import time
import queue
import threading
import requests
import socket
from concurrent.futures import ThreadPoolExecutor

usage = "Usage: python3 port_scanner.py TARGET START_PORT END_PORT THREADS"

print("*" * 50)
print("Advanced Python Port Scanner")
print("*" * 50)

if len(sys.argv) != 5:
    print(usage)
    sys.exit(1)

try:
    target = sys.argv[1]
    start_port = int(sys.argv[2])
    end_port = int(sys.argv[3])
    thread_count = int(sys.argv[4])
except (ValueError, IndexError):
    print("[-] Invalid arguments. Ports and thread count must be integers.")
    print(usage)
    sys.exit(1)

if start_port < 1 or end_port > 65535 or start_port > end_port:
    print("[-] Invalid port range. Use 1-65535.")
    sys.exit(1)

try:
    target_ip = socket.gethostbyname(target)
except socket.gaierror:
    print("[-] Cannot resolve hostname!")
    sys.exit(1)

print(f"[+] Target: {target} ({target_ip})")
print(f"[+] Scanning ports {start_port}-{end_port}")
print(f"[+] Using {thread_count} threads\n")

# Common service names for better output
SERVICE_NAMES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
    995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-Proxy'
}

results = []
lock = threading.Lock()
total_ports = end_port - start_port + 1


def get_banner(sock, port):
    """Extract service banner from socket connection"""
    if port in [80, 8080, 443]:
        try:
            sock.close()
            resp = requests.get(f"http://{target_ip}:{port}",
                                timeout=2, verify=False)
            return resp.headers.get('Server', 'HTTP')
        except:
            return 'HTTP'

    try:
        sock.settimeout(2)
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        # Clean up banner (remove newlines, limit length)
        banner = ' '.join(banner.splitlines())[:50]
        return banner if banner else 'Unknown'
    except:
        return 'Unknown'


def scan_port(port):
    """Scan single port and return result"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))

        if result == 0:  # Port open
            banner = get_banner(sock, port)
            service = SERVICE_NAMES.get(port, 'Unknown')
            with lock:
                results.append(f"{port:5d}\tOPEN  \t{service:<12}\t{banner}")
                print(f"\r[+] Port {port} OPEN ({service})", end='', flush=True)
        sock.close()
    except:
        pass


# Populate queue with ports
ports = list(range(start_port, end_port + 1))
start_time = time.time()

# Use ThreadPoolExecutor for better thread management
with ThreadPoolExecutor(max_workers=thread_count) as executor:
    executor.map(scan_port, ports)

end_time = time.time()
scan_time = end_time - start_time

# Sort results by port number
results.sort(key=lambda x: int(x.split()[0]))

# Print summary
print(f"\n\n[+] Scan completed in {scan_time:.2f}s")
print(f"[+] {len(results)}/{total_ports} ports open ({100 * len(results) / total_ports:.1f}%)")

if results:
    print("\n[+] Open ports:")
    print("PORT\tSTATE\tSERVICE\t\tBANNER")
    print("-" * 50)
    for result in results:
        print(result)
else:
    print("\n[-] No open ports found")

# Save results
output = f"Port scan results for {target} ({target_ip})\n"
output += f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
output += f"Range: {start_port}-{end_port} | Time: {scan_time:.2f}s\n"
output += f"Open: {len(results)}/{total_ports}\n\n"
output += "PORT\tSTATE\tSERVICE\t\tBANNER\n"
output += "-" * 50 + "\n"
output += "\n".join(results) + "\n"

filename = f"scan_{target_ip}_{start_port}-{end_port}.txt"
with open(filename, 'w') as f:
    f.write(output)

print(f"[+] Results saved to {filename}")