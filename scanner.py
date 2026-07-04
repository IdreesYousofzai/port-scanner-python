"""
Network Port Scanner
=====================
A basic multi-threaded TCP port scanner built with Python's socket library.

LEGAL / ETHICAL NOTICE
Only scan hosts you own or have explicit written permission to test
(e.g. your own home lab, localhost, or a CTF target). Scanning networks
you do not own or have authorization for is illegal in most countries
(e.g. under the UK Computer Misuse Act 1990, or the US CFAA) even if no
damage is done. See README.md for the full disclaimer.

Usage:
    python scanner.py --target 127.0.0.1 --start-port 1 --end-port 1024
    python scanner.py -t 127.0.0.1 -s 1 -e 65535 --timeout 0.5 --threads 200
    python scanner.py -t 127.0.0.1 --save report.txt
"""


import argparse
import socket
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ---------------------------------------------------------------------------
# Common port -> service name mappings.
# This is not exhaustive — it covers the most frequently seen services.
# ---------------------------------------------------------------------------

COMMON_PORTS = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle-DB",
    3000: "Node/Dev-Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

# Thread-safe container for results and a print lock so threaded output
# doesn't interleave garbled text on the terminal.
print_lock = threading.Lock()



def identify_service(port: int) -> str:
    """Return a human-readable service name for a well-known port."""
    return COMMON_PORTS.get(port, "Unknown")


def scan_port(target: str, port: int, timeout: float) -> tuple[int, bool]:
    """
    Attempt a TCP connect to (target, port).
    Returns (port, is_open).
    Uses connect_ex so it doesn't raise on refused connections — it just
    returns a non-zero error code, which is faster and cleaner to handle
    than wrapping connect() in try/except for every closed port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        return port, result == 0


def run_scan(target: str, start_port: int, end_port: int, timeout: float, max_threads: int):
    """
    Scan target across [start_port, end_port] using a thread pool.
    Yields (port, service) tuples for open ports, in ascending port order.
    """
    open_ports = []
    total_ports = end_port - start_port + 1

    with print_lock:
        print(f"\nScanning {target} — ports {start_port}-{end_port} "
              f"({total_ports} ports, {max_threads} threads, {timeout}s timeout)\n")

    start_time = datetime.now()

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(scan_port, target, port, timeout): port
            for port in range(start_port, end_port + 1)
        }
        for future in as_completed(futures):
            try:
                port, is_open = future.result()
            except socket.gaierror:
                with print_lock:
                    print(f"[!] Could not resolve hostname: {target}")
                sys.exit(1)
            except Exception as exc:
                # Individual port failures shouldn't kill the whole scan.
                continue

            if is_open:
                service = identify_service(port)
                open_ports.append((port, service))
                with print_lock:
                    print(f"[+] Port {port:>5} OPEN   -> {service}")

    elapsed = (datetime.now() - start_time).total_seconds()
    open_ports.sort(key=lambda p: p[0])
    return open_ports, elapsed


def write_report(path: str, target: str, start_port: int, end_port: int,
                  timeout: float, open_ports: list, elapsed: float):
    """Write scan results to a timestamped .txt report."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "w") as f:
        f.write("=" * 50 + "\n")
        f.write("PORT SCAN REPORT\n")
        f.write("=" * 50 + "\n")
        f.write(f"Timestamp:   {timestamp}\n")
        f.write(f"Target:      {target}\n")
        f.write(f"Port range:  {start_port}-{end_port}\n")
        f.write(f"Timeout:     {timeout}s\n")
        f.write(f"Duration:    {elapsed:.2f}s\n")
        f.write(f"Open ports:  {len(open_ports)}\n")
        f.write("-" * 50 + "\n")
        if open_ports:
            for port, service in open_ports:
                f.write(f"Port {port:>5}  OPEN   {service}\n")
        else:
            f.write("No open ports found.\n")
        f.write("=" * 50 + "\n")


def parse_args():
    parser = argparse.ArgumentParser(
        description="A basic multi-threaded TCP port scanner for authorized testing only.",
        epilog="Example: python scanner.py -t 127.0.0.1 -s 1 -e 1024 --save report.txt"
    )
    parser.add_argument("-t", "--target", default="127.0.0.1",
                         help="Target IP address or hostname (default: 127.0.0.1 / localhost)")
    parser.add_argument("-s", "--start-port", type=int, default=1,
                         help="Start of port range (default: 1)")
    parser.add_argument("-e", "--end-port", type=int, default=1024,
                         help="End of port range (default: 1024)")
    parser.add_argument("--timeout", type=float, default=0.5,
                         help="Socket timeout in seconds per port (default: 0.5)")
    parser.add_argument("--threads", type=int, default=100,
                         help="Number of worker threads (default: 100)")
    parser.add_argument("--save", nargs="?", const="AUTO", default=None,
                         metavar="FILENAME",
                         help="Save results to a .txt report. If no filename is given, "
                              "one is auto-generated with a timestamp.")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.start_port < 1 or args.end_port > 65535:
        print("[!] Ports must be between 1 and 65535.")
        sys.exit(1)
    if args.start_port > args.end_port:
        print("[!] start-port must be <= end-port.")
        sys.exit(1)

    # Resolve hostname to IP up front for a clean error message.
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[!] Could not resolve hostname: {args.target}")
        sys.exit(1)

    open_ports, elapsed = run_scan(
        target_ip, args.start_port, args.end_port, args.timeout, args.threads
    )

    print("\n" + "-" * 50)
    print(f"Scan complete in {elapsed:.2f}s. {len(open_ports)} open port(s) found.")
    print("-" * 50)

    if open_ports:
        for port, service in open_ports:
            print(f"  Port {port:>5}  ->  {service}")
    else:
        print("  No open ports found in the given range.")

    if args.save is not None:
        if args.save == "AUTO":
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_report_{ts}.txt"
        else:
            filename = args.save
        write_report(filename, args.target, args.start_port, args.end_port,
                      args.timeout, open_ports, elapsed)
        print(f"\n[✓] Report saved to {filename}")


if __name__ == "__main__":
    main()
