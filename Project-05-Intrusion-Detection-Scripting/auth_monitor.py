#!/usr/bin/env python3
import re
import sys
from collections import Counter

# Path to standard Linux authentication logs
LOG_FILE = "/var/log/auth.log"
FAILED_THRESHOLD = 5

def analyze_brute_force():
    print(f"[*] Analyzing {LOG_FILE} for brute-force signatures...")
    failed_ips = []
    
    try:
        with open(LOG_FILE, "r") as file:
            for line in file:
                # Regex pattern matching standard sshd failed password indicators
                if "Failed password for" in line:
                    # Extract the IP address using regex
                    ip_match = re.search(r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if ip_match:
                        failed_ips.append(ip_match.group(1))
    except FileNotFoundError:
        print(f"[!] Error: {LOG_FILE} not found. Ensure this script is running on a Linux system.")
        sys.exit(1)

    # Tally the failed attempts per unique IP address
    ip_counts = Counter(failed_ips)
    flagged_ips = 0

    print("\n[+] --- INTRUSION DETECTION ALERTS ---")
    for ip, count in ip_counts.items():
        if count >= FAILED_THRESHOLD:
            print(f"[ALERT] Malicious Activity Detected! Host IP: {ip} | Total Failed Attempts: {count}")
            flagged_ips += 1
            
    if flagged_ips == 0:
        print("[*] Scan complete. No suspicious authentication thresholds breached.")

if __name__ == "__main__":
    analyze_brute_force()
