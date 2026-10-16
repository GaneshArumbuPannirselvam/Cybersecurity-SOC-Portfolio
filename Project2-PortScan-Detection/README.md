# Project 2: Port Scan Reconnaissance Simulation & SIEM Alert Engineering

## 1. Executive Summary & Objective
This laboratory simulates malicious network reconnaissance (port scanning) targeting an enterprise network perimeter. The defensive objective is to ingest network/firewall events into an enterprise SIEM platform, establish a baseline for normal network traffic, and design a high-fidelity correlation rule capable of detecting stealthy and rapid scanning behaviors while ignoring authorized internal network monitoring tools.

## 2. Lab Architecture & Sandbox Topology
*   **Attacker Node:** Kali Linux (IP: `192.168.1.50`) simulating an external or rogue internal threat actor running `Nmap`.
*   **Target Enterprise Endpoint:** Linux Web/Database Server (IP: `192.168.1.100`) exposing multiple network services.
*   **SIEM Analytics Core:** Splunk Enterprise / ELK Stack (IP: `192.168.1.150`) continuously aggregating system network connection states.

---

## 3. Threat Simulation & Attack Phase
To map the target's attack surface and identify exploitable vectors, multiple scanning techniques were executed from the Kali Linux node using the network utility `Nmap`:

### Active Syn Stealth Scan (TCP Half-Open):
```bash
nmap -sS -p 1-1024 -T4 192.168.1.100
```
*This command fires rapid TCP SYN packets without completing the 3-way handshake, attempting to bypass standard application-layer logging engines.*

### Comprehensive Service/OS Enumeration Scan:
```bash
nmap -sV -O -p 22,80,443 192.168.1.100
```
*This probe interacts directly with open ports to grab software version banners and fingerprint the underlying operating system kernel.*

---

## 4. SIEM Log Analysis & Threshold Alert Queries
A standard system logs a single connection when a user connects. However, an active port scan causes a single source IP to connect to hundreds of different ports in a matter of seconds, creating a massive statistical spike.

### Production Detection Rule (Splunk SPL Query):
```splunk
index=network_firewall action=blocked OR action=allowed
| stats dc(dest_port) as unique_ports_targeted, values(dest_port) as targeted_services by src_ip
| where unique_ports_targeted > 25
| rename src_ip as "Suspected Scanner IP", unique_ports_targeted as "Distinct Ports Scanned"
```

### Analysis Checklist for SOC Analysts:
1. **Distinct Count (`dc`) Metric:** Rather than looking at total connection volume, tracking distinct counts isolates an attacker probing different services sequentially.
2. **False-Positive Whitelisting:** Internal IT asset scanners (like Nessus or Qualys) mimic this exact behavior. In a production environment, authorized internal monitoring IPs must be whitelisted out of this alert logic: `| where unique_ports_targeted > 25 AND NOT (src_ip="192.168.1.10")`.

---

## 5. Defensive Engineering & Remediation Strategy
To shield network topology and minimize external reconnaissance visibility, the following architectural controls were implemented:
1. **Network Firewall Hardening:** Enforce a strict "Default Deny" perimeter policy, ensuring all non-essential ports are completely closed and dropped at the network boundary.
2. **Adaptive Rate Limiting & Shunning:** Configure an Intrusion Prevention System (IPS) or configure local firewall modules (`iptables` / `nftables`) with rate-limiting rules to drop traffic automatically from any external host exceeding connection limits:
   ```bash
   iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --set
   iptables -A INPUT -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP
   ```
3. **Deploying Honeypots/Decoys:** Implement a network honeypot (e.g., `Pentbox` or `Cowrie`) on an unused IP address inside the subnet. Because legitimate corporate users have no business connecting to a honeypot, any connection attempt to it triggers an immediate high-severity SOC alert.
