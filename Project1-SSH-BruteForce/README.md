# Project 1: SSH Brute-Force Attack Simulation & SIEM Detection

## 1. Executive Summary & Objective
This laboratory simulates a high-frequency SSH brute-force credential attack against a Linux endpoint. The defensive objective is to ingest raw system authentication logs into an enterprise SIEM (Splunk), construct a statistical detection baseline, and engineer an optimized correlation rule to alert on active unauthorized access attempts while mitigating false positives.

## 2. Lab Architecture & Sandbox Topology
*   **Attacker Node:** Kali Linux (IP: `192.168.1.50`) running automated brute-force scripts via `Hydra`.
*   **Target Enterprise Endpoint:** Ubuntu Server 22.04 LTS (IP: `192.168.1.100`) running an open SSH daemon (`sshd`).
*   **Log Forwarding Agent:** Splunk Universal Forwarder tracking system states.
*   **SIEM Analytics Core:** Splunk Enterprise (IP: `192.168.1.150`).

---

## 3. Threat Simulation & Attack Phase
To replicate an external malicious actor targeting management interfaces, the automated password-cracking utility `Hydra` was executed from the Kali Linux node against the target server using a common user list and a customized wordlist:

```bash
hydra -L users.txt -P passwords.txt ssh://192.168.1.100 -V -t 4
```
*This command forces high-volume parallel authentication transactions, generating extensive failed system events within the target's operating system kernels.*

---

## 4. SIEM Log Analysis & Threat Hunting Queries
The target Linux server stores authentication metrics inside `/var/log/auth.log`. Once forwarded to Splunk, the raw data was parsed to track anomalous patterns.

### Production Detection Rule (SPL Query):
```splunk
index=linux sourcetype=auth "failed password"
| stats count, dc(user) as targeted_users, values(user) as attempted_accounts by src_ip
| where count > 10
| rename src_ip as "Attacker IP", count as "Failed Attempts"
```

### Analysis Checklist for SOC Analysts:
1. **Volumetric Thresholding:** The query filters for instances where a single external source IP address triggers more than 10 unique authentication failures within a 5-minute rolling window.
2. **Account Targeting:** Tracking the distinct count (`dc`) of users helps differentiate a broad dictionary attack from a targeted spear-brute-force attempt against a specific administrator account.

---

## 5. Defensive Engineering & Remediation Strategy
To defend the corporate perimeter against this threat vector, the following mitigations were designed and evaluated:
1. **Network Layer Access Controls:** Restrict SSH access exclusively to authorized enterprise network ranges or require a secure corporate VPN gateway.
2. **Host-Based Intrusion Prevention:** Deploy and configure `Fail2Ban` on the server to automatically drop traffic at the local firewall (`iptables`) if a source IP exceeds 5 failed attempts within 10 minutes.
3. **Authentication Hardening:** Completely disable standard password authentication within `/etc/ssh/sshd_config` and enforce mandatory cryptographic **SSH Key-Pair Authentication** combined with Multi-Factor Authentication (MFA).
