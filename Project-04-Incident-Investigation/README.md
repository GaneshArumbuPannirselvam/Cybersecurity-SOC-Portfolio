# Project 4: End-to-End Incident Investigation & Timeline Reconstruction
**Category:** Incident Response & Security Operations  
**Core Technologies:** Splunk Enterprise (SIEM), Wireshark, Nmap, Syslog, Markdown Reporting

---

## 1. Executive Summary
On [Insert Date, e.g., October 24, 2026], a high-severity security incident was initiated against our core corporate infrastructure. An anomalous, high-volume data egress condition triggered an automated alert via our centralized SIEM platform (Splunk). This repository documents the full-lifecycle investigative process executed to isolate the compromised endpoint, determine the initial vector of compromise, trace lateral movements, perform log correlation, and compile a formal executive incident report.

---

## 2. Incident Timeline & Attack Reconstruction

Through strict cross-log synchronization, the complete attack lifecycle was successfully isolated and mapped into a structured chronological timeline:

| Timestamp (EST) | Source Component / Log Type | Event Details & Observations |
| :--- | :--- | :--- |
| **14:02:15** | Nginx Web Access Logs | Target IP `192.168.10.45` launched an aggressive vulnerability sweep using an unauthorized User-Agent string. |
| **14:11:40** | Windows Security Event ID 4625 | 14 consecutive failed authentication attempts targeted at a local administrative account on server `SRV-PROD-01`. |
| **14:13:02** | Windows Security Event ID 4624 | Successful authentication event recorded for the targeted administrative account, establishing initial access. |
| **14:22:50** | Sysmon Event ID 1 (Process Creation) | Execution of an unauthorized network reconnaissance tool binary from a hidden user temporary folder (`C:\Users\Public\Temp\`). |
| **14:45:10** | Firewall Connection Traffic Logs | Initiation of an unencrypted, persistent outbound connection from `SRV-PROD-01` to an external malicious IP, initiating 4.2GB of data egress. |

---

## 3. Advanced Log Correlation & Search Diagnostics (Splunk)

To isolate the root cause, a multi-stage search sequence was executed across our indexed data repositories. 

### Step 3.1: Identifying Brute-Force Authentication Indicators
The initial query correlated massive spikes in authentication failures immediately preceding the successful system compromise:

```splunk
index=security_logs event_id=4625 OR event_id=4624
| stats count by src_ip, event_id, user
| xyseries src_ip, event_id, count
| rename 4625 as Failed_Logins, 4624 as Successful_Logins
| where Failed_Logins > 10 AND Successful_Logins > 0
```

### Step 3.2: Isolation of Data Egress Vector
Once the compromised host was identified, network traffic volumes were parsed to verify data exfiltration boundaries:

```splunk
index=network_firewall src_ip="192.168.10.12" 
| stats sum(bytes_out) as TotalEgress by dest_ip
| eval TotalEgress_GB = round(TotalEgress/1024/1024/1024, 2)
| where TotalEgress_GB > 1.0
| sort - TotalEgress_GB
```

---

## 4. Deep Packet Inspection & Telemetry (Wireshark)

Following SIEM pattern identification, raw network stream analysis was conducted on PCAP artifacts collected from the affected network segment:

1. **Protocol Analysis:** Inspected the persistent outbound TCP session on port `443`. Packet inspection revealed a distinct lack of proper TLS handshaking parameters, proving the malicious entity was tunneling unencrypted data through an ordinary web traffic port to bypass native edge filtering.
2. **Flag Analysis:** Isolated persistent `PUSH/ACK` sequence loops containing structural database schemas and proprietary string formats, confirming unauthorized data extraction was actively occurring during the timeline.

---

## 5. Containment, Eradication & Remediation Actions

To mitigate corporate risk and protect operational infrastructure, a multi-tiered remediation response was executed immediately following verification:

* **Host Isolation:** Issued an immediate network containment command via the Endpoint Detection and Response (EDR) interface to decouple `SRV-PROD-01` from the active subnet.
* **Credential Revocation:** Executed a global forced password reset and token revocation across Active Directory / Entra ID for the compromised administrative identity.
* **Firewall Engineering:** Implemented a persistent block rule on the edge **pfSense appliance** to drop all incoming and outgoing connections interacting with the external malicious controller IP.
* **Post-Incident Hardening:** Deployed updated **CIS Benchmark** group policies to completely restrict local administrative login capabilities over public-facing network interface boundaries.
