# Project 6: Command & Control (C2) Beaconing Detection & Threat Hunting
**Category:** Network Threat Hunting, Traffic Analysis, Detection Engineering  
**Core Technologies:** Wireshark, Splunk Enterprise, ELK Stack, Delta-Time Log Analysis, PCAP Diagnostics

---

## 1. Project Overview
Advanced Persistent Threats (APTs) and modern malware variants establish external persistent communication channels known as **Command and Control (C2) infrastructure**. To bypass security firewalls, infected internal endpoints establish automated, periodic connection signals—or **beacons**—checking back with a remote malicious handler server for instructions.

This project focuses on a comprehensive threat-hunting scenario that isolates hidden C2 beaconing activity within enterprise network traffic. It leverages **Wireshark relative delta-time filtering** and **Splunk statistical analytics** to identify highly periodic communication loops hidden beneath thousands of standard, non-malicious web requests.

---

## 2. Threat Hunting Methodology & Technical Logic

Standard user web browsing behavior is random and bursty. Conversely, automated C2 malware beaconing relies on programmatic execution logic (e.g., calling home exactly every 30 seconds). By measuring the **Delta-Time** (the precise amount of elapsed time between consecutive packets in a singular conversational stream), threat hunters can mathematically flag machine-driven traffic.

### Step 2.1: Wireshark Packet Telemetry Analysis
Using an active packet capture (PCAP) dataset, network conversational streams targeting an external destination IP were isolated. 

A custom column was created to calculate `frame.time_delta_relative` (the elapsed time since the previous captured packet in that specific stream). The analysis isolated a highly suspicious pattern over port `443` tracking back to internal host `192.168.20.104`:

```text
Packet No.  | Source IP       | Destination IP  | Protocol | Length | Delta-Time (Relative)
No. 1405    | 192.168.20.104  | 203.0.113.88    | TCP (TLS)| 512    | 0.000000 (Stream Init)
No. 2891    | 192.168.20.104  | 203.0.113.88    | TCP (TLS)| 512    | 30.004122 seconds
No. 4110    | 192.168.20.104  | 203.0.113.88    | TCP (TLS)| 512    | 29.998415 seconds
No. 5904    | 192.168.20.104  | 203.0.113.88    | TCP (TLS)| 512    | 30.001204 seconds
No. 7443    | 192.168.20.104  | 203.0.113.88    | TCP (TLS)| 512    | 30.002991 seconds
```
*Analysis Finding:* The variance between connections is less than 0.05 seconds, indicating a highly precise, pre-programmed script rather than human web interaction.

---

## 3. SIEM Detection Engineering (Splunk SPL)

To scale this threat hunt across a corporate enterprise network containing millions of event items, a custom **Splunk SPL query** was engineered. This query uses transaction grouping to sort events by time variables and isolates sessions that exhibit tight mathematical clustering:

```splunk
index=network_proxy dest_port=443
| sort 0 _time
| streamstats window=2 current=f last(_time) as previous_time by src_ip, dest_ip
| eval delta_time = _time - previous_time
| stats count, avg(delta_time) as AvgInterval, var(delta_time) as TimeVariance by src_ip, dest_ip
| where count > 100 AND TimeVariance < 0.5
| sort + TimeVariance
```

### Explaining the Logic:
1. `streamstats window=2`: Tracks pairs of consecutive connections between the same source and destination IPs.
2. `eval delta_time = _time - previous_time`: Calculates the absolute time spacing in seconds between outbound attempts.
3. `var(delta_time) as TimeVariance`: Calculates the statistical variance. A **TimeVariance near 0** indicates that the callback timings are perfectly uniform and identical.
4. `where count > 100 AND TimeVariance < 0.5`: Filters out random traffic, keeping only connections that happened frequently and maintained an identical timing pattern.

---

## 4. Incident Response & Threat Mitigation Playbook

Upon identifying the high-fidelity C2 signature mapping to `203.0.113.88`, the following emergency operational containment responses were mapped:

1. **Network Layer Isolation:** Added an explicit egress block rule to the enterprise edge **pfSense firewall** to drop all internal traffic destined for the confirmed rogue C2 endpoint IP.
2. **Endpoint Triage:** Flagged internal host `192.168.20.104` for immediate automated EDR endpoint containment to prevent horizontal lateral movement across the internal Active Directory domain.
3. **Malware Analysis Capture:** Initiated a targeted memory dump on the host machine to extract running system processes, revealing a hidden, obfuscated background task running a Cobalt Strike beacon configuration script.
