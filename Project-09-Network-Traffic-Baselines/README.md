# Project 9: Network Traffic Baseline Benchmarking & Statistical Anomaly Detection
**Category:** Network Security, Network Telemetry, Infrastructure Monitoring  
**Core Technologies:** Wireshark, Splunk Enterprise, Nmap, Packet Profiling, CSV Data Analytics

---

## 1. Project Overview
In large-scale corporate networks, identifying malicious activity based on signatures alone is insufficient; sophisticated threat actors often utilize non-signature-based tools or native system utilities ("living off the land"). To capture these silent tactics, an organization must establish a **Network Traffic Baseline**—a granular mathematical blueprint of what "normal" data transfer rates, protocols, and communication pairs look like on a typical business day.

This project outlines an empirical network profiling case study. By running persistent network captures during normal operational hours, a statistical network baseline profile was established. This profile was then ingested into **Splunk** to engineer a statistical anomaly detection model capable of automatically flagging network anomalies—such as data exfiltration spikes or aggressive network reconnaissance scans—the moment a device deviates from its standard operational baseline.

---

## 2. Packet Profiling & Baselining Methodology (Wireshark)

To establish an accurate organizational baseline, traffic telemetry was captured from a core switches' spanning port across a multi-hour production window. 

### Step 2.1: Collecting Protocol Statistics
Using **Wireshark's Statistics > Protocol Hierarchy** and **Conversations** dashboards, the network was profiled to determine the exact distribution of standard traffic.

The analysis established the following baseline operational thresholds for a standard workstation node:
* **DNS Traffic (Port 53):** Averaged 120 requests per hour. Packet sizes strictly bounded between 64 and 150 bytes.
* **Web Traffic (Port 443/HTTPS):** Represented 88% of total network volume. Consistent payload throughput during standard business hours (9:00 AM – 5:00 PM).
* **Internal Administration (SSH/RDP):** Authorized strictly between designated internal IT administrator endpoints and core server subnets; 0% baseline profile footprint on local employee subnets.

### Step 2.2: Exporting Baseline Metrics
The network profiling data was exported as a structured CSV asset (`network_baseline_metrics.csv`) to establish the mathematical boundary limits for our automated alert system.

---

## 3. SIEM Anomaly Detection Engineering (Splunk SPL)

With the baseline data integrated into our central monitoring pipeline, a custom **Splunk search query** was engineered. Instead of looking for static indicators of compromise, this query calculates the **Standard Deviation (stdev)** of live network data transfers and flags any device that breaches a 3x standard deviation threshold.

### Splunk Query: Tracking Sudden Volume Exfiltration Spikes
This advanced query monitors outbound network bytes per machine, compares live traffic against historical operational baselines, and flags anomalous data transfers:

```splunk
index=network_firewall direction=outbound
| bucket _time span=1h
| stats sum(bytes_out) as LiveTraffic volume by src_ip, _time
| eventstats avg(LiveTraffic) as AvgTraffic, stdev(LiveTraffic) as StdDevTraffic by src_ip
| eval UpperThreshold = AvgTraffic + (3 * StdDevTraffic)
| where LiveTraffic > UpperThreshold AND LiveTraffic > 524288000
| eval LiveTraffic_MB = round(LiveTraffic/1024/1024, 2), Threshold_MB = round(UpperThreshold/1024/1024, 2)
| table _time, src_ip, LiveTraffic_MB, Threshold_MB
```

### Explaining the Statistical Logic:
1. `bucket _time span=1h`: Groups all outbound network data transfers into uniform 1-hour time blocks.
2. `eventstats avg(LiveTraffic)... stdev(...)`: Calculates the moving average and statistical standard deviation for every device based on historical logs.
3. `eval UpperThreshold = AvgTraffic + (3 * StdDevTraffic)`: Enforces a strict statistical boundary rule. In networking statistics, any activity that breaches **3 standard deviations (3rd Sigma)** represents a high-fidelity anomaly (99.7% variance from normal behavior).
4. `where LiveTraffic > UpperThreshold`: Instantly triggers an alert only when a device transfers a volume of data that violently shatters its normal business baseline profile.

---

## 4. Anomaly Verification & Network Reconnaissance Triage

To validate the detection model, an intentional internal reconnaissance sweep was executed from a test machine using **Nmap** (`nmap -sS -p 1-65535 192.168.10.0/24`). 

The baseline model instantly flagged the activity:
* **The Baseline:** Normal employee nodes have a baseline profiling metric of interacting with a maximum of 3 unique internal destination IPs per hour over port 443.
* **The Anomaly:** During the Nmap port sweep, the test machine generated connections targeting 254 unique internal IP addresses over 10,000 distinct ports within 45 seconds.
* **The Outcome:** The SIEM detection rule immediately triggered a critical alert, identifying the source IP, isolating the anomalous protocol spike, and preventing potential lateral network discovery.
