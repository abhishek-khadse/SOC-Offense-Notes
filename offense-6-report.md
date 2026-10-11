# SOC Offense 6

## Offense Details

- **Date & Time:** September 10, 2026, 12:41:37 AM
- **Source:** Experience Center (Checkpoint, Linux OS, Oracle DB, Bluecoat, CRE)
- **Affected Host:** 192.168.10.6
- **Affected User:** victim

## Rules Triggered

1. Excessive Firewall Denies Across Multiple Hosts from Local Host (magnitude 7)
2. Local Database Scanner Detected - Targeted Attack (magnitude 5)
3. Infected workstation downloads data from critical server - Targeted Attack (magnitude 9)

## Network Details

- **Source IP:** 192.168.10.6 (source port 4567)
- **Destination IPs:** 192.168.82.28 (port 1521), 192.168.149.223, 192.168.163.234 (port 1521), 192.168.15.25, 192.168.15.125
- **External IP:** 198.51.100.90 (port 443)

## Timeline

- **12:41:37:** Firewall Drop from 192.168.10.6:4567 to 192.168.82.28:1521, packet logged (Checkpoint, 57 events, different destination IPs)
- **12:42:17:** Excessive Firewall Denies Across Multiple Hosts from Local Host, more than 40 attempts across at least 40 destination IPs in 5 minutes (CRE)
- **12:42:19 to 12:42:26:** Firewall Drop events continue (Checkpoint)
- **12:42:26:** Local Database Scanner Detected - Targeted Attack, scan of at least 30 hosts on port 1521 (CRE)
- **12:42:27 to 12:42:28:** ESTABLISH, a connection was established before, user victim (Oracle DB log source, 2 events)
- **12:42:29:** SFTP Session Open, SFTP login successful, user victim (Linux OS @ 192.168.15.25)
- **12:42:29:** Infected workstation downloads data from critical server - Targeted Attack, FTP action allowed, magnitude 9 (CRE)
- **12:42:30:** SFTP Session Closed (Linux OS @ 192.168.15.25)
- **12:42:30 to 12:42:34:** Misc GET Request, 5 events (Bluecoat). The 12:42:34 event shows a GET to attacker[.]example[.]com (198.51.100.90:443)
- **12:42:35 to 12:42:42:** More Firewall Drop events, New Host Discovered at 12:42:39

## Analysis

The host 192.168.10.6 first sent traffic to many internal IPs on port 1521 (the Oracle database port). Checkpoint denied this traffic, and at 12:42:17 the CRE rule fired for more than 40 attempts across at least 40 destination IPs in 5 minutes. This looks like a scan of the internal network to find databases.

At 12:42:26 the Local Database Scanner rule fired for a scan of at least 30 hosts, which confirms the database reconnaissance.

After the scan, the same host made connections that were allowed. The Oracle DB log source recorded ESTABLISH events at 12:42:27 and 12:42:28, and then a successful SFTP login to 192.168.15.25 with the user victim at 12:42:29. Right after that, the CRE rule "Infected workstation downloads data from critical server" fired with the FTP action allowed (magnitude 9), so data was downloaded from the server. The SFTP session was closed at 12:42:30. The logs do not show which files were downloaded or how much data.

From 12:42:30 to 12:42:34 the same host sent 5 HTTP GET requests through Bluecoat. The 12:42:34 request went to attacker.example.com (198.51.100.90) on port 443, with no action information available. This may be contact with an external server, but the logs do not show what was sent or received, so data exfiltration is not confirmed.

Firewall drops from the same host continued until at least 12:42:42, and a new host was discovered at 12:42:39.

The whole chain (scan, login, download, external request) happened within about a minute from one internal host, which fits a targeted attack. The logs do not show how the workstation was infected, or whether the victim account was stolen or used normally.

## MITRE ATT&CK Mapping

1. **Discovery (TA0007)**
   - Technique: T1046 Network Service Discovery

2. **Lateral Movement (TA0008)**
   - Technique: T1021.004 Remote Services: SSH (SFTP login with the victim account)

3. **Collection (TA0009)**
   - Technique: T1005 Data from Local System (data downloaded from 192.168.15.25)

4. **Command and Control (TA0011)**
   - Technique: T1071.001 Application Layer Protocol: Web Protocols (conditional, only the GET requests are seen)

## IOCs

**Hosts and IPs**

- **Source host:** 192.168.10.6 (source port 4567)
- **Scanned / denied targets:** 192.168.82.28 (port 1521), 192.168.149.223, 192.168.163.234 (port 1521)
- **SFTP/FTP server:** 192.168.15.25
- **Oracle DB (log source):** 192.168.15.125
- **External IP:** 198.51.100.90 (port 443)

**Domains and URLs**

- **Domain:** attacker[.]example[.]com (HTTP GET at 12:42:34, no available action information)

**Ports**

- **1521:** Oracle database port, destination of the denied packets and the database scan

**Accounts**

- **User:** victim (SFTP login, ESTABLISH, FTP download)

**Log sources**

- Checkpoint @ checkpoint.firewall-1.test.com
- CRE-8 QRadar XPro
- Linux OS @ 192.168.15.25
- Oracle DB @ 192.168.15.125
- Bluecoat @ bluecoat.think2019.test

## Recommendations

1. Isolate 192.168.10.6 from the network and find the process responsible for the scan and the connections.
2. Disable the victim account and reset credentials, then check where else it logged in.
3. Block attacker.example.com and 198.51.100.90 at the proxy and firewall, and check the Bluecoat logs for the other 4 GET requests.
4. Check what was downloaded from 192.168.15.25 (file names and size) and whether it contains sensitive data.
5. Review the Oracle DB logs on 192.168.15.125 for logins or queries from 192.168.10.6.
6. Check the other scanned hosts for any successful connections from 192.168.10.6.
7. Confirm whether this activity matches an authorized scan or pentest before treating it as a live breach.

## Classification

**True Positive.** The same host scanned 40+ hosts, logged in over SFTP and downloaded data from a critical server, then made an external request, all within about a minute.
