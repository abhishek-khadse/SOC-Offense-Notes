# SOC Offense 4

## Offense Details

- **Date & Time:** September 10, 2026, 12:39:26 AM
- **Magnitude:** 3
- **Source:** Experience Center Firewall
- **Offense Name:** Personal Data Transferred to third countries/regions - SSL Tunneling
- **Affected User:** user1 (sample user)

## Rule Triggered

- Personal Data is Transferred to third countries/regions

## Network Details

- **Source IP:** 172.16.0.21
- **Source Port:** 31753
- **Destination IP:** 60.209.29.106 (Jinan, China)
- **Destination Port:** 8444
- **Protocol:** TCP

## Analysis

Check Point Smart Defense detected SSL tunneling activity from the internal host 172.16.0.21 connecting outbound to the external IP 60.209.29.106 over TCP port 8444. The event was raised under the SSL Tunneling protection, matched firewall rule 84 and was observed outbound.

The destination IP resolves to Jinan, China, which is what tripped the "Personal Data Transferred to third countries" GDPR related monitoring rule. This is a policy/compliance rule, not a malware or intrusion detection.

SSL tunneling is a technique often used to bypass security controls and hide data exfiltration inside what looks like ordinary encrypted traffic. That said, the firewall event alone confirms the tunnel happened, it does not confirm that personal data was actually transferred or that the connection is malicious. That requires cross-referencing endpoint, proxy, DNS and DLP telemetry.

## MITRE ATT&CK Mapping

1. **Command and Control (TA0011)**
   - Technique: T1572 Protocol Tunneling

2. **Exfiltration (TA0010)**
   - Technique: T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol

## IOCs

- **Destination IP:** 60.209.29.106 (Jinan, China)
- **Destination port:** 8444
- **Source IP:** 172.16.0.21
- **Source port:** 31753
- **Protocol:** TCP
- **Firewall rule:** 84
- **Protection type:** app_control
- **Profile:** DMZ
- **Management:** ibm.sales.example
- **User:** user1 (sample user)
- **User mail:** user1@experiencecenter.qradar.ibm.test
- **Log sources:** Check Point firewall @ checkpoint.firewall-1.example.com, CRE-8 QRadar XPro

## Recommendations

1. Immediate containment: Block destination IP at the firewall.
2. Isolate source host 172.16.0.21 for forensic investigation.
3. Validate whether the connection from 172.16.0.21 to 60.209.29.106:8444 was authorized or not.
4. Identify the process/application on 172.16.0.21 responsible for establishing the SSL tunnel.
5. Validate ownership, reputation and business purpose of 60.209.29.106.
6. If confirmed legitimate with no personal data transferred, document the business justification and close as legitimate activity.
7. If unauthorized or unjustifiable, escalate for further investigation and consider containment per security procedure.
