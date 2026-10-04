# SOC Offense 2

## Offense Details

- **Date & Time:** September 10, 2026, 12:38:11 AM
- **Magnitude:** 4.6
- **Source:** AWS CloudTrail, CRE, Cisco IronPort, Windows authentication server
- **Alert Name:** Detected a successful login from different geographies for the same username, AWS Cloud (Exp Center)
- **Affected User:** User D
- **Affected Endpoint:** JE8WIN7 (169.254.3.6)

## Rules Triggered

1. Detected a massive creation of EC2 instances
2. Detected an email with an attachment from a spam sender
3. An AWS API has been invoked from Kali
4. A database backup has been downloaded from S3 bucket
5. Microsoft Word launched from a command shell
6. Detected a successful login from different geographies for the same username

## Network Details

- **Source IPs:** 89.223.26.52 (Russian Federation Europe), 193.184.16.214 (Finland)
- **Destination IP:** 192.168.0.17 (AWS syslog log source)
- **Other IPs seen:** 192.168.0.15 (IronPort log source), 169.254.3.6 (endpoint JE8WIN7, Sysmon event)

## Timeline

- **12:38:11:** Mail server info message, email "Urgent AWS Bill" received by User D
- **12:38:12:** Spam sender email with attachment detected, Word launches cmd.exe
- **12:38:13:** Console login from Finland IP
- **12:38:14:** Console login success from Russian IP, no MFA. Geo login rule fires
- **12:38:15:** Run Instances (100 events), AWS API invoked from Kali, mass EC2 creation
- **12:38:16:** List Buckets
- **12:38:17:** Get Object, DB backup downloaded from S3

## Analysis

The first suspicious activity found in the logs was an email pretending to be AWS billing, with a DOCX attachment sent to User D. The sender was admin.aws.console.management.aws.amazon[.]com@yoyobadh[.]date, the subject was "Urgent AWS Bill" and the attachment was named "Critical AWS Bill.docx". Cisco IronPort flagged it in Exp Center.

After the DOCX was opened, Sysmon recorded WINWORD.EXE spawning cmd.exe (Create Process, Windows auth server). The file hash from this event was checked and was not flagged as malicious.

A successful cloud login was then detected from a Finland IP, which was also not flagged on VirusTotal or similar platforms. Right after, another successful login for the same username came from a Russian Federation Europe IP. MFA was not used on this login. Two successful logins for the same username were seen from Finland and Russia within about one second. This is unusual and should be checked for stolen credentials, VPN/proxy use, or some other normal reason. Both logins used Chrome 69, which is a very old browser version.

A Kali Linux VM creation was then attempted in AWS region us-east-2. Run Instances showed 100 events, which lines up with the massive EC2 creation rule. A port scan was detected by a remote host, followed by S3 bucket listing, followed by a DB backup (fullDB-dump 30102018.dump) being downloaded from the bucket db_backups2032 (us-west-2).

This whole process (login, recon, bucket access, backup download) repeated 6 times, and the full chain ran in about 6 seconds, so it looks automated.

Lateral movement still needs to be checked across the affected hosts.

## MITRE ATT&CK Mapping (Kill Chain)

1. **Initial Access (TA0001)**
   - Spoofed "AWS billing" email with suspicious DOCX attachment
   - Technique: T1566.001 Phishing: Spearphishing Attachment

2. **Execution (TA0002)**
   - Docx opened, winword.exe spawns cmd.exe
   - Technique: T1204.002 User Execution: Malicious File, T1059.003 Command and Scripting Interpreter: Windows Command Shell

3. **Initial Access (TA0001)**
   - Successful cloud login from Finland IP, then Russian IP, same username, logins from two different countries
   - Technique: T1078.004 Valid Accounts: Cloud Accounts

4. **Defense Impairment (TA0112)**
   - Kali Linux VM creation attempted on AWS (us-east-2)
   - Technique: T1578.002 — Modify Cloud Compute Infrastructure: Create Cloud Instance

5. **Discovery (TA0007)**
   - Host port scan detected, S3 bucket list accessed
   - Technique: T1046 Network Service Discovery, T1619 Cloud Storage Object Discovery

6. **Collection (TA0009)**
   - DB backup downloaded from S3 bucket dump files
   - Technique: T1530 Data from Cloud Storage Object

7. **Impact (TA0040)**
   - 100 EC2 RunInstances events were seen. This points to possibly unauthorized cloud resource creation. Resource Hijacking (T1496) needs more evidence that the resources were being misused for heavy work like cryptomining.
   - Technique: T1496 Resource Hijacking (conditional, not confirmed)

## IOCs

- **Sender email:** admin.aws.console.management.aws.amazon[.]com@yoyobadh[.]date
- **Sender domain:** yoyobadh[.]date
- **Mail subject:** Urgent AWS Bill
- **Attachment:** Critical AWS Bill.docx
- **Recipient:** User D
- **File hash (MD5):** 6242E3D67787CCDF4E06AD2982853144
- **Process chain:** C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE spawning C:\Windows\System32\cmd.exe
- **Source IP:** 89.223.26.52 (Russian Federation Europe)
- **Source IP:** 193.184.16.214 (Finland)
- **AWS region:** us-east-2 (logins, instance creation)
- **S3 bucket:** db_backups2032 (us-west-2)
- **File accessed:** fullDB-dump 30102018.dump
- **User agent:** Google Chrome 69.0.3497.100, Windows 10 64 bit

## Recommendations

1. Isolate the affected endpoint.
2. Disable the user account and reset credentials.
3. Block the malicious IPs, domain, hashes and URL in security controls.
4. Remove the malicious document and investigate for persistence.
5. Review authentication logs and check for suspicious tokens and sessions.
6. Investigate AWS activity: EC2 creation, S3 access and download. Terminate any unauthorized instances.
7. Enforce MFA on AWS console logins.
8. Check for lateral movement across affected hosts.

## Classification

**True Positive.** Phishing email, code execution, logins from two different countries with no MFA, new EC2 instances created through the affected AWS account, and a confirmed DB backup download all match up across different log sources.
