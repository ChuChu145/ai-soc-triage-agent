## Case Report: RDP Brute Force → Credential Dumping → Persistence

**Case ID:** SYNTH-2026-0911-01  
**Host(s) affected:** WKSTN-FIN07  
**Time window:** 2026-09-10 02:14:01Z – 02:25:30Z (approximately 11 minutes)  
**Verdict:** True Positive  
**Severity:** Critical

### Summary
An external attacker successfully brute-forced the j.reyes account via RDP from a known Tor exit node (185.220.101.47) after 37 failed attempts. Within minutes of gaining access, the attacker executed a malicious credential dumping tool masquerading as a legitimate Windows process (svhost_update.exe), harvested LSASS memory, exfiltrated data to a known C2 IP address, and established persistence via a scheduled task running with SYSTEM privileges. This is a complete compromise requiring immediate containment.

### Timeline

1. **02:14:01Z – 02:19:58Z** – 37 failed RDP logon attempts against account j.reyes from 185.220.101.47 (known malicious Tor exit node)
2. **02:20:12Z** – Successful RDP logon for j.reyes from same IP; brute force succeeded
3. **02:21:47Z** – Malicious executable svhost_update.exe (typosquatting "svchost") launched from j.reyes temp directory with command-line arguments to dump lsass and output to C:\Windows\Temp\sysdiag.tmp
4. **02:21:48Z** – svhost_update.exe accessed lsass.exe process memory with handle 0x1010 (consistent with credential extraction)
5. **02:23:05Z** – svhost_update.exe established outbound TCP/443 connection to 45.153.240.18 (suspicious C2 infrastructure)
6. **02:25:30Z** – Scheduled task "WindowsUpdateCheck" created via schtasks.exe to execute C:\Windows\Temp\sysdiag.tmp on logon with SYSTEM privileges, spawned by svhost_update.exe

### Analysis

This is a confirmed intrusion with multiple high-confidence indicators:

**Initial Access & Credential Access:** The 37 failed RDP logons followed by immediate success is textbook brute forcing (T1110). The source IP 185.220.101.47 is a known malicious Tor exit node frequently used in brute force campaigns, giving high confidence this was unauthorized access.

**Defense Evasion:** The attacker used a binary named "svhost_update.exe" – a deliberate typosquatting of the legitimate Windows "svchost.exe" – to masquerade as a system process (T1036). The file hash is confirmed malicious by threat intelligence (52 malicious votes, 0 harmless).

**Credential Harvesting:** Sysmon Event 10 shows svhost_update.exe accessing lsass.exe memory with handle rights consistent with credential dumping. The command line explicitly references "--dump lsass", and the output file "sysdiag.tmp" is designed to appear benign. This is T1003.001 (LSASS Memory dumping).

**Command & Control:** The outbound connection to 45.153.240.18:443 from the dumping tool indicates data exfiltration or C2 check-in. This IP is flagged as suspicious C2 infrastructure on bulletproof hosting with no legitimate business justification for a finance workstation. The use of port 443 is an attempt to blend with legitimate HTTPS traffic (T1071.001).

**Persistence:** The scheduled task "WindowsUpdateCheck" is configured to run sysdiag.tmp (the credential dump output file, likely a renamed executable) with SYSTEM privileges on every logon (T1053.005). This ensures the attacker maintains access even if the j.reyes account is disabled.

**Valid Accounts (post-compromise):** After the initial brute force, the attacker used the now-valid j.reyes credentials to execute all subsequent actions (T1078). This is distinct from the initial compromise and represents credential reuse.

All TTPs form a coherent kill chain: initial access → defense evasion → credential access → C2 → persistence. The severity is Critical due to SYSTEM-level persistence, confirmed credential theft, and external C2 communication.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Events |
|--------------|----------------|--------|
| T1110 | Brute Force | Events 1-4 (failed logons), Event 5 (successful logon) |
| T1021.001 | Remote Services: Remote Desktop Protocol | Event 5 (RDP logon type 10) |
| T1078 | Valid Accounts | Event 5 onwards (use of j.reyes account post-compromise) |
| T1036 | Masquerading | Event 6 (svhost_update.exe typosquatting svchost.exe) |
| T1003.001 | OS Credential Dumping: LSASS Memory | Events 6-7 (lsass dumping activity) |
| T1071.001 | Application Layer Protocol: Web Protocols | Event 8 (C2 connection over TCP/443) |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Event 9 (persistence via schtasks) |

### Recommended Actions

1. **IMMEDIATE: Isolate WKSTN-FIN07** from the network to prevent lateral movement and ongoing C2 communication. Do not shut down – preserve volatile memory for forensics.

2. **IMMEDIATE: Disable account j.reyes** across all systems and force password reset for all domain accounts, assuming credential harvesting succeeded and credentials may be in attacker hands.

3. **IMMEDIATE: Block IOCs** at perimeter and endpoint: IPs 185.220.101.47 and 45.153.240.18, file hash 91B5F3A1C2E4D6789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567.

4. **HIGH PRIORITY: Hunt for lateral movement** – search all domain controllers and servers for j.reyes logons after 02:20:12Z and any executions of svhost_update.exe, sysdiag.tmp, or scheduled tasks named "WindowsUpdateCheck" on other hosts.

5. **HIGH PRIORITY: Memory dump WKSTN-FIN07** for forensic analysis to recover dumped credentials and confirm scope of compromise before re-imaging.

6. **MEDIUM PRIORITY: Review RDP exposure** – implement MFA for all RDP access, restrict RDP to VPN-only, and deploy account lockout policies (if not present) to mitigate future brute force.

7. **MEDIUM PRIORITY: Threat hunt for C:\Windows\Temp\sysdiag.tmp** and scheduled task "WindowsUpdateCheck" across the environment in case attacker achieved lateral movement before detection.

8. **POST-INCIDENT: Conduct credential rotation** for all service accounts and privileged users that may have been cached on WKSTN-FIN07.