## Case Report: RDP Brute Force to Credential Dumping with C2 & Persistence

**Case ID:** SYNTH-2026-0911-01  
**Host(s) affected:** WKSTN-FIN07  
**Time window:** 2026-09-10 02:14:01Z to 02:25:30Z (approximately 11 minutes active intrusion)  
**Verdict:** True Positive  
**Severity:** Critical

### Summary
WKSTN-FIN07 was compromised following a successful RDP brute-force attack originating from a known Tor exit node (185.220.101.47). After 37 failed authentication attempts, the attacker successfully authenticated as user j.reyes at 02:20:12Z. Within minutes, the attacker deployed a confirmed credential dumping tool (svhost_update.exe) that accessed LSASS memory, established a C2 connection to suspicious infrastructure (45.153.240.18), and created a SYSTEM-level scheduled task for persistence. This represents a complete kill chain from initial access through persistence with evidence of credential theft and C2 communication.

### Timeline

1. **02:14:01Z - 02:19:58Z** — 37 failed RDP logon attempts (Event ID 4625) targeting account "j.reyes" from 185.220.101.47 (confirmed Tor exit node and brute force source)

2. **02:20:12Z** — Successful RDP logon (Event ID 4624) for j.reyes from same source IP 185.220.101.47, logon type 10 (RemoteInteractive)

3. **02:21:47Z** — Malicious executable `svhost_update.exe` launched from j.reyes temp directory (Sysmon Event ID 1). Command line explicitly references LSASS dumping: `--dump lsass --out C:\Windows\Temp\sysdiag.tmp`. File hash confirmed malicious (credential dumper).

4. **02:21:48Z** — Process access event (Sysmon Event ID 10) showing svhost_update.exe accessing lsass.exe memory with granted access 0x1010, consistent with credential dumping behavior.

5. **02:23:05Z** — Outbound TCP connection (Sysmon Event ID 3) from svhost_update.exe to 45.153.240.18:443, a suspicious IP associated with C2 infrastructure and bulletproof hosting.

6. **02:25:30Z** — Scheduled task creation (Sysmon Event ID 1) via schtasks.exe, spawned by svhost_update.exe. Task named "WindowsUpdateCheck" configured to run `C:\Windows\Temp\sysdiag.tmp` (the dumped credentials file) as SYSTEM at every logon.

### Analysis

**Verdict Justification:**  
This is a definitive True Positive representing an active, successful compromise with multiple high-confidence indicators:

- **Initial Access (T1110, T1021.001):** The 37 failed RDP attempts from a known malicious IP (Tor exit node historically used for brute forcing) followed immediately by success is textbook brute-force compromise. The timing gap and pattern strongly suggest password spraying or dictionary attack success.

- **Credential Theft (T1003.001):** IOC reputation confirms the file hash as a known LSASS dumping tool. The command line explicitly states `--dump lsass`, and Sysmon Event 10 confirms memory access to lsass.exe with appropriate access rights (0x1010). The output file `sysdiag.tmp` is designed to blend in with legitimate system diagnostic files.

- **Command & Control (T1071.001):** The outbound connection to 45.153.240.18 has no legitimate business justification from a finance workstation and matches IOC reputation data for C2 infrastructure. This occurred 1 minute after credential dumping, suggesting automated exfiltration or callback behavior.

- **Persistence (T1053.005):** The scheduled task creation attempts to maintain access by executing the dumped credential file as SYSTEM on every logon. The task name "WindowsUpdateCheck" is designed to evade casual inspection.

**Process Lineage:** The attack exhibits clear parent-child relationships: cmd.exe → svhost_update.exe → schtasks.exe, showing the attacker's progression through the attack chain.

**Severity Rationale:**  
Critical severity is warranted because:
- Successful credential theft means lateral movement is imminent
- SYSTEM-level persistence has been established
- C2 channel indicates ongoing attacker access
- Finance workstation suggests access to sensitive financial data/systems
- Complete kill chain executed in under 12 minutes

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Relevant Events |
|-------------|----------------|-----------------|
| T1110 | Brute Force | Event ID 4625 (37 failed logons 02:14-02:19) |
| T1021.001 | Remote Services: Remote Desktop Protocol | Event ID 4624 (successful RDP logon 02:20:12) |
| T1003.001 | OS Credential Dumping: LSASS Memory | Sysmon Event ID 1 & 10 (svhost_update.exe, 02:21:47-48) |
| T1071.001 | Application Layer Protocol: Web Protocols | Sysmon Event ID 3 (C2 connection to 45.153.240.18:443, 02:23:05) |
| T1053.005 | Scheduled Task/Job: Scheduled Task | Sysmon Event ID 1 (schtasks.exe, 02:25:30) |

### Recommended Actions

1. **IMMEDIATE CONTAINMENT:** Isolate WKSTN-FIN07 from the network to prevent lateral movement and ongoing C2 communication. Do NOT shut down until memory capture is complete.

2. **CREDENTIAL RESET:** Force password reset for j.reyes account and any other accounts that may have been accessed from WKSTN-FIN07. Assume all credentials on this host are compromised. Review j.reyes' access logs for signs of lateral movement to other systems.

3. **MEMORY FORENSICS:** Capture full memory dump from WKSTN-FIN07 before shutdown to recover dumped credentials and identify what data may have been exfiltrated. The file `C:\Windows\Temp\sysdiag.tmp` should be preserved as evidence.

4. **PERSISTENCE REMOVAL:** Delete scheduled task "WindowsUpdateCheck", remove files `C:\Users\j.reyes\AppData\Local\Temp\svhost_update.exe` and `C:\Windows\Temp\sysdiag.tmp`, and conduct full registry/filesystem sweep for additional persistence mechanisms.

5. **NETWORK BLOCKING:** Block 185.220.101.47 and 45.153.240.18 at perimeter firewall. Review firewall logs for any other systems communicating with 45.153.240.18 to identify potential lateral movement victims.

6. **RDP HARDENING:** Disable direct RDP access from Internet for all systems. Implement MFA for RDP, enforce account lockout policies (5 failed attempts), and require VPN+jump box for remote access.

7. **THREAT HUNT:** Search all Windows Security logs enterprise-wide for Event ID 4624/4625 from source IP 185.220.101.47 to identify other compromised systems. Query EDR/Sysmon for file hash 91B5F3A1C2E4D6789ABCDEF0123456789ABCDEF01234567 and process access to lsass.exe across the environment.

8. **INCIDENT RESPONSE ESCALATION:** Engage incident response team for full forensic investigation and breach notification assessment, particularly given finance workstation context and regulatory implications.