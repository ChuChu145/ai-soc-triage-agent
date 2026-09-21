# Answer key — SYNTH-2026-0911-01

Don't feed this file to the agent. Use it after the agent produces its report, to check whether it got the right picture.

**What actually happened (the intended scenario):**

1. Brute force RDP against `j.reyes` from `185.220.101.47` (known Tor exit node range — that IP pattern is intentional) — **T1110 Brute Force**, **T1021.001 Remote Services: RDP**.
2. Attacker succeeds, logs on as `j.reyes` — **T1078 Valid Accounts**.
3. Drops `svhost_update.exe` (note the deliberate typo of `svchost.exe` — a masquerading trick) and uses it to read LSASS memory — **T1003.001 OS Credential Dumping: LSASS Memory**, **T1036 Masquerading**.
4. Beacons out to `45.153.240.18:443` — **T1071.001 Application Layer Protocol: Web Protocols** (likely C2).
5. Creates a SYSTEM-level logon-triggered scheduled task pointing at the dropped binary — **T1053.005 Scheduled Task/Job**, for persistence and privilege escalation.

**Verdict a good report should reach:** True Positive, high severity, recommend isolating `WKSTN-FIN07`, resetting `j.reyes` credentials, blocking both IPs, and hunting for the same file hash / scheduled task name elsewhere in the estate.

**Things to check the agent didn't miss:**
- Did it flag the failed-logon burst as brute force rather than ignoring it as noise?
- Did it connect the process name typo (`svhost_update.exe` vs `svchost.exe`) as a masquerading indicator?
- Did it map the LSASS access to credential dumping rather than describing it vaguely as "suspicious"?
- Did it treat the scheduled task as persistence, not just "some admin activity"?
- Did it produce a severity/verdict, not just a narrated timeline?
