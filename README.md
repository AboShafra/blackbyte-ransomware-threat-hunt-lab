# BlackByte Ransomware Threat Hunt Lab

A self-hosted SOC lab where I simulated a multi-stage ransomware intrusion modeled on Microsoft's BlackByte incident response case study, then hunted it cold — using only Splunk, Sysmon, and native Windows Event Logs — exactly as a SOC analyst would during a real investigation.

I executed every attacker action myself against a Windows 10 host from a Kali Linux attack box, forwarded the resulting telemetry into a self-hosted Splunk instance, and then performed structured, hypothesis-driven threat hunts across the full kill chain: execution, persistence, defense evasion, command & control, and lateral movement.

This repo documents both halves of that work — what I did as the attacker, and how I found it as the defender — with every Splunk query, every pivot, and every screenshot included.

## Why I Built This

Course material teaches you to recognize techniques. It doesn't prove you can operate independently against a real dataset. I wanted a project where every claim is backed by a query I actually ran, against logs I actually generated, on infrastructure I actually built — not a walkthrough I followed.

One detail I think matters: I documented my own mistakes as part of this, not just the clean final answers. In the persistence hunt, for example, I initially scoped my detection logic to four standard registry Run key paths and missed an entry — it had landed in a WOW64-redirected path because the attacker's tooling was 32-bit. Catching and correcting that gap is in the writeup, because that kind of iteration is the actual job, not just the final query that worked.

## Environment

| Component | Detail |
|---|---|
| Target host | `PC01` (Windows 10) |
| Domain | `mydfir.local` |
| Target IP | `192.168.7.138` |
| Attacker infrastructure | Kali Linux, Python HTTP server at `192.168.7.250` |
| Telemetry pipeline | Sysmon → Splunk Universal Forwarder → Splunk |
| Tools used | Impacket (psexec, secretsdump), NetExec, Mimikatz, CertUtil, PSTree Splunk add-on, regex101 |

## Contents

| Phase | Description |
|---|---|
| [01 — Attack Simulation](01-attack-simulation/README.md) | Full intrusion chain: credential spraying, PSExec lateral movement, discovery, ingress tool transfer, registry persistence, log clearing, credential harvesting |
| [02 — Hunting Execution Artifacts](02-hunting-execution-artifacts/README.md) | Hunting PowerShell and CMD execution via Sysmon and Security 4688, plus process tree reconstruction with PSTree |
| [03 — Hunting Persistence](03-hunting-persistence/README.md) | Registry Run key hunting, WOW64 redirection gap, and lookup-table-driven detection |
| [04 — Hunting Defense Evasion](04-hunting-defense-evasion/README.md) | Detecting Windows Event Log clearing via EID 1102/104 and process correlation |
| [05 — Hunting Command & Control](05-hunting-command-and-control/README.md) | Ingress tool transfer hunted across process, file system, and network telemetry |
| [06 — Hunting Lateral Movement](06-hunting-lateral-movement/README.md) | PSExec service creation hunting, plus reverse-engineering Impacket's source code into generalized regex detections |

## Skills Demonstrated

- Hypothesis-driven threat hunting methodology (hypothesis → investigative questions → evidence source → query)
- Splunk SPL: stats/eval/regex/lookup/subsearch construction, cross-source field correlation
- Log source triage across Sysmon, Windows Security Log, System Log, and PowerShell Operational Log, including known fidelity trade-offs between sources
- Building and deploying Splunk lookup tables for scalable, maintainable detection logic
- Reverse-engineering open-source attacker tooling (Impacket) to derive regex-based detections from naming logic, rather than relying on static IOCs
- Process tree reconstruction via PID/GUID pivoting, both manually and via the PSTree Splunk add-on
- IOC enrichment and validation via VirusTotal and EchoTrail
- MITRE ATT&CK mapping for every confirmed technique

## ATT&CK Coverage

Techniques confirmed across this lab, by tactic:

| Tactic | Techniques |
|---|---|
| Credential Access | T1110.003, T1003.002, T1003.004 |
| Execution | T1059.001, T1059.003, T1569.002 |
| Persistence | T1547.001 |
| Defense Evasion | T1070.001, T1218.011, T1036.005, T1112 |
| Discovery | T1082, T1016 |
| Command & Control | T1105 |
| Lateral Movement | T1021.002, T1543.003, T1559.001 |

---

**Start here:** [Phase 1 — Attack Simulation →](01-attack-simulation/README.md)
