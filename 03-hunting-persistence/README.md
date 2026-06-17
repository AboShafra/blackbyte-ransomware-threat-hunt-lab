# Hunting Persistence

[← Back to main README](../README.md)

## Hypothesis

An attacker established persistence by modifying registry Run keys to trigger program execution at startup or user logon.

Persistence is the natural next phase to hunt after execution. Once an attacker has a foothold, the next priority is making sure they don't lose it — a reboot, a logoff, or a patch cycle shouldn't cost them access. Registry Run keys are one of the oldest and still most commonly abused mechanisms for this (MITRE T1547.001), which made it the right place to focus first.

## What I Was Hunting For

- Registry value set events (Sysmon EID 13) targeting known Run/RunOnce key paths
- The process responsible for each registry modification
- What the persistence entry actually executes
- Confirmation that legitimate Run key noise (Microsoft Edge auto-launch, installers) doesn't get mistaken for malicious activity
- Evidence that the persistence mechanism actually fired

## Two-Part Investigation

| File | What It Covers |
|---|---|
| [`hunting-registry-run-keys.md`](hunting-registry-run-keys.md) | Initial hunt scoped to the four standard MITRE-documented Run key paths — and the coverage gap I discovered when the attacker's payload landed somewhere those paths didn't cover |
| [`hunting-lookup-tables.md`](hunting-lookup-tables.md) | Solving that gap by building a Splunk lookup table for scalable persistence-path detection, plus three additional independent ways to hunt the same technique |

## Why I'm Documenting This as Two Files Instead of One Clean Hunt

I want to be upfront about how this actually played out, because the iteration is the point. My first hunt was scoped to the four standard Run/RunOnce paths under `HKCU` and `HKLM`. It returned six results, and none of them looked obviously malicious until I traced one Edge-related entry that turned out to be expected noise — but it also meant I'd only checked the most common locations and nothing else.

The attacker's actual persistence entry didn't show up there. It had landed in `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` — a registry path that exists specifically because the attacker's tooling was 32-bit, and Windows silently redirects 32-bit registry writes targeting `HKLM\SOFTWARE\` into a parallel `WOW6432Node` hive. My hardcoded query never looked there.

Rather than just quietly fixing my query and presenting a clean final result, I kept both stages of this hunt: the version that missed it, and the version that caught it using a Splunk lookup table built to cover persistence paths broadly instead of a hand-maintained wildcard list. The lookup table also turned out to be the right long-term fix — not just a patch for this one gap, but a maintainable way to expand detection coverage without rewriting SPL every time a new persistence technique gets documented.

## ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Persistence | Boot/Logon Autostart: Registry Run Keys / Startup Folder | T1547.001 |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 |
| Defense Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Defense Evasion | Modify Registry | T1112 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |

---

**Next:** [Hunting Persistence: Registry Run Keys →](hunting-registry-run-keys.md)
