# Hunting Execution Artifacts

## Hypothesis

An attacker executed commands on a compromised endpoint using built-in Windows interpreters — `cmd.exe` and `powershell.exe`.

This is the first hunt I ran against the dataset, and deliberately so. **Command and Scripting Interpreter (T1059)** is one of the broadest and highest-yield techniques in any intrusion — almost every attacker, regardless of sophistication, eventually needs a shell or a scripting engine to execute post-exploitation actions. Starting here gives the most return for the least specificity in the hypothesis.

I approached this cold: no prior knowledge of the attack chain, working purely from the structured hunting methodology of *hypothesis → investigative questions → evidence source → query*.

## Investigative Questions

Breaking the hypothesis down into answerable, evidence-backed questions:

- Are there process creation events where `cmd.exe` or `powershell.exe` was spawned?
- What spawned them — what is the parent process?
- Was execution interactive (user-initiated) or programmatic?
- What command-line arguments were passed?
- Under what privilege/user context did execution occur?
- Does the command line contain encoded payloads, suspicious flags, or known attacker patterns?

## Evidence Sources

| Log Source | Event ID | What It Gives You |
|---|---|---|
| Sysmon | 1 | Process creation, full command line, parent process, hashes, ProcessGuid |
| Windows Security Log | 4688 | Process creation + command line (only if GPO command-line auditing is enabled) |

I deliberately hunted this technique through **three separate lenses** to demonstrate both depth on a single tool and adaptability across log sources:

| File | Focus | Primary Log Source |
|---|---|---|
| [`hunting-powershell-execution.md`](hunting-powershell-execution.md) | PowerShell-specific execution, full pivot chain to IOC confirmation | Sysmon EID 1, PowerShell 4103/4104 |
| [`hunting-cmd-execution.md`](hunting-cmd-execution.md) | Same attack chain, reconstructed using **Security EID 4688 only** — no Sysmon | Windows Security Log |
| [`hunting-process-trees.md`](hunting-process-trees.md) | Visual reconstruction of the full attacker process tree using the PSTree Splunk add-on | Sysmon EID 1 |

## Why Three Approaches to the Same Hunt

Real environments don't always have Sysmon deployed. I wanted to prove I could reconstruct the same attacker timeline two different ways — once with high-fidelity Sysmon telemetry, once using only what's available natively in every Windows environment (Security EID 4688). The third file shows how a visualization tool (PSTree) collapses what took 4+ sequential manual pivot queries into a single readable output — useful to know exists, but only valuable once you understand the manual process it's replacing.

## What This Hunt Surfaced

Across all three approaches, the same attacker timeline was confirmed independently:

- A 32-bit (`SysWOW64`) `cmd.exe` running under `SYSTEM` context, spawned by a randomly-named PSExec service binary (`MyMVPfXG.exe`)
- A 32-bit `powershell.exe` under that shell, used to pull `dghelper.dll` from attacker infrastructure via `Invoke-WebRequest`
- The full downstream command sequence: discovery commands, registry persistence, log clearing, and credential harvesting via Mimikatz

## ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 |
| Execution | System Services: Service Execution | T1569.002 |

---

**Next:** [Hunting PowerShell Execution →](hunting-powershell-execution.md)
