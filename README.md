# AD Fortress — Active Directory Attack Detection & Response Lab

A home-built blue team lab where I set up an Active Directory environment, wired it into Wazuh for centralized monitoring, and then attacked my own infrastructure with Atomic Red Team to see whether I could actually catch what I was doing.

**Author:** Mohamed Jasim Z
**Stack:** Wazuh, Sysmon, Atomic Red Team, Sigma, MITRE ATT&CK
**Environment:** Ubuntu (Wazuh Manager), Windows Server 2019 (Domain Controller), Windows 10 Pro (endpoint)

---

## Why I built this

Most "I know SIEM tools" claims are hard to verify — anyone can watch a Wazuh install tutorial. I wanted something I could actually defend in an interview: a lab where I generated the attack myself, watched what telemetry it produced, wrote the detection logic from scratch, and then walked through the investigation like an analyst would.

The whole point was the loop, not any single tool:

**simulate an attack → collect the telemetry it leaves behind → write a detection for it → validate the alert fires → investigate it like a real incident → map it to ATT&CK → clean up and document it.**

That loop is what I actually got out of this, more than any individual product on the resume line.

## Architecture

Three VMs, kept deliberately simple so I could focus on the detection engineering instead of fighting infrastructure:

```
                    ┌────────────────────────────┐
                    │        Ubuntu VM           │
                    │  Wazuh Manager + Dashboard │
                    └──────────────┬─────────────┘
                                   │  agent traffic
                 ┌─────────────────┴─────────────────┐
                 │                                   │
  ┌──────────────────────────┐        ┌──────────────────────────┐
  │  Windows Server 2019     │        │      Windows 10 Pro      │
  │  Domain Controller (AD)  │        │  Monitored endpoint      │
  │  Wazuh Agent + Sysmon    │        │  Wazuh Agent + Sysmon    │
  │                          │        │  Atomic Red Team         │
  └──────────────────────────┘        └──────────────────────────┘
```

| Machine | OS | Role |
|---|---|---|
| VM1 | Ubuntu | Wazuh Manager + Dashboard, detection logic, alerting |
| VM2 | Windows Server 2019 | Domain Controller, AD DS, test user/group management |
| VM3 | Windows 10 Pro | Domain-joined endpoint, where the attack simulation actually runs |

## Tech stack

| Category | Tool |
|---|---|
| SIEM / XDR | Wazuh |
| Endpoint telemetry | Sysmon |
| Attack simulation | Atomic Red Team |
| Detection format | Sigma-style logic |
| Threat framework | MITRE ATT&CK |
| Directory services | Active Directory (Windows Server 2019) |
| Scripting / config | PowerShell, XML, YAML |

## What I actually set up

**Active Directory.** Windows Server 2019 as the domain controller, with a test user and the Windows 10 box domain-joined. Nothing exotic — the goal was a realistic-enough identity layer to generate real AD security events, not a full enterprise topology.

**Wazuh + Sysmon.** Sysmon runs on both Windows boxes, feeding the operational channel (`Microsoft-Windows-Sysmon/Operational`) into Wazuh via an eventchannel localfile config:

```xml
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```

I also pulled in `Microsoft-Windows-PowerShell/Operational`, since PowerShell is the first thing I wanted visibility into — it's used constantly for legitimate admin work and just as often for attacker execution, so distinguishing the two was a big part of the exercise.

**Windows security auditing.** Enabled the event categories that actually matter for AD-focused detection — logons/failed logons (4624/4625), process creation (4688), account and group changes (4720, 4728, 4732, 4738), scheduled tasks (4698). These get correlated against Sysmon and Wazuh alerts during investigation rather than treated as a standalone log source.

## Attack simulation → detection loop

I used Atomic Red Team to trigger specific ATT&CK techniques on the Windows 10 endpoint rather than improvising "hacking" — the point was reproducible, mapped behavior I could detect and re-test, not chaos. Workflow per test: pick a technique, check prerequisites, run it, watch what Sysmon/Wazuh actually captured, write or tune a detection against it, confirm it fires, clean up.

Techniques I worked through included PowerShell execution, Windows command-shell execution, scheduled task creation, account/group discovery, and account manipulation (creating accounts, modifying privileged group membership).

### Example: catching suspicious PowerShell

This is the one I spent the most time on, since PowerShell is noisy by nature and a naive "alert on powershell.exe" rule is useless in a real environment.

Wazuh rule (trimmed down from what I actually run):

```xml
<group name="windows,sysmon,custom,">
  <rule id="100100" level="10">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image">powershell.exe</field>
    <description>Suspicious PowerShell process detected by Sysmon</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

Investigation angle once this fires: who ran it, what the full command line was (encoded commands are the first thing I check for), what the parent process was, and what happened immediately before/after on that host. Sysmon Event ID 1 plus the PowerShell operational log together give enough to answer most of that without guessing.

### MITRE ATT&CK coverage

| Technique | ID | Primary telemetry |
|---|---|---|
| PowerShell | T1059.001 | Sysmon + PowerShell operational log |
| Windows Command Shell | T1059.003 | Sysmon process creation |
| Scheduled Task/Job | T1053.005 | Security log (4698) + Sysmon |
| Account Discovery | T1087 | Windows security events |
| Domain Groups Discovery | T1069.002 | Windows security events |
| Create Account | T1136.002 | Security log (4720) |
| Account Manipulation | T1098 | Security log (4728, 4732, 4738) |

## Response side

Once an alert validated, I ran through containment and remediation on the test assets involved — disabling the test account, pulling it out of the privileged group, killing the malicious test process, removing any persistence I'd set up, then re-checking the endpoint to confirm it actually worked. All of this stayed inside the isolated lab; nothing here touches production credentials or real infrastructure.

## What was actually hard about this

**Turning raw logs into a detection that means something.** Windows throws off a huge volume of events. The hard part was never "collect the data" — it was figuring out which fields and event relationships actually separated normal admin activity from something worth an alert.

**One log source is rarely enough.** A believable investigation usually needed Sysmon, the Windows security log, and the PowerShell operational log together. Looking at any one of them in isolation left gaps.

**Alert volume vs. alert quality.** It's trivially easy to build a rule that fires on everything — that's not a detection, that's a smoke alarm that goes off every time you make toast. I spent more time tuning down false positives than writing new rules.

**Turning behavior into ATT&CK language.** Logs don't explain intent by themselves. Mapping what I saw to specific technique IDs forced me to actually understand what the simulated attacker was doing, not just that "something happened."

## Repo structure

```
AD-Fortress/
├── README.md
├── architecture/
│   └── lab-architecture.png
├── sysmon/
│   └── sysmonconfig.xml
├── wazuh/
│   ├── ossec.conf
│   └── local_rules.xml
├── sigma/
│   └── selected-rules/
├── atomic-tests/
│   └── test-results.md
├── detections/
│   ├── powershell.md
│   ├── command-execution.md
│   ├── scheduled-task.md
│   ├── account-management.md
│   └── discovery.md
├── investigations/
│   └── incident-reports/
└── screenshots/
```

> No credentials, tokens, or internal IP ranges are committed to this repo — screenshots and configs are sanitized before being added.

## What's next

Phase 6 (tightening the Windows audit policy and PowerShell logging config) is where I'm currently focused. After that I'm planning to bring in Zeek or Suricata for network-layer telemetry, add a couple of Kerberos and lateral-movement detections, and start tracking detection coverage more formally instead of ad hoc.

---

**Mohamed Jasim Z** — Cybersecurity Student
