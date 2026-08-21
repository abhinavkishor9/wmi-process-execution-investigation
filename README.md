# Lab 57 – Suspicious Management Instrumentation Activity Investigation

## Overview

This lab investigates suspicious Windows Management Instrumentation (WMI) and CIM-based activity on a Windows 11 workstation. The investigation focuses on how PowerShell can use CIM/WMI functionality to interact with Windows management interfaces and create a process, while security telemetry from Sysmon, Windows WMI-Activity logs, and Wazuh is used to establish what happened and when.

The objective is not to classify every WMI event as malicious. Instead, the investigation demonstrates how a SOC analyst can distinguish potentially suspicious management-instrumentation activity from legitimate Windows and security-software behavior by correlating process creation, parent-child relationships, command execution, user context, timestamps, and SIEM telemetry.

## Lab Details

| Field | Details |
|---|---|
| Lab | Lab 57 |
| Investigation | Suspicious Management Instrumentation Activity Investigation |
| Host | `DESKTOP-9MMM37V` |
| User | `DESKTOP-9MMM37V\dell` |
| Operating System | Windows 11 Pro |
| Windows Build | `22621` |
| Manufacturer | Dell Inc. |
| Model | Latitude 5420 |
| PowerShell | `7.6.5` |
| Wazuh Agent | `4.12.0` |
| Primary Sysmon Event | Event ID 1 - Process Creation |
| Primary WMI Log | `Microsoft-Windows-WMI-Activity/Operational` |
| Primary WMI Events | 5857 and 5858 |
| Investigation Type | SOC / DFIR / Threat Hunting |

## Investigation Scenario

A SOC analyst observes Windows management-instrumentation activity on a workstation and needs to determine whether the activity represents legitimate system administration, application behavior, or potentially suspicious process execution through WMI/CIM.

The analyst performs controlled CIM/WMI activity using PowerShell and then correlates the resulting process and WMI telemetry. The investigation focuses on identifying the process created through WMI, validating the command that executed, establishing the affected user and host, examining process relationships, and determining whether the available telemetry supports a malicious interpretation.

## Investigation Objectives

The investigation aims to determine:

- Whether WMI/CIM was used to create a process.
- Which command was executed through the management interface.
- Which user initiated the activity.
- Which process was created.
- Whether Sysmon recorded the resulting process creation.
- Whether Windows WMI-Activity logs recorded the management activity.
- What process relationships were visible during the investigation.
- Whether the observed activity appears malicious, benign, or inconclusive.
- Whether Wazuh successfully received telemetry from the Windows endpoint.

## Environment

### Windows Endpoint

```text
Hostname:       DESKTOP-9MMM37V
User:           DESKTOP-9MMM37V\dell
OS:             Microsoft Windows 11 Pro
Version:        10.0.22621
Build:          22621
Manufacturer:   Dell Inc.
Model:          Latitude 5420
PowerShell:     7.6.5
```

### Wazuh

The endpoint was monitored by a Wazuh agent:

```text
Agent ID:          001
Agent Name:        DESKTOP-9MMM37V
IP Address:        any
Status:            Active
Operating System:  Microsoft Windows 11 Pro
Client Version:    Wazuh v4.12.0
```

The Wazuh agent was active during the investigation, allowing Windows telemetry to be forwarded to the SIEM environment.

## Investigation Workflow

```text
Establish Host/User Context
          |
          v
Create Investigation Directory
          |
          v
Collect Process Baseline
          |
          v
Execute Controlled CIM/WMI Process Creation
          |
          v
Validate Created Process / Output
          |
          v
Query Windows Process Information
          |
          v
Review Sysmon Event ID 1
          |
          v
Review WMI-Activity Events
          |
          v
Correlate Host, User, Process and Time
          |
          v
Review Wazuh Agent Telemetry
          |
          v
Determine Investigation Assessment
```

## 1. Establishing Host and User Context

The investigation began by identifying the Windows host, logged-in user, and current timestamp.

```powershell
hostname
whoami
Get-Date
```

Observed values:

```text
Hostname: DESKTOP-9MMM37V
User:     desktop-9mmm37v\dell
Date:     21 August 2026
```

This information establishes the baseline identity and system context for the investigation.

## 2. Investigation Workspace

A dedicated directory was created:

```powershell
New-Item -Path "C:\ManagementInstrumentationLab" -ItemType Directory -Force
```

The directory was then validated:

```powershell
Get-Item "C:\ManagementInstrumentationLab"
```

The directory was used to store investigation artifacts such as:

```text
process-baseline.txt
whoami-output.txt
process-query.txt
```

## 3. Process Baseline

A process baseline was collected:

```powershell
Get-Process |
Select-Object ProcessName, Id, StartTime |
Sort-Object ProcessName |
Out-File "C:\ManagementInstrumentationLab\process-baseline.txt"
```

The process baseline provides a reference point for identifying processes that may appear during or after the controlled WMI/CIM activity.

## 4. Controlled WMI/CIM Process Creation

The key test was performed using `Invoke-CimMethod` against the `Win32_Process` class:

```powershell
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine = "cmd.exe /c whoami > C:\ManagementInstrumentationLab\whoami-output.txt"
}
```

The operation returned:

```text
ProcessId ReturnValue
--------- -----------
22580     0
```

The `ReturnValue` of `0` indicates that the WMI/CIM process-creation request completed successfully.

The command executed through the management interface was:

```text
cmd.exe /c whoami > C:\ManagementInstrumentationLab\whoami-output.txt
```

## 5. Command Execution Validation

The generated output file was checked:

```powershell
Get-Content "C:\ManagementInstrumentationLab\whoami-output.txt"
```

Result:

```text
desktop-9mmm37v\dell
```

This confirms that the created `cmd.exe` process executed successfully and ran the `whoami` command under the observed user context.

The file metadata was also collected:

```powershell
Get-Item "C:\ManagementInstrumentationLab\whoami-output.txt" |
Select-Object FullName, Length, CreationTime, LastWriteTime
```

Observed:

```text
FullName:
C:\ManagementInstrumentationLab\whoami-output.txt

Length:
22

CreationTime:
21-08-2026 07:48:40

LastWriteTime:
21-08-2026 07:48:40
```

The matching creation and modification timestamps are consistent with the file being created by the test command.

## 6. CIM Process Enumeration

The investigation then queried `Win32_Process`:

```powershell
Get-CimInstance -ClassName Win32_Process |
Select-Object Name, ProcessId, ParentProcessId |
Out-File "C:\ManagementInstrumentationLab\process-query.txt"
```

A focused query was also performed for PowerShell, CMD, and Explorer processes:

```powershell
Get-CimInstance -ClassName Win32_Process |
Where-Object {
    $_.Name -match "powershell|cmd|explorer"
} |
Select-Object Name, ProcessId, ParentProcessId, CommandLine
```

Observed processes included:

```text
explorer.exe
explorer.exe
cmd.exe
cmd.exe
```

The observed `cmd.exe` processes included:

```text
PID      Parent PID
17344    16172
4392     16172
```

The command lines showed activity associated with installed McAfee components:

```text
C:\Program Files\McAfee\WebAdvisor\...
C:\Program Files\McAfee\wps\...
```

This is important because process names alone should not be treated as evidence of malicious activity. The surrounding command line, parent process, executable path, user context, and timing must also be considered.

## 7. Operating System Enumeration

The operating system information was collected using CIM:

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem |
Select-Object Caption, Version, BuildNumber
```

Observed:

```text
Caption:
Microsoft Windows 11 Pro

Version:
10.0.22621

BuildNumber:
22621
```

## 8. Process Tree Baseline

The first ten processes returned from `Win32_Process` included:

```text
System Idle Process    PID 0
System                 PID 4
Secure System          PID 108
Registry               PID 144
smss.exe               PID 636
csrss.exe              PID 928
wininit.exe            PID 1016
services.exe           PID 904
lsass.exe              PID 1100
svchost.exe            PID 1236
```

This provides additional system context and demonstrates how CIM can expose process and parent-process information useful during DFIR investigations.

## 9. Sysmon Event ID 1

Sysmon Event ID 1 was used as the primary process-creation telemetry source.

The Windows event log contained:

```text
Log Name:
Microsoft-Windows-Sysmon/Operational

Event ID:
1

Task Category:
Process Create
```

A relevant event showed:

```text
Image:
C:\WINDOWS\System32\cmd.exe

ProcessId:
15268

UtcTime:
2026-08-21 02:23:06.671

Computer:
DESKTOP-9MMM37V

User:
SYSTEM
```

The event confirms that Sysmon was actively recording process creation on the endpoint.

The Windows Event Viewer contained a large volume of Sysmon Event ID 1 telemetry:

```text
Total Sysmon Operational events:
53,382

Filtered Event ID 1 events:
13,319
```

The large event volume demonstrates an important SOC challenge: process creation telemetry is valuable but noisy. Detection logic therefore needs additional context instead of alerting on every `cmd.exe` or WMI-related process.

## 10. WMI-Activity Telemetry

The Windows WMI-Activity operational log was also examined.

Observed event volume:

```text
WMI-Activity events:
1,279
```

Recent events included:

```text
Event ID 5857
Event ID 5858
```

A representative Event ID 5857 showed:

```text
Win32_EncryptableVolumeProvider provider started with result code 0x0.

HostProcess:
wmiprvse.exe

ProcessID:
6948

ProviderPath:
C:\Windows\System32\wbem\Win32_EncryptableVolume.dll

User:
NETWORK SERVICE
```

This event represents WMI provider activity associated with Windows functionality.

It is therefore important not to interpret every WMI-Activity event as malicious.

## 11. WMI-Activity Event 5858

The WMI-Activity log also contained Event ID 5858 entries with an `Error` level.

```text
Event ID:
5858

Level:
Error

Log:
Microsoft-Windows-WMI-Activity/Operational
```

These events require additional context before they can be classified as suspicious. A WMI error alone does not establish malicious activity.

The investigation therefore treats the Event ID 5858 observations as supporting telemetry rather than standalone evidence of compromise.

## 12. Wazuh Agent Validation

The Wazuh agent was checked from the Wazuh manager:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

The agent was reported as:

```text
Agent ID:       001
Agent Name:     DESKTOP-9MMM37V
IP address:     any
Status:         Active
OS:             Microsoft Windows 11 Pro
Client version: Wazuh v4.12.0
```

The agent's Syscheck activity was also visible:

```text
Syscheck last started:
Thu Aug 20 21:01:32 2026

Syscheck last ended:
Fri Aug 21 07:34:10 2026
```

This confirms that the Windows endpoint was actively enrolled with Wazuh and communicating with the manager.

## Key Evidence

| Evidence | Observation | Investigation Value |
|---|---|---|
| Host | `DESKTOP-9MMM37V` | Identifies endpoint |
| User | `DESKTOP-9MMM37V\dell` | Establishes user context |
| OS | Windows 11 Pro Build 22621 | Establishes platform |
| PowerShell | `7.6.5` | Execution environment |
| CIM Class | `Win32_Process` | Management interface used |
| CIM Method | `Create` | Process creation capability |
| Created Process | `cmd.exe` | Resulting process |
| Command | `cmd.exe /c whoami > ...` | Validates executed command |
| Process Output | `desktop-9mmm37v\dell` | Confirms execution context |
| Sysmon | Event ID 1 | Process creation telemetry |
| WMI Activity | Events 5857/5858 | WMI provider/activity telemetry |
| Wazuh | Agent 001 Active | SIEM telemetry availability |

## SOC Analysis

The most important observation in this lab is the successful use of CIM to invoke the `Win32_Process.Create` method and launch `cmd.exe`. From a SOC perspective, this is relevant because WMI/CIM can provide a legitimate administrative mechanism for process execution but can also be abused by attackers for execution, lateral movement, persistence, or remote management.

However, the observed activity was deliberately generated as a controlled lab action. The command executed was a simple `whoami` command that redirected its output to a known investigation directory. There is no evidence in the provided telemetry of credential theft, encoded PowerShell, persistence, lateral movement, or malicious payload execution.

The WMI-Activity Event ID 5857 observed during the investigation was associated with the legitimate `Win32_EncryptableVolumeProvider`, further demonstrating why WMI telemetry must be correlated with process, command-line, provider, user, and timing information before generating a high-confidence alert.

## Detection Opportunities

A stronger detection strategy should correlate multiple signals rather than alerting solely on WMI activity.

Potential detection logic:

```text
WMI/CIM activity
      |
      +-- Process creation
              |
              +-- Suspicious child process
              |
              +-- Unusual parent-child relationship
              |
              +-- Suspicious command line
              |
              +-- Unexpected user/context
```

Higher-risk examples could include WMI/CIM activity resulting in:

```text
powershell.exe
cmd.exe
rundll32.exe
regsvr32.exe
mshta.exe
wscript.exe
cscript.exe
```

Additional suspicious indicators could include:

- Encoded PowerShell commands.
- Download or execution of remote content.
- Processes launched from unusual directories.
- WMI execution performed by unexpected accounts.
- Remote WMI activity.
- WMI-launched processes with suspicious command-line arguments.
- Process creation occurring shortly after unusual authentication activity.
- WMI execution combined with network connections.

## MITRE ATT&CK Relevance

This lab is primarily relevant to:

```text
T1047 - Windows Management Instrumentation
```

The process execution portion can also provide supporting telemetry for:

```text
T1059 - Command and Scripting Interpreter
```

The specific ATT&CK mapping should be applied based on the behavior observed rather than simply labeling all WMI activity as malicious.

## Important Investigation Finding

The investigation successfully demonstrated that WMI/CIM can be used to create a process through:

```text
Win32_Process
    |
    +-- Create
          |
          +-- cmd.exe
                |
                +-- whoami
```

The resulting execution produced a verifiable file artifact and corresponding process telemetry.

At the same time, the WMI-Activity logs contained legitimate provider activity. This distinction is important for SOC operations because WMI is a normal Windows management technology and therefore generates legitimate background telemetry.

## Conclusion

This lab demonstrated a complete investigation workflow for suspicious management-instrumentation activity on a Windows 11 endpoint. CIM was used to invoke `Win32_Process.Create`, resulting in controlled `cmd.exe` execution, while process enumeration, Sysmon Event ID 1, WMI-Activity events, and Wazuh agent telemetry provided multiple sources for validation and correlation.

The observed activity is best classified as **controlled WMI/CIM process-execution activity rather than confirmed malicious behavior**. The lab demonstrates why effective WMI detection requires correlation between management-instrumentation events, process creation, command lines, parent-child relationships, user context, and additional endpoint telemetry instead of treating individual WMI events as inherently malicious.

## Skills Demonstrated

- Windows DFIR
- SOC investigation
- WMI investigation
- CIM investigation
- PowerShell analysis
- Windows process analysis
- Process tree analysis
- Sysmon Event ID 1 analysis
- WMI-Activity log analysis
- Wazuh agent validation
- SIEM telemetry correlation
- Detection engineering
- MITRE ATT&CK mapping
- False-positive analysis
- Evidence-based threat assessment


## Disclaimer

This repository documents a controlled cybersecurity lab performed on a personal Windows environment for defensive security, SOC investigation, DFIR, and detection-engineering practice. The WMI/CIM process creation activity was intentionally generated for investigation and validation purposes.
