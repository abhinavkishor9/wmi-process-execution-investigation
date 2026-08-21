# wmi-process-execution-investigation
## Overview

Windows management instrumentation provides legitimate administrative capabilities for querying and managing systems. Common activity may involve:

wmic.exe
WMI queries
WMI process execution
PowerShell CIM/WMI commands
Management-related process creation

The investigation challenge is that this activity may be completely legitimate.
For example:

Administrator
    ↓
wmic.exe
    ↓
Query system information

may be normal administration.

But an execution chain such as:

powershell.exe
    ↓
wmic.exe / WMI
    ↓
Create process
    ↓
cmd.exe

deserves closer investigation.

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
A monitored Windows workstation shows suspicious Management Instrumentation activity involving Windows Management Instrumentation (WMI) and CIM. The activity includes management-interface usage, process creation, and related WMI and Sysmon telemetry that requires investigation.

The analyst must determine:

- Who initiated the activity?
- Which process initiated the WMI/CIM operation?
- Which WMI class and method were used?
- What command was requested through the management interface?
- Was the activity performed locally or directed at another system?
- Did the WMI/CIM operation create another process?
- What process was created and what did it execute?
- Was a file created as a result of the execution?
- Does the process ancestry support the observed activity?
- Is the WMI-Activity telemetry consistent with legitimate Windows behavior?
- Was the activity expected for the user and workstation?
- Is there evidence of persistence, lateral movement, credential theft, or other malicious behavior?
- Does the available evidence support malicious use of WMI/CIM?

## Investigation Objectives

- Identify the endpoint, user, operating system, and investigation timeframe.
- Understand how Invoke-CimMethod can interact with the Win32_Process WMI class.
- Identify the significance of the Win32_Process.Create method.
- Validate whether a WMI/CIM request resulted in actual process execution.
- Identify the process created as a result of the management-instrumentation activity.
- Examine process IDs and parent-process relationships.
- Use CIM queries to investigate running processes and operating-system information.
- Identify filesystem artifacts created by a command executed through WMI/CIM.
- Analyze Sysmon Event ID 1 for process-creation evidence.
- Investigate Windows WMI-Activity Event IDs 5857 and 5858.
- Distinguish legitimate WMI provider activity from potentially suspicious WMI execution.
- Understand why cmd.exe or wmiprvse.exe alone should not be treated as malicious indicators.
- Correlate WMI activity with process creation, command execution, user context, and filesystem activity.
- Validate that the Windows endpoint is actively reporting telemetry to Wazuh.
- Account for UTC versus local timestamps during event correlation.
- Recognize the difference between controlled test activity and unrelated background Windows activity.
- Develop a contextual approach for detecting potential WMI abuse.
- Determine whether the available evidence supports a malicious-activity conclusion.




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


## Disclaimer

This repository documents a controlled cybersecurity lab performed on a personal Windows environment for defensive security, SOC investigation, DFIR, and detection-engineering practice. The WMI/CIM process creation activity was intentionally generated for investigation and validation purposes.
