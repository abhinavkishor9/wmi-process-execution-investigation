# Lab 57 - Investigation Notes


## Investigation Objective

Investigate controlled Windows Management Instrumentation (WMI) and CIM activity and determine whether the activity resulted in process execution. Correlate PowerShell, CIM/WMI, process information, Sysmon Event ID 1, WMI-Activity logs, and Wazuh telemetry.

## Host Information

| Field | Value |
|---|---|
| Hostname | `DESKTOP-9MMM37V` |
| User | `DESKTOP-9MMM37V\dell` |
| Operating System | Microsoft Windows 11 Pro |
| Windows Version | `10.0.22621` |
| Build | `22621` |
| Manufacturer | Dell Inc. |
| Model | Latitude 5420 |
| PowerShell | `7.6.5` |

## Wazuh Information

| Field | Value |
|---|---|
| Agent ID | `001` |
| Agent Name | `DESKTOP-9MMM37V` |
| Status | `Active` |
| Operating System | Microsoft Windows 11 Pro |
| Wazuh Version | `4.12.0` |

## Investigation Directory

The investigation workspace was created at:

`C:\ManagementInstrumentationLab`

Artifacts generated during the investigation:

- `process-baseline.txt`
- `process-query.txt`
- `whoami-output.txt`

## 1. Initial Host Validation

The following commands were used to establish the host, user, and time context:

```powershell
hostname
whoami
Get-Date
```

Observed results:

```text
Hostname: DESKTOP-9MMM37V
User: desktop-9mmm37v\dell
Date: 21 August 2026
```

This establishes the endpoint and account context for the investigation.

## 2. Investigation Workspace Creation

The investigation directory was created with:

```powershell
New-Item -Path "C:\ManagementInstrumentationLab" -ItemType Directory -Force
```

The directory was verified with:

```powershell
Get-Item "C:\ManagementInstrumentationLab"
```

The directory was successfully created:

```text
C:\ManagementInstrumentationLab
```

## 3. Process Baseline

A process baseline was collected using:

```powershell
Get-Process |
Select-Object ProcessName, Id, StartTime |
Sort-Object ProcessName |
Out-File "C:\ManagementInstrumentationLab\process-baseline.txt"
```

The baseline provides a reference for comparing process activity observed during the investigation.

The collected information included:

- Process name
- Process ID
- Process start time

## 4. WMI/CIM Process Creation

The primary investigation activity used `Invoke-CimMethod` against the `Win32_Process` class.

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

The `ReturnValue` of `0` indicates that the requested WMI/CIM operation completed successfully.

### Target

| Field | Value |
|---|---|
| CIM Class | `Win32_Process` |
| Method | `Create` |
| Process | `cmd.exe` |
| Command | `cmd.exe /c whoami` |
| Output File | `C:\ManagementInstrumentationLab\whoami-output.txt` |

This demonstrates that CIM was used to request Windows process creation.

## 5. Command Execution Validation

The generated file was checked using:

```powershell
Get-Content "C:\ManagementInstrumentationLab\whoami-output.txt"
```

Result:

```text
desktop-9mmm37v\dell
```

This confirms that:

1. The requested process creation succeeded.
2. `cmd.exe` executed.
3. The `whoami` command executed successfully.
4. The command produced output.
5. The output was written to disk.
6. The observed execution context corresponds to the `dell` user.

## 6. File Artifact Analysis

The generated file was examined using:

```powershell
Get-Item "C:\ManagementInstrumentationLab\whoami-output.txt" |
Select-Object FullName, Length, CreationTime, LastWriteTime
```

Observed metadata:

| Attribute | Value |
|---|---|
| FullName | `C:\ManagementInstrumentationLab\whoami-output.txt` |
| Length | `22` bytes |
| CreationTime | `21-08-2026 07:48:40` |
| LastWriteTime | `21-08-2026 07:48:40` |

The matching creation and modification timestamps are consistent with the file being created during the controlled command execution.

The file therefore provides a useful filesystem artifact for correlating the process execution with a tangible endpoint change.

## 7. CIM Process Enumeration

The investigation queried the `Win32_Process` class:

```powershell
Get-CimInstance -ClassName Win32_Process |
Select-Object Name, ProcessId, ParentProcessId |
Out-File "C:\ManagementInstrumentationLab\process-query.txt"
```

A focused query was also performed:

```powershell
Get-CimInstance -ClassName Win32_Process |
Where-Object {
    $_.Name -match "powershell|cmd|explorer"
} |
Select-Object Name, ProcessId, ParentProcessId, CommandLine
```

Observed processes included:

- `explorer.exe`
- `explorer.exe`
- `cmd.exe`
- `cmd.exe`

Observed `cmd.exe` processes:

| Process | Process ID | Parent Process ID |
|---|---:|---:|
| `cmd.exe` | `17344` | `16172` |
| `cmd.exe` | `4392` | `16172` |

The command-line information also showed activity associated with installed McAfee components:

```text
C:\Program Files\McAfee\WebAdvisor\...
C:\Program Files\McAfee\wps\...
```

### SOC Interpretation

The presence of `cmd.exe` alone is not sufficient to classify the activity as malicious.

A SOC analyst should examine:

- Parent process
- Command line
- Executable path
- User context
- Process creation time
- Network activity
- Associated WMI activity
- Remote versus local execution
- Suspicious command arguments

This is important because legitimate Windows software frequently invokes `cmd.exe`.

## 8. Operating System Enumeration

The operating system was enumerated through CIM:

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem |
Select-Object Caption, Version, BuildNumber
```

Observed results:

```text
Caption:
Microsoft Windows 11 Pro

Version:
10.0.22621

BuildNumber:
22621
```

The endpoint was therefore confirmed as a Windows 11 Pro system running build `22621`.

## 9. Process Enumeration

The first ten processes returned by `Win32_Process` included:

| Process | Process ID | Parent Process ID |
|---|---:|---:|
| `System Idle Process` | `0` | `0` |
| `System` | `4` | `0` |
| `Secure System` | `108` | `4` |
| `Registry` | `144` | `4` |
| `smss.exe` | `636` | `4` |
| `csrss.exe` | `928` | `736` |
| `wininit.exe` | `1016` | `736` |
| `services.exe` | `904` | `1016` |
| `lsass.exe` | `1100` | `1016` |
| `svchost.exe` | `1236` | `904` |

Process relationships are important when investigating WMI because suspicious execution may become clearer when parent-child relationships are examined.

Example investigation model:

```text
powershell.exe
    |
    +-- WMI/CIM
          |
          +-- cmd.exe
                |
                +-- suspicious-command
```

## 10. Sysmon Event ID 1 Analysis

Sysmon Event ID 1 was used to investigate process creation.

### Event Details

| Field | Value |
|---|---|
| Log Name | `Microsoft-Windows-Sysmon/Operational` |
| Event ID | `1` |
| Task Category | `Process Create` |
| Image | `C:\WINDOWS\System32\cmd.exe` |
| Process ID | `15268` |
| UTC Time | `2026-08-21 02:23:06.671` |
| Computer | `DESKTOP-9MMM37V` |
| User | `SYSTEM` |

The event confirms that Sysmon was actively recording process creation activity on the endpoint.

## 11. Sysmon Event Volume

The Windows Event Viewer showed:

| Metric | Count |
|---|---:|
| Sysmon Operational events | `53,382` |
| Sysmon Event ID 1 events | `13,319` |

The high volume demonstrates a common SIEM detection challenge.

Process creation is highly valuable telemetry, but it is also noisy.

A detection based only on:

```text
Image = cmd.exe
```

would likely generate significant false positives.

A stronger detection should correlate process creation with:

- WMI/CIM activity
- Suspicious command-line arguments
- Unexpected parent process
- Unusual user context
- Unusual executable path
- Network activity
- Persistence indicators

## 12. WMI-Activity Log Analysis

The Windows WMI-Activity operational log was examined:

```text
Microsoft-Windows-WMI-Activity/Operational
```

Observed event volume:

```text
1,279 events
```

Relevant events included:

- Event ID `5857`
- Event ID `5858`

This confirms that WMI-related activity was being logged on the endpoint.

## 13. WMI-Activity Event 5857

A representative Event ID 5857 showed:

| Field | Value |
|---|---|
| Provider | `Win32_EncryptableVolumeProvider` |
| Result Code | `0x0` |
| Host Process | `wmiprvse.exe` |
| Process ID | `6948` |
| Provider Path | `C:\Windows\System32\wbem\Win32_EncryptableVolume.dll` |
| User | `NETWORK SERVICE` |

The event indicates that the `Win32_EncryptableVolumeProvider` provider started successfully.

### SOC Assessment

This event should not automatically be classified as malicious.

WMI is a legitimate Windows management framework, and Windows components and security software can generate WMI provider activity during normal system operations.

The following should be evaluated before generating an alert:

- Provider name
- Provider path
- Host process
- User context
- Parent process
- Command line
- Timing
- Network activity
- Remote versus local execution

## 14. WMI-Activity Event 5858

Event ID `5858` was also observed with an `Error` level.

The presence of a WMI-Activity error does not independently demonstrate malicious activity.

Possible legitimate causes include:

- Windows services
- Security software
- Application queries
- Provider failures
- Permission issues
- Failed management operations
- Application compatibility issues

Event ID 5858 should therefore be correlated with other telemetry before assigning malicious intent.

## 15. Wazuh Agent Validation

The Wazuh agent was checked from the Wazuh manager using:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed agent information:

| Field | Value |
|---|---|
| Agent ID | `001` |
| Agent Name | `DESKTOP-9MMM37V` |
| IP Address | `any` |
| Status | `Active` |
| Operating System | Microsoft Windows 11 Pro |
| Client Version | `Wazuh v4.12.0` |

### Syscheck Information

| Field | Value |
|---|---|
| Last Started | `Thu Aug 20 21:01:32 2026` |
| Last Ended | `Fri Aug 21 07:34:10 2026` |

The active Wazuh agent confirms that the endpoint was enrolled and communicating with the Wazuh manager.

## 16. Evidence Correlation

The investigation produced several relevant evidence sources:

| Evidence Source | Observation | Investigation Value |
|---|---|---|
| PowerShell | `Invoke-CimMethod` | Shows CIM-based activity |
| CIM Class | `Win32_Process` | Identifies management interface |
| CIM Method | `Create` | Demonstrates process creation |
| Process | `cmd.exe` | Resulting process |
| Command | `cmd.exe /c whoami` | Confirms command execution |
| File | `whoami-output.txt` | Filesystem artifact |
| Sysmon | Event ID `1` | Process creation telemetry |
| WMI-Activity | Events `5857` and `5858` | WMI telemetry |
| Wazuh | Agent `001` Active | SIEM visibility |

The combination of these sources provides stronger investigative confidence than relying on a single event.

## 21. MITRE ATT&CK Mapping

### T1047 - Windows Management Instrumentation

**Technique:** `T1047 - Windows Management Instrumentation`

The primary technique associated with this investigation is Windows Management Instrumentation.

The lab demonstrates use of the Windows management infrastructure to interact with `Win32_Process` and request process creation.

### T1059 - Command and Scripting Interpreter

**Technique:** `T1059 - Command and Scripting Interpreter`

Supporting relevance exists because the resulting process executed:

```text
cmd.exe /c whoami
```

The exact sub-technique should be determined based on the final detection logic and behavior being documented.

