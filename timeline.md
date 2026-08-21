# Lab 57 - Timeline

## Suspicious Management Instrumentation Activity Investigation

> Timeline of the controlled WMI/CIM process-creation activity and supporting Windows, Sysmon, WMI-Activity, and Wazuh telemetry.

---

## Investigation Timeline

| Time | Source | Event / Activity | Significance |
|---|---|---|---|
| `07:39:45` | PowerShell | `Get-Date` executed | Established the investigation start time |
| `07:44` | PowerShell | `C:\ManagementInstrumentationLab` created | Created the controlled investigation workspace |
| `07:44` | PowerShell | Investigation directory verified | Confirmed workspace availability |
| `07:44+` | PowerShell | Process baseline collected | Established baseline process information |
| `07:48+` | PowerShell | `Invoke-CimMethod` executed against `Win32_Process` | Initiated controlled WMI/CIM process creation |
| `07:48+` | WMI/CIM | `Win32_Process.Create` returned `ReturnValue = 0` | Confirmed successful management-instrumentation request |
| `07:48:40` | Filesystem | `whoami-output.txt` created | Confirmed a filesystem artifact from the command execution |
| `07:48:40` | Filesystem | `whoami-output.txt` last modified | Creation and modification times matched |
| `07:48+` | PowerShell | `Get-Content` read `whoami-output.txt` | Confirmed command execution result |
| `07:48+` | CIM | `Win32_Process` queried | Enumerated running processes |
| `07:48+` | CIM | Focused query for `powershell`, `cmd`, and `explorer` | Investigated potentially relevant processes |
| `07:48+` | CIM | Windows operating system queried | Confirmed Windows 11 Pro build `22621` |
| `07:48+` | CIM | Process hierarchy queried | Provided process and parent-process context |
| `07:53:06` | Sysmon | Event ID `1` for `cmd.exe` | Provided process-creation telemetry |
| `07:53:12` | Sysmon | Additional Event ID `1` events | Demonstrated continued process-creation activity |
| `07:54:03` | WMI-Activity | Event ID `5858` | WMI error activity observed |
| `07:55:03` | WMI-Activity | Event ID `5857` | WMI provider activity observed |
| `07:55:23` | WMI-Activity | Event ID `5857` | Additional WMI provider activity observed |
| `07:55+` | Event Viewer | Sysmon Event ID `1` filtering showed `13,319` events | Demonstrated high process-creation telemetry volume |
| `07:55+` | Event Viewer | WMI-Activity showed `1,279` events | Demonstrated WMI telemetry volume |
| `07:55+` | Wazuh | Agent `001` verified as `Active` | Confirmed endpoint SIEM connectivity |

---

## 1. 07:39:45 - Investigation Start

PowerShell was used to establish the initial investigation time:

```powershell
Get-Date
```

Result:

```text
21 August 2026 07:39:45
```

This established the initial time anchor for the investigation.

---

## 2. 07:44 - Investigation Workspace Created

A dedicated investigation directory was created:

```powershell
New-Item -Path "C:\ManagementInstrumentationLab" -ItemType Directory -Force
```

The directory was then verified:

```powershell
Get-Item "C:\ManagementInstrumentationLab"
```

The workspace was successfully created at:

```text
C:\ManagementInstrumentationLab
```

This directory was used to store investigation artifacts.

---

## 3. 07:44+ - Process Baseline Collected

A process baseline was generated using:

```powershell
Get-Process |
Select-Object ProcessName, Id, StartTime |
Sort-Object ProcessName |
Out-File "C:\ManagementInstrumentationLab\process-baseline.txt"
```

The baseline provided a reference for comparing process activity observed during the investigation.

---

## 4. 07:48+ - WMI/CIM Process Creation

The controlled WMI/CIM activity was executed using:

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

The `ReturnValue` of `0` confirmed that the requested CIM method completed successfully.

The command supplied to the WMI process-creation method was:

```text
cmd.exe /c whoami > C:\ManagementInstrumentationLab\whoami-output.txt
```

This established the primary execution event investigated throughout the lab.

---

## 5. 07:48+ - Command Execution Validation

The generated output file was examined:

```powershell
Get-Content "C:\ManagementInstrumentationLab\whoami-output.txt"
```

Result:

```text
desktop-9mmm37v\dell
```

This confirmed that:

- `cmd.exe` executed.
- `whoami` executed successfully.
- The command produced output.
- The output was written to disk.
- The observed execution context corresponded to the `dell` user.

---

## 6. 07:48:40 - Filesystem Artifact Created

The generated file was:

```text
C:\ManagementInstrumentationLab\whoami-output.txt
```

The file metadata showed:

| Attribute | Value |
|---|---|
| Length | `22` bytes |
| Creation Time | `21-08-2026 07:48:40` |
| Last Write Time | `21-08-2026 07:48:40` |

The matching creation and modification timestamps are consistent with the file being created during the controlled command execution.

The file therefore became a useful filesystem artifact for correlating the WMI/CIM execution with endpoint activity.

---

## 7. 07:48+ - CIM Process Enumeration

Running processes were enumerated through CIM:

```powershell
Get-CimInstance -ClassName Win32_Process |
Select-Object Name, ProcessId, ParentProcessId |
Out-File "C:\ManagementInstrumentationLab\process-query.txt"
```

A focused process query was also performed:

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

Observed `cmd.exe` processes included:

| Process | Process ID | Parent Process ID |
|---|---:|---:|
| `cmd.exe` | `17344` | `16172` |
| `cmd.exe` | `4392` | `16172` |

The command-line information also showed activity associated with installed McAfee components.

This demonstrated that `cmd.exe` activity existed independently of the controlled test and reinforced the need for process-context analysis.

---

## 8. 07:48+ - Operating System Enumeration

The operating system was queried through CIM:

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem |
Select-Object Caption, Version, BuildNumber
```

Observed results:

| Field | Value |
|---|---|
| Caption | Microsoft Windows 11 Pro |
| Version | `10.0.22621` |
| Build Number | `22621` |

This confirmed the Windows platform involved in the investigation.

---

## 9. 07:48+ - Process Hierarchy Enumeration

The investigation queried process relationships using:

```powershell
Get-CimInstance -ClassName Win32_Process |
Select-Object -First 10 Name, ProcessId, ParentProcessId
```

Observed processes included:

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

Process relationships are important during WMI investigations because suspicious execution may become more apparent when parent-child relationships are examined.

---

## 10. 07:53:06 - Sysmon Event ID 1

Sysmon recorded a process creation event:

```text
Event ID:
1

Image:
C:\WINDOWS\System32\cmd.exe

Process ID:
15268

UTC Time:
2026-08-21 02:23:06.671

Computer:
DESKTOP-9MMM37V
```

The event was recorded under:

```text
Microsoft-Windows-Sysmon/Operational
```

The event confirmed that Sysmon was providing process-creation telemetry on the endpoint.

---

## 11. 07:53:12 - Additional Sysmon Process Creation Activity

Additional Sysmon Event ID `1` events were observed at:

```text
21-08-2026 07:53:12
```

This demonstrated that the endpoint was generating continued process-creation telemetry.

The high event volume meant that individual process events required additional filtering and contextual analysis.

---

## 12. 07:54:03 - WMI-Activity Event ID 5858

The WMI-Activity operational log recorded Event ID `5858`:

```text
Event ID:
5858

Level:
Error
```

The event was treated as supporting WMI telemetry rather than direct evidence of malicious behavior.

A WMI error may be generated by:

- Windows services
- Security software
- WMI provider failures
- Permission issues
- Application queries
- Failed management operations

Therefore, the event required correlation with other evidence.

---

## 13. 07:55:03 - WMI-Activity Event ID 5857

WMI-Activity recorded Event ID `5857`.

Observed details included:

| Field | Value |
|---|---|
| Provider | `Win32_EncryptableVolumeProvider` |
| Host Process | `wmiprvse.exe` |
| Process ID | `6948` |
| Provider Path | `C:\Windows\System32\wbem\Win32_EncryptableVolume.dll` |
| User | `NETWORK SERVICE` |
| Result Code | `0x0` |

The event indicated that the provider started successfully.

The provider path was located under the standard Windows WMI directory:

```text
C:\Windows\System32\wbem\
```

The event was therefore not treated as malicious based on the available evidence.

---

## 14. 07:55:23 - Additional WMI-Activity Event ID 5857

Another WMI-Activity Event ID `5857` was observed:

```text
21-08-2026 07:55:23
```

The continued WMI provider activity demonstrated that the endpoint was actively generating WMI-related telemetry.

This reinforced the need to distinguish:

- Controlled WMI/CIM execution
- Legitimate Windows WMI activity
- Security-software WMI activity
- Potential malicious WMI execution

---

## 15. 07:55+ - Sysmon Event Volume Review

Windows Event Viewer showed:

```text
Operational Number of events: 53,382
```

After filtering for:

```text
Log:
Microsoft-Windows-Sysmon/Operational

Event ID:
1
```

the number of events was:

```text
13,319
```

This demonstrated that process-creation telemetry was high volume.

A detection based only on:

```text
cmd.exe
```

would likely generate significant false positives.

---

## 16. 07:55+ - WMI-Activity Event Volume Review

The WMI-Activity operational log contained:

```text
1,279 events
```

Relevant events included:

```text
5857
5858
```

This demonstrated that WMI telemetry can also be noisy on a normal Windows endpoint.

---

## 17. Wazuh Agent Verification

The Wazuh agent was verified from the Wazuh manager:

```bash
sudo /var/ossec/bin/agent_control -i 001
```

Observed information:

| Field | Value |
|---|---|
| Agent ID | `001` |
| Agent Name | `DESKTOP-9MMM37V` |
| Status | `Active` |
| Operating System | Microsoft Windows 11 Pro |
| Client Version | `Wazuh v4.12.0` |

Syscheck information showed:

| Field | Value |
|---|---|
| Last Started | `Thu Aug 20 21:01:32 2026` |
| Last Ended | `Fri Aug 21 07:34:10 2026` |

The active agent confirmed that the Windows endpoint was connected to the Wazuh manager.

---

## 18. Timeline Correlation

The controlled execution chain was:

```text
PowerShell
    |
    v
Invoke-CimMethod
    |
    v
Win32_Process.Create
    |
    v
cmd.exe
    |
    v
whoami
    |
    v
whoami-output.txt
```

Supporting endpoint telemetry included:

```text
WMI/CIM
    |
    +-- Win32_Process.Create
    |
    +-- Process Enumeration
    |
    +-- Windows Process Information

Sysmon
    |
    +-- Event ID 1
    |
    +-- cmd.exe Process Creation

WMI-Activity
    |
    +-- Event ID 5857
    |
    +-- Event ID 5858

Wazuh
    |
    +-- Agent 001 Active
```

---

## 19. Timestamp Correlation Note

The investigation contains both local Windows timestamps and UTC timestamps.

For example, Sysmon reported:

```text
UtcTime:
2026-08-21 02:23:06.671
```

while Event Viewer displayed:

```text
21-08-2026 07:53:06
```

When performing forensic correlation, timestamps should be normalized to a common timezone before determining the exact order of events.

This is particularly important when correlating:

- PowerShell history
- Sysmon
- Windows Event Viewer
- WMI-Activity
- Wazuh
- Filesystem timestamps

---

## 20. Investigation Outcome

The timeline confirms that the controlled WMI/CIM operation successfully resulted in command execution.

The strongest evidence is the following sequence:

```text
Invoke-CimMethod
        |
        v
Win32_Process.Create
        |
        v
cmd.exe
        |
        v
whoami
        |
        v
whoami-output.txt
```

The resulting activity was observable through multiple telemetry sources.

### Confirmed

- WMI/CIM process creation
- `Win32_Process.Create`
- `cmd.exe` execution
- `whoami` execution
- Filesystem artifact creation
- Sysmon Event ID 1 telemetry
- WMI-Activity telemetry
- Active Wazuh agent

### Not Confirmed

- Malicious payload
- Credential theft
- Persistence
- Lateral movement
- Remote WMI execution
- Data exfiltration
- Privilege escalation
- Suspicious network activity

---

## Final Timeline Assessment

**WMI/CIM PROCESS EXECUTION CONFIRMED**

**COMMAND EXECUTION CONFIRMED**

**FILESYSTEM ARTIFACT CONFIRMED**

**SYSMON PROCESS-CREATION TELEMETRY CONFIRMED**

**WMI-ACTIVITY TELEMETRY CONFIRMED**

**WAZUH AGENT VISIBILITY CONFIRMED**

**MALICIOUS ACTIVITY NOT CONFIRMED**

The primary SOC lesson from this timeline is that WMI activity must be analyzed using **temporal correlation, process ancestry, command-line context, user context, and supporting endpoint or network telemetry** rather than treating individual WMI or process-creation events as inherently malicious.
