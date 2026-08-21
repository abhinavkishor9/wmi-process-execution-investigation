# Lab 57 - Timeline

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

