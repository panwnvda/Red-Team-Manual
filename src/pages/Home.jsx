import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';

const allColumns = [
  {
    header: 'INFRASTRUCTURE',
    color: 'cyan',
    nodes: [
      { title: 'C2', subtitle: 'Cobalt Strike • Sliver • listeners • pivots' },
      { title: 'OPSEC', subtitle: 'Redirectors • Traffic Control • Beacons • Channels' },
      { title: 'Implants', subtitle: 'BOFs • Shellcode Runners • OPSEC Principles' },
    ]
  },
  {
    header: 'RECONNAISSANCE',
    color: 'cyan',
    nodes: [
      { title: 'OSINT', subtitle: 'SOCK Puppets • DNS Records • Google Dorks • Social Media' },
      { title: 'Scanning', subtitle: 'Port Scanning • FTP • SSH • SMB • NFS • SMTP • SNMP • SQL' },
      { title: 'Packet Capture', subtitle: 'Wireshark • tshark • passive credential harvest' },
      { title: 'Internal Recon', subtitle: 'Domain Recon • BloodHound • PowerView • ADSearch' },
    ]
  },
  {
    header: 'INITIAL COMPROMISE',
    color: 'emerald',
    nodes: [
      { title: 'Credential Attacks', subtitle: 'Password Spraying • OWA • O365 • Kerberos' },
      { title: 'Phishing', subtitle: 'AiTM • Evilginx • GoPhish • TeamsPhisher • Droplets • Evasive Infra • Device Code • Pretexting' },
      { title: 'Payload Development', subtitle: 'Shellcode Development • msfvenom' },
      { title: 'Delivery', subtitle: 'VBA Macros • LNK • HTML Smuggling • Supply Chain • OneNote • XLL • Payload Evasion • LOLBins' },
      { title: 'Physical & USB', subtitle: 'Rubber Ducky & HID • Malicious USB Drops' },
      { title: 'Containers & Images', subtitle: 'ISO • VHD • IMG Delivery • Docker Compromise • Malicious VM Images' },
    ]
  },
  {
    header: 'EXECUTION',
    color: 'emerald',
    nodes: [
      { title: 'Shellcode & DLL', subtitle: 'Injection • reflective load • custom stagers' },
      { title: 'Managed Code', subtitle: 'Assembly loading • .NET • PowerShell' },
      { title: 'LOLBINs & Scripts', subtitle: 'Living off the land • LOLBAS • scripts' },
      { title: 'Remote & Token', subtitle: 'WMI • DCOM • token impersonation' },
    ]
  },
  {
    header: 'HOST OPERATIONS',
    color: 'emerald',
    nodes: [
      { title: 'Host Recon', subtitle: 'Seatbelt • processes • sessions • Linux • macOS recon' },
      { title: 'User Persistence', subtitle: 'Startup • Task Scheduler • registry' },
      { title: 'Elevated Persistence', subtitle: 'Services • WMI • Linux systemd • macOS LaunchAgents' },
    ]
  },
  {
    header: 'PRIVILEGE ESCALATION',
    color: 'red',
    nodes: [
      { title: 'Service Exploits', subtitle: 'Weak perms • binary perms • unquoted • TCC/SIP bypass' },
      { title: 'Token & Secrets', subtitle: 'Token impersonation • DPAPI • SUID • sudo' },
      { title: 'Kernel Exploits', subtitle: 'DirtyPipe • PwnKit • PrintNightmare • EternalBlue' },
    ]
  },
  {
    header: 'CREDENTIAL ACCESS',
    color: 'red',
    nodes: [
      { title: 'Secrets', subtitle: 'Linux creds • shadow • SSH keys • env files' },
      { title: 'Memory Dumps', subtitle: 'Mimikatz • LSASS • minidump • DCSync' },
      { title: 'Kerberos & AD', subtitle: 'Kerberoasting • ASREProast • ticket extraction' },
      { title: 'Offline Cracking', subtitle: 'Hashcat • john • wordlists • rules' },
    ]
  },
  {
    header: 'LATERAL MOVEMENT',
    color: 'orange',
    nodes: [
      { title: 'Authentication', subtitle: 'Pass-the-Hash • Overpass-the-Hash • SSH • macOS ARD' },
      { title: 'Remote Execution', subtitle: 'WinRM • PsExec • WMI • DCOM' },
      { title: 'Network Pivoting', subtitle: 'SOCKS • Ligolo-ng • Chisel • SMB relay' },
    ]
  },
  {
    header: 'DOMAIN DOMINANCE',
    color: 'yellow',
    nodes: [
      { title: 'Ticket Forgery', subtitle: 'Silver • Golden • Diamond tickets' },
      { title: 'Cert & Data', subtitle: 'Cert forgery • Data exfiltration • hunting' },
    ]
  },
  {
    header: 'DEFENSE EVASION',
    color: 'orange',
    nodes: [
      { title: 'Payload & Staging', subtitle: 'Artifact Kit • AMSI bypass • AppLocker' },
      { title: 'C2 Profile & Templates', subtitle: 'Malleable C2 • CLM bypass • Resource Kit' },
      { title: 'Post-Exploitation', subtitle: 'Memory cleanup • RW→RX • Fork-and-run' },
      { title: 'Process Masking', subtitle: 'PPID spoof • Cmd spoof • Pipes • ETW bypass' },
    ]
  },
  {
    header: 'EDR EVASION',
    color: 'red',
    nodes: [
      { title: 'Hook & Syscall', subtitle: 'Hook detection • direct & indirect syscalls' },
      { title: 'Implant Evasion', subtitle: 'Sleep mask • stack spoof • UDRL' },
      { title: 'Kernel Level', subtitle: 'Kernel callbacks • BYOVD • DKOM' },
      { title: 'Vendor Specific', subtitle: 'CrowdStrike • MDE • SentinelOne • Cortex • Elastic • ESET' },
    ]
  },
  {
    header: 'WINDOWS APIs',
    color: 'emerald',
    nodes: [
      { title: 'Direct API Calls', subtitle: 'CreateProcess • WinAPI • NT APIs' },
      { title: 'Dynamic Invocation', subtitle: 'P/Invoke • D/Invoke • API hashing' },
      { title: 'Error Handling', subtitle: 'GetLastError • NTSTATUS • exceptions' },
    ]
  },
  {
    header: 'ASR & WDAC',
    color: 'orange',
    nodes: [
      { title: 'ASR', subtitle: 'Rule enumeration • exclusion abuse • bypass' },
      { title: 'WDAC', subtitle: 'Policy enum • LOLBAS • trusted signers • filename rules' },
    ]
  },
  {
    header: 'PROCESS INJECTION',
    color: 'red',
    nodes: [
      { title: 'Local Injection', subtitle: 'CreateThread • QueueUserAPC • fiber' },
      { title: 'Remote Injection', subtitle: 'CreateRemoteThread • VirtualAllocEx • APC' },
      { title: 'NT Injection', subtitle: 'NtMapViewOfSection • Section mapping • syscalls' },
    ]
  },
  {
    header: 'MALWARE',
    color: 'red',
    nodes: [
      { title: 'Injection', subtitle: 'Process inject • reflective DLL • hollowing • module stomp • FLS RCE • IOCP • GhostWriting' },
      { title: 'API & Syscalls', subtitle: 'API hashing • IAT hiding • direct/indirect syscalls • Heaven\'s Gate • VProtect substitute' },
      { title: 'Evasion', subtitle: 'AMSI deep • ETW spoof • KnownDlls stomp • CET bypass • TxF phantom • anti-debug • entropy' },
      { title: 'Loader & Staging', subtitle: 'Custom loaders • staging • sleep masking • packer • PPID spoof • arg spoof' },
      { title: 'Stealth', subtitle: 'NTDLL unhook • DLL sideload • stealth chain • WFP backdoor • keylogging • persistence' },
      { title: 'Build & Sign', subtitle: 'MinGW cross-compile • Authenticode • HWBP evasion • PE obfuscation' },
      { title: 'Sandbox & Escapes', subtitle: 'PPL bypass • LSASS dump • UAC IFileOp • ACG JIT • COM AppDomain • Token Filter • WOW64 Heaven\'s Gate' },
      { title: 'Kernel & Callbacks', subtitle: 'Callback removal • DKOM • memory forensics evasion • filter driver • PTE • Intel PT' },
      { title: 'Hypervisor & Secure', subtitle: 'macOS XPC • Chrome Mojo • iOS Mach • Android Binder • Hypervisor • Container • TEE' },
      { title: 'Novel Escapes', subtitle: 'BHI Spectre • SGX D-Cache • IOMMU race • VBS covert channel • CPU microcode oracle' },
      { title: 'C2 & Steganography', subtitle: 'Custom C2 protocols • polymorphic engine • stealth communication • evasion' },
      { title: 'Advanced Exploits', subtitle: 'Heap UAF • COM deep abuse • PE format • Linux rootkits • eBPF implant' },
      { title: 'Shellcode & Assembly', subtitle: 'PIC x64 ASM • stack spoofing • BOF development • custom encoders' },
    ]
  },
  {
    header: 'MOBILE APPLICATIONS',
    color: 'green',
    nodes: [
      { title: 'Reconnaissance', subtitle: 'APK/IPA extract • advanced Frida tracing • Stalker coverage • runtime memory' },
      { title: 'Authentication', subtitle: 'Biometric bypass • SSL pinning • mTLS bypass • TrustKit • cert extraction' },
      { title: 'Data Storage', subtitle: 'SharedPrefs • SQLite • Keychain • deep links • IPC • content providers' },
      { title: 'Network & API', subtitle: 'IDOR • JWT • WebView • tapjacking • overlay attacks • JS bridge' },
      { title: 'Binary & Runtime', subtitle: 'Root bypass • binary RE • Ghidra • crypto intercept • heap scanning' },
    ]
  },
  {
    header: 'WEB APPLICATIONS',
    color: 'blue',
    nodes: [
      { title: 'Web Reconnaissance', subtitle: 'Enumeration • fingerprinting • mapping' },
      { title: 'Authentication', subtitle: 'Brute force • JWT • MFA bypass' },
      { title: 'Session Management', subtitle: 'Session fixation • CSRF • cookies' },
      { title: 'Authorization', subtitle: 'IDOR • BOLA • privilege escalation' },
      { title: 'Server-Side Attacks', subtitle: 'SQLi • RCE • SSRF • XXE • SSTI' },
      { title: 'Client-Side Attacks', subtitle: 'XSS • DOM XSS • CORS • CSP' },
      { title: 'API Attacks', subtitle: 'GraphQL • REST • mass assignment' },
      { title: 'Protocol Attacks', subtitle: 'Request smuggling • cache poison • verb tampering' },
      { title: 'Source Code Analysis', subtitle: 'SAST • taint analysis • dataflow' },
    ]
  },
  {
    header: 'WI-FI',
    color: 'cyan',
    nodes: [
      { title: 'Wi-Fi Reconnaissance', subtitle: 'airodump-ng • signal mapping • clients' },
      { title: 'WPA2 Attacks', subtitle: 'Handshake • PMKID • offline cracking' },
      { title: 'WPS Attacks', subtitle: 'Pixie Dust • PIN brute-force • reaver' },
      { title: 'WPA3 Attacks', subtitle: 'Dragonblood • SAE downgrade • fragmentation • timing side-channel • GCMP bypass • transition mode abuse' },
      { title: 'WPA Enterprise (802.1X)', subtitle: 'Rogue AP • EAP • RADIUS exploitation' },
      { title: 'Rogue AP & MITM', subtitle: 'Evil twin • traffic interception • SSL strip' },
      { title: 'Post-WiFi Access', subtitle: 'Internal recon • SMB relay • pivoting' },
    ]
  },
  {
    header: 'ACTIVE DIRECTORY',
    color: 'cyan',
    nodes: [
      { title: 'Kerberos Attacks', subtitle: 'Kerberoasting • ASREPRoast • delegation abuse • Diamond Ticket • AES OPSEC' },
      { title: 'Cert & Policy (ADCS)', subtitle: 'ESC1-15 • certifried CVE-2022-26923 • EKU override • Group Policy creds' },
      { title: 'Services & Infra', subtitle: 'MSSQL chains • SCCM NAA • LAPS backdoor • Exchange relay' },
      { title: 'Trusts & Coercion', subtitle: 'SID history forest escalation • coercion • Azure hybrid • noPAC' },
      { title: 'Persistence', subtitle: 'AdminSDHolder backdoor • DCSync rights • DACL persistence • schema abuse' },
      { title: 'Advanced Recon', subtitle: 'BloodHound Cypher • DPAPI chain • GMSA • pre-foothold spray' },
    ]
  },
  {
    header: 'DEVOPS',
    color: 'blue',
    nodes: [
      { title: 'Docker & K8s', subtitle: 'Container escape • RBAC • service accounts' },
      { title: 'CI/CD Pipelines', subtitle: 'Jenkins • GitHub Actions • GitLab CI' },
      { title: 'Config Management', subtitle: 'Ansible • Terraform • vault decrypt' },
      { title: 'Secrets Management', subtitle: 'HashiCorp Vault • AWS SSM • IMDS' },
    ]
  },
  {
    header: 'AI / ML',
    color: 'purple',
    nodes: [
      { title: 'Prompt Injection', subtitle: 'Direct • indirect • jailbreak • system leak' },
      { title: 'LLM Output Attacks', subtitle: 'Markdown inject • exfil • downstream' },
      { title: 'AI Data Attacks', subtitle: 'Training poison • backdoor • RAG poison' },
      { title: 'App & System', subtitle: 'Plugin abuse • agent hijack • supply chain' },
      { title: 'AI Evasion', subtitle: 'FGSM • PGD • one-pixel • patch attacks' },
      { title: 'AI Privacy', subtitle: 'Membership inference • model inversion • extraction' },
    ]
  },
];





export default function Home() {
  return (
    <div>
      {/* Title */}
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-red-500">Red Team</span>
          <span className="text-slate-200"> Operations</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">
          Full Red Team Operations Reference — Methodology, Tooling &amp; Techniques
        </p>
      </div>

      {/* Description */}
      <div className="max-w-3xl mx-auto text-center mb-10">
        <p className="text-slate-400 text-sm leading-relaxed">
          A personal red team operations reference covering the full adversary lifecycle — from initial reconnaissance and compromise through to domain dominance and EDR evasion. Built as a cheatsheet for offensive security engagements, certification prep, and tool research.
        </p>
      </div>


      {/* Combined Map */}
      <ArchitectureMap columns={allColumns} />


    </div>
  );
}