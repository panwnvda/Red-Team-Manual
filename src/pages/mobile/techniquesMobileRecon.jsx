export const mobileReconTechniques = [
  {
    id: 'mob-passive-recon',
    title: 'Mobile Passive Reconnaissance',
    subtitle: 'OSINT, app store analysis, and metadata harvesting before touching the target app',
    tags: ['OSINT', 'app store', 'APK metadata', 'IPA', 'permissions', 'certificate pinning', 'Google Dorks'],
    accentColor: 'cyan',
    overview: 'Gather intelligence on the target mobile application without installing or running it. Analyse the app store listing, extract the binary, and enumerate permissions, endpoints, and secrets baked into the package.',
    steps: [
      'Download APK/IPA from the store or use third-party mirrors (APKPure, APKMirror)',
      'Check app store listing for version history, change logs, developer email, and linked domains',
      'Extract APK: unzip app.apk → classes.dex, AndroidManifest.xml, assets/, lib/',
      'Decode manifest: apktool d app.apk → readable AndroidManifest.xml with permissions and exported components',
      'Search for hardcoded secrets: grep recursively for api_key, secret, password, access_token in decompiled source',
      'Extract strings from binary: strings app.apk | grep -iE "http|api|key|token|secret|password"',
      'Check linked domains in Traffic: decode network_security_config.xml for pinned certificates and cleartext domains',
    ],
    commands: [
      {
        title: 'APK static analysis — extract and enumerate',
        code: `# Download APK via ADB (from device)
adb shell pm list packages | grep target
adb shell pm path com.target.app
adb pull /data/app/com.target.app-1/base.apk ./app.apk

# Decode with apktool
apktool d app.apk -o app_decoded/
cat app_decoded/AndroidManifest.xml | grep -iE "permission|exported|intent|provider|receiver"

# Extract strings / secrets
grep -r "api_key\|secret\|password\|token\|access" app_decoded/ --include="*.xml" --include="*.smali"

# Decompile DEX → Java with jadx
jadx -d output/ app.apk
grep -r "http\|api\|BuildConfig\|SECRET\|TOKEN" output/ | grep -v ".class"

# MobSF automated static analysis
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
# Upload APK at http://localhost:8000 → get full static report

# iOS IPA — extract and analyse
unzip app.ipa -d app_extracted/
strings app_extracted/Payload/App.app/App | grep -iE "http|api|key|secret"
otool -L app_extracted/Payload/App.app/App  # Linked libraries`
      }
    ]
  },
  {
    id: 'mob-active-enum',
    title: 'Dynamic App Enumeration & Instrumentation Setup',
    subtitle: 'Configure a mobile testing environment with proxy, root/jailbreak, and Frida',
    tags: ['Burp Suite', 'HTTP proxy', 'ADB', 'Frida', 'rooted device', 'jailbreak', 'SSL kill switch'],
    accentColor: 'cyan',
    overview: 'Active testing requires routing all app traffic through a proxy, installing Frida for dynamic instrumentation, and optionally bypassing SSL pinning and root/jailbreak detection. Set this up before any dynamic testing.',
    steps: [
      'Install Burp Suite CA certificate on device: export DER, push via ADB, install as user/system cert',
      'Configure Android proxy: Settings → Wi-Fi → Proxy → Manual → Burp IP:8080',
      'For apps targeting API 24+: Frida or Objection needed to patch network_security_config at runtime',
      'Root Android device with Magisk; jailbreak iOS with Dopamine/palera1n',
      'Install Frida server on device: push frida-server, chmod 755, run as root',
      'Install Objection: pip install objection — wraps Frida for rapid mobile pentesting',
      'Verify interception: launch app, confirm traffic appears in Burp Proxy → HTTP history',
    ],
    commands: [
      {
        title: 'Android proxy and Frida setup',
        code: `# Push Burp CA to Android (API < 24 — user cert sufficient)
adb push burp_ca.der /sdcard/burp_ca.der
# Settings → Security → Install from storage → select burp_ca.der

# For API 24+ (system cert required or use Frida)
# Magisk: install MagiskTrustUserCerts module → system cert auto-trust

# Frida setup (Android)
adb push frida-server /data/local/tmp/
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c "/data/local/tmp/frida-server &"

# Verify Frida
frida-ps -U  # List processes on USB device

# Objection — attach and explore
objection -g com.target.app explore

# List activities, services, broadcast receivers
android hooking list activities
android hooking list services

# iOS — SSL Kill Switch 2 (Cydia tweak)
# Or: Objection on jailbroken device
objection -g com.target.app explore
ios sslpinning disable`
      }
    ]
  },
];