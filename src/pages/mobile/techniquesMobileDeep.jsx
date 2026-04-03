export const mobileDeepTechniques = [
  {
    id: 'mob-deep-intent-redirection',
    title: 'Intent Redirection & Task Affinity Hijacking',
    subtitle: 'Exploit Android intent routing to steal authentication results, hijack activity stacks, and intercept OAuth callbacks',
    tags: ['intent redirect', 'task affinity', 'startActivityForResult', 'OAuth callback hijack', 'activity hijack', 'android:exported', 'FLAG_ACTIVITY_NEW_TASK'],
    accentColor: 'purple',
    overview: 'Android\'s intent routing system allows any app to register for specific intents. Task affinity hijacking exploits the fact that activities with the same taskAffinity can be inserted into another app\'s back stack. When a victim app launches an activity via startActivityForResult expecting a trusted result, a malicious app with matching intent filters intercepts the call, captures the result data (OAuth codes, file URIs, auth tokens), and returns a crafted response. This breaks OAuth PKCE flows, custom URI scheme handlers, and file pickers.',
    steps: [
      'Enumerate exported activities and intent filters via AndroidManifest.xml parsing or jadx',
      'Identify activities using startActivityForResult for sensitive operations: auth flows, file pickers, custom URI handlers',
      'Create a malicious app with identical intent filters to intercept the intent',
      'Exploit task affinity: set android:taskAffinity to match the victim app to inject into their task stack',
      'Return crafted onActivityResult data: fake OAuth code, poisoned file URI, or null result to bypass auth',
      'Use adb to simulate intent delivery: adb shell am start -n com.victim/.AuthActivity -a android.intent.action.VIEW -d "malicious-redirect"',
    ],
    commands: [
      {
        title: 'Intent redirection and OAuth callback interception',
        code: `# Enumerate exposed activities and intent filters
apktool d target.apk -o decompiled/
grep -r "intent-filter" decompiled/AndroidManifest.xml
grep -r "android:exported=\"true\"" decompiled/AndroidManifest.xml

# jadx: search for startActivityForResult usage
jadx-gui target.apk
# Search for: startActivityForResult, registerForActivityResult, Intent.ACTION_VIEW

# Test intent redirection via ADB
# If the app has a custom URI scheme handler (e.g., myapp://oauth/callback)
adb shell am start -a android.intent.action.VIEW \\
  -d "myapp://oauth/callback?code=STOLEN_CODE&state=VALID_STATE" \\
  -n com.target.app/.OAuthCallbackActivity

# Frida: intercept onActivityResult to see what data is returned
Java.perform(function() {
  var Activity = Java.use("android.app.Activity");
  Activity.onActivityResult.implementation = function(requestCode, resultCode, data) {
    console.log("[onActivityResult] requestCode: " + requestCode + " resultCode: " + resultCode);
    if (data != null) {
      console.log("[onActivityResult] data: " + data.toUri(0));
      var extras = data.getExtras();
      if (extras != null) {
        var keys = extras.keySet().toArray();
        for (var i = 0; i < keys.length; i++) {
          console.log("  [extra] " + keys[i] + " = " + extras.get(keys[i]));
        }
      }
    }
    return this.onActivityResult(requestCode, resultCode, data);
  };
});

# Monitor all intents received by target app
adb shell am monitor --user 0
# Then trigger the OAuth flow in target app — observe interceptable intents

# Task affinity hijacking — malicious app manifest snippet
# <activity android:name=".MaliciousActivity" 
#   android:taskAffinity="com.target.app"  ← matches victim task
#   android:allowTaskReparenting="true">
#   <intent-filter>
#     <action android:name="android.intent.action.VIEW"/>
#     <data android:scheme="myapp" android:host="oauth"/>
#   </intent-filter>`
      }
    ]
  },

  {
    id: 'mob-deep-frida-stalker',
    title: 'Frida Stalker — Code Coverage & Hidden Code Discovery',
    subtitle: 'Use Frida Stalker to trace every instruction executed, discover dynamically loaded code, and find obfuscated decryption routines',
    tags: ['Frida Stalker', 'code coverage', 'dynamic code', 'instruction trace', 'DEX loading', 'native trace', 'obfuscation reverse'],
    accentColor: 'purple',
    overview: 'Frida Stalker is a code tracing engine that follows execution at the instruction level, providing complete coverage maps of what code paths execute during specific actions. Unlike function hooking (which requires knowing function names), Stalker captures ALL executed code including dynamically loaded DEX files, JIT-compiled code, and native routines decrypted at runtime. This is critical for reversing heavily obfuscated apps that decrypt their real logic at runtime and never expose it to static analysis.',
    steps: [
      'Identify the target operation to trace: login button press, payment flow, certificate pinning check',
      'Use Stalker.follow() to begin tracing the target thread during the operation',
      'Capture basic block coverage: map every code address executed',
      'Cross-reference with loaded modules to identify what native libraries ran',
      'Look for code executing in anonymous memory regions (no module name) — dynamic code loading',
      'Use Stalker.exclude() to filter out known framework code (Android runtime, libc) and focus on app code',
      'Transform callbacks allow modifying instructions in real-time: patch JNZ to JMP to bypass checks',
    ],
    commands: [
      {
        title: 'Frida Stalker complete code coverage script',
        code: `// frida_stalker_coverage.js — trace all executed code with module mapping
'use strict';

const coverage = new Map(); // address → count
const dynamicRegions = []; // anonymous memory execution

// Get list of loaded modules at start
const modules = new ModuleMap();

function traceThread(threadId) {
  Stalker.follow(threadId, {
    events: {
      call: true,   // track CALL instructions
      ret: false,
      exec: false,  // set true for full instruction trace (very verbose)
      block: true,  // track basic block entry (good balance)
    },
    
    onReceive: function(events) {
      const reader = Stalker.parse(events, { stringify: false });
      for (const event of reader) {
        if (event[0] === 'block') {
          const addr = event[1]; // start address of basic block
          coverage.set(addr, (coverage.get(addr) || 0) + 1);
          
          // Check if address is in any loaded module
          const module = modules.find(addr);
          if (!module) {
            // Executing from anonymous/dynamic memory
            dynamicRegions.push({ addr: addr.toString(), time: Date.now() });
            console.log('[DYNAMIC CODE] Executing at: 0x' + addr.toString(16));
            // Dump the code around this address
            try {
              console.log(hexdump(ptr(addr), { length: 64 }));
            } catch(e) {}
          }
        }
      }
    },
    
    // Transform: can modify instructions in real-time
    transform: function(iterator) {
      let instruction = iterator.next();
      do {
        // Example: patch all CMP instructions in app code to see comparison values
        if (instruction.mnemonic === 'cmp') {
          const addr = instruction.address;
          const module = modules.find(addr);
          if (module && module.name.includes('com.target')) {
            // Log the comparison values (requires register access, complex)
            console.log('[CMP] at ' + addr.toString() + ': ' + instruction.toString());
          }
        }
        iterator.keep();
      } while ((instruction = iterator.next()) !== null);
    }
  });
}

// Hook Java to trace during specific operation
Java.perform(function() {
  const LoginActivity = Java.use('com.target.app.LoginActivity');
  LoginActivity.performLogin.implementation = function(user, pass) {
    console.log('[*] Login triggered, starting Stalker trace...');
    
    // Trace current thread
    const threadId = Process.getCurrentThreadId();
    traceThread(threadId);
    
    const result = this.performLogin(user, pass);
    
    // Stop tracing after login completes
    setTimeout(function() {
      Stalker.unfollow(threadId);
      Stalker.flush();
      
      // Report: top 20 most-executed addresses
      const sorted = [...coverage.entries()].sort((a,b) => b[1] - a[1]).slice(0, 20);
      console.log('\\n[*] Top executed addresses:');
      for (const [addr, count] of sorted) {
        const mod = modules.find(ptr(addr));
        const name = mod ? mod.name + '+0x' + (addr - mod.base.toInt32()).toString(16) : 'ANONYMOUS';
        console.log('  0x' + addr.toString(16) + ' (' + count + 'x): ' + name);
      }
      
      if (dynamicRegions.length > 0) {
        console.log('\\n[!] Dynamic code execution detected in ' + dynamicRegions.length + ' regions');
      }
    }, 3000);
    
    return result;
  };
});`
      }
    ]
  },

  {
    id: 'mob-deep-ios-class-dump',
    title: 'iOS Runtime Class Dumping & Private API Exploitation',
    subtitle: 'Extract Objective-C class hierarchies, private methods, and undocumented APIs from iOS app binaries at runtime',
    tags: ['iOS class dump', 'Objective-C runtime', 'private API', 'class-dump', 'ivar injection', 'method swizzling', 'iOS runtime'],
    accentColor: 'purple',
    overview: 'iOS apps compiled from Objective-C retain full class and method metadata in the binary. The Objective-C runtime allows complete introspection at runtime: listing all classes, methods, protocols, instance variables, and properties. Frida provides full access to this metadata without requiring a jailbreak (via gadget injection). Private APIs — Apple frameworks not exposed in the public SDK — can be discovered and called directly, bypassing App Store restrictions and accessing low-level system functionality.',
    steps: [
      'Dump all Objective-C classes from a running app using Frida ObjC.enumerateLoadedClasses()',
      'Identify classes related to authentication, networking, and crypto by name patterns',
      'Enumerate all methods on a class including private ones not in public headers',
      'Hook method implementations to intercept arguments and return values',
      'Access private instance variables (ivars) via object_getInstanceVariable or Frida\'s .field()',
      'Call private methods directly: objc_msgSend(target, sel_registerName("privateMethod:"), args)',
    ],
    commands: [
      {
        title: 'iOS class hierarchy dumping and private method access',
        code: `// iOS class and method enumeration via Frida
'use strict';

// Enumerate ALL loaded Objective-C classes
ObjC.enumerateLoadedClasses({
  onMatch: function(name, handle) {
    // Filter for app classes (exclude system frameworks)
    if (!name.startsWith('NS') && !name.startsWith('UI') && !name.startsWith('_')) {
      try {
        const cls = ObjC.classes[name];
        const methods = cls.$ownMethods;
        if (methods.length > 0) {
          console.log('\\n[Class] ' + name);
          methods.forEach(function(m) { console.log('  ' + m); });
        }
      } catch(e) {}
    }
  },
  onComplete: function() { console.log('[*] Enumeration complete'); }
});

// Deep introspect a specific class
function inspectClass(className) {
  const cls = ObjC.classes[className];
  console.log('\\n=== ' + className + ' ===');
  
  // Own methods (not inherited)
  cls.$ownMethods.forEach(m => console.log('[method] ' + m));
  
  // Instance variables
  cls.$ivars.forEach(ivar => console.log('[ivar] ' + ivar));
  
  // Properties
  const props = cls.$protocols;
  Object.keys(props).forEach(p => console.log('[protocol] ' + p));
}

// Find and hook authentication-related classes
ObjC.enumerateLoadedClasses({
  onMatch: function(name) {
    if (name.toLowerCase().match(/auth|login|token|credential|session|passw|biometric/)) {
      console.log('[AUTH CLASS] ' + name);
      try {
        const cls = ObjC.classes[name];
        cls.$ownMethods.forEach(function(method) {
          if (method.startsWith('-')) {
            Interceptor.attach(cls[method].implementation, {
              onEnter: function(args) {
                const self = new ObjC.Object(args[0]);
                const sel = ObjC.selectorAsString(args[1]);
                console.log('[' + name + ' ' + sel + '] called');
                // Print remaining args
                for (let i = 2; i < 6; i++) {
                  try {
                    const arg = new ObjC.Object(args[i]);
                    console.log('  arg' + i + ': ' + arg.toString());
                  } catch(e) {}
                }
              },
              onLeave: function(retval) {
                try {
                  const ret = new ObjC.Object(retval);
                  console.log('  → ' + ret.toString());
                } catch(e) {}
              }
            });
          }
        });
      } catch(e) {}
    }
  },
  onComplete: function() {}
});

// Access private ivar directly
const session = ObjC.classes.NetworkSession.$new();
console.log('[ivar] authToken = ' + session.$ivars['_authToken'].value);
console.log('[ivar] sessionKey = ' + session.$ivars['_sessionKey'].value);

// Call private method
ObjC.classes.CryptoManager['- decryptData:withKey:'].call(
  ObjC.classes.CryptoManager.$new(),
  encryptedData, secretKey
);`
      }
    ]
  },

  {
    id: 'mob-deep-android-binder-audit',
    title: 'Android Binder Transaction Fuzzing & AIDL Interface Audit',
    subtitle: 'Fuzz Binder IPC transactions to discover permission bypass, type confusion, and UAF in system service interfaces',
    tags: ['Binder', 'AIDL', 'Binder transaction', 'IPC fuzzing', 'system service', 'parcel', 'type confusion', 'service manager'],
    accentColor: 'purple',
    overview: 'Android Binder is the kernel-level IPC mechanism connecting apps to system services. Every Android API call (camera, location, telephony, etc.) eventually becomes a Binder transaction. Each system service exposes an AIDL interface — the interface definition defines exactly which transaction codes correspond to which methods. Improperly validated transaction codes, malformed Parcel data, or missing permission checks in system services can lead to privilege escalation. Binder fuzzing has historically found critical Android vulnerabilities.',
    steps: [
      'Enumerate system services: service list command or ServiceManager.listServices()',
      'Obtain the IBinder interface to a target service: ServiceManager.getService("target_service")',
      'Analyze the AIDL interface: use adb shell dumpsys, AOSP source, or decompile service APK for transaction codes',
      'Send raw Parcel data with different transaction codes to discover undocumented interfaces',
      'Fuzz Parcel field types and lengths: type confusion in readException() or writeInterfaceToken()',
      'Monitor for SecurityException (missing permission check) vs acceptable error — SecurityException means auth checked, silent failure may mean bypass',
    ],
    commands: [
      {
        title: 'Android Binder fuzzing via Frida',
        code: `// Binder transaction interceptor and fuzzer
'use strict';

Java.perform(function() {
  // Hook BinderProxy.transact to see all Binder calls from this process
  const BinderProxy = Java.use('android.os.BinderProxy');
  BinderProxy.transact.implementation = function(code, data, reply, flags) {
    console.log('[Binder.transact] code=' + code + ' flags=' + flags);
    
    // Log the data parcel
    if (data != null) {
      console.log('  dataPosition=' + data.dataPosition());
      console.log('  dataSize=' + data.dataSize());
    }
    
    return this.transact(code, data, reply, flags);
  };
  
  // Find a specific service and fuzz its transaction codes
  const ServiceManager = Java.use('android.os.ServiceManager');
  const IBinder = Java.use('android.os.IBinder');
  const Parcel = Java.use('android.os.Parcel');
  
  function fuzzService(serviceName, maxCode) {
    console.log('[*] Fuzzing service: ' + serviceName);
    const binder = ServiceManager.getService(serviceName);
    if (binder == null) {
      console.log('[-] Service not found');
      return;
    }
    
    for (let code = 1; code <= maxCode; code++) {
      const data = Parcel.obtain();
      const reply = Parcel.obtain();
      
      try {
        // Write interface descriptor (required for most services)
        data.writeInterfaceToken("android.app.IActivityManager"); // Replace with target
        
        // Try with empty data first
        const result = binder.transact(code, data, reply, 0);
        
        if (result) {
          console.log('[+] code=' + code + ' succeeded!');
          // Read exception code
          try {
            reply.readException();
            console.log('    No exception returned');
          } catch(e) {
            console.log('    Exception: ' + e.message);
          }
        }
      } catch(e) {
        if (!e.message.includes('SecurityException')) {
          // Not a permission denial — interesting!
          console.log('[!] code=' + code + ' non-security error: ' + e.message);
        }
      } finally {
        data.recycle();
        reply.recycle();
      }
    }
  }
  
  // Fuzz common system services
  // fuzzService('activity', 200);
  // fuzzService('package', 200);
  // fuzzService('telephony.registry', 100);
  
  // Enumerate all services
  const serviceList = ServiceManager.listServices();
  for (let i = 0; i < serviceList.length; i++) {
    console.log('[service] ' + serviceList[i]);
  }
});

# ADB: enumerate and dump system service info
adb shell service list
adb shell dumpsys activity services
adb shell dumpsys package
adb shell dumpsys window`
      }
    ]
  },

  {
    id: 'mob-deep-ios-jailbreak-toolchain',
    title: 'iOS Kernel Exploitation Fundamentals — PAC, PPL & kASLR Bypass',
    subtitle: 'Understand iOS kernel security mechanisms: Pointer Authentication Codes, Page Protection Layer, and kASLR defeat strategies',
    tags: ['iOS kernel', 'PAC bypass', 'PPL', 'kASLR', 'tfp0', 'kernel exploit', 'iOS jailbreak', 'pointer authentication'],
    accentColor: 'purple',
    overview: 'Modern iOS security architecture relies on multiple hardware and software mitigations. Pointer Authentication Codes (PAC) sign pointers using secret keys in ARMv8.3 hardware — forging a pointer requires either knowing the key or bypassing authentication. The Page Protection Layer (PPL) runs at a higher privilege level than the kernel and controls page table modifications. kASLR randomizes kernel base address. Successful iOS kernel exploitation requires bypassing all three: typically via type confusion in a privileged kernel extension, PAC oracle to forge authenticated pointers, and PPL bypass via hardware feature abuse.',
    steps: [
      'kASLR defeat: kernel addresses leak via certain sysctl calls, IOKit user clients returning kernel pointers, or timing side-channels',
      'PAC oracle: find a code path that signs an attacker-controlled value — use as an oracle to forge authenticated pointers',
      'tfp0 (task-for-pid 0): obtaining a Mach send right to the kernel task port is the traditional goal — grants read/write to kernel memory',
      'PPL bypass: write to PPL-protected memory requires either finding a PPL escape or using hardware DMA techniques',
      'Common starting points: IOKit driver type confusion, kernel UAF in networking stack, format string bugs in kernel logging',
    ],
    commands: [
      {
        title: 'iOS security research environment setup and tooling',
        code: `# === iOS Security Research Toolkit ===

# Checkra1n / Palera1n (hardware-based jailbreak for testing devices)
# Use dedicated research devices — never production devices

# Once jailbroken: install research tools
# SSH to device (default root:alpine)
ssh root@DEVICE_IP

# Install core research packages via Sileo/Cydia
# - debugserver (Apple developer tools)
# - LLDB (for on-device debugging)
# - frida-server (latest version for iOS)
# - class-dump (Objective-C metadata extraction)
# - Clutch / bfdecrypt (binary decryption)

# Decrypt App Store binary (removes FairPlay DRM)
bfdecrypt -targetBundleId com.target.app

# class-dump: extract Objective-C headers from decrypted binary
class-dump -H /var/mobile/Containers/Bundle/Application/*/TargetApp.app/TargetApp -o headers/

# Understand memory layout
# kASLR slide from kernel panic reports or:
python3 -c "
import subprocess
result = subprocess.check_output(['sysctl', 'hw.targettype'])
print(result)
"

# Kernel pointer leakage via task_info (older iOS versions)
# mach_vm_region_recurse leaks kernel addresses in some configurations

# Frida on iOS (requires jailbreak or gadget injection)
# On device:
frida-server &
# On host:
frida -U --no-pause -f com.target.app -l hook_ios.js

# iOS kernel debugging with LLDB (requires developer certificate + SIP disabled)
# Attach to SpringBoard
debugserver *:1234 -a SpringBoard
lldb -o "platform select remote-ios" -o "process connect connect://DEVICE_IP:1234"

# Monitor Mach port rights
# Enumerate task's Mach port namespace
# Useful for finding tfp0 paths via port name guessing

# Heap spray detection
# Monitor allocations in kalloc.* zones via dtrace (macOS) or Instruments`
      }
    ]
  },
];