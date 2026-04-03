import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';
import { mobileReconTechniques } from './mobile/techniquesMobileRecon';
import { mobileAuthTechniques } from './mobile/techniquesMobileAuth';
import { mobileStorageTechniques } from './mobile/techniquesMobileStorage';
import { mobileNetworkTechniques } from './mobile/techniquesMobileNetwork';
import { mobileAdvancedTechniques } from './mobile/techniquesMobileAdvanced';
import { mobileAdvanced2Techniques } from './mobile/techniquesMobileAdvanced2';
import { mobileDeepTechniques } from './mobile/techniquesMobileDeep';

const mapColumns = [
  {
    header: 'RECONNAISSANCE',
    color: 'cyan',
    nodes: [
      { title: 'Passive Recon', subtitle: 'App store • APK/IPA extract • secrets • permissions', id: 'mob-passive-recon' },
      { title: 'Dynamic Setup', subtitle: 'Proxy • Frida • root/jailbreak • interception', id: 'mob-active-enum' },
      { title: 'Advanced Frida Hooking', subtitle: 'Class tracing • constructor hooks • Stalker coverage', id: 'mob-frida-advanced-hooks' },
      { title: 'Runtime Memory Analysis', subtitle: 'Heap scan • JWT extraction • key material • Fridump', id: 'mob-runtime-memory-analysis' },
    ]
  },
  {
    header: 'AUTHENTICATION',
    color: 'blue',
    nodes: [
      { title: 'Auth Bypass', subtitle: 'Biometric hook • token storage • Frida runtime patch', id: 'mob-auth-bypass' },
      { title: 'SSL Pinning Bypass', subtitle: 'Objection • OkHttp hook • APK re-patch • Frida', id: 'mob-ssl-pinning' },
      { title: 'mTLS & CT Bypass', subtitle: 'Custom TrustManager • mTLS cert extract • TrustKit bypass', id: 'mob-network-security-bypass' },
    ]
  },
  {
    header: 'DATA STORAGE',
    color: 'purple',
    nodes: [
      { title: 'Insecure Storage', subtitle: 'SharedPrefs • SQLite • NSUserDefaults • Keychain • logs', id: 'mob-insecure-storage' },
      { title: 'Deep Links & Intents', subtitle: 'Exported activities • URI hijack • OAuth interception', id: 'mob-deep-links' },
      { title: 'IPC & Content Providers', subtitle: 'SQLi via URI • broadcast abuse • path traversal', id: 'mob-ipc-attacks' },
    ]
  },
  {
    header: 'NETWORK & API',
    color: 'orange',
    nodes: [
      { title: 'API Authorization', subtitle: 'IDOR • JWT tampering • device-ID spoof • shadow API', id: 'mob-api-testing' },
      { title: 'WebView Attacks', subtitle: 'JS bridge • file:// access • intent scheme • XSS', id: 'mob-webview' },
      { title: 'Tapjacking & Overlays', subtitle: 'TYPE_APPLICATION_OVERLAY • accessibility intercept • tap hijack', id: 'mob-tapjacking-overlay-attack' },
    ]
  },
  {
    header: 'BINARY & RUNTIME',
    color: 'red',
    nodes: [
      { title: 'Root/Jailbreak Bypass', subtitle: 'SafetyNet • Play Integrity • Magisk • anti-Frida', id: 'mob-root-detection-bypass' },
      { title: 'Binary Reversing', subtitle: 'jadx • Ghidra • ARM disasm • crypto intercept', id: 'mob-binary-analysis' },
    ]
  },
  {
    header: 'DEEP TECHNIQUES',
    color: 'purple',
    nodes: [
      { title: 'Intent Redirection & Task Hijack', subtitle: 'startActivityForResult intercept • OAuth callback steal', id: 'mob-deep-intent-redirection' },
      { title: 'Frida Stalker Coverage', subtitle: 'Full code tracing • dynamic DEX discovery • instruction map', id: 'mob-deep-frida-stalker' },
      { title: 'iOS Runtime Class Dumping', subtitle: 'ObjC runtime • private API • ivar injection • method swizzle', id: 'mob-deep-ios-class-dump' },
      { title: 'Android Binder Fuzzing', subtitle: 'AIDL transaction fuzz • system service audit • privilege escape', id: 'mob-deep-android-binder-audit' },
      { title: 'iOS PAC / PPL / kASLR', subtitle: 'Kernel security • pointer auth • Page Protection Layer', id: 'mob-deep-ios-jailbreak-toolchain' },
    ]
  },
];

const techniques = [
  ...mobileReconTechniques,
  ...mobileAuthTechniques,
  ...mobileStorageTechniques,
  ...mobileNetworkTechniques,
  ...mobileAdvancedTechniques,
  ...mobileAdvanced2Techniques,
  ...mobileDeepTechniques,
];

export default function MobileApplications() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Mobile </span><span className="text-green-400">Applications</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">Recon • Frida Tracing • Runtime Memory • Auth Bypass • mTLS • SSL Pinning • Storage • IPC • API • WebView • Tapjacking • Root Detection • Binary RE</p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {techniques.map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}