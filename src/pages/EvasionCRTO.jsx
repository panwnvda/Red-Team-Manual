import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';
import { evasionCRTOTechniques } from './evasion/techniquesEvasionCRTO';

const mapColumns = [
  {
    header: 'PAYLOAD & STAGING',
    color: 'blue',
    nodes: [
      { title: 'Artifact Kit', subtitle: 'Custom stager bypass • CS/Sliver templates', id: 'artifact-kit' },
      { title: 'AMSI Bypasses', subtitle: 'amsiInitFailed • patch • CLR host • HWBP', id: 'amsi' },
      { title: 'AppLocker', subtitle: 'Policy enum • writable paths • LOLBAS • DLL delivery', id: 'applocker' },
    ]
  },
  {
    header: 'C2 PROFILE & TEMPLATES',
    color: 'orange',
    nodes: [
      { title: 'Malleable C2 Evasion', subtitle: 'spawnto • ppid • pipename • obfuscate', id: 'malleable-evasion' },
      { title: 'PowerShell CLM', subtitle: 'Custom runspace • PS v2 • powerpick', id: 'clm' },
      { title: 'Resource Kit', subtitle: 'PS/VBA/HTA template customization • gogarble', id: 'resource-kit' },
    ]
  },
  {
    header: 'POST-EXPLOITATION',
    color: 'pink',
    nodes: [
      { title: 'Memory Indicators', subtitle: 'PE header wipe • BOF cleanup • module stomp', id: 'mem-indicators' },
      { title: 'Memory Permissions', subtitle: 'RW→RX • NtProtectVirtualMemory • syscalls', id: 'mem-perms' },
      { title: 'Fork-and-Run', subtitle: 'Sacrificial process • BOF • powerpick • smartinject', id: 'fork-run' },
      { title: 'PPID Spoofing', subtitle: 'PROC_THREAD_ATTRIBUTE_PARENT_PROCESS • explorer', id: 'ppid' },
      { title: 'ETW Bypass', subtitle: 'EtwEventWrite patch • CLR ETW • HWBP intercept', id: 'etw' },
      { title: 'Tool Signatures', subtitle: 'ThreatCheck bisect • ConfuserEx • string patch', id: 'signatures' },
    ]
  },
  {
    header: 'PROCESS MASKING',
    color: 'purple',
    nodes: [
      { title: 'Command Line Spoofing', subtitle: 'CREATE_SUSPENDED • PEB CommandLine overwrite', id: 'cmdline-spoof' },
      { title: 'SMB Named Pipes', subtitle: 'Custom pipe names • ## wildcard • svcctl pattern', id: 'smb-pipes' },
    ]
  },
];

export default function EvasionCRTO() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">Defense</span>
          <span className="text-orange-400"> Evasion</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">
          Artifact Kit • AMSI • Malleable C2 • AppLocker • CLM • Memory Hygiene • PPID • ETW • Cmd Spoof • Named Pipes
        </p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {evasionCRTOTechniques.map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}