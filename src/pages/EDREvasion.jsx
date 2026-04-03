import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';
import { hookTechniques } from './edr/techniquesHook';
import { implantTechniques } from './edr/techniquesImplant';
import { kernelTechniques } from './edr/techniquesKernel';
import { vendorTechniques } from './edr/techniquesVendor';

const mapColumns = [
  {
    header: 'HOOK & SYSCALL',
    color: 'cyan',
    nodes: [
      { title: 'Hook Detection & Bypass', subtitle: 'Export walk • JMP scan • strategy selection', id: 'hook-bypass' },
      { title: 'Direct & Indirect Syscalls', subtitle: 'SSN • SysWhispers3 • HellsGate • TartarusGate', id: 'syscalls' },
    ]
  },
  {
    header: 'IMPLANT EVASION',
    color: 'blue',
    nodes: [
      { title: 'Sleep Mask', subtitle: 'Ekko • Cronos • RC4 encrypt • RW during sleep', id: 'sleep-mask' },
      { title: 'Thread Stack Spoofing', subtitle: 'HWBP VEH • synthetic frames • JMP gadgets', id: 'stack-spoof' },
      { title: 'UDRL', subtitle: 'Custom reflective loader • PEB walk • module stomp', id: 'udrl' },
    ]
  },
  {
    header: 'KERNEL LEVEL',
    color: 'red',
    nodes: [
      { title: 'Kernel Callbacks (BYOVD)', subtitle: 'KDU • PsNotify removal • Backstab • EDRSilencer', id: 'kernel-callbacks' },
    ]
  },
  {
    header: 'VENDOR SPECIFIC',
    color: 'orange',
    nodes: [
      { title: 'CrowdStrike Falcon', subtitle: 'ETW-Ti • Overwatch • ML bypass • BYOVD chain', id: 'cs-falcon' },
      { title: 'Microsoft Defender MDE', subtitle: 'No userland hooks • domain fronting • SmartScreen', id: 'ms-defender' },
      { title: 'SentinelOne', subtitle: 'Static AI • CPL bypass • ETW patch • kernel callbacks', id: 'sentinelone' },
      { title: 'Palo Alto Cortex XDR', subtitle: 'BTP rules • NtMapViewOfSection • Java • fronting', id: 'cortex-xdr' },
      { title: 'Elastic Security', subtitle: 'EQL rule research • section+APC • expired cert sign', id: 'elastic' },
      { title: 'ESET Endpoint Security', subtitle: 'VAD scan • module stomp • sub-page EPT • LiveGrid', id: 'eset' },
    ]
  },
];

const allTechniques = [
  ...hookTechniques,
  ...implantTechniques,
  ...kernelTechniques,
  ...vendorTechniques,
];

export default function EDREvasion() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">EDR </span><span className="text-cyan-400">Evasion</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">
          Hook Bypass • Syscalls • Sleep Mask • Stack Spoof • UDRL • BYOVD • CrowdStrike • MDE • SentinelOne • Cortex XDR • Elastic • ESET
        </p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {allTechniques.map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}