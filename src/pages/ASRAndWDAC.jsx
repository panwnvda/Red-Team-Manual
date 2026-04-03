import React from 'react';
import ArchitectureMap from '../components/ArchitectureMap';
import TechniqueCard from '../components/TechniqueCard';
import { asrTechniques } from './asr/techniquesASR';

const mapColumns = [
  {
    header: 'ASR',
    color: 'yellow',
    nodes: [
      { title: 'ASR Rules', subtitle: 'Enumerate GUIDs • mode mapping • SYSTEM exemption', id: 'asr-rules' },
      { title: 'ASR Exclusion Abuse', subtitle: 'Path & process exclusions • inject into excluded', id: 'asr-exclusions' },
      { title: 'GadgetToJScript', subtitle: 'COM gadget • JScript .NET load • Office ASR bypass', id: 'gadget-jscript' },
    ]
  },
  {
    header: 'WDAC',
    color: 'orange',
    nodes: [
      { title: 'WDAC Enumeration & Bypass', subtitle: 'p7b → XML • FileRules • LOLBAS • wildcard paths', id: 'wdac' },
      { title: 'Trusted Signers & Filename', subtitle: 'OriginalFilename spoof • cert chain • DLL sideload', id: 'trusted-signers' },
    ]
  },
];

export default function ASRAndWDAC() {
  const scrollTo = (id) => { const el = document.getElementById(id); if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' }); };
  return (
    <div className="space-y-12">
      <div className="text-center mb-10">
        <h1 className="text-3xl md:text-5xl font-bold font-mono tracking-tight">
          <span className="text-slate-200">ASR & </span><span className="text-yellow-400">WDAC</span>
        </h1>
        <p className="text-slate-500 font-mono text-sm mt-3">
          ASR Rule Enum • Exclusion Abuse • GadgetToJScript • WDAC Policy Parse • Filename Spoof • Trusted Signer
        </p>
      </div>
      <ArchitectureMap columns={mapColumns} onNodeClick={scrollTo} />
      <div className="border-t border-slate-800/50 pt-10 grid grid-cols-1 gap-4">
        {asrTechniques.map((t) => (
          <div key={t.id} id={t.id}>
            <TechniqueCard title={t.title} subtitle={t.subtitle} tags={t.tags} accentColor={t.accentColor} overview={t.overview} steps={t.steps} commands={t.commands} />
          </div>
        ))}
      </div>
    </div>
  );
}