import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Menu, X, Shield, ChevronRight } from 'lucide-react';

const crtoItems = [
  { name: 'C2 & OPSEC', page: 'C2OPSEC', color: 'text-cyan-400' },
  { name: 'Recon', page: 'Reconnaissance', color: 'text-cyan-400' },
  { name: 'Initial Compromise', page: 'InitialCompromise', color: 'text-emerald-400' },
  { name: 'Host Ops', page: 'HostOperations', color: 'text-emerald-400' },
  { name: 'Privesc', page: 'PrivilegeEscalation', color: 'text-red-400' },
  { name: 'Cred Access', page: 'CredentialAccess', color: 'text-red-400' },
  { name: 'Lateral Move', page: 'LateralMovement', color: 'text-orange-400' },
  { name: 'Kerberos', page: 'Kerberos', color: 'text-purple-400' },
  { name: 'AD Attacks', page: 'ADAttacks', color: 'text-pink-400' },
  { name: 'Domain Dom.', page: 'DomainDominance', color: 'text-yellow-400' },
  { name: 'Evasion', page: 'EvasionCRTO', color: 'text-orange-400' },
];

const crtlItems = [
  { name: 'C2 Infra', page: 'C2Infrastructure', color: 'text-cyan-400' },
  { name: 'WinAPIs', page: 'WindowsAPIs', color: 'text-emerald-400' },
  { name: 'Proc Injection', page: 'ProcessInjection', color: 'text-red-400' },
  { name: 'Def Evasion', page: 'DefenceEvasion', color: 'text-purple-400' },
  { name: 'ASR & WDAC', page: 'ASRAndWDAC', color: 'text-orange-400' },
  { name: 'EDR Evasion', page: 'EDREvasion', color: 'text-red-400' },
];

const navItems = [
  { name: 'Home', page: 'Home', color: 'text-slate-300' },
  ...crtoItems,
  ...crtlItems,
];

export default function Layout({ children, currentPageName }) {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#0a0e1a]">
      {/* Top Nav */}
      <nav className="sticky top-0 z-50 bg-[#0a0e1a]/90 backdrop-blur-xl border-b border-slate-800/50">
        <div className="max-w-[1440px] mx-auto px-4 md:px-6">
          <div className="flex items-center justify-between h-14">
            {/* Logo */}
            <Link to="/" className="flex items-center gap-2.5 group">
              <Shield className="w-5 h-5 text-red-500 group-hover:text-red-400 transition-colors" />
              <span className="font-mono font-bold text-sm text-slate-200 hidden sm:block">
                RED<span className="text-red-500">OPS</span>
              </span>
            </Link>

            {/* Desktop Nav */}
            <div className="hidden md:flex items-center gap-1">
              {navItems.map((item) => (
                <Link
                  key={item.page}
                  to={`/${item.page}`}
                  className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all ${
                    currentPageName === item.page
                      ? `${item.color} bg-white/5`
                      : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                  }`}
                >
                  {item.name}
                </Link>
              ))}
            </div>

            {/* Mobile Toggle */}
            <button
              onClick={() => setMobileOpen(!mobileOpen)}
              className="md:hidden text-slate-400 hover:text-slate-200 transition-colors"
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Nav */}
        {mobileOpen && (
          <div className="md:hidden border-t border-slate-800/50 bg-[#0a0e1a]/95 backdrop-blur-xl">
            <div className="px-4 py-3 space-y-1">
              {navItems.map((item) => (
                <Link
                  key={item.page}
                  to={`/${item.page}`}
                  onClick={() => setMobileOpen(false)}
                  className={`flex items-center gap-2 px-3 py-2.5 rounded-lg text-sm font-mono transition-all ${
                    currentPageName === item.page
                      ? `${item.color} bg-white/5`
                      : 'text-slate-500 hover:text-slate-300 hover:bg-white/5'
                  }`}
                >
                  <ChevronRight className="w-3 h-3" />
                  {item.name}
                </Link>
              ))}
            </div>
          </div>
        )}
      </nav>

      {/* Content */}
      <main className="max-w-[1440px] mx-auto px-4 md:px-6 py-8 md:py-12">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/50 py-6">
        <div className="max-w-[1440px] mx-auto px-4 md:px-6">
          <p className="text-center text-slate-600 font-mono text-xs">
            Wencheng Xue — Red Team Operations Reference
          </p>
        </div>
      </footer>
    </div>
  );
}