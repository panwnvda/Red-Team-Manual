import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { Menu, X, Shield, ChevronRight } from 'lucide-react';

const navItems = [
  { name: 'Home', page: 'Home', color: 'text-slate-300' },
  { name: 'Infrastructure', page: 'C2OPSEC', color: 'text-cyan-400' },
  { name: 'Reconnaissance', page: 'Reconnaissance', color: 'text-cyan-400' },
  { name: 'Initial Compromise', page: 'InitialCompromise', color: 'text-emerald-400' },
  { name: 'Execution', page: 'Execution', color: 'text-emerald-400' },
  { name: 'Host Operations', page: 'HostOperations', color: 'text-emerald-400' },
  { name: 'Privilege Escalation', page: 'PrivilegeEscalation', color: 'text-red-400' },
  { name: 'Credential Access', page: 'CredentialAccess', color: 'text-red-400' },
  { name: 'Lateral Movement', page: 'LateralMovement', color: 'text-orange-400' },
  { name: 'Domain Dominance', page: 'DomainDominance', color: 'text-yellow-400' },
  { name: 'Defense Evasion', page: 'EvasionCRTO', color: 'text-orange-400' },
  { name: 'EDR Evasion', page: 'EDREvasion', color: 'text-red-400' },
  { name: 'Windows API', page: 'WindowsAPIs', color: 'text-emerald-400' },
  { name: 'ASR & WDAC', page: 'ASRAndWDAC', color: 'text-orange-400' },
  { name: 'Process Injection', page: 'ProcessInjection', color: 'text-red-400' },
  { name: 'Malware', page: 'Malware', color: 'text-red-400' },
  { name: 'Mobile Applications', page: 'MobileApplications', color: 'text-green-400' },
  { name: 'Web Applications', page: 'WebApplications', color: 'text-blue-400' },
  { name: 'Wi-Fi', page: 'WiFi', color: 'text-cyan-400' },
  { name: 'Active Directory', page: 'ADAttacks', color: 'text-cyan-400' },
  { name: 'DevOps', page: 'DevOps', color: 'text-blue-400' },
  { name: 'AI / ML', page: 'AIML', color: 'text-purple-400' },
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
            <Link to="/" className="flex items-center gap-2.5 group mr-8">
              <Shield className="w-5 h-5 text-red-500 group-hover:text-red-400 transition-colors" />
              <span className="font-mono font-bold text-sm text-white hidden sm:block">
                RED TEAM <span className="text-red-500">|</span> MANUAL
              </span>
            </Link>

            {/* Desktop Nav */}
            <div className="hidden md:flex items-center gap-1 overflow-x-auto flex-1 px-4" style={{ scrollbarWidth: 'thin' }}>
              {navItems.map((item) => (
                <Link
                  key={item.page}
                  to={`/${item.page}`}
                  className={`px-3 py-1.5 rounded-md text-xs font-mono font-medium transition-all whitespace-nowrap ${
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
            Red Team Operations Reference
          </p>
        </div>
      </footer>
    </div>
  );
}