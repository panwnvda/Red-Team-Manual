import { Toaster } from "@/components/ui/toaster"
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClientInstance } from '@/lib/query-client'
// pages.config removed — using explicit routes instead
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import PageNotFound from './lib/PageNotFound';
import { AuthProvider, useAuth } from '@/components/AuthContext';
import UserNotRegisteredError from '@/components/UserNotRegisteredError';

// CRTO pages
import C2OPSEC from './pages/C2OPSEC';
import Reconnaissance from './pages/Reconnaissance';
import InitialCompromise from './pages/InitialCompromise';
import WiFi from './pages/WiFi';
import HostOperations from './pages/HostOperations';
import PrivilegeEscalation from './pages/PrivilegeEscalation';
import CredentialAccess from './pages/CredentialAccess';
import LateralMovement from './pages/LateralMovement';
import ADAttacks from './pages/ADAttacks';
import DomainDominance from './pages/DomainDominance';
import Evasion from './pages/EvasionCRTO';
import MobileApplications from './pages/MobileApplications';
import WebApplications from './pages/WebApplications';
import Execution from './pages/Execution';
// CRTL pages
// C2Infrastructure merged into C2OPSEC
import WindowsAPIs from './pages/WindowsAPIs';
import ProcessInjection from './pages/ProcessInjection';
import Malware from './pages/Malware';

import ASRAndWDAC from './pages/ASRAndWDAC';
import EDREvasion from './pages/EDREvasion';
import DevOps from './pages/DevOps';
import AIML from './pages/AIML';

import Layout from './pages/Layout.jsx';
import Home from './pages/Home.jsx';

const LayoutWrapper = ({ children, currentPageName }) => 
  <Layout currentPageName={currentPageName}>{children}</Layout>;

const AuthenticatedApp = () => {
  const { isLoadingAuth, isLoadingPublicSettings, authError, navigateToLogin } = useAuth();

  // Show loading spinner while checking app public settings or auth
  if (isLoadingPublicSettings || isLoadingAuth) {
    return (
      <div className="fixed inset-0 flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-slate-200 border-t-slate-800 rounded-full animate-spin"></div>
      </div>
    );
  }

  // Handle authentication errors
  if (authError) {
    if (authError.type === 'user_not_registered') {
      return <UserNotRegisteredError />;
    } else if (authError.type === 'auth_required') {
      // Redirect to login automatically
      navigateToLogin();
      return null;
    }
  }

  // Render the main app
  return (
    <Routes>
      <Route path="/" element={
        <LayoutWrapper currentPageName="Home">
          <Home />
        </LayoutWrapper>
      } />
      <Route path="/Home" element={
        <LayoutWrapper currentPageName="Home">
          <Home />
        </LayoutWrapper>
      } />
      {/* CRTO pages */}
      <Route path="/C2OPSEC" element={<LayoutWrapper currentPageName="C2OPSEC"><C2OPSEC /></LayoutWrapper>} />
      <Route path="/Reconnaissance" element={<LayoutWrapper currentPageName="Reconnaissance"><Reconnaissance /></LayoutWrapper>} />
      <Route path="/InitialCompromise" element={<LayoutWrapper currentPageName="InitialCompromise"><InitialCompromise /></LayoutWrapper>} />
      <Route path="/WiFi" element={<LayoutWrapper currentPageName="WiFi"><WiFi /></LayoutWrapper>} />
      <Route path="/HostOperations" element={<LayoutWrapper currentPageName="HostOperations"><HostOperations /></LayoutWrapper>} />
      <Route path="/PrivilegeEscalation" element={<LayoutWrapper currentPageName="PrivilegeEscalation"><PrivilegeEscalation /></LayoutWrapper>} />
      <Route path="/CredentialAccess" element={<LayoutWrapper currentPageName="CredentialAccess"><CredentialAccess /></LayoutWrapper>} />
      <Route path="/LateralMovement" element={<LayoutWrapper currentPageName="LateralMovement"><LateralMovement /></LayoutWrapper>} />
      <Route path="/ADAttacks" element={<LayoutWrapper currentPageName="ADAttacks"><ADAttacks /></LayoutWrapper>} />
      <Route path="/DomainDominance" element={<LayoutWrapper currentPageName="DomainDominance"><DomainDominance /></LayoutWrapper>} />
      <Route path="/EvasionCRTO" element={<LayoutWrapper currentPageName="EvasionCRTO"><Evasion /></LayoutWrapper>} />
      <Route path="/MobileApplications" element={<LayoutWrapper currentPageName="MobileApplications"><MobileApplications /></LayoutWrapper>} />
      <Route path="/WebApplications" element={<LayoutWrapper currentPageName="WebApplications"><WebApplications /></LayoutWrapper>} />
      <Route path="/Execution" element={<LayoutWrapper currentPageName="Execution"><Execution /></LayoutWrapper>} />
      {/* C2Infrastructure removed — content merged into C2OPSEC */}
      <Route path="/WindowsAPIs" element={<LayoutWrapper currentPageName="WindowsAPIs"><WindowsAPIs /></LayoutWrapper>} />
      <Route path="/ProcessInjection" element={<LayoutWrapper currentPageName="ProcessInjection"><ProcessInjection /></LayoutWrapper>} />
      <Route path="/Malware" element={<LayoutWrapper currentPageName="Malware"><Malware /></LayoutWrapper>} />

      <Route path="/ASRAndWDAC" element={<LayoutWrapper currentPageName="ASRAndWDAC"><ASRAndWDAC /></LayoutWrapper>} />
      <Route path="/EDREvasion" element={<LayoutWrapper currentPageName="EDREvasion"><EDREvasion /></LayoutWrapper>} />
      <Route path="/DevOps" element={<LayoutWrapper currentPageName="DevOps"><DevOps /></LayoutWrapper>} />
      <Route path="/AIML" element={<LayoutWrapper currentPageName="AIML"><AIML /></LayoutWrapper>} />
      <Route path="*" element={<PageNotFound />} />
    </Routes>
  );
};


function App() {

  return (
    <AuthProvider>
      <QueryClientProvider client={queryClientInstance}>
        <Router>
          <AuthenticatedApp />
        </Router>
        <Toaster />
      </QueryClientProvider>
    </AuthProvider>
  )
}

export default App