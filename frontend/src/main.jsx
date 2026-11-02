import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import './index.css';
import App from './App.jsx';
import { AuthProvider } from './auth/AuthContext';
import AuthGate from './auth/AuthGate';
import { ModalProvider } from './components/ui/ModalProvider.jsx';
import { ThemeProvider } from './components/ui/ThemeProvider.jsx';
createRoot(document.getElementById('root')).render(<StrictMode>
    <ThemeProvider>
      <ModalProvider>
        <AuthProvider><AuthGate><App /></AuthGate></AuthProvider>
      </ModalProvider>
    </ThemeProvider>
  </StrictMode>);
