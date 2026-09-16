import { useEffect, useState } from "react";
import { NavLink, Routes, Route, Navigate } from "react-router-dom";
import {
  LayoutDashboard,
  UploadCloud,
  FileSearch,
  ShieldAlert,
  FileText,
  LogOut,
  Shield,
  Moon,
  Sun,
} from "lucide-react";

import Dashboard from "./pages/Dashboard";
import Upload from "./pages/Upload";
import Analysis from "./pages/Analysis";
import History from "./pages/History";
import Alerts from "./pages/Alerts";
import Reports from "./pages/Reports";
import SignIn from "./pages/SignIn";
import SignUp from "./pages/SignUp";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import { getCurrentUser, logout } from "./services/api";

import "./App.css";

const THEME_KEY = "threatlens_theme";

function ThemeToggle() {
  const [theme, setTheme] = useState(
    () => localStorage.getItem(THEME_KEY) || "dark"
  );

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem(THEME_KEY, theme);
  }, [theme]);

  const nextTheme = theme === "dark" ? "light" : "dark";

  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={() => setTheme(nextTheme)}
      aria-label={`Switch to ${nextTheme} theme`}
      title={`Switch to ${nextTheme} theme`}
    >
      {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
      <span>{theme === "dark" ? "Light mode" : "Dark mode"}</span>
    </button>
  );
}

function Layout({ user, onLogout }) {
  const navigation = [
    {
      name: "Dashboard",
      path: "/dashboard",
      icon: LayoutDashboard,
    },
    {
      name: "Analyze File",
      path: "/upload",
      icon: UploadCloud,
    },
    {
      name: "Analysis",
      path: "/analysis",
      icon: FileSearch,
    },
    {
      name: "Detection History",
      path: "/history",
      icon: FileSearch,
    },
    {
      name: "Alerts",
      path: "/alerts",
      icon: ShieldAlert,
    },
    {
      name: "Reports",
      path: "/reports",
      icon: FileText,
    },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={24} />
          </div>

          <div>
            <h2>ThreatLens AI</h2>
            <span>Threat monitoring platform</span>
          </div>
        </div>

        <ThemeToggle />

        <nav className="navigation">
          <div className="nav-label">MONITORING</div>

          {navigation.map((item) => {
            const Icon = item.icon;

            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  isActive ? "nav-link active" : "nav-link"
                }
              >
                <Icon size={19} />
                <span>{item.name}</span>
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot"></span>
            <div>
              <strong>System Online</strong>
              <small>ThreatLens API</small>
            </div>
          </div>

          <button className="logout-button" onClick={onLogout}>
            <LogOut size={18} />
            <span>Logout</span>
          </button>

          {user && (
            <div className="user-pill">
              <span>{user.name}</span>
            </div>
          )}
        </div>
      </aside>

      <main className="main-content">
        <Routes>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/upload" element={<Upload />} />
          <Route path="/analysis" element={<Analysis />} />
          <Route path="/history" element={<History />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/reports" element={<Reports />} />
        </Routes>
      </main>
    </div>
  );
}

function App() {
  const [user, setUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);

  useEffect(() => {
    document.documentElement.dataset.theme =
      localStorage.getItem(THEME_KEY) || "dark";

    getCurrentUser()
      .then((data) => setUser(data.user || data))
      .catch(() => setUser(null))
      .finally(() => setAuthLoading(false));
  }, []);

  const handleSignIn = (loggedInUser) => {
    setUser(loggedInUser);
  };

  const handleLogout = () => {
    logout();
    setUser(null);
  };

  if (authLoading) {
    return <div className="loading">Loading...</div>;
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/signin" element={<SignIn onSignIn={handleSignIn} />} />
        <Route path="/signup" element={<SignUp />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="*" element={<Navigate to="/signin" replace />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/signin" element={<Navigate to="/dashboard" replace />} />
      <Route path="/signup" element={<Navigate to="/dashboard" replace />} />
      <Route path="/forgot-password" element={<Navigate to="/dashboard" replace />} />
      <Route path="/reset-password" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<Layout user={user} onLogout={handleLogout} />} />
    </Routes>
  );
}

export default App;