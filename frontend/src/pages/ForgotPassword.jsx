import { useState } from "react";
import { ArrowLeft, Mail, ShieldCheck } from "lucide-react";
import { Link } from "react-router-dom";
import { forgotPassword } from "../services/api";

function ThemeToggle() {
  const [theme, setTheme] = useState(() => localStorage.getItem("threatlens_theme") || "dark");
  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.dataset.theme = next;
    localStorage.setItem("threatlens_theme", next);
  }
  return <button type="button" className="theme-toggle" onClick={toggle}>{theme === "dark" ? "Light mode" : "Dark mode"}</button>;
}

function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  function handleSubmit(event) {
    event.preventDefault();
    if (!email.trim()) { setError("Enter the email address associated with your account."); return; }
    setLoading(true);
    setError("");
    setMessage("");
    forgotPassword(email.trim().toLowerCase())
      .then((response) => setMessage(response.message))
      .catch((requestError) => setError(requestError.message || "Unable to request a password reset."))
      .finally(() => setLoading(false));
  }
  return <main className="auth-page"><section className="auth-card auth-card-simple"><div className="auth-card-top"><span>ACCOUNT RECOVERY</span><ThemeToggle /></div><div className="auth-header"><div className="brand-icon auth-brand-icon"><ShieldCheck size={25} /></div><h2>Reset your password</h2><p>Enter the email address associated with your ThreatLens AI account and we&apos;ll help you regain access.</p></div><form className="auth-form" onSubmit={handleSubmit}>{error && <div className="auth-error">{error}</div>}{message && <div className="auth-success">{message}</div>}<label><span>Email address</span><div className="input-with-icon"><Mail size={17} /><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} placeholder="you@company.com" autoComplete="email" /></div></label><button type="submit" className="auth-button" disabled={loading}>{loading ? "Sending..." : "Send Reset Link"}</button></form><p className="auth-switch"><Link to="/signin"><ArrowLeft size={14} /> Back to sign in</Link></p></section></main>;
}

export default ForgotPassword;
