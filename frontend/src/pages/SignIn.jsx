import { useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";

import { signin } from "../services/api";

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

function SignIn({ onSignIn }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({ email: "", password: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function handleChange(event) {
    const { name, value } = event.target;
    setFormData((previous) => ({ ...previous, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const email = formData.email.trim().toLowerCase();
    if (!email || !formData.password) {
      setError("Enter your email address and password to continue.");
      return;
    }
    try {
      setLoading(true);
      setError("");
      const data = await signin(email, formData.password);
      if (rememberMe) localStorage.setItem("threatlens_remember", "true");
      else localStorage.removeItem("threatlens_remember");
      onSignIn(data.user);
      navigate("/dashboard", { replace: true });
    } catch (requestError) {
      setError(requestError.message || "Unable to sign in. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-layout">
        <section className="auth-intro">
          <div className="auth-brand-row"><div className="brand-icon auth-brand-icon"><ShieldCheck size={25} /></div><div><strong>ThreatLens AI</strong><span>Intelligent Malware Detection &amp; Threat Monitoring</span></div></div>
          <div className="auth-intro-copy"><span className="eyebrow">SECURITY OPERATIONS</span><h1>Clarity when every signal matters.</h1><p>Analyze suspicious files, understand risk, and keep your security posture visible from one focused workspace.</p></div>
          <div className="auth-signal"><span className="status-dot" /> Live threat intelligence workspace</div>
        </section>
        <section className="auth-card">
          <div className="auth-card-top"><span>SECURE ACCESS</span><ThemeToggle /></div>
          <div className="auth-header"><h2>Welcome back</h2><p>Sign in to continue monitoring and analyzing cybersecurity threats.</p></div>
          <form className="auth-form" onSubmit={handleSubmit} noValidate>
            {(error || location.state?.message) && <div className={error ? "auth-error" : "auth-success"}>{error || location.state.message}</div>}
            <label><span>Email address</span><input type="email" name="email" value={formData.email} onChange={handleChange} placeholder="you@company.com" autoComplete="email" /></label>
            <label><span>Password</span><div className="password-field"><input type={showPassword ? "text" : "password"} name="password" value={formData.password} onChange={handleChange} placeholder="Enter your password" autoComplete="current-password" /><button type="button" className="password-toggle" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label>
            <div className="auth-options"><label className="checkbox-label"><input type="checkbox" checked={rememberMe} onChange={(event) => setRememberMe(event.target.checked)} /><span>Remember me</span></label><Link to="/forgot-password">Forgot password?</Link></div>
            <button type="submit" className="auth-button" disabled={loading}>{loading ? "Signing in..." : "Sign In"}</button>
          </form>
          <p className="auth-switch">Don&apos;t have an account? <Link to="/signup">Create an account</Link></p>
        </section>
      </div>
    </main>
  );
}

export default SignIn;
