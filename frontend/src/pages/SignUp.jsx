import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";

import { signup } from "../services/api";

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

function SignUp() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({ name: "", email: "", password: "", confirmPassword: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function handleChange(event) {
    const { name, value } = event.target;
    setFormData((previous) => ({ ...previous, [name]: value }));
  }

  async function handleSubmit(event) {
    event.preventDefault();
    const name = formData.name.trim();
    const email = formData.email.trim().toLowerCase();
    const { password, confirmPassword } = formData;
    if (!name || !email || !password || !confirmPassword) { setError("Complete all fields to create your account."); return; }
    if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z\d]/.test(password)) { setError("Use at least 8 characters with letters, numbers, and symbols."); return; }
    if (password !== confirmPassword) { setError("Passwords do not match. Check both fields and try again."); return; }
    try {
      setLoading(true);
      setError("");
      await signup(name, email, password);
      navigate("/signin", { replace: true, state: { message: "Account created. Sign in to continue." } });
    } catch (requestError) {
      setError(requestError.message || "Unable to create your account. Please try again.");
    } finally { setLoading(false); }
  }

  return (
    <main className="auth-page"><div className="auth-layout auth-layout-compact"><section className="auth-intro"><div className="auth-brand-row"><div className="brand-icon auth-brand-icon"><ShieldCheck size={25} /></div><div><strong>ThreatLens AI</strong><span>Intelligent Malware Detection &amp; Threat Monitoring</span></div></div><div className="auth-intro-copy"><span className="eyebrow">PROTECTED BY DESIGN</span><h1>Make every investigation more actionable.</h1><p>Start analyzing files and monitoring cybersecurity threats with ThreatLens AI.</p></div><div className="auth-signal"><span className="status-dot" /> Your security workspace starts here</div></section>
      <section className="auth-card"><div className="auth-card-top"><span>NEW WORKSPACE</span><ThemeToggle /></div><div className="auth-header"><h2>Create your account</h2><p>Set up secure access to your malware analysis workspace.</p></div><form className="auth-form" onSubmit={handleSubmit} noValidate>{error && <div className="auth-error">{error}</div>}<label><span>Full name</span><input type="text" name="name" value={formData.name} onChange={handleChange} placeholder="Your full name" autoComplete="name" /></label><label><span>Email address</span><input type="email" name="email" value={formData.email} onChange={handleChange} placeholder="you@company.com" autoComplete="email" /></label><label><span>Password</span><div className="password-field"><input type={showPassword ? "text" : "password"} name="password" value={formData.password} onChange={handleChange} placeholder="Create a strong password" autoComplete="new-password" /><button type="button" className="password-toggle" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div><small className="field-hint">Use at least 8 characters with a combination of letters, numbers, and symbols.</small></label><label><span>Confirm password</span><div className="password-field"><input type={showConfirmPassword ? "text" : "password"} name="confirmPassword" value={formData.confirmPassword} onChange={handleChange} placeholder="Repeat your password" autoComplete="new-password" /><button type="button" className="password-toggle" onClick={() => setShowConfirmPassword(!showConfirmPassword)} aria-label={showConfirmPassword ? "Hide confirm password" : "Show confirm password"}>{showConfirmPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label><button type="submit" className="auth-button" disabled={loading}>{loading ? "Creating account..." : "Create Account"}</button></form><p className="auth-switch">Already have an account? <Link to="/signin">Sign in</Link></p></section></div></main>
  );
}

export default SignUp;
