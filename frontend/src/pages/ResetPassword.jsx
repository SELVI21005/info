import { useState } from "react";
import { Link, useSearchParams, useNavigate } from "react-router-dom";
import { Eye, EyeOff, ShieldCheck } from "lucide-react";
import { resetPassword } from "../services/api";

function ResetPassword() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const token = searchParams.get("token") || "";

  async function handleSubmit(event) {
    event.preventDefault();
    if (!token) { setError("This reset link is missing or invalid."); return; }
    if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password) || !/[^A-Za-z\d]/.test(password)) { setError("Use at least 8 characters with letters, numbers, and symbols."); return; }
    if (password !== confirmPassword) { setError("Passwords do not match."); return; }
    try {
      setLoading(true);
      setError("");
      await resetPassword(token, password);
      navigate("/signin", { replace: true, state: { message: "Password reset successfully. Sign in with your new password." } });
    } catch (requestError) { setError(requestError.message || "Unable to reset your password."); } finally { setLoading(false); }
  }

  return <main className="auth-page"><section className="auth-card auth-card-simple"><div className="auth-card-top"><span>SECURE PASSWORD RESET</span></div><div className="auth-header"><div className="brand-icon auth-brand-icon"><ShieldCheck size={25} /></div><h2>Choose a new password</h2><p>Set a new password for your ThreatLens AI account.</p></div><form className="auth-form" onSubmit={handleSubmit}>{error && <div className="auth-error">{error}</div>}<label><span>New password</span><div className="password-field"><input type={showPassword ? "text" : "password"} value={password} onChange={(event) => setPassword(event.target.value)} placeholder="Create a strong password" autoComplete="new-password" /><button type="button" className="password-toggle" onClick={() => setShowPassword(!showPassword)} aria-label={showPassword ? "Hide password" : "Show password"}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label><label><span>Confirm password</span><div className="password-field"><input type={showConfirmPassword ? "text" : "password"} value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} placeholder="Repeat your password" autoComplete="new-password" /><button type="button" className="password-toggle" onClick={() => setShowConfirmPassword(!showConfirmPassword)} aria-label={showConfirmPassword ? "Hide confirm password" : "Show confirm password"}>{showConfirmPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div></label><small className="field-hint">Use at least 8 characters with a combination of letters, numbers, and symbols.</small><button type="submit" className="auth-button" disabled={loading}>{loading ? "Updating..." : "Update Password"}</button></form><p className="auth-switch"><Link to="/signin">Back to sign in</Link></p></section></main>;
}

export default ResetPassword;
