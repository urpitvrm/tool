import React, { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import { api, apiError } from '../../api.js';
import { pendingChallenge, useAuth } from '../../auth/AuthContext.jsx';
import { AuthLayout, Notice, PasswordInput } from '../../auth/components.jsx';

export default function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { signedIn } = useAuth();
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [setup, setSetup] = useState(null);

  useEffect(() => { api.get('/auth/setup-status').then((r) => setSetup(r.data)).catch(() => {}); }, []);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/auth/login', { identifier: identifier.trim(), password, remember });
      if (data.status === 'authenticated') { signedIn(data.user); navigate('/', { replace: true }); return; }
      const flow = data.status === 'otp_required' ? 'login' : 'email';
      pendingChallenge.set({ ...data.challenge, flow, identifier: identifier.trim() });
      navigate(flow === 'login' ? '/verify-otp' : '/verify-email');
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout title="Welcome back" subtitle="Sign in to your security workspace.">
      {setup?.setup_required && (
        <Notice tone="info">
          No administrator exists yet. {setup.browser_setup_enabled ? <Link to="/setup">Run first-time setup</Link> : 'Create the first Super Administrator with the server CLI (see README).'}
        </Notice>
      )}
      <Notice tone="info">{location.state?.notice}</Notice>
      <form onSubmit={submit} className="auth-form">
        <label>
          Username or email
          <input autoComplete="username" value={identifier} onChange={(event) => setIdentifier(event.target.value)} required maxLength={254} autoFocus />
        </label>
        <PasswordInput label="Password" value={password} onChange={setPassword} />
        <div className="auth-row">
          <label className="check-inline"><input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} /> Keep me signed in on this device</label>
          <Link className="text-button" to="/forgot-password">Forgot password?</Link>
        </div>
        <Notice>{error}</Notice>
        <button className="primary wide" disabled={busy}>{busy ? 'Checking…' : 'Sign in'} <ChevronRight size={16} /></button>
      </form>
    </AuthLayout>
  );
}
