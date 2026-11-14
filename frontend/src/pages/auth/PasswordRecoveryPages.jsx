import React, { useEffect, useState } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import { ChevronRight, RotateCcw } from 'lucide-react';
import { api, apiError } from '../../api.js';
import { pendingChallenge } from '../../auth/AuthContext.jsx';
import { AuthLayout, formatSeconds, Notice, OtpInput, passwordAcceptable, PasswordInput, PasswordStrength, useCountdown } from '../../auth/components.jsx';

export function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/auth/forgot-password', { email: email.trim() });
      pendingChallenge.set({ ...data.challenge, flow: 'reset', email: email.trim(), message: data.message });
      navigate('/reset-password');
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout eyebrow="ACCOUNT RECOVERY" title="Reset your password" subtitle="Enter the email address of your account. If it is registered, we'll send a reset code.">
      <form className="auth-form" onSubmit={submit}>
        <label>Email address<input type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required maxLength={254} autoFocus /></label>
        <Notice>{error}</Notice>
        <button className="primary wide" disabled={busy}>{busy ? 'Sending…' : 'Send reset code'} <ChevronRight size={16} /></button>
        <div className="auth-row"><Link className="text-button" to="/login">Back to sign in</Link></div>
      </form>
    </AuthLayout>
  );
}

/** Step 1: reset code. Step 2: new password (using the single-use reset grant). */
export function ResetPasswordPage() {
  const navigate = useNavigate();
  const [challenge, setChallenge] = useState(() => pendingChallenge.get());
  const [otp, setOtp] = useState('');
  const [grant, setGrant] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState(() => pendingChallenge.get()?.message || '');
  const [busy, setBusy] = useState(false);
  const expiresIn = useCountdown(challenge?.expires_at);
  const resendIn = useCountdown(challenge?.resend_available_at);

  if (!challenge || challenge.flow !== 'reset') return <Navigate to="/forgot-password" replace />;

  async function verify(code = otp) {
    if (code.length !== 6 || busy) return;
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/auth/verify-reset-otp', { challenge_id: challenge.challenge_id, otp: code });
      setGrant(data.reset_token);
      setInfo('');
    } catch (requestError) {
      setError(apiError(requestError));
      setOtp('');
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    setError('');
    try {
      const { data } = await api.post('/auth/resend-otp', { challenge_id: challenge.challenge_id });
      const next = { ...data.challenge, flow: 'reset', email: challenge.email };
      pendingChallenge.set(next);
      setChallenge(next);
      setInfo('If the address is registered, a new code was sent.');
    } catch (requestError) {
      setError(apiError(requestError));
    }
  }

  async function reset(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/auth/reset-password', { reset_token: grant, password, confirm_password: confirm });
      pendingChallenge.clear();
      navigate('/login', { replace: true, state: { notice: `${data.message} All other sessions were signed out.` } });
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  if (grant) {
    const ready = passwordAcceptable(password, { email: challenge.email }) && password === confirm;
    return (
      <AuthLayout eyebrow="ACCOUNT RECOVERY" title="Choose a new password" subtitle="Your new password must meet the security policy and differ from recent passwords.">
        <form className="auth-form" onSubmit={reset}>
          <PasswordInput label="New password" value={password} onChange={setPassword} autoComplete="new-password" autoFocus />
          <PasswordStrength password={password} identity={{ email: challenge.email }} />
          <PasswordInput label="Confirm new password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          {confirm && confirm !== password && <Notice>Passwords do not match.</Notice>}
          <Notice>{error}</Notice>
          <button className="primary wide" disabled={busy || !ready}>{busy ? 'Saving…' : 'Update password'} <ChevronRight size={16} /></button>
        </form>
      </AuthLayout>
    );
  }

  return (
    <AuthLayout eyebrow="ACCOUNT RECOVERY" title="Enter your reset code" subtitle={<>If <b>{challenge.email}</b> belongs to an account, a 6-digit code is on its way.</>}>
      <form className="auth-form" onSubmit={(event) => { event.preventDefault(); verify(); }}>
        <OtpInput value={otp} onChange={setOtp} onComplete={verify} disabled={busy || expiresIn === 0} />
        <div className={`otp-timer ${expiresIn < 60 ? 'warn' : ''}`}>{expiresIn ? <>Code expires in <b>{formatSeconds(expiresIn)}</b></> : 'This code has expired. Request a new one.'}</div>
        <Notice tone="info">{info}</Notice>
        <Notice>{error}</Notice>
        <button className="primary wide" disabled={busy || otp.length !== 6}>{busy ? 'Verifying…' : 'Continue'} <ChevronRight size={16} /></button>
        <div className="auth-row">
          <button type="button" className="text-button" disabled={resendIn > 0} onClick={resend}><RotateCcw size={12} /> {resendIn > 0 ? `Resend code in ${resendIn}s` : 'Resend code'}</button>
          <Link className="text-button" to="/login">Back to sign in</Link>
        </div>
      </form>
    </AuthLayout>
  );
}

export function AcceptInvitationPage() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const navigate = useNavigate();
  const [invite, setInvite] = useState(null);
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!token) { setError('This invitation link is incomplete.'); return; }
    api.post('/auth/invitation', { token }).then((r) => setInvite(r.data)).catch((requestError) => setError(apiError(requestError)));
  }, [token]);

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/auth/accept-invitation', { token, password });
      navigate('/login', { replace: true, state: { notice: data.message } });
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  const identity = { username: invite?.username };
  return (
    <AuthLayout eyebrow="ACCOUNT INVITATION" title={invite ? `Welcome, ${invite.full_name || invite.username}` : 'Accept invitation'}
      subtitle={invite ? <>You were invited as <b>{invite.role}</b>. Your username is <b>{invite.username}</b>. Choose a password to activate your account.</> : 'Checking your invitation…'}>
      {invite ? (
        <form className="auth-form" onSubmit={submit}>
          <PasswordInput label="Password" value={password} onChange={setPassword} autoComplete="new-password" autoFocus />
          <PasswordStrength password={password} identity={identity} />
          <PasswordInput label="Confirm password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          {confirm && confirm !== password && <Notice>Passwords do not match.</Notice>}
          <Notice>{error}</Notice>
          <button className="primary wide" disabled={busy || !passwordAcceptable(password, identity) || password !== confirm}>{busy ? 'Activating…' : 'Activate account'} <ChevronRight size={16} /></button>
        </form>
      ) : (
        <>
          <Notice>{error}</Notice>
          <div className="auth-row"><Link className="text-button" to="/login">Go to sign in</Link></div>
        </>
      )}
    </AuthLayout>
  );
}

export function SetupPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ setup_token: '', full_name: '', username: '', email: '', password: '', confirm: '' });
  const [status, setStatus] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const set = (key) => (event) => setForm({ ...form, [key]: event.target.value });

  useEffect(() => { api.get('/auth/setup-status').then((r) => setStatus(r.data)).catch((requestError) => setError(apiError(requestError))); }, []);
  if (status && !status.setup_required) return <Navigate to="/login" replace />;

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { confirm: _confirm, ...body } = form;
      const { data } = await api.post('/auth/setup', body);
      pendingChallenge.set({ ...data.challenge, flow: 'email', identifier: form.username });
      navigate('/verify-email');
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  const identity = { username: form.username, email: form.email };
  return (
    <AuthLayout eyebrow="FIRST-TIME SETUP" title="Create the Super Administrator" subtitle="Requires the one-time AUTH_SETUP_TOKEN configured on the server. The email address is verified before the account is activated.">
      {status && !status.browser_setup_enabled ? (
        <Notice>Browser setup is disabled. Set AUTH_SETUP_TOKEN on the server, or create the administrator with <code>npm run admin -- create-super-admin</code>.</Notice>
      ) : (
        <form className="auth-form" onSubmit={submit}>
          <PasswordInput label="Setup token" value={form.setup_token} onChange={(value) => setForm({ ...form, setup_token: value })} autoComplete="off" autoFocus />
          <label>Full name<input value={form.full_name} onChange={set('full_name')} required maxLength={120} autoComplete="name" /></label>
          <label>Username<input value={form.username} onChange={set('username')} required minLength={3} maxLength={64} pattern="[A-Za-z0-9._-]+" autoComplete="username" /></label>
          <label>Email<input type="email" value={form.email} onChange={set('email')} required maxLength={254} autoComplete="email" /></label>
          <PasswordInput label="Password" value={form.password} onChange={(value) => setForm({ ...form, password: value })} autoComplete="new-password" />
          <PasswordStrength password={form.password} identity={identity} />
          <PasswordInput label="Confirm password" value={form.confirm} onChange={(value) => setForm({ ...form, confirm: value })} autoComplete="new-password" />
          <Notice>{error}</Notice>
          <button className="primary wide" disabled={busy || !passwordAcceptable(form.password, identity) || form.password !== form.confirm}>{busy ? 'Creating…' : 'Create administrator'} <ChevronRight size={16} /></button>
        </form>
      )}
    </AuthLayout>
  );
}

