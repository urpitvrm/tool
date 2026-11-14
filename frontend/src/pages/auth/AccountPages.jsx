import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, LogOut, Monitor, RefreshCw, ShieldAlert } from 'lucide-react';
import { api, apiError } from '../../api.js';
import { useAuth } from '../../auth/AuthContext.jsx';
import { Notice, passwordAcceptable, PasswordInput, PasswordStrength } from '../../auth/components.jsx';
import { Empty, ErrorState, Loading, PageHeading, StatusPill, useToast } from '../../components/common.jsx';
import { fmtDate } from '../../lib/format.js';

export function ChangePasswordPage() {
  const { user, reload } = useAuth();
  const { notify } = useToast();
  const navigate = useNavigate();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const identity = { username: user?.username, email: user?.email };

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post('/auth/change-password', { current_password: current, new_password: next, confirm_password: confirm });
      notify(data.other_sessions_revoked ? `Password changed. ${data.other_sessions_revoked} other session(s) signed out.` : 'Password changed.');
      setCurrent(''); setNext(''); setConfirm('');
      const wasForced = user?.force_password_change;
      await reload();
      if (wasForced) navigate('/', { replace: true });
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeading title="Change Password" eyebrow="ACCOUNT" description="Use a unique password of at least 12 characters. Your last passwords cannot be reused." />
      {user?.force_password_change && <div className="notice-banner warn"><ShieldAlert size={15} /><span>An administrator requires you to change your password before you can continue.</span></div>}
      <form className="panel account-form" onSubmit={submit}>
        <div className="modal-body">
          <PasswordInput label="Current password" value={current} onChange={setCurrent} autoFocus />
          <PasswordInput label="New password" value={next} onChange={setNext} autoComplete="new-password" />
          <PasswordStrength password={next} identity={identity} />
          <PasswordInput label="Confirm new password" value={confirm} onChange={setConfirm} autoComplete="new-password" />
          {confirm && confirm !== next && <Notice>Passwords do not match.</Notice>}
          <Notice>{error}</Notice>
        </div>
        <div className="modal-actions">
          <span className="muted note-line">Other signed-in sessions will be signed out.</span>
          <span className="spacer" />
          <button className="primary" disabled={busy || !current || !passwordAcceptable(next, identity) || next !== confirm}><KeyRound size={14} /> {busy ? 'Saving…' : 'Change password'}</button>
        </div>
      </form>
    </>
  );
}

const STATUS_LABEL = { success: 'Signed in', failed: 'Failed', locked: 'Blocked (locked)', otp_sent: 'Code sent' };

export function SessionsPage() {
  const { logout } = useAuth();
  const { notify } = useToast();
  const client = useQueryClient();
  const sessions = useQuery({ queryKey: ['auth-sessions'], queryFn: () => api.get('/auth/sessions').then((r) => r.data) });
  const history = useQuery({ queryKey: ['auth-login-history'], queryFn: () => api.get('/auth/login-history', { params: { limit: 50 } }).then((r) => r.data) });

  async function revoke(session) {
    if (session.current) { await logout(); return; }
    try {
      await api.delete(`/auth/sessions/${session.id}`);
      notify('Session signed out');
      client.invalidateQueries({ queryKey: ['auth-sessions'] });
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  async function logoutAll() {
    if (!window.confirm('Sign out of every session, including this one?')) return;
    await logout(true);
  }

  return (
    <>
      <PageHeading title="Sessions" eyebrow="ACCOUNT" description="Devices currently signed in to your account, and recent sign-in activity.">
        <button className="secondary" onClick={() => { sessions.refetch(); history.refetch(); }}><RefreshCw size={14} /> Refresh</button>
        <button className="secondary" onClick={logoutAll}><LogOut size={14} /> Sign out everywhere</button>
      </PageHeading>
      <div className="panel table-panel module-table">
        <div className="table-toolbar"><div><b>Active sessions</b><span>{sessions.data?.length ?? 0} signed in</span></div></div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Device</th><th>IP address</th><th>Signed in</th><th>Last activity</th><th>Expires</th><th /></tr></thead>
            <tbody>
              {sessions.isLoading ? <tr><td colSpan={6}><Loading /></td></tr>
                : sessions.error ? <tr><td colSpan={6}><ErrorState error={sessions.error} /></td></tr>
                  : sessions.data.length ? sessions.data.map((session) => (
                    <tr key={session.id}>
                      <td><Monitor size={13} className="muted" /> {session.device_information || 'Unknown device'} {session.current && <span className="status-pill ok"><i />This device</span>}</td>
                      <td className="mono">{session.ip_address || '—'}</td>
                      <td className="timestamp">{fmtDate(session.created_at)}</td>
                      <td className="timestamp">{fmtDate(session.last_used_at)}</td>
                      <td className="timestamp">{fmtDate(session.expires_at)}{session.remember ? '' : ' · browser session'}</td>
                      <td className="row-actions"><button className="secondary" onClick={() => revoke(session)}>{session.current ? 'Sign out' : 'Revoke'}</button></td>
                    </tr>
                  )) : <tr><td colSpan={6}><Empty message="No active sessions." /></td></tr>}
            </tbody>
          </table>
        </div>
      </div>
      <div className="panel table-panel">
        <div className="table-toolbar"><div><b>Recent sign-in activity</b><span>Last 50 events</span></div></div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Time</th><th>Result</th><th>Detail</th><th>Device</th><th>IP address</th></tr></thead>
            <tbody>
              {history.isLoading ? <tr><td colSpan={5}><Loading /></td></tr>
                : history.error ? <tr><td colSpan={5}><ErrorState error={history.error} /></td></tr>
                  : history.data.map((item) => (
                    <tr key={item.id}>
                      <td className="timestamp">{fmtDate(item.created_at)}</td>
                      <td><StatusPill status={item.login_status === 'success' ? 'completed' : item.login_status === 'otp_sent' ? 'pending' : 'failed'} /> <small className="cell-sub">{STATUS_LABEL[item.login_status] || item.login_status}</small></td>
                      <td>{String(item.failure_reason || '').replaceAll('_', ' ')}</td>
                      <td>{item.device_information || '—'}</td>
                      <td className="mono">{item.ip_address}</td>
                    </tr>
                  ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}

