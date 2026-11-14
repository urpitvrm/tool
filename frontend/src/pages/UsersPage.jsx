import React, { useMemo, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Lock, LockOpen, Mail, MonitorX, Pencil, Power, PowerOff, RefreshCw, Search, UserPlus } from 'lucide-react';
import { api, apiError } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { Drawer, Empty, ErrorState, Field, Loading, Modal, PageHeading, StatusPill, useToast } from '../components/common.jsx';
import { fmtDate } from '../lib/format.js';

const isLocked = (user) => user.locked_until && new Date(user.locked_until) > new Date();

export default function UsersPage() {
  const { user: me } = useAuth();
  const { notify } = useToast();
  const client = useQueryClient();
  const users = useQuery({ queryKey: ['admin-users'], queryFn: () => api.get('/users').then((r) => r.data) });
  const roles = useQuery({ queryKey: ['admin-roles'], queryFn: () => api.get('/roles').then((r) => r.data), staleTime: 300_000 });
  const [filter, setFilter] = useState('');
  const [editing, setEditing] = useState(null); // null | {} (invite) | user
  const [detail, setDetail] = useState(null);

  const refresh = () => client.invalidateQueries({ queryKey: ['admin-users'] });
  const rows = useMemo(() => (users.data || []).filter((user) => !filter || `${user.username} ${user.full_name} ${user.email} ${user.role}`.toLowerCase().includes(filter.toLowerCase())), [users.data, filter]);

  async function act(user, action, label, body) {
    try {
      const response = action === 'sessions' ? await api.delete(`/users/${user.id}/sessions`) : await api.post(`/users/${user.id}/${action}`, body);
      notify(label(response.data));
      refresh();
      if (detail?.id === user.id) setDetail({ ...detail, ...(response.data?.id ? response.data : {}) });
    } catch (error) {
      notify(apiError(error), 'error');
    }
  }

  const actions = (user) => [
    user.status === 'invited' && { icon: Mail, title: 'Resend invitation', run: () => act(user, 'resend-invitation', () => 'Invitation sent') },
    user.status === 'active'
      ? user.id !== me.id && { icon: PowerOff, title: 'Deactivate', run: () => window.confirm(`Deactivate ${user.username}? All sessions end immediately.`) && act(user, 'deactivate', () => `${user.username} deactivated`) }
      : ['deactivated', 'pending_approval'].includes(user.status) && { icon: Power, title: 'Activate', run: () => act(user, 'activate', () => `${user.username} activated`) },
    isLocked(user) && { icon: LockOpen, title: 'Unlock', run: () => act(user, 'unlock', () => `${user.username} unlocked`) },
    user.status === 'active' && !user.force_password_change && { icon: KeyRound, title: 'Require password change', run: () => window.confirm(`Require ${user.username} to change their password at next request?`) && act(user, 'force-password-change', () => 'Password change required', { revoke_sessions: false }) },
    user.active_sessions > 0 && { icon: MonitorX, title: 'Sign out all sessions', run: () => window.confirm(`Sign ${user.username} out everywhere?`) && act(user, 'sessions', (data) => `${data.revoked} session(s) revoked`) },
  ].filter(Boolean);

  return (
    <>
      <PageHeading title="User Management" eyebrow="ADMINISTRATION" description="Invite users, manage roles and account status. Users set their own passwords from a single-use invitation link.">
        <button className="secondary" onClick={refresh}><RefreshCw size={14} /> Refresh</button>
        <button className="primary" onClick={() => setEditing({})}><UserPlus size={14} /> Invite user</button>
      </PageHeading>
      <div className="panel filter-panel">
        <div className="toolbar-row"><div className="query-input"><Search size={14} /><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter by name, username, email or role" /></div></div>
      </div>
      <div className="panel table-panel">
        <div className="table-scroll">
          <table>
            <thead><tr><th>User</th><th>Email</th><th>Roles</th><th>Status</th><th>Last sign-in</th><th>Sessions</th><th /></tr></thead>
            <tbody>
              {users.isLoading ? <tr><td colSpan={7}><Loading /></td></tr>
                : users.error ? <tr><td colSpan={7}><ErrorState error={users.error} /></td></tr>
                  : rows.length ? rows.map((user) => (
                    <tr key={user.id} className="click-row" onClick={() => setDetail(user)}>
                      <td><b>{user.full_name || user.username}</b><small className="cell-sub">{user.username}{user.id === me.id ? ' · you' : ''}</small></td>
                      <td>{user.email || <span className="muted">No email</span>}{user.email && !user.email_verified && <small className="cell-sub">unverified</small>}</td>
                      <td>{user.role}{user.additional_roles?.length > 0 && <small className="cell-sub">+ {user.additional_roles.join(', ')}</small>}</td>
                      <td>
                        <StatusPill status={user.status} />
                        {isLocked(user) && <small className="cell-sub lock-note"><Lock size={10} /> locked until {fmtDate(user.locked_until, { timeStyle: 'short' })}</small>}
                        {user.force_password_change && <small className="cell-sub">password change required</small>}
                      </td>
                      <td className="timestamp">{fmtDate(user.last_login_at)}</td>
                      <td>{user.active_sessions}</td>
                      <td className="row-actions" onClick={(event) => event.stopPropagation()}>
                        <button className="icon-button" title="Edit" onClick={() => setEditing(user)}><Pencil size={13} /></button>
                        {actions(user).map((action) => <button key={action.title} className="icon-button" title={action.title} aria-label={action.title} onClick={action.run}><action.icon size={13} /></button>)}
                      </td>
                    </tr>
                  )) : <tr><td colSpan={7}><Empty message="No users match the filter." /></td></tr>}
            </tbody>
          </table>
        </div>
      </div>
      {editing && <UserForm user={editing.id ? editing : null} roles={roles.data || []} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); refresh(); }} />}
      {detail && <UserDrawer user={detail} onClose={() => setDetail(null)} actions={actions(detail)} />}
    </>
  );
}

function UserForm({ user, roles, onClose, onSaved }) {
  const { notify } = useToast();
  const [form, setForm] = useState({
    full_name: user?.full_name || '', email: user?.email || '', username: user?.username || '',
    role: user?.role || 'Security Analyst', additional_roles: user?.additional_roles || [],
  });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const set = (key) => (event) => setForm({ ...form, [key]: event.target.value });

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      if (user) {
        const { username: _u, ...body } = form;
        await api.patch(`/users/${user.id}`, body);
        notify(form.email.toLowerCase() !== String(user.email || '').toLowerCase() ? 'User updated. The new email must be verified at next sign-in.' : 'User updated');
      } else {
        const { data } = await api.post('/users', form);
        notify(data.invitation.delivery === 'sent' ? `Invitation sent to ${data.invitation.destination}` : 'User created, but the invitation email failed. Use Resend invitation.', data.invitation.delivery === 'sent' ? 'ok' : 'error');
      }
      onSaved();
    } catch (requestError) {
      setError(apiError(requestError));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal title={user ? `Edit ${user.username}` : 'Invite user'} eyebrow="USER MANAGEMENT" onClose={onClose}>
      <form onSubmit={submit}>
        {!user && <p className="muted note-line">The user receives a single-use link to verify their email and choose a password. No password is sent by email.</p>}
        <Field label="Full name"><input required maxLength={120} value={form.full_name} onChange={set('full_name')} autoFocus /></Field>
        <Field label="Email"><input type="email" required maxLength={254} value={form.email} onChange={set('email')} /></Field>
        <Field label="Username" hint={user ? 'Usernames cannot be changed' : 'Letters, numbers, dots, underscores and hyphens'}><input required minLength={3} maxLength={64} pattern="[A-Za-z0-9._-]+" value={form.username} onChange={set('username')} disabled={Boolean(user)} /></Field>
        <Field label="Primary role">
          <select value={form.role} onChange={set('role')}>{roles.map((role) => <option key={role.id}>{role.name}</option>)}</select>
        </Field>
        <Field label="Additional roles" hint="Permissions from all assigned roles are combined">
          <div className="column-picker">
            {roles.filter((role) => role.name !== form.role).map((role) => (
              <label key={role.id} className="check-inline">
                <input type="checkbox" checked={form.additional_roles.includes(role.name)}
                  onChange={(event) => setForm({ ...form, additional_roles: event.target.checked ? [...form.additional_roles, role.name] : form.additional_roles.filter((name) => name !== role.name) })} />
                {role.name}
              </label>
            ))}
          </div>
        </Field>
        {error && <ErrorState error={error} title={user ? 'Could not update user' : 'Could not invite user'} hint="" />}
        <div className="modal-actions"><button type="button" className="secondary" onClick={onClose}>Cancel</button><button className="primary" disabled={busy}>{busy ? 'Saving…' : user ? 'Save changes' : 'Send invitation'}</button></div>
      </form>
    </Modal>
  );
}

function UserDrawer({ user, onClose, actions }) {
  const history = useQuery({ queryKey: ['admin-login-history', user.id], queryFn: () => api.get(`/users/${user.id}/login-history`, { params: { limit: 30 } }).then((r) => r.data) });
  const sessions = useQuery({ queryKey: ['admin-user-sessions', user.id], queryFn: () => api.get(`/users/${user.id}/sessions`).then((r) => r.data) });
  return (
    <Drawer title={user.full_name || user.username} eyebrow={`USER ${user.username}`} onClose={onClose}
      actions={actions.map((action) => <button key={action.title} className="secondary" onClick={action.run}><action.icon size={13} /> {action.title}</button>)}>
      <div className="drawer-meta"><StatusPill status={user.status} /></div>
      <div className="detail-sections">
        <section>
          {[['Email', user.email], ['Email verified', user.email_verified ? fmtDate(user.email_verified_at) : 'No'], ['Primary role', user.role],
            ['Additional roles', (user.additional_roles || []).join(', ')], ['Failed attempts', user.failed_login_attempts], ['Locked until', isLocked(user) ? fmtDate(user.locked_until) : ''],
            ['Last sign-in', fmtDate(user.last_login_at)], ['Password changed', fmtDate(user.password_changed_at)], ['Created', fmtDate(user.created_at)]]
            .filter(([, value]) => value !== '' && value != null).map(([label, value]) => <div className="detail-row" key={label}><span>{label}</span><b>{String(value)}</b></div>)}
        </section>
        <section><h4>Active sessions ({sessions.data?.length ?? '…'})</h4>
          {(sessions.data || []).map((session) => <div className="detail-row" key={session.id}><span>{session.device_information}</span><b className="mono">{session.ip_address} · {fmtDate(session.last_used_at)}</b></div>)}
        </section>
        <section><h4>Recent sign-in activity</h4>
          {history.isLoading ? <Loading /> : (history.data || []).map((item) => (
            <div className="detail-row" key={item.id}><span>{fmtDate(item.created_at)}</span><b>{item.login_status}{item.failure_reason ? ` · ${item.failure_reason.replaceAll('_', ' ')}` : ''}</b><span className="mono">{item.ip_address}</span></div>
          ))}
        </section>
      </div>
    </Drawer>
  );
}
