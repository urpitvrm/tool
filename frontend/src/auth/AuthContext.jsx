import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { api } from '../api.js';

const AuthContext = createContext(null);
const CHALLENGE_KEY = 'siem_auth_challenge';

/** The pending OTP challenge (id + metadata only) survives a page reload within the tab. */
export const pendingChallenge = {
  get() { try { return JSON.parse(sessionStorage.getItem(CHALLENGE_KEY)); } catch { return null; } },
  set(value) { try { sessionStorage.setItem(CHALLENGE_KEY, JSON.stringify(value)); } catch { /* ignore */ } },
  clear() { try { sessionStorage.removeItem(CHALLENGE_KEY); } catch { /* ignore */ } },
};

export function AuthProvider({ children }) {
  const client = useQueryClient();
  const [state, setState] = useState({ status: 'loading', user: null });

  const loadUser = useCallback(async () => {
    try {
      const { data } = await api.get('/auth/me');
      setState({ status: 'authenticated', user: data });
      return data;
    } catch {
      setState({ status: 'anonymous', user: null });
      return null;
    }
  }, []);

  useEffect(() => { loadUser(); }, [loadUser]);

  useEffect(() => {
    const onLogout = () => { client.clear(); setState({ status: 'anonymous', user: null }); };
    const onForced = () => setState((current) => (current.user ? { ...current, user: { ...current.user, force_password_change: true } } : current));
    window.addEventListener('siem-logout', onLogout);
    window.addEventListener('siem-password-change-required', onForced);
    return () => { window.removeEventListener('siem-logout', onLogout); window.removeEventListener('siem-password-change-required', onForced); };
  }, [client]);

  const signedIn = useCallback((user) => {
    pendingChallenge.clear();
    client.clear();
    setState({ status: 'authenticated', user });
  }, [client]);

  const logout = useCallback(async (all = false) => {
    try { await api.post(all ? '/auth/logout-all' : '/auth/logout'); } catch { /* cookies are cleared server-side when possible */ }
    client.clear();
    setState({ status: 'anonymous', user: null });
  }, [client]);

  const value = useMemo(() => ({
    ...state,
    can: (permission) => Boolean(state.user?.permissions?.includes(permission)),
    signedIn, logout, reload: loadUser,
  }), [state, signedIn, logout, loadUser]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
