import React, { useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, Circle, Eye, EyeOff, LockKeyhole, Shield } from 'lucide-react';

/** Two-panel layout reusing the existing login screen design. */
export function AuthLayout({ eyebrow = 'SECURE ACCESS', title, subtitle, children, footer }) {
  return (
    <div className="login-screen">
      <div className="login-art">
        <div className="brand-mark large"><Shield size={25} /></div>
        <span className="eyebrow">SECURITY OPERATIONS PLATFORM</span>
        <h1>Clarity in the<br /><span>signal.</span></h1>
        <p>Unified visibility for your security operations. Investigate events, understand risk, and coordinate response.</p>
        <div className="login-orbit"><div /><div /><div /><Shield size={30} /></div>
        <small>OpenSearch · Wazuh · PostgreSQL</small>
      </div>
      <div className="login-card auth-card">
        <div className="mobile-brand"><div className="brand-mark"><Shield size={19} /></div><b>Sentinel / SOC</b></div>
        <span className="eyebrow">{eyebrow}</span>
        <h2>{title}</h2>
        {subtitle && <p>{subtitle}</p>}
        {children}
        <div className="login-foot"><LockKeyhole size={13} /> {footer || 'Protected with email verification and encrypted sessions'}</div>
      </div>
    </div>
  );
}

export function Notice({ tone = 'error', children }) {
  if (!children) return null;
  return (
    <div className={`auth-notice ${tone}`} role={tone === 'error' ? 'alert' : 'status'}>
      {tone === 'error' ? <AlertTriangle size={14} /> : <CheckCircle2 size={14} />}<span>{children}</span>
    </div>
  );
}

/** Six single-digit boxes with paste, backspace and arrow-key support. */
export function OtpInput({ value, onChange, onComplete, disabled, autoFocus = true }) {
  const refs = useRef([]);
  const digits = Array.from({ length: 6 }, (_, index) => value[index] || '');
  useEffect(() => { if (autoFocus) refs.current[0]?.focus(); }, [autoFocus]);
  const set = (next) => {
    const clean = next.replace(/\D/g, '').slice(0, 6);
    onChange(clean);
    if (clean.length === 6) onComplete?.(clean);
  };
  const handle = (index, event) => {
    const char = event.target.value.replace(/\D/g, '').slice(-1);
    if (!char) return;
    const next = digits.slice();
    next[index] = char;
    set(next.join(''));
    refs.current[Math.min(index + 1, 5)]?.focus();
  };
  const keyDown = (index, event) => {
    if (event.key === 'Backspace') {
      event.preventDefault();
      const next = digits.slice();
      if (next[index]) next[index] = '';
      else if (index > 0) { next[index - 1] = ''; refs.current[index - 1]?.focus(); }
      onChange(next.join('').trimEnd());
    } else if (event.key === 'ArrowLeft') refs.current[Math.max(0, index - 1)]?.focus();
    else if (event.key === 'ArrowRight') refs.current[Math.min(5, index + 1)]?.focus();
  };
  return (
    <div className="otp-input" onPaste={(event) => { event.preventDefault(); set(event.clipboardData.getData('text')); refs.current[5]?.focus(); }}>
      {digits.map((digit, index) => (
        <input key={index} ref={(element) => { refs.current[index] = element; }} value={digit} disabled={disabled}
          inputMode="numeric" autoComplete={index === 0 ? 'one-time-code' : 'off'} maxLength={1} aria-label={`Digit ${index + 1}`}
          onChange={(event) => handle(index, event)} onKeyDown={(event) => keyDown(index, event)} onFocus={(event) => event.target.select()} />
      ))}
    </div>
  );
}

export function PasswordInput({ label, value, onChange, autoComplete = 'current-password', autoFocus, name }) {
  const [visible, setVisible] = useState(false);
  return (
    <label>
      {label}
      <div className="password-field">
        <input type={visible ? 'text' : 'password'} value={value} onChange={(event) => onChange(event.target.value)} autoComplete={autoComplete} autoFocus={autoFocus} name={name} required maxLength={128} />
        <button type="button" className="icon-button" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'} title={visible ? 'Hide password' : 'Show password'}>
          {visible ? <EyeOff size={15} /> : <Eye size={15} />}
        </button>
      </div>
    </label>
  );
}

// Mirrors backend/src/utils/password.js (the server remains the authority, including the breached-password list).
export function passwordRules(password, { username = '', email = '' } = {}) {
  const lower = password.toLowerCase();
  const identities = [username, String(email).split('@')[0]].map((item) => String(item).toLowerCase()).filter((item) => item.length >= 3);
  return [
    ['At least 12 characters', password.length >= 12],
    ['Uppercase and lowercase letters', /[a-z]/.test(password) && /[A-Z]/.test(password)],
    ['A number', /\d/.test(password)],
    ['A special character', /[^A-Za-z0-9]/.test(password)],
    ['No character repeated 4+ times', password.length > 0 && !/(.)\1{3,}/.test(password)],
    ['Does not contain your username or email', password.length > 0 && !identities.some((item) => lower.includes(item))],
  ];
}

export function PasswordStrength({ password, identity }) {
  const rules = passwordRules(password, identity);
  const met = rules.filter(([, ok]) => ok).length;
  const lengthBonus = password.length >= 16 ? 1 : 0;
  const score = password ? Math.min(4, Math.max(0, met - 2 + lengthBonus)) : 0;
  const labels = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong'];
  return (
    <div className="password-strength" aria-live="polite">
      <div className="strength-bar"><span className={`level-${score}`} style={{ width: `${(score / 4) * 100}%` }} /></div>
      <div className="strength-label">{password ? labels[score] : 'Password strength'}</div>
      <ul>
        {rules.map(([label, ok]) => <li key={label} className={ok ? 'ok' : ''}>{ok ? <CheckCircle2 size={12} /> : <Circle size={12} />}{label}</li>)}
      </ul>
    </div>
  );
}

export const passwordAcceptable = (password, identity) => passwordRules(password, identity).every(([, ok]) => ok);

/** Seconds remaining until `target` (re-renders every second). */
export function useCountdown(target) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);
  return target ? Math.max(0, Math.ceil((new Date(target).getTime() - now) / 1000)) : 0;
}

export const formatSeconds = (seconds) => `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
