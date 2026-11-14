import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, ChevronDown, ChevronLeft, ChevronRight, Clock3, Database, X } from 'lucide-react';
import { apiError } from '../api.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { RANGE_PRESETS, toLocalInput } from '../lib/time.js';
import { severityOf } from '../lib/format.js';

// ---- State primitives (shared with App.jsx) ---------------------------------

export function ErrorState({ error, title = 'Data could not be loaded', hint = 'Check integration connectivity and API permissions, then retry.' }) {
  return (
    <div className="error-panel">
      <div className="error-icon"><AlertTriangle size={19} /></div>
      <div><b>{title}</b><p>{typeof error === 'string' ? error : apiError(error)}</p>{hint && <small>{hint}</small>}</div>
    </div>
  );
}

export function Loading({ label = 'Loading live data…' }) {
  return <div className="loading-state"><span className="spinner" />{label}</div>;
}

export function Empty({ message, title = 'No data available' }) {
  return (
    <div className="empty-state">
      <div><Database size={18} /></div>
      <b>{title}</b>
      <span>{message}</span>
    </div>
  );
}

export function PanelTitle({ title, subtitle, tag, children }) {
  return (
    <div className="panel-title">
      <div><h3>{title}</h3>{subtitle && <p>{subtitle}</p>}</div>
      {children || (tag && <span className="panel-tag">{tag}</span>)}
    </div>
  );
}

export function PageHeading({ title, eyebrow = 'SECURITY OPERATIONS', description, children }) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow"><span className="heading-dot" /> {eyebrow} <span className="heading-slash">/</span> {title.toUpperCase()}</div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children && <div className="heading-actions">{children}</div>}
    </div>
  );
}

// ---- Badges --------------------------------------------------------------------

export function SeverityBadge({ level, severity }) {
  const band = severity || severityOf(level);
  return <span className={`severity-badge ${band}`}>{level ?? band}</span>;
}

const STATUS_TONES = {
  active: 'ok', completed: 'ok', connected: 'ok', sent: 'ok', passed: 'ok', 'not applicable': 'muted',
  deactivated: 'bad', invited: 'warn', pending_verification: 'warn', pending_approval: 'warn',
  disconnected: 'bad', failed: 'bad', email_failed: 'bad', never_connected: 'warn',
  paused: 'muted', expired: 'muted', pending: 'warn', queued: 'info', running: 'info', retrying: 'warn',
};

export function StatusPill({ status }) {
  return <span className={`status-pill ${STATUS_TONES[status] || 'muted'}`}><i />{String(status || 'unknown').replaceAll('_', ' ')}</span>;
}

// ---- Overlays ------------------------------------------------------------------

export function Modal({ title, eyebrow, onClose, children, wide = false, footer }) {
  useEffect(() => {
    const onKey = (event) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-scrim" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className={`modal-card ${wide ? 'modal-wide' : ''}`} role="dialog" aria-modal="true" aria-label={title}>
        <button type="button" className="icon-button modal-close" onClick={onClose} aria-label="Close"><X size={17} /></button>
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h2>{title}</h2>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-actions">{footer}</div>}
      </div>
    </div>
  );
}

export function Drawer({ title, eyebrow, onClose, children, actions }) {
  useEffect(() => {
    const onKey = (event) => event.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="drawer-scrim" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className="detail-drawer" role="dialog" aria-modal="true" aria-label={title}>
        <div className="drawer-head">
          <div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>
          <button className="icon-button" onClick={onClose} aria-label="Close"><X size={17} /></button>
        </div>
        <div className="drawer-body">{children}</div>
        {actions && <div className="drawer-actions">{actions}</div>}
      </aside>
    </div>
  );
}

// ---- Tables ---------------------------------------------------------------------

export function Pagination({ page, size, total, onPage, onSize, sizes = [25, 50, 100], maxWindow }) {
  const pages = Math.max(1, Math.ceil((maxWindow ? Math.min(total, maxWindow) : total) / size));
  const first = total ? (page - 1) * size + 1 : 0;
  const last = Math.min(page * size, total);
  return (
    <div className="pagination">
      <span>
        Showing {first.toLocaleString()}–{last.toLocaleString()} of {Number(total || 0).toLocaleString()}
        {maxWindow && total > maxWindow ? ` · first ${maxWindow.toLocaleString()} pageable` : ''}
      </span>
      <div>
        {onSize && (
          <select className="compact-select" value={size} onChange={(event) => onSize(Number(event.target.value))} aria-label="Rows per page">
            {sizes.map((value) => <option key={value} value={value}>{value} / page</option>)}
          </select>
        )}
        <button className="secondary" disabled={page <= 1} onClick={() => onPage(page - 1)}><ChevronLeft size={13} /> Previous</button>
        <span className="page-count">Page {page} of {pages.toLocaleString()}</span>
        <button className="secondary" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next <ChevronRight size={13} /></button>
      </div>
    </div>
  );
}

export function SortHeader({ label, field, sort, onSort }) {
  if (!field) return <th>{label}</th>;
  const active = sort.field === field;
  return (
    <th>
      <button className={`sort-header ${active ? 'active' : ''}`} onClick={() => onSort({ field, order: active && sort.order === 'desc' ? 'asc' : 'desc' })}>
        {label} {active ? (sort.order === 'desc' ? '↓' : '↑') : ''}
      </button>
    </th>
  );
}

// ---- Time range ----------------------------------------------------------------

export function TimeRangePicker({ value, onChange }) {
  const [draft, setDraft] = useState(() => ({
    from: value.from || toLocalInput(Date.now() - 86_400_000),
    to: value.to || toLocalInput(Date.now()),
  }));
  const invalid = value.preset === 'custom' && !(draft.from && draft.to && new Date(draft.from) < new Date(draft.to));
  return (
    <div className="time-range">
      <div className="range-picker">
        <Clock3 size={14} />
        <select value={value.preset} onChange={(event) => onChange(event.target.value === 'custom' ? { preset: 'custom', ...draft } : { preset: event.target.value })} aria-label="Time range">
          {RANGE_PRESETS.map((preset) => <option key={preset.key} value={preset.key}>{preset.label}</option>)}
        </select>
        <ChevronDown size={12} />
      </div>
      {value.preset === 'custom' && (
        <div className="custom-range">
          <input type="datetime-local" value={draft.from} max={draft.to} onChange={(event) => setDraft({ ...draft, from: event.target.value })} aria-label="Start" />
          <span>→</span>
          <input type="datetime-local" value={draft.to} min={draft.from} onChange={(event) => setDraft({ ...draft, to: event.target.value })} aria-label="End" />
          <button className="secondary" disabled={invalid} onClick={() => onChange({ preset: 'custom', ...draft })}>Apply</button>
        </div>
      )}
    </div>
  );
}

// ---- Form helpers ------------------------------------------------------------------

export function Field({ label, hint, children, className = '' }) {
  return (
    <label className={`field ${className}`}>
      <span className="field-label">{label}</span>
      {children}
      {hint && <small className="field-hint">{hint}</small>}
    </label>
  );
}

export function ChipToggle({ options, value, onChange, disabled }) {
  const toggle = (key) => onChange(value.includes(key) ? value.filter((item) => item !== key) : [...value, key]);
  return (
    <div className="chip-row">
      {options.map((option) => (
        <button type="button" key={option.key} disabled={disabled} className={`chip ${value.includes(option.key) ? 'on' : ''} ${option.tone || option.key}`} onClick={() => toggle(option.key)}>
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Segmented({ options, value, onChange }) {
  return (
    <div className="segmented" role="radiogroup">
      {options.map((option) => (
        <button type="button" role="radio" aria-checked={value === option.key} key={option.key} className={value === option.key ? 'on' : ''} onClick={() => onChange(option.key)}>
          {option.label}
        </button>
      ))}
    </div>
  );
}

// ---- Notifications --------------------------------------------------------------

const ToastContext = createContext({ notify: () => {} });

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const notify = useCallback((message, tone = 'ok') => {
    const id = Math.random().toString(36).slice(2);
    setToasts((current) => [...current, { id, message, tone }]);
    setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), tone === 'error' ? 7000 : 4000);
  }, []);
  const value = useMemo(() => ({ notify }), [notify]);
  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast ${toast.tone}`}>
            {toast.tone === 'error' ? <AlertTriangle size={15} /> : <CheckCircle2 size={15} />}
            <span>{toast.message}</span>
            <button className="icon-button" onClick={() => setToasts((current) => current.filter((item) => item.id !== toast.id))} aria-label="Dismiss"><X size={13} /></button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export const useToast = () => useContext(ToastContext);

// ---- Current user ------------------------------------------------------------------

// Backed by AuthProvider; kept for existing callers.
export function useCurrentUser() {
  const { user, can, status } = useAuth();
  return { user, can, loading: status === 'loading' };
}
