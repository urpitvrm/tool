import { config } from '../config/index.js';
import { pool } from '../config/db.js';
import { renderTemplate, sendMail, smtpConfigured } from './email.service.js';

// Administrators can override the support contact in Application Settings (key auth.support_contact).
async function supportContact() {
  try {
    const { rows } = await pool.query("SELECT value FROM application_settings WHERE key = 'auth.support_contact'");
    const value = rows[0]?.value;
    if (typeof value === 'string' && value.trim()) return value.trim().slice(0, 200);
  } catch { /* fall back to environment */ }
  return config.auth.supportContact;
}

const when = (date = new Date()) => `${date.toISOString().replace('T', ' ').slice(0, 19)} UTC`;
const nameOf = (user) => user.full_name || user.username || 'there';
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

async function deliver(user, subject, template, data, textLines) {
  if (!smtpConfigured()) throw Object.assign(new Error('Email delivery is not configured on the server (SMTP).'), { status: 503, code: 'SMTP_NOT_CONFIGURED' });
  const shared = { appName: config.auth.appName, supportContact: await supportContact(), userName: nameOf(user), subject, preheader: textLines[0] };
  const html = await renderTemplate(template, { ...shared, ...data });
  const text = [`Hello ${nameOf(user)},`, '', ...textLines, '', `${config.auth.appName} will never ask for your password or verification code.`,
    ...(shared.supportContact ? [`Support: ${shared.supportContact}`] : [])].join('\n');
  return sendMail({ to: user.email, subject, html, text });
}

// ---- One-time codes (callers must treat failures as fatal) ---------------------------------------

export function sendLoginOtp(user, otp, client) {
  return deliver(user, `${config.auth.appName} sign-in code`, 'loginOtp',
    { otp, expiresMinutes: config.auth.otpMinutes, device: client.device, ip: client.ip, time: when() },
    [`Your sign-in code is ${otp}. It expires in ${config.auth.otpMinutes} minutes.`, `Requested from ${client.device} (${client.ip}).`, 'If you did not try to sign in, change your password immediately.']);
}

export function sendEmailVerificationOtp(user, otp) {
  return deliver(user, `Verify your email for ${config.auth.appName}`, 'emailVerification',
    { otp, expiresMinutes: config.auth.otpMinutes },
    [`Your email verification code is ${otp}. It expires in ${config.auth.otpMinutes} minutes.`]);
}

export function sendPasswordResetOtp(user, otp, client) {
  return deliver(user, `${config.auth.appName} password reset code`, 'passwordReset',
    { otp, expiresMinutes: config.auth.otpMinutes, device: client.device, ip: client.ip, time: when() },
    [`Your password reset code is ${otp}. It expires in ${config.auth.otpMinutes} minutes.`, 'If you did not ask to reset your password, ignore this email.']);
}

export function sendInvitation(user, { link, expiresAt, inviterName, roleName }) {
  return deliver(user, `You have been invited to ${config.auth.appName}`, 'accountInvitation',
    { link, expiresAt: when(expiresAt), inviterName: inviterName || 'An administrator', roleName, username: user.username },
    [`You have been invited to ${config.auth.appName} as ${roleName}. Username: ${user.username}.`, `Accept the invitation (expires ${when(expiresAt)}): ${link}`]);
}

// ---- Security notifications (best effort; failures are logged, never block the action) ----------

const NOTICES = {
  account_activated: { subject: 'Your account is active', heading: 'Account activated', accent: '#25a37e', message: 'Your account has been activated. You can now sign in.', advice: 'Sign in with your username or email and your password. A verification code will be emailed to you.' },
  account_deactivated: { subject: 'Your account has been deactivated', heading: 'Account deactivated', accent: '#d03b3b', message: 'An administrator deactivated your account and ended all of its sessions.', advice: 'If you think this is a mistake, contact your administrator.' },
  password_changed: { subject: 'Your password was changed', heading: 'Password changed', accent: '#ec835a', message: 'The password for your account was just changed.', advice: 'If you did not make this change, reset your password now and contact your security team.' },
  new_login: { subject: 'New sign-in to your account', heading: 'New sign-in', accent: '#4b8ee0', message: 'Your account was just used to sign in.', advice: 'If this was you, no action is needed. If not, change your password and sign out all sessions.' },
  suspicious_login: { subject: 'Sign-in from a new device or location', heading: 'Unrecognized sign-in', accent: '#d03b3b', message: 'Your account signed in from a device or IP address it has not used recently.', advice: 'If this was not you, change your password immediately, sign out all sessions from the Sessions page and contact your security team.' },
  account_locked: { subject: 'Your account has been temporarily locked', heading: 'Account locked', accent: '#d03b3b', message: 'Your account was locked after repeated failed sign-in attempts.', advice: 'It unlocks automatically after the time shown below. If these attempts were not yours, someone may be trying to access your account; contact your security team.' },
};

export async function sendSecurityNotice(user, kind, details = {}) {
  const notice = NOTICES[kind];
  if (!notice || !user?.email || !smtpConfigured()) return;
  const rows = Object.entries(details).filter(([, value]) => value);
  const detailsTable = rows.length
    ? `<table role="presentation" cellpadding="0" cellspacing="0" style="font-size:13px">${rows.map(([label, value]) => `<tr><td style="padding:3px 14px 3px 0;color:#64748b">${escape(label)}</td><td>${escape(value)}</td></tr>`).join('')}</table>`
    : '';
  try {
    await deliver(user, `${config.auth.appName}: ${notice.subject}`, 'securityNotification',
      { ...notice, detailsTable, link: kind === 'account_activated' ? `${config.publicBaseUrl}/login` : '', linkText: 'Sign in' },
      [notice.message, ...rows.map(([label, value]) => `${label}: ${value}`), notice.advice]);
  } catch (error) {
    console.error(`Security notification "${kind}" could not be sent: ${error.code || error.message}`);
  }
}

export const loginDetails = (client, extra = {}) => ({ Time: when(), Device: client.device, 'IP address': client.ip, ...extra });
