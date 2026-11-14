import nodemailer from 'nodemailer';
import { config } from '../config/index.js';

let transport;

export function smtpConfigured() {
  return Boolean(config.smtp.host && config.smtp.from);
}

function transporter() {
  if (!smtpConfigured()) {
    throw Object.assign(new Error('SMTP is not configured (SMTP_HOST and SMTP_FROM are required).'), { status: 503, permanent: true });
  }
  if (!transport) {
    transport = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.password } : undefined,
      tls: { rejectUnauthorized: config.smtp.verifyTls },
      pool: true,
      maxConnections: 3,
      connectionTimeout: 15_000,
      greetingTimeout: 10_000,
      socketTimeout: 60_000,
    });
  }
  return transport;
}

/** Network problems and SMTP 4xx replies are worth retrying; auth, envelope and 5xx errors are not. */
export function isTransientEmailError(error) {
  if (error?.permanent) return false;
  if (['ECONNECTION', 'ETIMEDOUT', 'ESOCKET', 'ECONNRESET', 'EDNS', 'ECONNREFUSED'].includes(error?.code)) return true;
  const responseCode = Number(error?.responseCode);
  if (responseCode >= 400 && responseCode < 500) return true;
  return false;
}

/** Enforce REPORT_EMAIL_ALLOWED_DOMAINS when configured. */
export function assertAllowedRecipients(addresses) {
  const allowed = config.reports.allowedEmailDomains;
  if (!allowed.length) return;
  const rejected = addresses.filter((address) => {
    const domain = String(address).split('@').pop().toLowerCase();
    return !allowed.some((entry) => domain === entry || domain.endsWith(`.${entry}`));
  });
  if (rejected.length) {
    throw Object.assign(new Error(`Recipients outside the allowed email domains: ${rejected.join(', ')}`), { status: 422 });
  }
}

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

function emailBodies({ message, report, downloadUrl, linkExpiresAt }) {
  const details = [
    ['Report', report.name],
    ['Type', report.typeLabel],
    ['Period', report.period],
    ['Format', String(report.format).toUpperCase()],
  ];
  const text = [
    message || 'Your scheduled security report is ready.',
    '',
    ...details.map(([label, value]) => `${label}: ${value}`),
    ...(downloadUrl ? ['', `Download (expires ${linkExpiresAt}): ${downloadUrl}`] : ['', 'The report is attached to this email.']),
    '',
    'This message was generated automatically by Sentinel SOC. The report may contain sensitive security information.',
  ].join('\n');

  const html = `<!doctype html><html><body style="font-family:Arial,Helvetica,sans-serif;color:#0f172a;background:#f8fafc;padding:24px">
  <table role="presentation" style="max-width:600px;margin:auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:8px" cellpadding="0" cellspacing="0" width="100%">
    <tr><td style="background:#1e293b;color:#ffffff;padding:18px 24px;border-radius:8px 8px 0 0;border-bottom:3px solid #20a383">
      <div style="font-size:11px;color:#94a3b8;letter-spacing:1px">SENTINEL SOC</div>
      <div style="font-size:18px;font-weight:bold;margin-top:4px">${escapeHtml(report.name)}</div></td></tr>
    <tr><td style="padding:20px 24px;font-size:14px;line-height:1.5">
      <p style="margin:0 0 16px;white-space:pre-line">${escapeHtml(message || 'Your scheduled security report is ready.')}</p>
      <table role="presentation" style="font-size:13px;border-collapse:collapse">${details.map(([label, value]) => `<tr><td style="color:#64748b;padding:3px 16px 3px 0">${escapeHtml(label)}</td><td>${escapeHtml(value)}</td></tr>`).join('')}</table>
      ${downloadUrl
    ? `<p style="margin:20px 0 4px"><a href="${escapeHtml(downloadUrl)}" style="background:#20a383;color:#ffffff;padding:10px 18px;border-radius:6px;text-decoration:none;display:inline-block">Download report</a></p><p style="font-size:12px;color:#64748b">The link expires ${escapeHtml(linkExpiresAt)}.</p>`
    : '<p style="margin:20px 0 0;font-size:13px">The report is attached to this email.</p>'}
    </td></tr>
    <tr><td style="padding:12px 24px;font-size:11px;color:#94a3b8;border-top:1px solid #e2e8f0">Generated automatically by Sentinel SOC. This report may contain sensitive security information; do not forward it outside your organization.</td></tr>
  </table></body></html>`;
  return { text, html };
}

/**
 * Send a report email. Returns the SMTP message id.
 * report: { name, typeLabel, period, format }
 */
export async function sendReportEmail({ to, cc = [], bcc = [], subject, message, report, attachment, downloadUrl, linkExpiresAt }) {
  const { text, html } = emailBodies({ message, report, downloadUrl, linkExpiresAt });
  const info = await transporter().sendMail({
    from: config.smtp.from,
    to,
    cc: cc.length ? cc : undefined,
    bcc: bcc.length ? bcc : undefined,
    subject,
    text,
    html,
    attachments: attachment ? [attachment] : [],
  });
  return info.messageId;
}

export async function verifySmtp() {
  await transporter().verify();
  return true;
}

// ---- Templated mail (authentication and account notifications) -----------------------------

const templateCache = new Map();
const templateDir = new URL('../templates/', import.meta.url);

async function loadTemplate(name) {
  if (!templateCache.has(name)) {
    const { readFile } = await import('node:fs/promises');
    templateCache.set(name, await readFile(new URL(`${name}.html`, templateDir), 'utf8'));
  }
  return templateCache.get(name);
}

/** Minimal mustache-style rendering: {{value}} escaped, {{{value}}} raw, {{#key}}…{{/key}} conditional. */
export function renderTemplateString(template, data) {
  return template
    .replace(/\{\{#(\w+)\}\}([\s\S]*?)\{\{\/\1\}\}/g, (_match, key, inner) => (data[key] ? inner : ''))
    .replace(/\{\{\{(\w+)\}\}\}/g, (_match, key) => String(data[key] ?? ''))
    .replace(/\{\{(\w+)\}\}/g, (_match, key) => escapeHtml(data[key]));
}

export async function renderTemplate(name, data) {
  const content = renderTemplateString(await loadTemplate(name), data);
  return renderTemplateString(await loadTemplate('layout'), { ...data, content });
}

/** Send one HTML + text email. Throws on delivery failure; callers decide whether that is fatal. */
export async function sendMail({ to, subject, html, text }) {
  const info = await transporter().sendMail({ from: config.smtp.from, to, subject, html, text });
  return info.messageId;
}
