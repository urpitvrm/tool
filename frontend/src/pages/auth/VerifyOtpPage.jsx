import React, { useState } from 'react';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { ChevronRight, RotateCcw } from 'lucide-react';
import { api, apiCode, apiError } from '../../api.js';
import { pendingChallenge, useAuth } from '../../auth/AuthContext.jsx';
import { AuthLayout, formatSeconds, Notice, OtpInput, useCountdown } from '../../auth/components.jsx';

const COPY = {
  login: { title: 'Check your email', endpoint: '/auth/verify-login-otp', eyebrow: 'TWO-STEP VERIFICATION', intro: 'We sent a 6-digit sign-in code to' },
  email: { title: 'Verify your email', endpoint: '/auth/verify-email', eyebrow: 'EMAIL VERIFICATION', intro: 'Confirm your email address. We sent a 6-digit code to' },
};

/** Login OTP (/verify-otp) and email verification (/verify-email). */
export default function VerifyOtpPage({ mode = 'login' }) {
  const navigate = useNavigate();
  const { signedIn } = useAuth();
  const [challenge, setChallenge] = useState(() => pendingChallenge.get());
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState('');
  const [busy, setBusy] = useState(false);
  const expiresIn = useCountdown(challenge?.expires_at);
  const resendIn = useCountdown(challenge?.resend_available_at);
  const copy = COPY[mode];

  if (!challenge || challenge.flow !== mode) return <Navigate to="/login" replace />;

  async function verify(code = otp) {
    if (code.length !== 6 || busy) return;
    setBusy(true);
    setError('');
    try {
      const { data } = await api.post(copy.endpoint, { challenge_id: challenge.challenge_id, otp: code });
      if (data.status === 'authenticated') { signedIn(data.user); navigate('/', { replace: true }); return; }
      pendingChallenge.clear();
      navigate('/login', { replace: true, state: { notice: data.message } });
    } catch (requestError) {
      setError(apiError(requestError));
      setOtp('');
      if (['OTP_ATTEMPTS_EXCEEDED', 'ACCOUNT_LOCKED'].includes(apiCode(requestError))) setChallenge({ ...challenge, exhausted: true });
    } finally {
      setBusy(false);
    }
  }

  async function resend() {
    setError('');
    setInfo('');
    try {
      const { data } = await api.post('/auth/resend-otp', { challenge_id: challenge.challenge_id });
      const next = { ...data.challenge, flow: mode, identifier: challenge.identifier };
      pendingChallenge.set(next);
      setChallenge(next);
      setOtp('');
      setInfo('A new code was sent. Earlier codes no longer work.');
    } catch (requestError) {
      setError(apiError(requestError));
    }
  }

  const expired = expiresIn === 0 || challenge.exhausted;
  return (
    <AuthLayout eyebrow={copy.eyebrow} title={copy.title} subtitle={<>{copy.intro} <b>{challenge.destination || 'your email address'}</b>.</>}>
      <form className="auth-form" onSubmit={(event) => { event.preventDefault(); verify(); }}>
        <OtpInput value={otp} onChange={setOtp} onComplete={verify} disabled={busy || expired} />
        <div className={`otp-timer ${expiresIn < 60 ? 'warn' : ''}`}>
          {expired ? 'This code can no longer be used. Request a new one.' : <>Code expires in <b>{formatSeconds(expiresIn)}</b> · {challenge.max_attempts} attempts allowed</>}
        </div>
        <Notice>{error}</Notice>
        <Notice tone="info">{info}</Notice>
        <button className="primary wide" disabled={busy || otp.length !== 6 || expired}>{busy ? 'Verifying…' : 'Verify'} <ChevronRight size={16} /></button>
        <div className="auth-row">
          <button type="button" className="text-button" disabled={resendIn > 0} onClick={resend}>
            <RotateCcw size={12} /> {resendIn > 0 ? `Resend code in ${resendIn}s` : 'Resend code'}
          </button>
          <Link className="text-button" to="/login" onClick={() => pendingChallenge.clear()}>Use a different account</Link>
        </div>
        <p className="auth-hint">Didn't get it? Check spam or quarantine folders. Never share this code. Our team will never ask for it.</p>
      </form>
    </AuthLayout>
  );
}
