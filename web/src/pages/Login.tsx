import { useState } from 'react';
import { ArrowRight, Layers, Lock, Shield } from 'react-feather';
import { request, setToken, write } from '../lib/api';
import { useApi } from '../lib/queries';
import { errorMessage, passwordError } from '../lib/format';
import { ErrorState, Loading } from '../lib/ui';

export function Login() {
  const auth = useApi<{ password_configured: boolean }>('/auth/status');
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const setup = auth.data?.password_configured === false;
  return (
    <div className="login-page">
      <div className="login-intro">
        <div className="brand login-brand">
          <span className="brand-symbol">
            <Layers size={27} />
          </span>
          <span>
            routerd<span className="brand-caption">NETWORK CONSOLE</span>
          </span>
        </div>
        <div className="login-copy">
          <span className="eyebrow">A CLEARER VIEW OF YOUR NETWORK</span>
          <h1>
            Every connection.
            <br />
            One place.
          </h1>
          <p>A quieter workspace for the network that keeps you connected.</p>
          <div className="login-network" aria-hidden="true">
            <span className="network-node node-left">
              <MonitorGlyph />
            </span>
            <span className="network-hub">
              <Layers size={38} />
            </span>
            <span className="network-node node-right">
              <WifiGlyph />
            </span>
            <span className="network-node node-bottom">
              <Shield size={23} />
            </span>
          </div>
        </div>
        <p className="login-credit">
          Built for routerd. Inspired by Yacd-meta.
        </p>
      </div>
      <div className="login-form-side">
        <div className="login-form">
          <div className="login-lock">
            <Lock size={22} />
          </div>
          <h2>{setup ? 'Set up your console' : 'Welcome back'}</h2>
          <p>
            {setup
              ? 'Create an administrator password to secure your router.'
              : 'Sign in to manage your router.'}
          </p>
          {auth.isPending ? (
            <Loading />
          ) : auth.isError ? (
            <ErrorState error={auth.error} retry={() => void auth.refetch()} />
          ) : (
            <form
              onSubmit={async (event) => {
                event.preventDefault();
                setError('');
                const invalid = passwordError(password);
                if (invalid) {
                  setError(invalid);
                  return;
                }
                if (setup && password !== confirmation) {
                  setError('Passwords do not match.');
                  return;
                }
                setBusy(true);
                try {
                  if (setup) {
                    await write('/auth/setup', { password });
                    await auth.refetch();
                  }
                  const result = await request<{ token: string }>(
                    '/auth/login',
                    { method: 'POST', body: { password } },
                  );
                  setPassword('');
                  setConfirmation('');
                  setToken(result.token);
                } catch (failure) {
                  setError(errorMessage(failure));
                  void auth.refetch();
                } finally {
                  setBusy(false);
                }
              }}
            >
              <div className="field">
                <label htmlFor="password">Administrator password</label>
                <input
                  id="password"
                  autoFocus
                  type="password"
                  autoComplete={setup ? 'new-password' : 'current-password'}
                  required
                  value={password}
                  disabled={busy}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>
              {setup && (
                <div className="field">
                  <label htmlFor="confirm-password">Confirm password</label>
                  <input
                    id="confirm-password"
                    type="password"
                    autoComplete="new-password"
                    required
                    disabled={busy}
                    value={confirmation}
                    onChange={(event) => setConfirmation(event.target.value)}
                  />
                </div>
              )}
              {error && (
                <p className="form-error" role="alert">
                  {error}
                </p>
              )}
              <button className="primary login-submit" disabled={busy}>
                {busy
                  ? 'Connecting…'
                  : setup
                    ? 'Create password & sign in'
                    : 'Sign in'}
                <ArrowRight size={18} />
              </button>
            </form>
          )}
          <p className="login-security">
            <Shield size={15} />
            Use a trusted management network or HTTPS. Your password and
            configuration are sensitive.
          </p>
        </div>
      </div>
    </div>
  );
}
function MonitorGlyph() {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
    >
      <rect x="3" y="3" width="18" height="13" rx="2" />
      <path d="M8 21h8m-4-5v5" />
    </svg>
  );
}
function WifiGlyph() {
  return (
    <svg
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
    >
      <path d="M2 8a16 16 0 0 1 20 0M5 12a11 11 0 0 1 14 0m-10 4a5 5 0 0 1 6 0" />
      <circle cx="12" cy="20" r="1" />
    </svg>
  );
}
