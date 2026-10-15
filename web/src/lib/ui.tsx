import { createContext, useContext, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { AlertCircle, CheckCircle, Loader, X } from 'react-feather';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { errorMessage } from './format';
import { getToken } from './api';

interface Notice {
  id: number;
  message: string;
  error: boolean;
}
interface Confirmation {
  title: string;
  message: string;
  label?: string;
  dangerous?: boolean;
  resolve: (value: boolean) => void;
}
interface UiState {
  notify: (message: string, error?: boolean) => void;
  confirm: (options: Omit<Confirmation, 'resolve'>) => Promise<boolean>;
  pending: boolean;
  markPending: (value: boolean) => void;
}
const UiContext = createContext<UiState | null>(null);
export const PENDING_KEY = 'routerd_pending_changes';

export function UiProvider({ children }: { children: ReactNode }) {
  const [notices, setNotices] = useState<Notice[]>([]);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [pending, setPending] = useState(
    localStorage.getItem(PENDING_KEY) === 'true',
  );
  const sequence = useRef(0);
  const session = useRef(getToken());
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  useEffect(() => () => timers.current.forEach(clearTimeout), []);
  useEffect(() => {
    const sync = () => {
      const token = getToken();
      if (token === session.current) return;
      session.current = token;
      confirmation?.resolve(false);
      setConfirmation(null);
      setNotices([]);
    };
    window.addEventListener('routerd-session', sync);
    window.addEventListener('storage', sync);
    return () => {
      window.removeEventListener('routerd-session', sync);
      window.removeEventListener('storage', sync);
    };
  }, [confirmation]);
  const notify = (message: string, error = false) => {
    const id = ++sequence.current;
    setNotices((current) => [...current.slice(-3), { id, message, error }]);
    const timeout = setTimeout(
      () => {
        timers.current.delete(timeout);
        setNotices((current) => current.filter((notice) => notice.id !== id));
      },
      error ? 15000 : 6500,
    );
    timers.current.add(timeout);
  };
  const close = (value: boolean) => {
    confirmation?.resolve(value);
    setConfirmation(null);
  };
  return (
    <UiContext.Provider
      value={{
        notify,
        pending,
        markPending: (value) => {
          setPending(value);
          localStorage.setItem(PENDING_KEY, String(value));
        },
        confirm: (options) =>
          new Promise((resolve) => setConfirmation({ ...options, resolve })),
      }}
    >
      {children}
      <div className="toasts" aria-live="polite" aria-relevant="additions">
        {notices.map((notice) => (
          <div
            className={`toast ${notice.error ? 'toast-error' : ''}`}
            key={notice.id}
            role={notice.error ? 'alert' : 'status'}
          >
            {notice.error ? (
              <AlertCircle size={19} />
            ) : (
              <CheckCircle size={19} />
            )}
            <span>{notice.message}</span>
            <button
              className="icon-button"
              aria-label="Dismiss notification"
              onClick={() =>
                setNotices((current) =>
                  current.filter((item) => item.id !== notice.id),
                )
              }
            >
              <X size={16} />
            </button>
          </div>
        ))}
      </div>
      {confirmation && (
        <Modal
          title={confirmation.title}
          description={confirmation.message}
          onClose={() => close(false)}
        >
          <div className="modal-actions">
            <button onClick={() => close(false)}>Cancel</button>
            <button
              className={confirmation.dangerous ? 'danger' : 'primary'}
              onClick={() => close(true)}
            >
              {confirmation.label ?? 'Confirm'}
            </button>
          </div>
        </Modal>
      )}
    </UiContext.Provider>
  );
}
export function useUi() {
  return useContext(UiContext)!;
}

export function useSave<Arguments>(
  operation: (args: Arguments) => Promise<unknown>,
  message = 'Configuration saved. Apply to activate.',
  pending = true,
) {
  const client = useQueryClient();
  const ui = useUi();
  return useMutation({
    mutationKey: ['write'],
    mutationFn: operation,
    onSuccess: async () => {
      if (pending) ui.markPending(true);
      ui.notify(message);
      await client.invalidateQueries();
    },
    onError: (error) => ui.notify(errorMessage(error), true),
  });
}

export function Modal({
  title,
  description,
  onClose,
  children,
  wide = false,
  busy = false,
  onEscapeKeyDown,
}: {
  title: string;
  description?: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  busy?: boolean;
  onEscapeKeyDown?: (event: KeyboardEvent) => void;
}) {
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className={`dialog ${wide ? 'dialog-wide' : ''}`}
          {...(!description ? { 'aria-describedby': undefined } : {})}
          onEscapeKeyDown={(event) => {
            if (busy) event.preventDefault();
            onEscapeKeyDown?.(event);
          }}
          onPointerDownOutside={(event) => event.preventDefault()}
        >
          <div className="dialog-header">
            <div>
              <Dialog.Title>{title}</Dialog.Title>
              {description && (
                <Dialog.Description>{description}</Dialog.Description>
              )}
            </div>
            <button
              className="icon-button"
              disabled={busy}
              onClick={onClose}
              aria-label="Close dialog"
            >
              <X size={20} />
            </button>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div>
        <div className="eyebrow">ROUTER CONTROL CENTER</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}
export function Card({
  title,
  subtitle,
  actions,
  children,
  className = '',
}: {
  title?: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <div className="card-header">
          <div>
            {title && <h2>{title}</h2>}
            {subtitle && <p>{subtitle}</p>}
          </div>
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}
export function Badge({
  children,
  tone = 'neutral',
}: {
  children: ReactNode;
  tone?: 'neutral' | 'success' | 'warning' | 'danger' | 'blue';
}) {
  return (
    <span className={`badge badge-${tone}`}>
      <span className="badge-dot" />
      {children}
    </span>
  );
}
export function Empty({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">◇</div>
      <h3>{title}</h3>
      {description && <p>{description}</p>}
      {action}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading" role="status">
      <Loader className="spin" size={22} />
      Loading router data…
    </div>
  );
}
export function ErrorState({
  error,
  retry,
}: {
  error: unknown;
  retry: () => void;
}) {
  return (
    <div className="error-state" role="alert">
      <AlertCircle size={20} />
      <div>
        <strong>Unable to load data</strong>
        <p>{errorMessage(error)}</p>
      </div>
      <button onClick={retry}>Retry</button>
    </div>
  );
}
export function QueryNotice({
  query,
}: {
  query: { isError: boolean; error: unknown; refetch: () => unknown };
}) {
  return query.isError ? (
    <ErrorState error={query.error} retry={() => void query.refetch()} />
  ) : null;
}
export function Table({
  columns,
  children,
}: {
  columns: string[];
  children: ReactNode;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column}>{column}</th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

let unsavedCount = 0;
export function canLeave() {
  return (
    !unsavedCount ||
    window.confirm(
      'Discard unsaved edits? Saved configuration will not be affected.',
    )
  );
}
export function useUnsaved(dirty: boolean) {
  useEffect(() => {
    if (!dirty) return;
    unsavedCount++;
    const handler = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', handler);
    return () => {
      unsavedCount--;
      window.removeEventListener('beforeunload', handler);
    };
  }, [dirty]);
}
