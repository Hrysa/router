import { useState } from 'react';
import { Save } from 'react-feather';
import { Modal, useUnsaved } from '../lib/ui';
import { errorMessage } from '../lib/format';
import { InterfacePicker } from './InterfacePicker';

export type Values = Record<string, string | boolean>;
export interface Field {
  name: string;
  label: string;
  type?:
    | 'text'
    | 'password'
    | 'number'
    | 'select'
    | 'textarea'
    | 'toggle'
    | 'interface';
  multiple?: boolean;
  excludeField?: string;
  options?: string[];
  placeholder?: string;
  hint?: string;
  required?: boolean;
  disabled?: boolean;
  min?: number;
  max?: number;
  wide?: boolean;
  when?: (values: Values) => boolean;
  list?: string;
}
export const text = (values: Values, key: string) =>
  String(values[key] ?? '').trim();
export const raw = (values: Values, key: string) => String(values[key] ?? '');
export const checked = (values: Values, key: string) => values[key] === true;
export function integer(
  values: Values,
  key: string,
  min: number,
  max: number,
): number {
  const value = text(values, key);
  const number = Number(value);
  if (
    !/^\d+$/.test(value) ||
    !Number.isSafeInteger(number) ||
    number < min ||
    number > max
  )
    throw new Error(`${key} must be a whole number between ${min} and ${max}.`);
  return number;
}

export function Editor({
  title,
  fields,
  initial,
  onSave,
  onClose,
  description = 'Save changes to configuration. Apply separately to activate.',
}: {
  title: string;
  fields: Field[];
  initial: Values;
  onSave: (values: Values) => Promise<unknown>;
  onClose: () => void;
  description?: string;
}) {
  const [baseline] = useState(initial);
  const [values, setValues] = useState(initial);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const dirty = JSON.stringify(values) !== JSON.stringify(baseline);
  useUnsaved(dirty);
  const close = () => {
    if (!busy && (!dirty || window.confirm('Discard unsaved edits?')))
      onClose();
  };
  return (
    <Modal
      title={title}
      description={description}
      onClose={close}
      busy={busy}
      onEscapeKeyDown={(event) => {
        if (
          event.target instanceof Element &&
          event.target.closest('[data-interface-picker-open="true"]')
        )
          event.preventDefault();
      }}
      wide
    >
      <form
        onSubmit={async (event) => {
          event.preventDefault();
          setError('');
          setBusy(true);
          try {
            await onSave(values);
            onClose();
          } catch (failure) {
            setError(errorMessage(failure));
          } finally {
            setBusy(false);
          }
        }}
      >
        <fieldset disabled={busy} className="form-grid">
          {fields
            .filter((field) => !field.when || field.when(values))
            .map((field) => {
              const id = `edit-${field.name}`;
              const update = (value: string | boolean) =>
                setValues((current) => ({ ...current, [field.name]: value }));
              if (field.type === 'toggle')
                return (
                  <label
                    key={field.name}
                    className={`toggle-field ${field.wide ? 'field-wide' : ''}`}
                  >
                    <input
                      type="checkbox"
                      checked={checked(values, field.name)}
                      onChange={(event) => update(event.target.checked)}
                    />
                    <span>
                      {field.label}
                      {field.hint && <small>{field.hint}</small>}
                    </span>
                  </label>
                );
              return (
                <div
                  className={`field ${field.wide ? 'field-wide' : ''}`}
                  key={field.name}
                >
                  <label htmlFor={id}>
                    {field.label}
                    {field.required && <span className="required"> *</span>}
                  </label>
                  {field.type === 'interface' ? (
                    <InterfacePicker
                      id={id}
                      label={field.label}
                      value={raw(values, field.name)}
                      onChange={update}
                      multiple={field.multiple}
                      required={field.required}
                      disabled={field.disabled}
                      placeholder={field.placeholder}
                      describedBy={field.hint ? `${id}-hint` : undefined}
                      exclude={
                        field.excludeField
                          ? text(values, field.excludeField)
                          : undefined
                      }
                    />
                  ) : field.type === 'select' ? (
                    <select
                      id={id}
                      value={raw(values, field.name)}
                      onChange={(event) => update(event.target.value)}
                      required={field.required}
                      disabled={field.disabled}
                    >
                      {field.options?.map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </select>
                  ) : field.type === 'textarea' ? (
                    <textarea
                      id={id}
                      rows={5}
                      value={raw(values, field.name)}
                      onChange={(event) => update(event.target.value)}
                      placeholder={field.placeholder}
                      required={field.required}
                      spellCheck={false}
                    />
                  ) : (
                    <input
                      id={id}
                      type={field.type ?? 'text'}
                      value={raw(values, field.name)}
                      onChange={(event) => update(event.target.value)}
                      placeholder={field.placeholder}
                      required={field.required}
                      disabled={field.disabled}
                      min={field.min}
                      max={field.max}
                      list={field.list}
                      autoComplete={
                        field.type === 'password' ? 'new-password' : 'off'
                      }
                    />
                  )}
                  {field.hint && <small id={`${id}-hint`}>{field.hint}</small>}
                </div>
              );
            })}
        </fieldset>
        {error && (
          <p className="form-error" role="alert">
            {error}
          </p>
        )}
        <div className="modal-actions">
          <button type="button" disabled={busy} onClick={close}>
            Cancel
          </button>
          <button className="primary" disabled={busy} type="submit">
            <Save size={16} />
            {busy ? 'Saving…' : 'Save configuration'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
