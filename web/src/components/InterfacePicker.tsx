import { useLayoutEffect, useRef, useState } from 'react';
import { ChevronDown } from 'react-feather';
import { list } from '../lib/format';
import { interfaceOptions, toggleInterface } from '../lib/interfaces';
import { useConfig, useInterfaces } from '../lib/queries';

export function InterfacePicker({
  id,
  label,
  value,
  onChange,
  multiple = false,
  required,
  disabled,
  placeholder,
  describedBy,
  exclude,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  multiple?: boolean;
  required?: boolean;
  disabled?: boolean;
  placeholder?: string;
  describedBy?: string;
  exclude?: string;
}) {
  const [open, setOpen] = useState(false);
  const container = useRef<HTMLDivElement>(null);
  const [placement, setPlacement] = useState({ above: false, height: 240 });
  useLayoutEffect(() => {
    if (!open || !container.current) return;
    const bounds = container.current.getBoundingClientRect();
    const dialog = container.current
      .closest('[role="dialog"]')
      ?.getBoundingClientRect();
    const below =
      Math.min(window.innerHeight, dialog?.bottom ?? window.innerHeight) -
      bounds.bottom -
      14;
    const above = bounds.top - Math.max(0, dialog?.top ?? 0) - 14;
    const upwards = below < 240 && above > below;
    setPlacement({
      above: upwards,
      height: Math.max(80, Math.min(240, upwards ? above : below)),
    });
  }, [open]);
  const config = useConfig();
  const live = useInterfaces();
  const selected = list(value);
  const options = interfaceOptions(
    config.data?.interfaces.items,
    live.data?.interfaces,
    selected,
    exclude,
  );
  return (
    <div
      className="interface-picker"
      data-interface-picker-open={open}
      ref={container}
      onBlur={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false);
      }}
      onKeyDown={(event) => {
        if (event.key === 'Escape' && open) {
          event.preventDefault();
          event.stopPropagation();
          setOpen(false);
        }
      }}
    >
      <div className="interface-picker-control">
        <input
          id={id}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onFocus={() => setOpen(true)}
          placeholder={placeholder}
          required={required}
          disabled={disabled}
          autoComplete="off"
          spellCheck={false}
          aria-describedby={describedBy}
        />
        <button
          type="button"
          aria-label={`Choose ${label.toLowerCase()}`}
          aria-expanded={open}
          aria-controls={`${id}-options`}
          disabled={disabled}
          onClick={() => setOpen((current) => !current)}
        >
          <ChevronDown size={16} aria-hidden="true" />
        </button>
      </div>
      {open && (
        <div
          className="interface-picker-options"
          id={`${id}-options`}
          data-side={placement.above ? 'above' : 'below'}
          style={{ maxHeight: placement.height }}
        >
          <small>
            {multiple ? 'Select any interfaces' : 'Select one interface'} or
            type
            {multiple ? ' comma-separated names' : ' a custom name'} above.
          </small>
          <div
            className="interface-picker-list"
            role="group"
            aria-label={`${label} options`}
          >
            {options.map((option) => (
              <label key={option.name} className="interface-picker-option">
                <input
                  type="checkbox"
                  aria-label={option.name}
                  checked={selected.includes(option.name)}
                  disabled={disabled}
                  onChange={() =>
                    onChange(toggleInterface(value, option.name, multiple))
                  }
                />
                <span>
                  <strong>{option.name}</strong>
                  {option.label && <span> — {option.label}</span>}
                  <small>
                    {option.source}
                    {option.up !== undefined &&
                      ` · ${option.up ? 'Up' : 'Down'}`}
                  </small>
                </span>
              </label>
            ))}
          </div>
          {!options.length && (
            <small>No interfaces available yet. Enter a name above.</small>
          )}
          {(config.isError || live.isError) && (
            <small>
              Some suggestions are unavailable. Manual entry still works.
            </small>
          )}
        </div>
      )}
    </div>
  );
}
