import { useState } from 'react';
import { useIsMutating, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle,
  FileText,
  RotateCcw,
  Shield,
} from 'react-feather';
import { encoded, getConfig, write } from '../lib/api';
import { bytes } from '../lib/format';
import { useApi } from '../lib/queries';
import type { ApplyResult, Backup } from '../lib/types';
import {
  Badge,
  Card,
  Empty,
  Loading,
  PageHeader,
  QueryNotice,
  Table,
  useSave,
  useUi,
} from '../lib/ui';

export function Backups() {
  const backups = useApi<{ backups: Backup[] }>('/config/backups');
  const ui = useUi();
  const client = useQueryClient();
  const writes = useIsMutating({ mutationKey: ['write'] });
  const [validation, setValidation] = useState<{
    valid: boolean;
    errors: { field: string; message: string }[];
  } | null>(null);
  const validate = useSave(
    async () => {
      const fresh = await getConfig();
      const result = await write<{
        valid: boolean;
        errors: { field: string; message: string }[];
      }>('/config/validate', fresh);
      setValidation(result);
    },
    'Schema validation completed. This does not apply configuration.',
    false,
  );
  const restore = useSave(
    async (id: string) => {
      const result = await write<ApplyResult>(
        `/config/backups/${encoded(id)}/restore`,
      );
      if (!result.success || result.errors?.length)
        throw new Error(
          result.errors?.join('\n') ||
            'Restore did not complete. Check the router for partial changes.',
        );
      ui.markPending(false);
      setValidation(null);
      client.removeQueries({ queryKey: ['/config'] });
    },
    'Backup restored and applied. If authentication changed, sign in again.',
    false,
  );
  return (
    <>
      <PageHeader
        title="Configuration"
        actions={
          <button disabled={writes > 0} onClick={() => validate.mutate()}>
            <Shield size={16} />
            {validate.isPending ? 'Validating…' : 'Validate saved config'}
          </button>
        }
      />
      <div className="config-info-grid">
        <Card>
          <span className="stat-icon blue">
            <FileText size={21} />
          </span>
          <h2>Save is not Apply</h2>
          <p>
            Editors save configuration on the router. Use Apply changes to
            reconcile services and the live firewall. The saved indicator only
            tracks saves made in this browser.
          </p>
          <Badge tone={ui.pending ? 'warning' : 'neutral'}>
            {ui.pending
              ? 'Saved changes not applied here'
              : 'No locally tracked pending saves'}
          </Badge>
        </Card>
        <Card>
          <span className="stat-icon amber">
            <RotateCcw size={21} />
          </span>
          <h2>Restore acts immediately</h2>
          <p>
            Restoring a backup replaces saved configuration and immediately
            applies it. The current configuration is backed up first. Failed
            apply is not automatically rolled back.
          </p>
        </Card>
      </div>
      {validation && (
        <div
          className={validation.valid ? 'success-banner' : 'warning-banner'}
          role="status"
        >
          {validation.valid ? (
            <CheckCircle size={20} />
          ) : (
            <AlertTriangle size={20} />
          )}
          <div>
            <strong>
              {validation.valid
                ? 'Saved configuration passes schema validation.'
                : 'Configuration needs attention.'}
            </strong>
            {validation.errors?.map((error, index) => (
              <p key={`${error.field}-${index}`}>
                {error.field}: {error.message}
              </p>
            ))}
            <p>
              Live apply also runs staged nftables validation and Kea validation
              when installed.
            </p>
          </div>
        </div>
      )}
      <QueryNotice query={backups} />
      <Card
        title="Configuration backups"
        subtitle="Snapshots created when the router configuration changes"
      >
        {backups.isPending ? (
          <Loading />
        ) : backups.data?.backups.length ? (
          <Table columns={['Snapshot', 'Created', 'Size', 'Actions']}>
            {backups.data.backups.map((backup) => (
              <tr key={backup.id}>
                <td className="mono">{backup.id}</td>
                <td>{new Date(backup.created).toLocaleString()}</td>
                <td>{bytes(backup.size)}</td>
                <td>
                  <button
                    disabled={writes > 0}
                    className="danger-text"
                    onClick={async () => {
                      if (
                        await ui.confirm({
                          title: 'Restore and apply this backup?',
                          message: `Restore ${backup.id}? This immediately changes live networking, firewall rules, services and possibly authentication. You may lose access. Failure can leave partial changes.`,
                          label: 'Restore & apply',
                          dangerous: true,
                        })
                      )
                        restore.mutate(backup.id);
                    }}
                  >
                    <RotateCcw size={15} />
                    Restore & apply
                  </button>
                </td>
              </tr>
            ))}
          </Table>
        ) : (
          <Empty
            title="No backups yet"
            description="Backups appear as configuration changes are saved on the router."
          />
        )}
      </Card>
    </>
  );
}
