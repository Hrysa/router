import { Play, RotateCw, Server, Square } from 'react-feather';
import { encoded, write } from '../lib/api';
import { useServices } from '../lib/queries';
import {
  Badge,
  Card,
  Empty,
  Loading,
  PageHeader,
  QueryNotice,
  useSave,
  useUi,
} from '../lib/ui';

export function Services() {
  const services = useServices();
  const ui = useUi();
  const action = useSave(
    ({ name, command }: { name: string; command: string }) =>
      write(`/service/${encoded(name)}/${command}`),
    'Service command completed.',
  );
  const control = async (name: string, display: string, command: string) => {
    if (
      await ui.confirm({
        title: `${command[0].toUpperCase()}${command.slice(1)} ${display}?`,
        message:
          'This acts on the running service immediately, not saved configuration. Network services can disconnect clients and your management session.',
        label: `${command[0].toUpperCase()}${command.slice(1)} service`,
        dangerous: true,
      })
    )
      action.mutate({ name, command });
  };
  return (
    <>
      <PageHeader title="Services" />
      <div className="info-banner">
        <Server size={19} />
        <p>
          Service controls act immediately. They do not wait for Apply or change
          which services are enabled in configuration.
        </p>
      </div>
      <QueryNotice query={services} />
      {services.isPending ? (
        <Loading />
      ) : services.data?.services.length ? (
        <div className="services-grid">
          {services.data.services.map((service) => (
            <Card key={service.name} className="service-card">
              <div className="service-heading">
                <span
                  className={`stat-icon ${service.active ? 'teal' : 'neutral'}`}
                >
                  <Server size={21} />
                </span>
                <Badge tone={service.active ? 'success' : 'neutral'}>
                  {service.active ? 'Running' : 'Inactive'}
                </Badge>
              </div>
              <h2>{service.display_name}</h2>
              <p className="mono service-unit">{service.name}</p>
              <dl className="details-list">
                <div>
                  <dt>Status</dt>
                  <dd>{service.status || 'Unknown'}</dd>
                </div>
                <div>
                  <dt>Process ID</dt>
                  <dd className="mono">{service.pid || '—'}</dd>
                </div>
              </dl>
              <div className="service-actions">
                <button
                  disabled={action.isPending || service.active}
                  onClick={() =>
                    void control(service.name, service.display_name, 'start')
                  }
                >
                  <Play size={14} />
                  Start
                </button>
                <button
                  disabled={action.isPending || !service.active}
                  onClick={() =>
                    void control(service.name, service.display_name, 'restart')
                  }
                >
                  <RotateCw size={14} />
                  Restart
                </button>
                <button
                  className="danger-text"
                  disabled={action.isPending || !service.active}
                  onClick={() =>
                    void control(service.name, service.display_name, 'stop')
                  }
                >
                  <Square size={14} />
                  Stop
                </button>
              </div>
            </Card>
          ))}
        </div>
      ) : (
        <Empty title="No managed services reported" />
      )}
    </>
  );
}
