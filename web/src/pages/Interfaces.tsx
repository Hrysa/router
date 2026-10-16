import { useState } from "react";
import { Edit2, Layers, Plus, Trash2 } from "react-feather";
import { encoded, write } from "../lib/api";
import { bytes, list, role } from "../lib/format";
import { useConfig, useInterfaces } from "../lib/queries";
import type { InterfaceConfig } from "../lib/types";
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
} from "../lib/ui";
import { checked, Editor, integer, raw, text } from "../components/Editor";
import type { Field, Values } from "../components/Editor";

const fields: Field[] = [
  {
    name: "name",
    label: "Interface name",
    required: true,
    placeholder: "eth0, br0, vlan10",
  },
  {
    name: "device_mtu", label: "Device MTU", type: "number", min: 1280, max: 9216,
    placeholder: "Default", hint: "Optional link MTU for this device. For PPPoE this is the parent device, separate from the tunnel MTU.",
  },
  {
    name: "mss_clamp_mtu", label: "TCP MSS path MTU", type: "number", min: 1280, max: 9216,
    placeholder: "Off", hint: "Optional cap in both directions. 1492 gives IPv4 MSS 1452 and IPv6 MSS 1432. Smaller advertised values are preserved. Applies to routed TCP, including router traffic; not bridge-only switching. For PPPoE this targets the tunnel and overrides its clamp setting.",
  },
  { name: "label", label: "Display label", placeholder: "Main uplink" },
  {
    name: "method",
    label: "Address method",
    type: "select",
    options: ["static", "dhcp", "pppoe"],
  },
  {
    name: "address",
    label: "Address / prefix",
    required: true,
    placeholder: "192.168.1.1/24",
    when: (values) => values.method === "static",
  },
  {
    name: "gateway",
    label: "Gateway",
    placeholder: "Leave empty for LAN",
    when: (values) => values.method === "static",
  },
  {
    name: "dns",
    label: "DNS servers",
    placeholder: "1.1.1.1, 9.9.9.9",
    when: (values) => values.method === "static",
  },
  {
    name: "return_routing",
    label: "WAN return routing",
    type: "toggle",
    hint: "Return incoming IPv4 connections through the same WAN. Enabled by default for static, DHCP and PPPoE WANs.",
    when: (values) => values.method !== "static" || Boolean(values.gateway),
  },
  {
    name: "return_route_table",
    label: "WAN return routing table",
    type: "number",
    min: 1,
    max: 65535,
    placeholder: "Automatic, or override (e.g. 100)",
    hint: "A stable table is allocated from the interface name. Overrides must be unique and unused (not 253–255 or a TPROXY table).",
    when: (values) => (values.method !== "static" || Boolean(values.gateway)) && values.return_routing !== false,
  },
  {
    name: "hostname",
    label: "DHCP client hostname",
    when: (values) => values.method === "dhcp",
  },
  {
    name: "username",
    label: "PPPoE username",
    required: true,
    when: (values) => values.method === "pppoe",
  },
  {
    name: "password",
    label: "PPPoE password",
    type: "password",
    required: true,
    when: (values) => values.method === "pppoe",
  },
  {
    name: "mtu",
    label: "PPPoE tunnel MTU",
    type: "number",
    min: 576,
    max: 1500,
    required: true,
    when: (values) => values.method === "pppoe",
  },
  {
    name: "keepalive_interval",
    label: "Keepalive interval (seconds)",
    type: "number",
    min: 0,
    max: 4294967295,
    required: true,
    when: (values) => values.method === "pppoe",
  },
  {
    name: "keepalive_failure",
    label: "Keepalive failure threshold",
    type: "number",
    min: 0,
    max: 4294967295,
    required: true,
    when: (values) => values.method === "pppoe",
  },
  {
    name: "mss_clamp",
    label: "Clamp TCP MSS",
    type: "toggle",
    when: (values) => values.method === "pppoe",
  },
  {
    name: "bridge_ports",
    label: "Bridge members",
    type: "interface",
    multiple: true,
    excludeField: "name",
    placeholder: "eth1, eth2",
    hint: "Choose members or enter names. Leave empty for a non-bridge.",
  },
  {
    name: "vlan_id",
    label: "VLAN ID",
    type: "number",
    min: 1,
    max: 4094,
    placeholder: "Optional",
  },
  {
    name: "parent",
    label: "VLAN parent",
    type: "interface",
    excludeField: "name",
    placeholder: "eth0",
    when: (values) => Boolean(values.vlan_id),
  },
];

function initial(iface?: InterfaceConfig): Values {
  return {
    name: iface?.name ?? "",
    device_mtu: iface?.mtu === undefined ? "" : String(iface.mtu),
    mss_clamp_mtu: iface?.mss_clamp_mtu === undefined ? "" : String(iface.mss_clamp_mtu),
    label: iface?.label ?? "",
    method: iface?.method ?? "static",
    address: iface?.static_config?.address ?? "",
    gateway: iface?.static_config?.gateway ?? "",
    return_routing: iface?.return_routing ?? true,
    return_route_table: iface?.return_route_table === undefined ? "" : String(iface.return_route_table),
    dns: iface?.static_config?.dns?.join(", ") ?? "",
    hostname: iface?.dhcp?.hostname ?? "",
    username: iface?.pppoe?.username ?? "",
    password: iface?.pppoe?.password ?? "",
    mtu: String(iface?.pppoe?.mtu ?? 1492),
    mss_clamp: iface?.pppoe?.mss_clamp ?? true,
    keepalive_interval: String(iface?.pppoe?.keepalive_interval ?? 10),
    keepalive_failure: String(iface?.pppoe?.keepalive_failure ?? 3),
    bridge_ports: iface?.bridge_ports?.join(", ") ?? "",
    vlan_id: iface?.vlan_id === undefined ? "" : String(iface.vlan_id),
    parent: iface?.parent ?? "",
  };
}
export function interfaceFromValues(
  values: Values,
  original?: InterfaceConfig,
): InterfaceConfig {
  const method = text(values, "method") as InterfaceConfig["method"];
  return {
    ...original,
    name: original?.name ?? text(values, "name"),
    mtu: text(values, "device_mtu") ? integer(values, "device_mtu", 1280, 9216) : undefined,
    mss_clamp_mtu: text(values, "mss_clamp_mtu") ? integer(values, "mss_clamp_mtu", 1280, 9216) : undefined,
    label: text(values, "label") || undefined,
    method,
    return_routing: (method !== "static" || text(values, "gateway"))
      ? values.return_routing !== false
      : undefined,
    return_route_table:
      (method !== "static" || text(values, "gateway")) && text(values, "return_route_table")
        ? integer(values, "return_route_table", 1, 65535)
        : undefined,
    static_config:
      method === "static"
        ? {
            ...original?.static_config,
            address: text(values, "address"),
            gateway: text(values, "gateway"),
            dns: list(text(values, "dns")),
          }
        : undefined,
    dhcp:
      method === "dhcp"
        ? { ...original?.dhcp, hostname: text(values, "hostname") || undefined }
        : undefined,
    pppoe:
      method === "pppoe"
        ? {
            ...original?.pppoe,
            username: text(values, "username"),
            password: raw(values, "password"),
            mtu: integer(values, "mtu", 576, 1500),
            mss_clamp: checked(values, "mss_clamp"),
            keepalive_interval: integer(
              values,
              "keepalive_interval",
              0,
              4294967295,
            ),
            keepalive_failure: integer(
              values,
              "keepalive_failure",
              0,
              4294967295,
            ),
          }
        : undefined,
    bridge_ports: list(text(values, "bridge_ports")),
    vlan_id: text(values, "vlan_id")
      ? integer(values, "vlan_id", 1, 4094)
      : undefined,
    parent: text(values, "vlan_id")
      ? text(values, "parent") || undefined
      : undefined,
  };
}

export function Interfaces() {
  const config = useConfig();
  const live = useInterfaces();
  const ui = useUi();
  const [editing, setEditing] = useState<InterfaceConfig | "new" | null>(null);
  const save = useSave(
    async ({
      original,
      values,
    }: {
      original?: InterfaceConfig;
      values: Values;
    }) =>
      write(
        original
          ? `/config/interfaces/${encoded(original.name)}`
          : "/config/interfaces",
        interfaceFromValues(values, original),
        original ? "PUT" : "POST",
      ),
  );
  const remove = useSave((name: string) =>
    write(`/config/interfaces/${encoded(name)}`, undefined, "DELETE"),
  );
  const items = config.data?.interfaces.items ?? [];
  return (
    <>
      <PageHeader
        title="Interfaces"
        actions={
          <button
            className="primary"
            onClick={() => setEditing("new")}
            disabled={!config.data}
          >
            <Plus size={17} />
            Add interface
          </button>
        }
      />
      <QueryNotice query={config} />
      <QueryNotice query={live} />
      <div className="summary-strip">
        <span>
          <Layers size={18} />
          <strong>{items.length}</strong> configured
        </span>
        <span>
          <i className="status-dot" />
          <strong>
            {live.data?.interfaces.filter((iface) => iface.up).length ?? "—"}
          </strong>{" "}
          live links up
        </span>
        <span>Changes take effect after Apply.</span>
      </div>
      <Card
        title="Configured interfaces"
        subtitle="Static, DHCP, PPPoE, bridges and VLANs"
      >
        {config.isPending ? (
          <Loading />
        ) : !items.length ? (
          <Empty
            title="Build your first connection"
            description="Add a WAN uplink or a static LAN interface to get started."
          />
        ) : (
          <Table
            columns={[
              "Interface",
              "Role / method",
              "Address",
              "Live link",
              "Actions",
            ]}
          >
            {items.map((iface) => {
              const detail = live.data?.interfaces.find(
                (item) => item.name === iface.name,
              );
              return (
                <tr key={iface.name}>
                  <td>
                    <div className="cell-title">
                      <span className="interface-symbol small-symbol">
                        <Layers size={18} />
                      </span>
                      <div>
                        <strong>{iface.label || iface.name}</strong>
                        <small className="mono">
                          {iface.name}
                          {iface.vlan_id ? ` · VLAN ${iface.vlan_id}` : ""}
                        </small>
                      </div>
                    </div>
                  </td>
                  <td>
                    <Badge tone="blue">{role(iface)}</Badge>
                    <small className="cell-detail">
                      {iface.method.toUpperCase()}
                    </small>
                  </td>
                  <td className="mono">
                    {iface.static_config?.address || "Automatic"}
                    {iface.static_config?.gateway && (
                      <small className="cell-detail">
                        via {iface.static_config.gateway}
                      </small>
                    )}
                  </td>
                  <td>
                    <Badge tone={detail?.up ? "success" : "neutral"}>
                      {detail ? (detail.up ? "Up" : "Down") : "Not detected"}
                    </Badge>
                    {detail && (
                      <small className="cell-detail">MTU {detail.mtu}</small>
                    )}
                  </td>
                  <td>
                    <div className="row-actions">
                      <button
                        className="icon-button"
                        aria-label={`Edit ${iface.name}`}
                        onClick={() => setEditing(iface)}
                      >
                        <Edit2 size={16} />
                      </button>
                      <button
                        className="icon-button danger-text"
                        disabled={remove.isPending}
                        aria-label={`Delete ${iface.name}`}
                        onClick={async () => {
                          if (
                            await ui.confirm({
                              title: `Delete ${iface.name}?`,
                              message:
                                "This removes the interface from saved configuration. Applying the change can disconnect devices or your management session.",
                              label: "Delete interface",
                              dangerous: true,
                            })
                          )
                            remove.mutate(iface.name);
                        }}
                      >
                        <Trash2 size={16} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>
      <Card
        title="Detected on the router"
        subtitle="Read-only system interfaces. Byte counters are cumulative."
      >
        <Table
          columns={[
            "Device",
            "Link",
            "MAC address",
            "MTU",
            "Received",
            "Transmitted",
          ]}
        >
          {live.data?.interfaces.map((iface) => (
            <tr key={iface.name}>
              <td className="mono">{iface.name}</td>
              <td>
                <Badge tone={iface.up ? "success" : "neutral"}>
                  {iface.up ? "Up" : "Down"}
                </Badge>
              </td>
              <td className="mono">{iface.mac || "—"}</td>
              <td>{iface.mtu}</td>
              <td>{bytes(iface.rx_bytes)}</td>
              <td>{bytes(iface.tx_bytes)}</td>
            </tr>
          ))}
        </Table>
        {live.data && !live.data.interfaces.length && (
          <Empty title="No interfaces detected" />
        )}
      </Card>
      {editing && (
        <Editor
          title={editing === "new" ? "Add interface" : `Edit ${editing.name}`}
          fields={fields.map((field) =>
            field.name === "name"
              ? { ...field, disabled: editing !== "new" }
              : field,
          )}
          initial={initial(editing === "new" ? undefined : editing)}
          onClose={() => setEditing(null)}
          onSave={(values) =>
            save.mutateAsync({
              values,
              original: editing === "new" ? undefined : editing,
            })
          }
        />
      )}
    </>
  );
}
