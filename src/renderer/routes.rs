use super::interfaces::NetworkFile;
use crate::config::{schema::InterfaceMethod, static_routes, Config};
use anyhow::{bail, Context, Result};

/// Add only saved routes to existing managed links. networkd owns their lifecycle.
pub fn append(config: &Config, files: &mut [NetworkFile]) -> Result<()> {
    let errors = static_routes::validate(config);
    if !errors.is_empty() {
        bail!(
            "invalid static routes: {}",
            errors
                .iter()
                .map(|error| format!("{}: {}", error.field, error.message))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    for route in config.routing.routes.iter().filter(|route| route.enabled) {
        let interface = config
            .interfaces
            .items
            .iter()
            .find(|interface| interface.name == route.interface)
            .context("route references an unconfigured interface")?;
        let name = if interface.method == InterfaceMethod::Pppoe {
            "ppp0"
        } else {
            &interface.name
        };
        let filename = format!("50-routerd-{name}.network");
        let file = files
            .iter_mut()
            .find(|file| file.filename == filename)
            .with_context(|| format!("no managed network file for route {}", route.id))?;
        let (network, prefix) = static_routes::destination(&route.destination)?;
        file.content.push_str(&format!(
            "\n# Static route {}\n[Route]\nDestination={network}/{prefix}\nTable={}\nMetric={}\n",
            route.id, route.table, route.metric
        ));
        if let Some(gateway) = &route.gateway {
            file.content.push_str(&format!("Gateway={gateway}\n"));
            if route.on_link {
                file.content.push_str("GatewayOnLink=yes\n");
            }
        } else if network.is_ipv4() {
            file.content.push_str("Scope=link\n");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::{routing::test_config, schema::InterfaceMethod, static_routes::test_route};

    #[test]
    fn routes_follow_interfaces_tables_and_enablement_without_new_network_files() {
        let mut config = test_config();
        let before = super::super::interfaces::render(&config).unwrap();
        config.routing.routes.push(test_route());
        let files = super::super::interfaces::render(&config).unwrap();
        assert_eq!(files.len(), before.len());
        let wan = files
            .iter()
            .find(|file| file.filename == "50-routerd-wan0.network")
            .unwrap();
        assert!(wan
            .content
            .contains("Destination=198.51.100.9/32\nTable=254\nMetric=100\nGateway=203.0.113.1"));
        config.interfaces.items[0].method = InterfaceMethod::Pppoe;
        config.routing.routes[0].gateway = None;
        config.routing.routes[0].table = 100;
        let files = super::super::interfaces::render(&config).unwrap();
        assert!(files
            .iter()
            .find(|file| file.filename == "50-routerd-ppp0.network")
            .unwrap()
            .content
            .contains("Destination=198.51.100.9/32\nTable=100\nMetric=100\nScope=link"));
        config.routing.routes[0].enabled = false;
        assert!(super::super::interfaces::render(&config)
            .unwrap()
            .iter()
            .all(|file| !file.content.contains("# Static route")));
        config.routing.routes[0].enabled = true;
        config.routing.routes[0].destination = "2001:db8:1::99/64".into();
        config.routing.routes[0].gateway = Some("fe80::1".into());
        config.routing.routes[0].on_link = true;
        let files = super::super::interfaces::render(&config).unwrap();
        assert!(files.iter().any(|file| file.content.contains("Destination=2001:db8:1::/64\nTable=100\nMetric=100\nGateway=fe80::1\nGatewayOnLink=yes")));
        config.routing.routes.clear();
        assert!(super::super::interfaces::render(&config)
            .unwrap()
            .iter()
            .all(|file| !file.content.contains("# Static route")));
    }
}
