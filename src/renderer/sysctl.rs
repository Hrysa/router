use crate::config::schema::*;
use anyhow::Result;

/// Render sysctl.conf from config — just returns the raw content.
pub fn render(config: &Config) -> Result<String> {
    Ok(config.advanced.sysctl.content.clone())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_default() {
        let config = Config::default();
        let output = render(&config).unwrap();
        assert!(output.contains("net.ipv4.ip_forward = 1"));
        assert!(output.contains("net.ipv6.conf.all.forwarding = 1"));
        assert!(output.contains("net.ipv4.conf.default.rp_filter = 2"));
    }
}
