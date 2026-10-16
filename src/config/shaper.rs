use super::{schema::InterfaceMethod, validator::ValidationError, Config};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Shaper {
    #[serde(default)]
    pub profiles: Vec<ShaperProfile>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShaperSide {
    #[default]
    Wan,
    Lan,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkLayer {
    #[default]
    None,
    Atm,
    Ptm,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShaperProfile {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub comment: String,
    pub interface: String,
    #[serde(default)]
    pub enabled: bool,
    /// WAN-facing egress is upload; LAN-facing egress is download.
    #[serde(default)]
    pub side: ShaperSide,
    /// Decimal kilobits per second; zero disables this direction.
    #[serde(default)]
    pub upload_kbit: u32,
    #[serde(default)]
    pub download_kbit: u32,
    #[serde(default = "nat_default")]
    pub nat: bool,
    #[serde(default)]
    pub overhead: i32,
    #[serde(default)]
    pub mpu: u16,
    #[serde(default)]
    pub link_layer: LinkLayer,
}
fn nat_default() -> bool {
    true
}
impl ShaperProfile {
    pub fn device<'a>(&'a self, config: &Config) -> &'a str {
        if config
            .interfaces
            .items
            .iter()
            .any(|i| i.name == self.interface && i.method == InterfaceMethod::Pppoe)
        {
            "ppp0"
        } else {
            &self.interface
        }
    }
    pub fn egress_rate(&self) -> u32 {
        if self.side == ShaperSide::Wan {
            self.upload_kbit
        } else {
            self.download_kbit
        }
    }
    pub fn ingress_rate(&self) -> u32 {
        if self.side == ShaperSide::Wan {
            self.download_kbit
        } else {
            self.upload_kbit
        }
    }
    pub fn ifb_name(&self) -> String {
        format!("rdsh{:08x}", self.id)
    }
    pub fn alias(&self) -> String {
        format!("routerd:shaper:{}", self.id)
    }
}
pub fn validate(config: &Config) -> Vec<ValidationError> {
    let mut errors = Vec::new();
    let mut ids = HashSet::new();
    let mut devices = HashSet::new();
    for (index, profile) in config.shaper.profiles.iter().enumerate() {
        let prefix = format!("shaper.profiles[{index}]");
        let mut error = |field: &str, message: &str| {
            errors.push(ValidationError {
                field: format!("{prefix}.{field}"),
                message: message.into(),
            })
        };
        if profile.id == 0 || !ids.insert(profile.id) {
            error("id", "must be nonzero and unique");
        }
        if !config
            .interfaces
            .items
            .iter()
            .any(|i| i.name == profile.interface)
        {
            error("interface", "must reference a configured interface");
        }
        if profile.interface == "lo" || profile.interface.starts_with("rdsh") {
            error(
                "interface",
                "loopback and managed IFB devices cannot be shaped",
            );
        }
        if profile.enabled && !devices.insert(profile.device(config)) {
            error(
                "interface",
                "only one enabled profile may target each resolved device",
            );
        }
        if profile.enabled && profile.upload_kbit == 0 && profile.download_kbit == 0 {
            error(
                "upload_kbit",
                "enable at least one direction with a nonzero rate",
            );
        }
        for (field, value) in [
            ("upload_kbit", profile.upload_kbit),
            ("download_kbit", profile.download_kbit),
        ] {
            if value > 100_000_000 {
                error(field, "must be at most 100000000 kbit/s");
            }
        }
        if !(-64..=256).contains(&profile.overhead) {
            error("overhead", "must be between -64 and 256 bytes");
        }
        if profile.mpu > 256 {
            error("mpu", "must be at most 256 bytes");
        }
    }
    errors
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn profile() -> ShaperProfile {
        serde_json::from_value(serde_json::json!({"id":1,"interface":"wan0","enabled":true,"upload_kbit":10000,"download_kbit":50000})).unwrap()
    }
    #[test]
    fn profile_defaults_rates_and_duplicate_device_validation() {
        let mut config = crate::config::routing::test_config();
        let mut p = profile();
        assert!(p.nat);
        assert_eq!((p.egress_rate(), p.ingress_rate()), (10000, 50000));
        p.side = ShaperSide::Lan;
        assert_eq!((p.egress_rate(), p.ingress_rate()), (50000, 10000));
        config.shaper.profiles = vec![p.clone()];
        assert!(validate(&config).is_empty());
        p.id = 2;
        config.shaper.profiles.push(p);
        assert!(validate(&config)
            .iter()
            .any(|e| e.field.ends_with("interface")));
        config.shaper.profiles[1].enabled = false;
        assert!(validate(&config).is_empty());
        config.shaper.profiles[0].overhead = 257;
        assert!(validate(&config)
            .iter()
            .any(|e| e.field.ends_with("overhead")));
        assert!(Shaper::default().profiles.is_empty());
    }
}
