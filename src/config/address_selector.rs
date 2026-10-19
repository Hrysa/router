use super::schema::NftSet;

/// Address-match syntax shared by validation and rendering. Translation targets
/// are single addresses and must not use this selector grammar.
#[derive(Debug, PartialEq, Eq)]
pub enum AddressSelector<'a> {
    Local,
    Set(&'a str),
    Network(&'a str),
}

impl<'a> AddressSelector<'a> {
    pub fn parse(value: &'a str) -> Self {
        if value == "@local" {
            Self::Local
        } else if let Some(name) = value.strip_prefix('@') {
            Self::Set(name)
        } else {
            Self::Network(value)
        }
    }

    pub fn supports_ipv4(&self, sets: &[NftSet]) -> bool {
        match self {
            Self::Local => true,
            Self::Set(name) => sets
                .iter()
                .any(|set| set.name == *name && set.set_type == "ipv4_addr"),
            Self::Network(value) => {
                super::static_routes::destination(value).is_ok_and(|(network, _)| network.is_ipv4())
            }
        }
    }
}
