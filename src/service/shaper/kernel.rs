use super::netlink::*;
use crate::config::shaper::{LinkLayer, ShaperProfile, ShaperSide};
use anyhow::{ensure, Context, Result};
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Link {
    pub index: u32,
    pub mtu: u32,
    pub name: String,
    pub alias: String,
    pub kind: String,
}
#[derive(Debug, Clone)]
pub struct Qdisc {
    pub index: u32,
    pub handle: u32,
    pub parent: u32,
    pub kind: String,
    pub options: Vec<u8>,
    pub stats: Stats,
}
#[derive(Debug, Clone)]
pub struct Filter {
    pub handle: u32,
    pub chain: u32,
    pub info: u32,
    pub kind: String,
    pub options: Vec<u8>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Stats {
    pub bytes: u64,
    pub packets: u64,
    pub drops: u64,
    pub backlog_bytes: u64,
    pub ecn_marks: u64,
    pub average_delay_us: u64,
}
pub struct Kernel {
    pub nl: Netlink,
}
impl Kernel {
    pub fn open() -> Result<Self> {
        Ok(Self {
            nl: Netlink::open()?,
        })
    }
    pub fn links(&mut self) -> Result<Vec<Link>> {
        self.nl
            .request(18, DUMP, link(0, 0, 0, vec![]))?
            .iter()
            .map(|body| {
                ensure!(body.len() >= 16, "short link reply");
                let attributes = &body[16..];
                let info = find(attributes, 18)?.unwrap_or_default();
                Ok(Link {
                    index: u32_at(body, 4)?,
                    mtu: u32_at(find(attributes, 4)?.context("link has no MTU")?, 0)?,
                    name: text(find(attributes, 3)?.context("link has no name")?)?,
                    alias: text(find(attributes, 20)?.unwrap_or_default())?,
                    kind: text(find(info, 1)?.unwrap_or_default())?,
                })
            })
            .collect()
    }
    pub fn qdiscs(&mut self) -> Result<Vec<Qdisc>> {
        self.nl
            .request(38, DUMP, tc(0, 0, 0, 0, vec![]))?
            .iter()
            .map(|body| {
                ensure!(body.len() >= 20, "short qdisc reply");
                let attributes = &body[20..];
                let kind = text(find(attributes, 1)?.context("qdisc has no kind")?)?;
                let stats = parse_stats(attributes, kind == "cake")?;
                Ok(Qdisc {
                    index: u32_at(body, 4)?,
                    handle: u32_at(body, 8)?,
                    parent: u32_at(body, 12)?,
                    kind,
                    options: find(attributes, 2)?.unwrap_or_default().to_vec(),
                    stats,
                })
            })
            .collect()
    }
    pub fn filters(&mut self, index: u32) -> Result<Vec<Filter>> {
        let mut filters = Vec::new();
        for body in self
            .nl
            .request(46, DUMP, tc(index, 0, INGRESS, 0, vec![]))?
        {
            ensure!(body.len() >= 20, "short filter reply");
            let handle = u32_at(&body, 8)?;
            let options = find(&body[20..], 2)?;
            // Dumps include a protocol/priority header before actual filters.
            if handle == 0 && options.is_none() {
                continue;
            }
            filters.push(Filter {
                handle,
                chain: find(&body[20..], 11)?
                    .map(|value| u32_at(value, 0))
                    .transpose()?
                    .unwrap_or(0),
                info: u32_at(&body, 16)?,
                kind: text(find(&body[20..], 1)?.context("filter has no kind")?)?,
                options: options.unwrap_or_default().to_vec(),
            });
        }
        Ok(filters)
    }
    pub fn create_ifb(&mut self, profile: &ShaperProfile) -> Result<()> {
        self.nl.request(
            16,
            ACK | CREATE | EXCL,
            link(
                0,
                0,
                0,
                vec![
                    string(3, &profile.ifb_name()),
                    nested(18, vec![string(1, "ifb")]),
                ],
            ),
        )?;
        // IFB creation does not retain IFLA_IFALIAS on all kernels. Tag the
        // newly created link explicitly; never tag/adopt a pre-existing link.
        let created = self
            .links()?
            .into_iter()
            .find(|l| l.name == profile.ifb_name())
            .context("created IFB missing")?;
        ensure!(
            created.kind == "ifb" && created.alias.is_empty(),
            "new IFB identity changed"
        );
        self.nl.request(
            16,
            ACK,
            link(created.index, 0, 0, vec![string(20, &profile.alias())]),
        )?;
        Ok(())
    }
    pub fn up(&mut self, index: u32, mtu: u32) -> Result<()> {
        self.nl
            .request(16, ACK, link(index, 1, 1, vec![number(4, mtu)]))?;
        Ok(())
    }
    pub fn delete_link(&mut self, index: u32) -> Result<()> {
        self.nl.request(17, ACK, link(index, 0, 0, vec![]))?;
        Ok(())
    }
    pub fn set_cake(
        &mut self,
        index: u32,
        profile: &ShaperProfile,
        ingress: bool,
        existing: bool,
    ) -> Result<()> {
        let options = cake_options(profile, ingress);
        self.nl.request(
            36,
            ACK | CREATE | if existing { REPLACE } else { EXCL },
            tc(
                index,
                CAKE,
                ROOT,
                0,
                vec![string(1, "cake"), attr(2, &options)],
            ),
        )?;
        Ok(())
    }
    pub fn ingress(&mut self, index: u32) -> Result<()> {
        self.nl.request(
            36,
            ACK | CREATE | EXCL,
            tc(
                index,
                INGRESS,
                INGRESS_PARENT,
                0,
                vec![string(1, "ingress"), attr(2, &[])],
            ),
        )?;
        Ok(())
    }
    pub fn delete_qdisc(&mut self, qdisc: &Qdisc) -> Result<()> {
        self.nl.request(
            37,
            ACK,
            tc(
                qdisc.index,
                qdisc.handle,
                qdisc.parent,
                0,
                vec![string(1, &qdisc.kind)],
            ),
        )?;
        Ok(())
    }
    pub fn redirect(&mut self, index: u32, ifb: u32, profile: &ShaperProfile) -> Result<()> {
        // tc_gen: index, capab, action=TC_ACT_STOLEN, refcnt, bindcnt;
        // mirred adds eaction=TCA_EGRESS_REDIR and IFB index.
        let parms: Vec<u8> = [0_u32, 0, 4, 0, 0, 1, ifb]
            .iter()
            .flat_map(|v| v.to_ne_bytes())
            .collect();
        let action = nested(
            1,
            vec![
                string(1, "mirred"),
                nested(2, vec![attr(2, &parms)]),
                attr(6, &cookie(profile.id)),
            ],
        );
        let options = [nested(2, vec![action]), number(3, 1)].concat(); // TCA_MATCHALL_ACT
        self.nl.request(
            44,
            ACK | CREATE | EXCL,
            tc(
                index,
                1,
                INGRESS,
                FILTER_INFO,
                vec![string(1, "matchall"), attr(2, &options)],
            ),
        )?;
        Ok(())
    }
}
pub fn cookie(id: u32) -> Vec<u8> {
    [b"rdshaper-v1".as_slice(), &id.to_ne_bytes()].concat()
}
pub fn owned_filter(filter: &Filter, ifb: u32, id: u32) -> Result<bool> {
    if filter.chain != 0
        || filter.handle != 1
        || filter.info != FILTER_INFO
        || filter.kind != "matchall"
    {
        return Ok(false);
    }
    if find(&filter.options, 3)?
        .map(|v| u32_at(v, 0))
        .transpose()?
        .unwrap_or(0)
        & 3
        != 1
    {
        return Ok(false);
    }
    let Some(actions) = find(&filter.options, 2)? else {
        return Ok(false);
    };
    let entries = attrs(actions)?;
    if entries.len() != 1 || entries[0].0 != 1 {
        return Ok(false);
    }
    let action = entries[0].1;
    if text(find(action, 1)?.unwrap_or_default())? != "mirred"
        || find(action, 6)? != Some(cookie(id).as_slice())
    {
        return Ok(false);
    }
    let options = find(action, 2)?.unwrap_or_default();
    let parms = find(options, 2)?.unwrap_or_default();
    Ok(parms.len() >= 28
        && u32_at(parms, 8)? == 4
        && u32_at(parms, 20)? == 1
        && u32_at(parms, 24)? == ifb)
}
pub fn cake_options(profile: &ShaperProfile, ingress: bool) -> Vec<u8> {
    let rate = if ingress {
        profile.ingress_rate()
    } else {
        profile.egress_rate()
    };
    // WAN egress isolates LAN sources; LAN egress isolates LAN destinations.
    let source = (profile.side == ShaperSide::Wan) != ingress;
    [
        attr(2, &(u64::from(rate) * 125).to_ne_bytes()),
        number(3, 3),
        number(
            4,
            match profile.link_layer {
                LinkLayer::None => 0,
                LinkLayer::Atm => 1,
                LinkLayer::Ptm => 2,
            },
        ),
        number(5, if source { 5 } else { 6 }),
        number(6, profile.overhead as u32),
        number(11, u32::from(profile.nat)),
        number(12, 0),
        number(15, u32::from(profile.mpu)),
        number(16, u32::from(ingress)),
        number(18, 1),
    ]
    .concat()
}
pub fn same_options(actual: &[u8], desired: &[u8]) -> Result<bool> {
    for (key, value) in attrs(desired)? {
        if find(actual, key)? != Some(value) {
            return Ok(false);
        }
    }
    Ok(true)
}
fn parse_stats(attributes: &[u8], cake: bool) -> Result<Stats> {
    let mut stats = Stats::default();
    if let Some(values) = find(attributes, 7)? {
        if let Some(basic) = find(values, 1)? {
            stats.bytes = u64_at(basic, 0)?;
            stats.packets = u64::from(u32_at(basic, 8)?);
        }
        if let Some(queue) = find(values, 3)? {
            stats.backlog_bytes = u64::from(u32_at(queue, 4)?);
            stats.drops = u64::from(u32_at(queue, 8)?);
        }
    }
    if !cake {
        return Ok(stats);
    }
    // CAKE exports extended stats under TCA_XSTATS as nested attributes.
    let app = find(attributes, 7)?
        .map(|stats| find(stats, 4))
        .transpose()?
        .flatten();
    if let Some(cake) = app.or(find(attributes, 4)?) {
        if let Some(tins) = find(cake, 10)? {
            for (_, tin) in attrs(tins)? {
                if let Some(ecn) = find(tin, 8)? {
                    stats.ecn_marks += u64::from(u32_at(ecn, 0)?);
                }
                if let Some(delay) = find(tin, 19)? {
                    stats.average_delay_us =
                        stats.average_delay_us.max(u64::from(u32_at(delay, 0)?));
                }
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cake_encodes_rate_host_isolation_nat_and_signed_overhead() {
        let mut p = crate::config::shaper::tests::profile();
        p.overhead = -8;
        let egress = cake_options(&p, false);
        assert_eq!(
            u64_at(find(&egress, 2).unwrap().unwrap(), 0).unwrap(),
            1_250_000
        );
        assert_eq!(u32_at(find(&egress, 5).unwrap().unwrap(), 0).unwrap(), 5);
        assert_eq!(
            u32_at(find(&egress, 6).unwrap().unwrap(), 0).unwrap() as i32,
            -8
        );
        let ingress = cake_options(&p, true);
        assert_eq!(u32_at(find(&ingress, 5).unwrap().unwrap(), 0).unwrap(), 6);
        p.side = ShaperSide::Lan;
        assert_eq!(
            u32_at(find(&cake_options(&p, false), 5).unwrap().unwrap(), 0).unwrap(),
            6
        );
    }
}
