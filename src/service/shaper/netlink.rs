//! Minimal Linux rtnetlink transport for traffic control. Native-endian UAPI fields;
//! attributes and multipart replies are checked before slicing. No tc/ip subprocesses.
use anyhow::{bail, ensure, Context, Result};
use nix::libc;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub const REQUEST: u16 = 1;
pub const ACK: u16 = 4;
pub const DUMP: u16 = 0x300;
pub const CREATE: u16 = 0x400;
pub const EXCL: u16 = 0x200;
pub const REPLACE: u16 = 0x100;
pub const ROOT: u32 = 0xffff_ffff;
pub const INGRESS_PARENT: u32 = 0xffff_fff1;
pub const INGRESS: u32 = 0xffff_0000;
pub const CAKE: u32 = 0xcafe_0000;
pub const FILTER_INFO: u32 = (49152 << 16) | (3_u16.to_be() as u32);

pub fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_ne_bytes(
        bytes
            .get(offset..offset + 2)
            .context("short netlink u16")?
            .try_into()?,
    ))
}
pub fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_ne_bytes(
        bytes
            .get(offset..offset + 4)
            .context("short netlink u32")?
            .try_into()?,
    ))
}
pub fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_ne_bytes(
        bytes
            .get(offset..offset + 8)
            .context("short netlink u64")?
            .try_into()?,
    ))
}
fn align(len: usize) -> usize {
    (len + 3) & !3
}
pub fn attr(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(align(value.len() + 4));
    out.extend_from_slice(&((value.len() + 4) as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    out.resize(align(out.len()), 0);
    out
}
pub fn number(kind: u16, value: u32) -> Vec<u8> {
    attr(kind, &value.to_ne_bytes())
}
pub fn string(kind: u16, value: &str) -> Vec<u8> {
    attr(kind, &[value.as_bytes(), &[0]].concat())
}
pub fn nested(kind: u16, children: Vec<Vec<u8>>) -> Vec<u8> {
    attr(kind | 0x8000, &children.concat())
}
pub fn attrs(mut bytes: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        ensure!(bytes.len() >= 4, "truncated netlink attribute header");
        let len = u16_at(bytes, 0)? as usize;
        ensure!(
            len >= 4 && len <= bytes.len(),
            "invalid netlink attribute length"
        );
        out.push((u16_at(bytes, 2)? & 0x3fff, &bytes[4..len]));
        ensure!(
            align(len) <= bytes.len(),
            "truncated netlink attribute padding"
        );
        bytes = &bytes[align(len)..];
    }
    Ok(out)
}
pub fn find(bytes: &[u8], kind: u16) -> Result<Option<&[u8]>> {
    Ok(attrs(bytes)?
        .into_iter()
        .find(|(k, _)| *k == kind)
        .map(|(_, value)| value))
}
pub fn text(bytes: &[u8]) -> Result<String> {
    Ok(std::str::from_utf8(bytes.split(|b| *b == 0).next().unwrap_or_default())?.to_string())
}
pub fn tc(index: u32, handle: u32, parent: u32, info: u32, attributes: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = vec![0; 4];
    for value in [index, handle, parent, info] {
        body.extend_from_slice(&value.to_ne_bytes());
    }
    body.extend(attributes.concat());
    body
}
pub fn link(index: u32, flags: u32, change: u32, attributes: Vec<Vec<u8>>) -> Vec<u8> {
    let mut body = vec![0; 4];
    for value in [index, flags, change] {
        body.extend_from_slice(&value.to_ne_bytes());
    }
    body.extend(attributes.concat());
    body
}

pub struct Netlink {
    fd: OwnedFd,
    sequence: u32,
}
impl Netlink {
    pub fn open() -> Result<Self> {
        // SAFETY: fixed socket arguments; OwnedFd takes exclusive ownership on success.
        let raw = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                libc::NETLINK_ROUTE,
            )
        };
        ensure!(
            raw >= 0,
            "opening rtnetlink: {}",
            std::io::Error::last_os_error()
        );
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let timeout = libc::timeval {
            tv_sec: 3,
            tv_usec: 0,
        };
        // SAFETY: initialized pointers and exact UAPI structure sizes.
        let result = unsafe {
            libc::setsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const _,
                std::mem::size_of_val(&timeout) as _,
            )
        };
        ensure!(
            result == 0,
            "setting netlink timeout: {}",
            std::io::Error::last_os_error()
        );
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        let result = unsafe {
            libc::bind(
                raw,
                &address as *const _ as *const _,
                std::mem::size_of_val(&address) as _,
            )
        };
        ensure!(
            result == 0,
            "binding rtnetlink: {}",
            std::io::Error::last_os_error()
        );
        Ok(Self { fd, sequence: 0 })
    }
    pub fn request(&mut self, kind: u16, flags: u16, body: Vec<u8>) -> Result<Vec<Vec<u8>>> {
        self.sequence = self.sequence.wrapping_add(1);
        let mut message = Vec::new();
        message.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
        message.extend_from_slice(&kind.to_ne_bytes());
        message.extend_from_slice(&(REQUEST | flags).to_ne_bytes());
        message.extend_from_slice(&self.sequence.to_ne_bytes());
        message.extend_from_slice(&0_u32.to_ne_bytes());
        message.extend(body);
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        // SAFETY: valid fd, initialized byte buffer and kernel destination sockaddr.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                message.as_ptr() as _,
                message.len(),
                0,
                &address as *const _ as _,
                std::mem::size_of_val(&address) as _,
            )
        };
        ensure!(
            sent == message.len() as isize,
            "sending rtnetlink: {}",
            std::io::Error::last_os_error()
        );
        let mut replies = Vec::new();
        loop {
            let mut bytes = vec![0_u8; 262144];
            let mut source: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            let mut source_len = std::mem::size_of_val(&source) as libc::socklen_t;
            // MSG_TRUNC returns the actual datagram length, so oversized messages fail safely.
            let count = unsafe {
                libc::recvfrom(
                    self.fd.as_raw_fd(),
                    bytes.as_mut_ptr() as _,
                    bytes.len(),
                    libc::MSG_TRUNC,
                    &mut source as *mut _ as _,
                    &mut source_len,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error).context("receiving rtnetlink");
            }
            ensure!(
                count > 0 && count as usize <= bytes.len(),
                "empty or truncated rtnetlink reply"
            );
            ensure!(
                source.nl_pid == 0,
                "rtnetlink reply did not originate from kernel"
            );
            let mut remaining = &bytes[..count as usize];
            while !remaining.is_empty() {
                ensure!(remaining.len() >= 16, "short rtnetlink header");
                let length = u32_at(remaining, 0)? as usize;
                ensure!(
                    length >= 16 && align(length) <= remaining.len(),
                    "invalid rtnetlink message length"
                );
                let part = &remaining[16..length];
                if u32_at(remaining, 8)? == self.sequence {
                    ensure!(
                        u16_at(remaining, 6)? & 0x10 == 0,
                        "rtnetlink dump interrupted; retry required"
                    );
                    match u16_at(remaining, 4)? {
                        2 => {
                            let error = u32_at(part, 0)? as i32;
                            if error != 0 {
                                return Err(std::io::Error::from_raw_os_error(-error)).context(format!("rtnetlink operation {kind} (CAKE/IFB/matchall/mirred kernel support may be required)"));
                            }
                            return Ok(replies);
                        }
                        3 => {
                            if part.len() >= 4 {
                                ensure!(u32_at(part, 0)? == 0, "rtnetlink dump failed");
                            }
                            return Ok(replies);
                        }
                        4 => bail!("rtnetlink overrun"),
                        _ => replies.push(part.to_vec()),
                    }
                }
                remaining = &remaining[align(length)..];
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attributes_round_trip_and_reject_malformed_lengths() {
        let encoded = [number(3, 77), nested(18, vec![string(1, "ifb")])].concat();
        assert_eq!(u32_at(find(&encoded, 3).unwrap().unwrap(), 0).unwrap(), 77);
        assert_eq!(
            text(
                find(find(&encoded, 18).unwrap().unwrap(), 1)
                    .unwrap()
                    .unwrap()
            )
            .unwrap(),
            "ifb"
        );
        for bytes in [
            &[1_u8][..],
            &[2, 0, 1, 0][..],
            &[8, 0, 1, 0, 0][..],
            &[5, 0, 1, 0, 1][..],
        ] {
            assert!(attrs(bytes).is_err());
        }
    }
}
