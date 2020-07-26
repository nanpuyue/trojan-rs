use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use regex::Regex;

use crate::error::Result;
use crate::socks5::Socks5Target;
use crate::util::TrimInPlace;

struct Section {
    domain: HashSet<String>,
    domain_suffix: HashSet<String>,
    ipv4: [HashSet<(u32, u8)>; 2],
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Action {
    Direct,
    Proxy,
    Reject,
}

pub struct Router {
    direct: Section,
    proxy: Section,
    reject: Section,
    default: Action,
}

impl Section {
    fn empty() -> Self {
        Self {
            domain: HashSet::new(),
            domain_suffix: HashSet::new(),
            ipv4: [HashSet::new(), HashSet::new()],
        }
    }

    fn insert_ipv4(&mut self, line: String) -> Result<()> {
        let mut split = line.splitn(2, '/');
        let ip = Ipv4Addr::from_str(split.next()?)?.into();
        let prefix = match split.next() {
            Some(x) => match u8::from_str(x)? {
                n @ 0..=32 => n,
                _ => return Err((line + ": Invalid prefix length!").into()),
            },
            None => 32,
        };

        let mut start = 0;
        let mut insert_index = |list: &[u8]| {
            for &index in list {
                if index > prefix {
                    break;
                } else if index > start {
                    start = index;
                    self.ipv4[0].insert((ip & (u32::MAX << (32 - index)), index));
                }
            }
        };
        insert_index(&[16]);
        insert_index(&[8, 24]);
        insert_index(&[4, 12, 20, 24, 28]);
        insert_index(&[2, 6, 10, 14, 18, 22, 26, 30]);

        self.ipv4[1].insert((ip, prefix));

        Ok(())
    }

    fn insert_domain(&mut self, mut line: String) -> Result<()> {
        if line.starts_with('^') {
            self.domain.insert(line.split_off(1));
        } else {
            self.domain_suffix.insert(line);
        }
        Ok(())
    }

    fn match_ipv4(&self, ip: Ipv4Addr) -> bool {
        if self.ipv4[1].contains(&(0, 0)) {
            return true;
        }
        let ip = ip.into();

        let (mut start, mut end) = (0, 32);
        for _ in 0..4 {
            let index = (start + end) / 2;
            if self.ipv4[0].contains(&(ip & (u32::MAX << (32 - index)), index)) {
                start = index;
            } else {
                end = index;
            }
        }

        if start == 0 {
            start = 1;
        } else if start == 30 && self.ipv4[1].contains(&(ip, 32)) {
            return true;
        }

        for index in start..end {
            if self.ipv4[1].contains(&(ip & (u32::MAX << (32 - index)), index)) {
                return true;
            }
        }

        false
    }

    fn match_domain(&self, domain: &str) -> bool {
        if self.domain.contains(domain) || self.domain_suffix.contains(domain) {
            return true;
        }

        for (i, _) in domain.match_indices('.') {
            if self.domain_suffix.contains(&domain[i + 1..]) {
                return true;
            }
        }

        false
    }
}

impl Router {
    fn empty() -> Self {
        Self {
            direct: Section::empty(),
            proxy: Section::empty(),
            reject: Section::empty(),
            default: Action::Proxy,
        }
    }

    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let domain = Regex::new(r"^\^?([a-zA-Z0-9_\-]+([.][a-zA-Z0-9_\-]+)*\.)?[a-zA-Z]{2,63}$")?;
        let ipv4 = Regex::new(r"^([0-9]+\.){3}[0-9]+(/[0-9]+)?$")?;

        let mut router = Self::empty();
        let mut section = None;
        let file = File::open(path)?;
        for line in BufReader::new(file).lines() {
            let mut line = line?;
            line.trim_in_place();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with('[') {
                section = match &line[1..] {
                    "direct]" => Some(&mut router.direct),
                    "proxy]" => Some(&mut router.proxy),
                    "reject]" => Some(&mut router.reject),
                    "default]" => None,
                    _ => return Err((line + ": Invalid section!").into()),
                };
                continue;
            }

            if section.is_some() {
                if ipv4.is_match(&line) {
                    section.as_mut().unwrap().insert_ipv4(line)?;
                    continue;
                }

                if domain.is_match(&line) {
                    section.as_mut().unwrap().insert_domain(line)?;
                    continue;
                }
            } else {
                router.default = match line.as_str() {
                    "direct" => Action::Direct,
                    "proxy" => Action::Proxy,
                    _ => return Err((line + ": Invalid default action!").into()),
                };
                continue;
            }

            return Err((line + ": Invalid rule!").into());
        }

        Ok(router)
    }

    fn route_ipv4(&self, ip: Ipv4Addr) -> Action {
        if self.reject.match_ipv4(ip) {
            Action::Reject
        } else if self.default == Action::Direct && self.proxy.match_ipv4(ip) {
            Action::Proxy
        } else if self.direct.match_ipv4(ip) {
            Action::Direct
        } else {
            self.default
        }
    }

    fn route_domain(&self, domain: &str) -> Action {
        if domain.ends_with(char::is_numeric) && domain.contains('.') {
            match Ipv4Addr::from_str(domain) {
                Ok(x) => self.route_ipv4(x),
                Err(_) => Action::Reject,
            }
        } else if self.reject.match_domain(domain) {
            Action::Reject
        } else if self.default == Action::Direct && self.proxy.match_domain(domain) {
            Action::Proxy
        } else if self.direct.match_domain(domain) {
            Action::Direct
        } else {
            self.default
        }
    }

    pub fn route(&self, target: &Socks5Target) -> Action {
        match target {
            Socks5Target::V4(x) => self.route_ipv4(*x.ip()),
            // TODO: ipv6 route
            Socks5Target::V6(_) => self.default,
            Socks5Target::Domain(x) => match x.splitn(2, ':').next() {
                Some(x) => self.route_domain(x),
                None => Action::Reject,
            },
        }
    }

    pub fn default(&self) -> Action {
        self.default
    }
}
