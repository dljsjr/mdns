use bstr::BString;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net;
use std::net::{IpAddr, SocketAddr};

/// A DNS response.
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct Response {
    pub answers: Vec<Record>,
    pub nameservers: Vec<Record>,
    pub additional: Vec<Record>,
}

/// Any type of DNS record.
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    #[serde(with = "serde_helpers::dns_class")]
    pub class: dns_parser::Class,
    pub ttl: u32,
    pub kind: RecordKind,
}

/// A specific DNS record variant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RecordKind {
    A(net::Ipv4Addr),
    AAAA(net::Ipv6Addr),
    CNAME(String),
    MX {
        preference: u16,
        exchange: String,
    },
    NS(String),
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    TXT(HashMap<String, TxtRecordValue>),
    PTR(String),
    /// A record kind that hasn't been implemented by this library yet.
    Unimplemented(Vec<u8>),
}

/// A TXT Record's Value for a present Attribute with following variants:
/// - None:   Attribute present, with no value
///           (e.g., "passreq" -- password required for this service)
/// - Empty:  Attribute present, with empty value
//            (e.g., "PlugIns=" -- the server supports plugins, but none are presently installed)
/// - Value(BString): Attribute present, with non-empty value
//                    (e.g., "PlugIns=JPEG,MPEG2,MPEG4")
/// RFC ref: https://datatracker.ietf.org/doc/html/rfc6763#section-6.4
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum TxtRecordValue {
    None,
    Empty,
    #[serde(with = "serde_helpers::bstring")]
    Value(BString),
}

/// A Case-insensitive wrapper for key string of TXT record following spec's mandate:
/// Case is ignored when interpreting a key,
/// so "papersize=A4", "PAPERSIZE=A4", and "Papersize=A4" are all identical.
#[derive(Eq, Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct TxtRecordKey(String);

impl Hash for TxtRecordKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.to_lowercase().hash(state)
    }
}

impl PartialEq<Self> for TxtRecordKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.to_lowercase() == other.0.to_lowercase()
    }
}

#[cfg(feature = "with-serde")]
pub(crate) mod serde_helpers {
    pub(crate) mod dns_class {
        pub fn serialize<S>(class: &dns_parser::Class, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            serializer.serialize_u8(*class as u8)
        }

        pub fn deserialize<'de, D>(d: D) -> Result<dns_parser::Class, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            d.deserialize_u8(DnsClassVisitor)
        }

        struct DnsClassVisitor;

        impl<'de> serde::de::Visitor<'de> for DnsClassVisitor {
            type Value = dns_parser::Class;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("DNS CLASS value according to RFC 1035")
            }

            fn visit_i8<E>(self, v: i8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                use dns_parser::Class::*;
                let class = match v {
                    1 => IN,
                    2 => CS,
                    3 => CH,
                    4 => HS,
                    _ => {
                        return Err(serde::de::Error::invalid_value(
                            serde::de::Unexpected::Signed(v as i64),
                            &self,
                        ))
                    }
                };

                Ok(class)
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_i8(v as i8)
            }
        }
    }

    pub(crate) mod bstring {
        use bstr::{BString, ByteSlice};

        pub fn serialize<S>(bstring: &BString, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::ser::Serializer,
        {
            serializer.serialize_bytes(bstring.as_bytes())
        }

        pub fn deserialize<'de, D>(d: D) -> Result<BString, D::Error>
        where
            D: serde::de::Deserializer<'de>,
        {
            d.deserialize_bytes(BStringVisitor)
        }

        struct BStringVisitor;

        impl<'de> serde::de::Visitor<'de> for BStringVisitor {
            type Value = BString;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("DNS CLASS value according to RFC 1035")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(BString::from(v))
            }
        }
    }
}

impl Response {
    pub fn from_packet(packet: &dns_parser::Packet) -> Self {
        Response {
            answers: packet
                .answers
                .iter()
                .map(Record::from_resource_record)
                .collect(),
            nameservers: packet
                .nameservers
                .iter()
                .map(Record::from_resource_record)
                .collect(),
            additional: packet
                .additional
                .iter()
                .map(Record::from_resource_record)
                .collect(),
        }
    }

    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.answers
            .iter()
            .chain(self.nameservers.iter())
            .chain(self.additional.iter())
    }

    pub fn is_empty(&self) -> bool {
        self.answers.is_empty() && self.nameservers.is_empty() && self.additional.is_empty()
    }

    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.records().find_map(|record| match record.kind {
            RecordKind::A(addr) => Some(addr.into()),
            RecordKind::AAAA(addr) => Some(addr.into()),
            _ => None,
        })
    }

    pub fn hostname(&self) -> Option<&str> {
        self.records().find_map(|record| match record.kind {
            RecordKind::PTR(ref host) => Some(host.as_str()),
            _ => None,
        })
    }

    pub fn port(&self) -> Option<u16> {
        self.records().find_map(|record| match record.kind {
            RecordKind::SRV { port, .. } => Some(port),
            _ => None,
        })
    }

    pub fn socket_address(&self) -> Option<SocketAddr> {
        Some((self.ip_addr()?, self.port()?).into())
    }

    pub fn txt_records(&self) -> impl Iterator<Item = (&str, &TxtRecordValue)> {
        self.records()
            .filter_map(|record| match record.kind {
                RecordKind::TXT(ref txt) => Some(txt),
                _ => None,
            })
            .flat_map(|txt| txt.iter())
            .map(|(key, value)| (key.as_str(), value))
    }
}

impl Record {
    fn from_resource_record(rr: &dns_parser::ResourceRecord) -> Self {
        Record {
            name: rr.name.to_string(),
            class: rr.cls,
            ttl: rr.ttl,
            kind: RecordKind::from_rr_data(&rr.data),
        }
    }
}

impl RecordKind {
    fn from_rr_data(data: &dns_parser::RData) -> Self {
        use dns_parser::RData;

        match *data {
            RData::A(dns_parser::rdata::a::Record(addr)) => RecordKind::A(addr),
            RData::AAAA(dns_parser::rdata::aaaa::Record(addr)) => RecordKind::AAAA(addr),
            RData::CNAME(ref name) => RecordKind::CNAME(name.to_string()),
            RData::MX(dns_parser::rdata::mx::Record {
                preference,
                ref exchange,
            }) => RecordKind::MX {
                preference,
                exchange: exchange.to_string(),
            },
            RData::NS(ref name) => RecordKind::NS(name.to_string()),
            RData::PTR(ref name) => RecordKind::PTR(name.to_string()),
            RData::SRV(dns_parser::rdata::srv::Record {
                priority,
                weight,
                port,
                ref target,
            }) => RecordKind::SRV {
                priority,
                weight,
                port,
                target: target.to_string(),
            },
            RData::TXT(ref txt) => {
                let mut txt_records: HashMap<TxtRecordKey, TxtRecordValue> = HashMap::new();
                for txt_record in txt.iter() {
                    let mut kv_split = txt_record.split(|c| c == &b'=');
                    if let Some(key_bytes) = kv_split.next() {
                        let key = String::from_utf8_lossy(key_bytes).into_owned();
                        if txt_records.contains_key(&TxtRecordKey(key.clone())) {
                            // RFC 6763 Section 6.4: If a client receives a TXT record containing
                            // the same key more than once, then the client MUST silently ignore
                            // all but the first occurrence of that attribute.
                            continue;
                        }
                        let value = if let Some(value_bytes) = kv_split.next() {
                            if value_bytes.is_empty() {
                                TxtRecordValue::Empty
                            } else {
                                TxtRecordValue::Value(BString::from(value_bytes))
                            }
                        } else {
                            TxtRecordValue::None
                        };
                        txt_records.insert(TxtRecordKey(key), value);
                    }
                }
                RecordKind::TXT(
                    txt_records
                        .into_iter()
                        .map(|(key, value)| (key.0, value))
                        .collect(),
                )
            }
            RData::SOA(..) => {
                RecordKind::Unimplemented("SOA record handling is not implemented".into())
            }
            RData::Unknown(data) => RecordKind::Unimplemented(data.to_owned()),
        }
    }
}
