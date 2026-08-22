use std::{
    io::{self, Write},
    ops::RangeInclusive,
    os::fd::RawFd,
    process::{Command, Stdio},
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NftablesPayload {
    nftables: Vec<NftObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
enum NftObject {
    Table { table: TableDef },
    Chain { chain: ChainDef },
    Rule { rule: RuleDef },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TableDef {
    family: String,
    name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ChainDef {
    family: String,
    table: String,
    name: String,
    #[serde(rename = "type")]
    chain_type: String,
    hook: String,
    prio: i32,
    policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RuleDef {
    family: String,
    table: String,
    chain: String,
    expr: Vec<Expression>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
enum Expression {
    Match {
        #[serde(rename = "match")]
        match_expr: MatchExpr,
    },
    TProxy {
        tproxy: TProxyExpr,
    },
    Mangle {
        mangle: MangleExpr,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MangleExpr {
    key: MangleKey,
    value: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MangleKey {
    meta: MetaKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MetaKey {
    key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MatchExpr {
    op: String,
    left: MatchValue,
    right: MatchValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct MatchValue {
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<PayloadExpr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    range: Option<(u16, u16)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PayloadExpr {
    protocol: String,
    field: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TProxyExpr {
    port: u16,
}

/// Sets IP_TRANSPARENT on a socket file descriptor for Linux TPROXY.
pub fn set_ip_transparent(fd: RawFd) -> io::Result<()> {
    const IP_TRANSPARENT: libc::c_int = 19;
    let opt: libc::c_int = 1;
    let res = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            IP_TRANSPARENT,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if res != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

const TABLE_NAME: &str = "fluct";
const PREROUTING: &str = "prerouting";

/// Generates the strongly-typed `NftablesPayload` for TPROXY redirection.
fn build_nat_payload(dest: u16, ranges: &[RangeInclusive<u16>]) -> NftablesPayload {
    let mut objects = vec![
        NftObject::Table {
            table: TableDef {
                family: "inet".to_string(),
                name: TABLE_NAME.to_string(),
            },
        },
        NftObject::Chain {
            chain: ChainDef {
                family: "inet".to_string(),
                table: TABLE_NAME.to_string(),
                name: PREROUTING.to_string(),
                chain_type: "filter".to_string(),
                hook: PREROUTING.to_string(),
                prio: -150,
                policy: "accept".to_string(),
            },
        },
    ];

    for range in ranges {
        objects.push(NftObject::Rule {
            rule: RuleDef {
                family: "inet".to_string(),
                table: TABLE_NAME.to_string(),
                chain: PREROUTING.to_string(),
                expr: vec![
                    Expression::Match {
                        match_expr: MatchExpr {
                            op: "==".to_string(),
                            left: MatchValue {
                                payload: Some(PayloadExpr {
                                    protocol: "tcp".to_string(),
                                    field: "dport".to_string(),
                                }),
                                range: None,
                            },
                            right: MatchValue {
                                payload: None,
                                range: Some((*range.start(), *range.end())),
                            },
                        },
                    },
                    Expression::TProxy {
                        tproxy: TProxyExpr { port: dest },
                    },
                    Expression::Mangle {
                        mangle: MangleExpr {
                            key: MangleKey {
                                meta: MetaKey {
                                    key: "mark".to_string(),
                                },
                            },
                            value: 1,
                        },
                    },
                ],
            },
        });
    }

    NftablesPayload { nftables: objects }
}

/// Applies an `NftablesPayload` by serializing it to JSON and running `nft -j -f -`.
fn apply_nat_payload(payload: &NftablesPayload) -> io::Result<()> {
    let json_bytes = serde_json::to_vec(payload)?;

    let mut child = Command::new("nft")
        .arg("-j")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&json_bytes)?;
    }

    let output = child.wait_with_output()?;
    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(
            format!("nft failed: {err}"),
        ));
    }

    Ok(())
}

/// Configures NAT redirection for multiple ranges of TCP ports to a destination port.
pub fn configure_netfilter(dest: u16, ranges: &[RangeInclusive<u16>]) -> io::Result<()> {
    let payload = build_nat_payload(dest, ranges);
    apply_nat_payload(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_nat_payload_structure() {
        let ranges = [1000..=2000, 3000..=4000];
        let payload = build_nat_payload(32767, &ranges);

        // 1 Table + 1 Chain + 2 Rules = 4 objects
        assert_eq!(payload.nftables.len(), 4);

        let json_bytes = serde_json::to_vec(&payload).unwrap();
        let json_str = String::from_utf8(json_bytes).unwrap();

        assert!(json_str.contains("\"tproxy\":{\"port\":32767}"));
        assert!(
            json_str.contains("\"mangle\":{\"key\":{\"meta\":{\"key\":\"mark\"}},\"value\":1}")
        );
        assert!(json_str.contains("\"table\":{\"family\":\"inet\",\"name\":\"fluct\"}"));
        assert!(!json_str.contains("\"table\":{\"table\""));
        assert!(!json_str.contains("\"tproxy\":{\"tproxy\""));
        assert!(json_str.contains("\"range\":[1000,2000]"));
        assert!(json_str.contains("\"range\":[3000,4000]"));
        assert!(json_str.contains("\"payload\":{\"protocol\":\"tcp\",\"field\":\"dport\"}"));
    }
}
