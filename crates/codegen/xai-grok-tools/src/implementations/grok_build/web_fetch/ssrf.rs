//! SSRF (Server-Side Request Forgery) protection for `web_fetch`.
//!
//! Validates that resolved IP addresses are not in private, link-local, or
//! cloud metadata ranges before allowing outbound HTTP requests.
//!
//! Returns the **allowed** socket addresses so the HTTP client can pin DNS
//! (`ClientBuilder::resolve_to_addrs`) and avoid DNS-rebinding TOCTOU where a
//! hostname resolves to a public IP at check time and a private IP at connect
//! time (CWE-918).
//!
//! Reference: [IANA IPv4 Special-Purpose Address Registry](https://www.iana.org/assignments/iana-ipv4-special-registry/)

use std::net::{IpAddr, SocketAddr};

use url::Url;

use super::error::WebFetchError;

/// Returns `true` if an IP address is in a private, link-local, or cloud
/// metadata range that should be blocked to prevent SSRF attacks.
///
/// **Allowed:** loopback (`127.x` / `::1`) for local development.
/// **Blocked:** RFC 1918, link-local, CGNAT/cloud metadata, unspecified.
pub(crate) fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Loopback (127.0.0.0/8) — allowed for local dev servers.
            if octets[0] == 127 {
                return false;
            }
            // RFC 1918: 10.0.0.0/8 — private network.
            if octets[0] == 10 {
                return true;
            }
            // RFC 1918: 172.16.0.0/12 — private network.
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // RFC 1918: 192.168.0.0/16 — private network.
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // RFC 3927: 169.254.0.0/16 — link-local.
            // Includes AWS/GCP/Azure metadata endpoint 169.254.169.254.
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // RFC 6598: 100.64.0.0/10 — CGNAT / shared address space.
            // Used by some cloud providers for internal metadata services.
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return true;
            }
            // 0.0.0.0 — unspecified address.
            if v4.is_unspecified() {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // ::1 — loopback, allowed for local dev.
            if v6.is_loopback() {
                return false;
            }
            // :: — unspecified.
            if v6.is_unspecified() {
                return true;
            }
            // IPv4-mapped IPv6 (::ffff:x.x.x.x) — delegate to v4 checks.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_blocked_ip(&IpAddr::V4(v4));
            }
            let segments = v6.segments();
            // RFC 4291: fe80::/10 — link-local unicast.
            if segments[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // RFC 4193: fc00::/7 — unique local address (ULA).
            if segments[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            false
        }
    }
}

/// Result of a successful SSRF check: DNS-validated addresses safe to connect to.
#[derive(Debug, Clone)]
pub(crate) struct SsrfAllow {
    /// Original host label (name or IP literal) from the URL.
    pub host: String,
    /// Non-blocked resolved addresses (at least one). Used to pin DNS on connect.
    pub addrs: Vec<SocketAddr>,
}

/// Resolve hostname via DNS, drop blocked private/link-local ranges, and
/// return the remaining addresses for DNS pinning.
///
/// If **every** resolved address is blocked, returns [`WebFetchError::SsrfBlocked`].
/// If the set is mixed (public + private), only public/allowed addresses are
/// returned so dual-stack hosts keep working while private targets stay unused.
pub(crate) async fn check_ssrf(url: &Url) -> Result<SsrfAllow, WebFetchError> {
    let host = url
        .host_str()
        .ok_or_else(|| WebFetchError::SingleLabelHost {
            host: String::new(),
        })?;

    let port = url.port_or_known_default().unwrap_or(443);

    // If the host is already a literal IP, check it directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked_ip(&ip) {
            return Err(WebFetchError::SsrfBlocked {
                host: host.to_string(),
                ip,
            });
        }
        return Ok(SsrfAllow {
            host: host.to_string(),
            addrs: vec![SocketAddr::new(ip, port)],
        });
    }

    // DNS resolution.
    let addr_str = format!("{host}:{port}");
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| WebFetchError::DnsResolution {
            host: host.to_string(),
            source: e,
        })?
        .collect();

    if addrs.is_empty() {
        return Err(WebFetchError::DnsEmpty(host.to_string()));
    }

    let mut blocked_example: Option<IpAddr> = None;
    let allowed: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|addr| {
            if is_blocked_ip(&addr.ip()) {
                blocked_example.get_or_insert(addr.ip());
                false
            } else {
                true
            }
        })
        .collect();

    if allowed.is_empty() {
        return Err(WebFetchError::SsrfBlocked {
            host: host.to_string(),
            ip: blocked_example.expect("blocked_example set when all addrs blocked"),
        });
    }

    Ok(SsrfAllow {
        host: host.to_string(),
        addrs: allowed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── IPv4 blocking ───────────────────────────────────────────────────

    #[test]
    fn blocks_rfc1918_10x() {
        assert!(is_blocked_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip(&"10.255.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918_172x() {
        assert!(is_blocked_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip(&"172.31.255.255".parse().unwrap()));
        assert!(!is_blocked_ip(&"172.15.0.1".parse().unwrap()));
        assert!(!is_blocked_ip(&"172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_rfc1918_192168() {
        assert!(is_blocked_ip(&"192.168.0.1".parse().unwrap()));
        assert!(is_blocked_ip(&"192.168.255.255".parse().unwrap()));
    }

    #[test]
    fn blocks_link_local() {
        assert!(is_blocked_ip(&"169.254.0.1".parse().unwrap()));
        assert!(is_blocked_ip(&"169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn blocks_cgnat_cloud_metadata() {
        assert!(is_blocked_ip(&"100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip(&"100.127.255.255".parse().unwrap()));
        assert!(!is_blocked_ip(&"100.63.0.1".parse().unwrap()));
        assert!(!is_blocked_ip(&"100.128.0.1".parse().unwrap()));
    }

    #[test]
    fn blocks_unspecified() {
        assert!(is_blocked_ip(&"0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip(&"::".parse().unwrap()));
    }

    #[test]
    fn allows_loopback() {
        assert!(!is_blocked_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_blocked_ip(&"127.0.0.2".parse().unwrap()));
        assert!(!is_blocked_ip(&"::1".parse().unwrap()));
    }

    #[test]
    fn allows_public_ips() {
        assert!(!is_blocked_ip(&"1.1.1.1".parse().unwrap()));
        assert!(!is_blocked_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip(&"142.250.80.46".parse().unwrap()));
    }

    // ── IPv6 ────────────────────────────────────────────────────────────

    #[test]
    fn blocks_ipv6_link_local() {
        assert!(is_blocked_ip(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv6_unique_local() {
        assert!(is_blocked_ip(&"fc00::1".parse().unwrap()));
        assert!(is_blocked_ip(&"fd00::1".parse().unwrap()));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_private() {
        assert!(is_blocked_ip(&"::ffff:10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(is_blocked_ip(
            &"::ffff:192.168.1.1".parse::<IpAddr>().unwrap()
        ));
    }

    #[test]
    fn allows_ipv4_mapped_ipv6_public() {
        assert!(!is_blocked_ip(&"::ffff:8.8.8.8".parse::<IpAddr>().unwrap()));
    }

    // ── check_ssrf integration ──────────────────────────────────────────

    #[tokio::test]
    async fn ssrf_blocks_ip_literal_private() {
        let url = Url::parse("https://10.0.0.1/secret").unwrap();
        let result = check_ssrf(&url).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("private"));
    }

    #[tokio::test]
    async fn ssrf_allows_ip_literal_public() {
        let url = Url::parse("https://1.1.1.1/").unwrap();
        let result = check_ssrf(&url).await;
        let allow = result.expect("public IP literal should be allowed");
        assert_eq!(allow.host, "1.1.1.1");
        assert_eq!(allow.addrs.len(), 1);
        assert_eq!(allow.addrs[0].ip(), "1.1.1.1".parse::<IpAddr>().unwrap());
        assert_eq!(allow.addrs[0].port(), 443);
    }

    #[tokio::test]
    async fn ssrf_allows_ip_literal_loopback_with_port() {
        let url = Url::parse("http://127.0.0.1:3000/").unwrap();
        let allow = check_ssrf(&url).await.expect("loopback allowed");
        assert_eq!(allow.addrs[0].port(), 3000);
    }
}
