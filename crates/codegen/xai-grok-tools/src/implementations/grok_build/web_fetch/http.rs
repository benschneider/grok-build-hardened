//! Cached HTTP client with atomic invalidation for `web_fetch`.
//!
//! The `reqwest::Client` is held behind an `ArcSwapOption` so it can be
//! atomically invalidated on transport errors, forcing the next call to rebuild
//! with a fresh connection pool. This prevents connection pool poisoning
//! (half-read connections being returned to the pool and corrupting subsequent
//! requests).

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;

use super::config::WebFetchParams;
use super::error::WebFetchError;
use super::ssrf::SsrfAllow;

/// Cached, invalidatable HTTP client for web fetching.
///
/// - **Normal path:** `get_or_rebuild()` returns the cached client via a
///   lock-free atomic load.
/// - **On transport error:** call `invalidate()` to atomically set the
///   client to `None`. The next `get_or_rebuild()` falls through and
///   builds a fresh client with a clean connection pool.
/// - **SSRF path:** `build_dns_pinned()` builds a one-shot client that forces
///   the host to the addresses already validated by [`check_ssrf`], closing
///   DNS-rebinding TOCTOU between allow-check and TCP connect.
#[derive(Clone, Debug)]
pub(crate) struct HttpClient {
    inner: Arc<ArcSwapOption<reqwest::Client>>,
    params: WebFetchParams,
}

impl HttpClient {
    pub(crate) fn new(params: &WebFetchParams) -> Result<Self, WebFetchError> {
        let client = Self::build(params, None)?;
        Ok(Self {
            inner: Arc::new(ArcSwapOption::from(Some(Arc::new(client)))),
            params: params.clone(),
        })
    }

    /// Get the current client, rebuilding if it was invalidated.
    pub(crate) fn get_or_rebuild(&self) -> Result<Arc<reqwest::Client>, WebFetchError> {
        // Fast path: lock-free atomic load.
        if let Some(client) = self.inner.load_full() {
            return Ok(client);
        }
        // Client was invalidated — rebuild with a fresh connection pool.
        let fresh = Arc::new(Self::build(&self.params, None)?);
        self.inner.store(Some(Arc::clone(&fresh)));
        Ok(fresh)
    }

    /// Build a client that pins `allow.host` to the SSRF-validated addresses.
    ///
    /// When an egress proxy is configured, DNS for the origin is performed by
    /// the proxy, so pinning is skipped and the shared client is used instead
    /// (residual rebinding risk sits at the proxy trust boundary).
    pub(crate) fn client_for_ssrf_allow(
        &self,
        allow: &SsrfAllow,
    ) -> Result<Arc<reqwest::Client>, WebFetchError> {
        if self.params.proxy_endpoint.is_some() {
            return self.get_or_rebuild();
        }
        Ok(Arc::new(Self::build(
            &self.params,
            Some((allow.host.as_str(), allow.addrs.as_slice())),
        )?))
    }

    /// Atomically invalidate the cached client. The next `get_or_rebuild()`
    /// will construct a fresh one with a clean connection pool.
    pub(crate) fn invalidate(&self) {
        self.inner.store(None);
    }

    fn build(
        params: &WebFetchParams,
        dns_pin: Option<(&str, &[SocketAddr])>,
    ) -> Result<reqwest::Client, WebFetchError> {
        let mut builder = reqwest::Client::builder()
            .timeout(params.timeout_secs())
            .connect_timeout(std::time::Duration::from_secs(10))
            // We manage redirects for SSRF.
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(2)
            .pool_idle_timeout(std::time::Duration::from_secs(30))
            .tcp_nodelay(true)
            // Reduce size of incoming payloads.
            .gzip(true)
            .brotli(true)
            .deflate(true);

        // Pin hostname → validated IPs so connect cannot re-resolve to a
        // blocked address (DNS rebinding). TLS SNI / cert verification still
        // use the original hostname from the request URL.
        if let Some((host, addrs)) = dns_pin
            && !addrs.is_empty()
        {
            builder = builder.resolve_to_addrs(host, addrs);
        }

        // Route all traffic through the egress proxy when configured.
        if let Some(ref endpoint) = params.proxy_endpoint {
            let proxy = reqwest::Proxy::all(endpoint)
                .map_err(|e| WebFetchError::ProxyConfigError(e.to_string()))?;
            builder = builder.proxy(proxy);
        }

        builder.build().map_err(WebFetchError::ClientBuildError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_or_rebuild_returns_client() {
        let client = HttpClient::new(&WebFetchParams::default()).unwrap();
        let http = client.get_or_rebuild().unwrap();
        assert!(Arc::strong_count(&http) >= 1);
    }

    #[test]
    fn invalidate_forces_rebuild() {
        let client = HttpClient::new(&WebFetchParams::default()).unwrap();
        let first = client.get_or_rebuild().unwrap();
        let first_ptr = Arc::as_ptr(&first);

        client.invalidate();

        let second = client.get_or_rebuild().unwrap();
        let second_ptr = Arc::as_ptr(&second);

        // After invalidation, we should get a different client instance.
        assert_ne!(first_ptr, second_ptr);
    }

    #[test]
    fn build_with_proxy_endpoint() {
        let params = WebFetchParams {
            proxy_endpoint: Some("https://proxy.corp.example.com".into()),
            ..Default::default()
        };
        // Should succeed — reqwest accepts the proxy URL.
        let client = HttpClient::new(&params);
        assert!(client.is_ok());
    }

    #[test]
    fn build_without_proxy_is_default() {
        let params = WebFetchParams::default();
        assert!(params.proxy_endpoint.is_none());
        let client = HttpClient::new(&params);
        assert!(client.is_ok());
    }

    #[test]
    fn build_with_invalid_proxy_endpoint() {
        let params = WebFetchParams {
            proxy_endpoint: Some("not a valid url".into()),
            ..Default::default()
        };
        let result = HttpClient::new(&params);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("proxy"),
            "Expected proxy-related error, got: {err}"
        );
    }

    #[test]
    fn dns_pin_builds_client() {
        let params = WebFetchParams::default();
        let addr: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let client = HttpClient::build(&params, Some(("example.com", &[addr])));
        assert!(client.is_ok());
    }

    #[test]
    fn client_for_ssrf_allow_pins_without_proxy() {
        use super::super::ssrf::SsrfAllow;

        let http = HttpClient::new(&WebFetchParams::default()).unwrap();
        let allow = SsrfAllow {
            host: "example.com".into(),
            addrs: vec!["93.184.216.34:443".parse().unwrap()],
        };
        assert!(http.client_for_ssrf_allow(&allow).is_ok());
    }

    #[test]
    fn client_for_ssrf_allow_uses_shared_pool_with_proxy() {
        use super::super::ssrf::SsrfAllow;

        let params = WebFetchParams {
            proxy_endpoint: Some("http://127.0.0.1:8080".into()),
            ..Default::default()
        };
        let http = HttpClient::new(&params).unwrap();
        let allow = SsrfAllow {
            host: "example.com".into(),
            addrs: vec!["93.184.216.34:443".parse().unwrap()],
        };
        // Must succeed (shared client path); pin is intentionally skipped.
        assert!(http.client_for_ssrf_allow(&allow).is_ok());
    }
}
