//! Opt-in HTTP redirect following (`--follow-redirects`).
//!
//! The redirect chain and the final destination's certificate are reported
//! in their own field. They never replace the scanned target's certificate.

use crate::report::{certificate_report, CertificateReport, HttpRedirectInfo};
use anyhow::{anyhow, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::Duration;

/// Settings for redirect following.
#[derive(Debug, Clone)]
pub struct RedirectOptions {
    pub max_redirects: u32,
    pub timeout: Duration,
    /// Trust anchors; `None` uses the webpki-roots bundle.
    pub trust_anchors: Option<Arc<RootCertStore>>,
}

impl Default for RedirectOptions {
    fn default() -> Self {
        Self {
            max_redirects: 10,
            timeout: Duration::from_secs(10),
            trust_anchors: None,
        }
    }
}

fn tls_config(opts: &RedirectOptions) -> ClientConfig {
    let roots = match &opts.trust_anchors {
        Some(store) => (**store).clone(),
        None => crate::handshake::webpki_root_store(),
    };
    let mut config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Follow HTTP redirects from `start` (a URL, or `host[:port]` meaning https).
///
/// Each hop is one HEAD request, retried as GET if HEAD fails or returns 405.
/// When the chain ends on a different origin, that origin's leaf certificate
/// is fetched with a separate handshake and returned as
/// `final_destination_certificate`.
pub async fn follow_redirects(start: &str, opts: &RedirectOptions) -> Result<HttpRedirectInfo> {
    let mut url = if start.starts_with("http://") || start.starts_with("https://") {
        start.to_string()
    } else {
        format!("https://{}/", start)
    };
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(opts.timeout)
        .use_preconfigured_tls(tls_config(opts))
        .build()
        .map_err(|e| anyhow!("failed to create HTTP client: {}", e))?;

    let mut chain = vec![url.clone()];
    let mut first_status = None;
    let mut redirect_count = 0;

    for _ in 0..=opts.max_redirects {
        let response = match client.head(&url).send().await {
            Ok(resp) if resp.status() != reqwest::StatusCode::METHOD_NOT_ALLOWED => resp,
            _ => client
                .get(&url)
                .send()
                .await
                .map_err(|e| anyhow!("request to {} failed: {}", url, e))?,
        };
        let status = response.status();
        tracing::debug!("{} -> {}", url, status);
        if first_status.is_none() {
            first_status = Some(status.as_u16());
        }
        if !status.is_redirection() {
            break;
        }
        let Some(location) = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
        else {
            break;
        };
        let next = url::Url::parse(&url)
            .and_then(|base| base.join(location))
            .map_err(|e| anyhow!("invalid Location '{}': {}", location, e))?
            .to_string();
        if chain.contains(&next) {
            tracing::debug!("redirect loop at {}", next);
            break;
        }
        redirect_count += 1;
        chain.push(next.clone());
        url = next;
    }

    let origin = |u: &str| {
        url::Url::parse(u)
            .ok()
            .map(|p| (p.host_str().map(str::to_string), p.port_or_known_default()))
    };
    let final_certificate = if redirect_count > 0 && origin(&url) != origin(&chain[0]) {
        match certificate_for_url(&url, opts).await {
            Ok(cert) => Some(cert),
            Err(e) => {
                tracing::debug!("could not fetch certificate for {}: {}", url, e);
                None
            }
        }
    } else {
        None
    };

    Ok(HttpRedirectInfo {
        detected: redirect_count > 0,
        status_code: first_status,
        redirect_chain: chain,
        final_destination: (redirect_count > 0).then(|| url.clone()),
        final_destination_certificate: final_certificate,
        redirect_count,
    })
}

/// Leaf certificate presented by the HTTPS origin of `url`.
async fn certificate_for_url(url: &str, opts: &RedirectOptions) -> Result<CertificateReport> {
    let parsed = url::Url::parse(url)?;
    if parsed.scheme() != "https" {
        return Err(anyhow!("not an https URL: {}", url));
    }
    let host = match parsed.host() {
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        Some(h) => h.to_string(),
        None => return Err(anyhow!("no host in {}", url)),
    };
    let port = parsed.port_or_known_default().unwrap_or(443);
    let stream = tokio::time::timeout(
        opts.timeout,
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| anyhow!("connect timeout"))??;
    let server_name =
        ServerName::try_from(host.clone()).map_err(|e| anyhow!("invalid server name: {}", e))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config(opts)));
    let tls = tokio::time::timeout(opts.timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| anyhow!("handshake timeout"))??;
    let cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| anyhow!("no certificate presented"))?;
    certificate_report(0, cert.as_ref()).map_err(|e| anyhow!(e))
}
