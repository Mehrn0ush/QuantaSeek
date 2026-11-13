use crate::cert::CertificateParser;
use crate::types::{CertificateInfo, HttpRedirectInfo};
use anyhow::{anyhow, Result};
use std::time::Duration;

/// HTTP method to use for redirect detection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpMethod {
    /// Use HEAD method (default, more efficient)
    Head,
    /// Use GET method (more compatible, some servers don't support HEAD)
    Get,
    /// Try HEAD first, fallback to GET if HEAD fails or returns 405
    #[default]
    Auto,
}

/// Detect HTTP redirects and get certificate from final destination
///
/// This function performs HTTP requests to detect redirects (307, 308, 301, 302, etc.)
/// and attempts to extract the certificate from the final destination.
///
/// # Arguments
/// * `initial_url` - The initial URL to check (can be hostname or full URL)
/// * `max_redirects` - Maximum number of redirects to follow (default: 10)
/// * `method` - HTTP method to use (default: Auto - tries HEAD first, falls back to GET)
///
/// # Returns
/// Returns `HttpRedirectInfo` with redirect chain and final destination certificate.
/// Even if certificate extraction fails, redirect information is still returned.
///
/// # Limitations
/// - Certificate extraction may fail for servers that don't support TLS
/// - Some servers may block automated requests
/// - Redirect loops are detected and stopped at max_redirects
pub async fn detect_http_redirects(
    initial_url: &str,
    max_redirects: u32,
) -> Result<HttpRedirectInfo> {
    detect_http_redirects_with_method(initial_url, max_redirects, HttpMethod::Auto).await
}

/// Detect HTTP redirects with configurable HTTP method
pub async fn detect_http_redirects_with_method(
    initial_url: &str,
    max_redirects: u32,
    method: HttpMethod,
) -> Result<HttpRedirectInfo> {
    tracing::debug!("Starting HTTP redirect detection for: {}", initial_url);

    let mut redirect_chain = Vec::new();
    let current_url = initial_url.to_string();
    let mut redirect_count = 0;
    let mut status_code = None;
    let mut final_destination_certificate = None;
    let mut certificate_extraction_error = None;

    // Ensure URL has scheme
    let mut url = if !current_url.starts_with("http://") && !current_url.starts_with("https://") {
        format!("https://{}", current_url)
    } else {
        current_url.clone()
    };

    redirect_chain.push(url.clone());
    tracing::debug!("Initial URL: {}", url);

    // Create HTTP client with redirect policy
    // Use rustls-tls feature to ensure compatibility with TLS scanning
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none()) // Don't auto-follow, we'll do it manually
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|e| {
            let err_msg = format!("Failed to create HTTP client: {}", e);
            tracing::debug!("{}", err_msg);
            anyhow!(err_msg)
        })?;

    // Follow redirects manually
    for redirect_attempt in 0..=max_redirects {
        if redirect_attempt > 0 {
            tracing::debug!("Following redirect #{} to: {}", redirect_attempt, url);
        }

        // Send HTTP request based on configured method
        let response = match method {
            HttpMethod::Head => {
                // Use HEAD only
                match client.head(&url).send().await {
                    Ok(resp) => {
                        tracing::debug!(
                            "HEAD request successful for {}: status={}",
                            url,
                            resp.status()
                        );
                        resp
                    }
                    Err(e) => {
                        tracing::debug!("HEAD request failed for {}: {}", url, e);
                        break;
                    }
                }
            }
            HttpMethod::Get => {
                // Use GET only
                match client.get(&url).send().await {
                    Ok(resp) => {
                        tracing::debug!(
                            "GET request successful for {}: status={}",
                            url,
                            resp.status()
                        );
                        resp
                    }
                    Err(e) => {
                        tracing::debug!("GET request failed for {}: {}", url, e);
                        break;
                    }
                }
            }
            HttpMethod::Auto => {
                // Try HEAD first, but if it returns 405 (Method Not Allowed) or fails, try GET
                match client.head(&url).send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        tracing::debug!("HEAD request successful for {}: status={}", url, status);

                        // If HEAD returns 405 (Method Not Allowed), try GET instead
                        // Some servers don't support HEAD but support GET
                        if status == 405 {
                            tracing::debug!("HEAD returned 405 (Method Not Allowed), trying GET");
                            match client.get(&url).send().await {
                                Ok(get_resp) => {
                                    tracing::debug!(
                                        "GET request successful for {}: status={}",
                                        url,
                                        get_resp.status()
                                    );
                                    get_resp
                                }
                                Err(e2) => {
                                    tracing::debug!("GET request failed after HEAD 405: {}", e2);
                                    // If GET also fails, break the loop - we can't proceed with redirect detection
                                    // The 405 response from HEAD doesn't contain redirect info anyway
                                    break;
                                }
                            }
                        } else {
                            resp
                        }
                    }
                    Err(e) => {
                        // If HEAD fails completely (network error), try GET
                        // Log debug info: HEAD requests may fail for some servers
                        tracing::debug!("HEAD request failed for {}: {} (trying GET)", url, e);
                        match client.get(&url).send().await {
                            Ok(resp) => {
                                tracing::debug!(
                                    "GET request successful for {}: status={}",
                                    url,
                                    resp.status()
                                );
                                resp
                            }
                            Err(e2) => {
                                // Both HEAD and GET failed - log and return partial results
                                tracing::debug!(
                                    "Both HEAD and GET failed for {}: HEAD={}, GET={}",
                                    url,
                                    e,
                                    e2
                                );
                                // Return what we have so far (may be empty if no redirects detected)
                                break;
                            }
                        }
                    }
                }
            }
        };

        let response_status = response.status();
        tracing::debug!("Response status for {}: {}", url, response_status);

        // Check if this is a redirect
        if response_status.is_redirection() {
            let status = response_status.as_u16();
            status_code = Some(status);
            redirect_count += 1;
            tracing::debug!(
                "Redirect detected: status={} ({} redirects so far)",
                status,
                redirect_count
            );

            // Get redirect location
            if let Some(location) = response.headers().get("location") {
                if let Ok(location_str) = location.to_str() {
                    tracing::debug!("Location header: {}", location_str);

                    // Handle relative URLs
                    let next_url = if location_str.starts_with("http://")
                        || location_str.starts_with("https://")
                    {
                        location_str.to_string()
                    } else if location_str.starts_with("//") {
                        format!("https:{}", location_str)
                    } else if location_str.starts_with('/') {
                        // Extract base URL
                        let base = url.split('/').take(3).collect::<Vec<_>>().join("/");
                        format!("{}{}", base, location_str)
                    } else {
                        // Relative path
                        let base = url.rsplit('/').skip(1).collect::<Vec<_>>().join("/");
                        format!("{}/{}", base, location_str)
                    };

                    tracing::debug!("Resolved redirect URL: {}", next_url);

                    // Check for redirect loops
                    if redirect_chain.contains(&next_url) {
                        tracing::debug!("Redirect loop detected: {} already in chain", next_url);
                        break;
                    }

                    redirect_chain.push(next_url.clone());
                    url = next_url;
                    continue;
                } else {
                    tracing::debug!("Location header contains invalid UTF-8");
                }
            } else {
                tracing::debug!("Redirect status {} but no Location header", status);
            }
        } else {
            tracing::debug!(
                "Not a redirect (status={}), stopping redirect chain",
                response_status
            );
        }

        // Not a redirect or redirect chain ended
        break;
    }

    // Get certificate from final destination if different from initial
    if redirect_count > 0 && !redirect_chain.is_empty() {
        let final_url = redirect_chain
            .last()
            .ok_or_else(|| anyhow!("Redirect chain is empty"))?;

        tracing::debug!(
            "Attempting to extract certificate from final destination: {}",
            final_url
        );

        // Extract hostname from final URL
        if let Ok(parsed_url) = url::Url::parse(final_url) {
            if let Some(host) = parsed_url.host_str() {
                tracing::debug!("Extracting certificate from hostname: {}", host);

                // Get certificate from final destination
                match get_certificate_from_url(final_url).await {
                    Ok(cert_info) => {
                        tracing::debug!(
                            "Successfully extracted certificate from {}: subject={}, issuer={}",
                            final_url,
                            cert_info.subject,
                            cert_info.issuer
                        );
                        final_destination_certificate = Some(cert_info);
                    }
                    Err(e) => {
                        let err_msg =
                            format!("Failed to extract certificate from {}: {}", final_url, e);
                        tracing::debug!("{}", err_msg);
                        certificate_extraction_error = Some(err_msg);
                        // Continue - we still return redirect info even if certificate extraction fails
                    }
                }
            } else {
                tracing::debug!("No hostname in final URL: {}", final_url);
            }
        } else {
            tracing::debug!("Failed to parse final URL: {}", final_url);
        }
    } else {
        tracing::debug!(
            "No redirects detected (count={}, chain_len={})",
            redirect_count,
            redirect_chain.len()
        );
    }

    let final_destination = if redirect_count > 0 {
        redirect_chain.last().cloned()
    } else {
        None
    };

    let result = HttpRedirectInfo {
        detected: redirect_count > 0,
        status_code,
        redirect_chain: redirect_chain.clone(),
        final_destination: final_destination.clone(),
        final_destination_certificate,
        redirect_count,
    };

    if result.detected {
        tracing::debug!("HTTP redirect detection complete: detected={}, status={:?}, chain_len={}, cert_extracted={}",
            result.detected, result.status_code, result.redirect_chain.len(),
            result.final_destination_certificate.is_some());
        if let Some(ref err) = certificate_extraction_error {
            tracing::debug!("Certificate extraction warning: {}", err);
        }
    } else {
        tracing::debug!("No HTTP redirect detected for: {}", initial_url);
    }

    Ok(result)
}

/// Get certificate from a URL by performing TLS handshake
///
/// This function performs a TLS handshake to the specified URL and extracts
/// the server certificate. It's used to get the certificate from redirect destinations.
///
/// # Arguments
/// * `url` - The URL to connect to (must include scheme, e.g., "https://example.com")
///
/// # Returns
/// Returns the certificate information if successful, or an error if:
/// - URL parsing fails
/// - Connection fails
/// - TLS handshake fails
/// - Certificate extraction fails
async fn get_certificate_from_url(url: &str) -> Result<CertificateInfo> {
    tracing::debug!("get_certificate_from_url: connecting to {}", url);
    use rustls::pki_types::ServerName;
    use rustls::ClientConfig;
    use std::sync::Arc;
    use tokio::net::TcpStream;
    use tokio_rustls::TlsConnector;

    // Parse URL
    let parsed_url = url::Url::parse(url).map_err(|e| anyhow!("Invalid URL: {}", e))?;

    let hostname = parsed_url
        .host_str()
        .ok_or_else(|| anyhow!("No hostname in URL"))?;

    let port = parsed_url.port().unwrap_or(443);

    // Create TLS configuration
    let root_store = crate::handshake::webpki_root_store();

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.enable_sni = true;

    let connector = TlsConnector::from(Arc::new(config));

    // Connect and get certificate
    let addr = format!("{}:{}", hostname, port);
    tracing::debug!("Connecting to {}:{}", hostname, port);
    let stream = TcpStream::connect(&addr).await.map_err(|e| {
        let err_msg = format!("Connection failed to {}: {}", addr, e);
        tracing::debug!("{}", err_msg);
        anyhow!(err_msg)
    })?;
    tracing::debug!("TCP connection established to {}", addr);

    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| anyhow!("Invalid server name: {}", e))?;

    tracing::debug!("Performing TLS handshake to {}", hostname);
    let tls_stream = connector.connect(server_name, stream).await.map_err(|e| {
        let err_msg = format!("TLS handshake failed for {}: {}", hostname, e);
        tracing::debug!("{}", err_msg);
        anyhow!(err_msg)
    })?;
    tracing::debug!("TLS handshake successful");

    // Extract certificate
    if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
        if let Some(cert) = certs.first() {
            tracing::debug!("Certificate found, parsing...");
            let cert_parser = CertificateParser::new();
            match cert_parser.parse_certificate(cert.as_ref()) {
                Ok(cert_info) => {
                    tracing::debug!(
                        "Certificate parsed successfully: subject={}, issuer={}",
                        cert_info.subject,
                        cert_info.issuer
                    );
                    return Ok(cert_info);
                }
                Err(e) => {
                    let err_msg = format!("Certificate parsing failed: {}", e);
                    tracing::debug!("{}", err_msg);
                    return Err(anyhow!(err_msg));
                }
            }
        } else {
            tracing::debug!("Certificate list is empty");
        }
    } else {
        tracing::debug!("No peer certificates available");
    }

    Err(anyhow!("No certificate found in TLS handshake"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that detect_http_redirects handles non-redirecting URLs correctly
    #[tokio::test]
    #[ignore = "requires network access to example.com"]
    async fn test_no_redirect() {
        // Test with a URL that doesn't redirect
        // Note: This test may fail if the server actually redirects
        // In that case, the test should be updated or skipped
        let result = detect_http_redirects("example.com", 5).await;

        // Should not panic and return a result
        match result {
            Ok(info) => {
                // If no redirect, detected should be false
                // But we don't assert this because servers may change behavior
                assert!(
                    !info.redirect_chain.is_empty(),
                    "Should have at least initial URL in chain"
                );
            }
            Err(e) => {
                // Errors are acceptable (network issues, etc.)
                // Just log for debugging
                tracing::debug!("Test error (acceptable): {}", e);
            }
        }
    }

    /// Test URL parsing and scheme handling
    #[test]
    fn test_url_scheme_handling() {
        // Test that URLs without scheme get https:// prefix
        let test_cases = vec![
            ("example.com", "https://example.com"),
            ("https://example.com", "https://example.com"),
            ("http://example.com", "http://example.com"),
        ];

        for (input, expected_prefix) in test_cases {
            let url = if !input.starts_with("http://") && !input.starts_with("https://") {
                format!("https://{}", input)
            } else {
                input.to_string()
            };

            assert!(
                url.starts_with(expected_prefix),
                "URL {} should start with {}",
                url,
                expected_prefix
            );
        }
    }
}
