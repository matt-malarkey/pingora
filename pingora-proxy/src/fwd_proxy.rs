// Based on pingora/examples/app/proxy.rs

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use async_trait::async_trait;
use bytes::Bytes;
use http::{header, Uri};
use log::info;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use pingora_core::InternalError;
use pingora_core::prelude::HttpPeer;
use pingora_core::protocols::l4::socket::SocketAddr;
use pingora_core::upstreams::peer::{PeerOptions, Scheme};
use pingora_http::ResponseHeader;
use pingora_core::Result;

use crate::{ProxyHttp, Session};

const ERROR_PAGE: &str = r#"
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error Page</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            text-align: center;
        }

        .container {
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            max-width: 400px;
            width: 100%;
        }

        h1 {
            color: #dc3545;
            margin-top: 0;
        }

        img {
            max-width: 100%;
            border-radius: 8px;
            margin-top: 20px;
        }
    </style>
</head>

<body>
    <div class="container">
        <h1>Error: Blocked By Toedi</h1>
        <p>The requested page is blocked by Toedi.</p>
        <img src="https://www.sac-cas.ch/processed/sa2020assetsprod/9/5/csm_1529074453_282291543master_5d70d66f47.jpg"
            alt="Blocked Image">
        <p>We don't ask shitty squid anymore!</p>
    </div>
</body>

</html>
"#;

pub struct MyCtx {
    host: String,
    ip: String,
    port: String,
}

unsafe impl Sync for MyCtx {}

unsafe impl Send for MyCtx {}

pub struct HttpFwdProxy();

#[async_trait]
impl ProxyHttp for HttpFwdProxy {
    type CTX = MyCtx;
    fn new_ctx(&self) -> Self::CTX {
        MyCtx {
            host: String::new(),
            ip: String::new(),
            port: String::new(),
        }
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let ip_addr = match Self::parse_ip_addr(&ctx.host) {
            Some(ip) => ip,
            _ => self.lookup_ip(&ctx.host).await.unwrap(),
        };
        info!("ip: {:?}", ip_addr);
        ctx.ip = ip_addr.clone();

        let mut peer_options = PeerOptions::new();
        peer_options.verify_cert = false; // Disable certificate verification
        // peer_options.verify_hostname = false; // Disable hostname verification if needed

        let http_peer = HttpPeer {
            _address: format!("{ip_addr}:{}", ctx.port)
                .parse::<SocketAddr>()
                .unwrap(),
            scheme: Scheme::HTTPS,
            sni: ctx.host.clone(),
            proxy: None,
            client_cert_key: None,
            group_key: 0,
            options: peer_options,
        };
        let peer = Box::new(http_peer);

        Ok(peer)
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        info!("req: {:?}", session.request_summary());
        info!("headers: {:?}", session.req_header());

        let (host, port) = Self::parse_request(session.req_header().uri.to_string())?;
        ctx.host = host.clone();
        ctx.port = port.to_string();
        info!("host: {:?}", host);
        info!("port: {:?}", port);

        if Self::domain_is_blocked(&host) {
            info!("blocked domain: {:?}", host);

            let body = Bytes::from_static(ERROR_PAGE.as_bytes());
            let resp = Self::gen_error_response(403, body.len());

            session.set_keepalive(None);
            let _ = session.write_response_header(Box::new(resp), true).await;
            let _ = session.write_response_body(Some(body), true).await;
            let _ = session
                .write_response_trailers(header::HeaderMap::new())
                .await;

            // true: tell the proxy that the response is already written
            return Ok(true);
        };
        return Ok(false);
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut pingora_http::RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        // upstream_request
        //     .insert_header("Host", "httpbingo.dev.osdp.open.ch")
        //     .unwrap();
        Ok(())
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        _upstream_response: &mut ResponseHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        _upstream_response.append_header("Via", "Toedi Secure Webgateway")?;

        Ok(())
    }
}

impl HttpFwdProxy {
    async fn execute_dig(&self, domain: &str) -> Option<String> {
        // workaround for local testing with envoy-tls-webserver
        if domain == "toe.di" {
            return Some("127.0.0.1".to_string());
        }

        let output = Command::new("dig")
            .arg("+short")
            .arg(domain)
            .output()
            .unwrap();

        if output.status.success() {
            // remove \n from the end
            let res = String::from_utf8(output.stdout).unwrap();
            let parts = res.split("\n").next();
            Some(parts.unwrap().to_string())
        } else {
            None
        }
    }

    async fn etc_resolv(&self, domain: &str) -> Option<String> {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let response = resolver.lookup_ip(domain).await.unwrap();
        return match response.iter().next() {
            Some(v) => Some(v.to_string()),
            _ => None,
        };
    }

    async fn lookup_ip(&self, domain: &str) -> Option<String> {
        match env::var("USE_DIG") {
            Ok(_) => self.execute_dig(domain).await,
            _ => self.etc_resolv(domain).await,
        }
    }

    fn parse_ip_addr(host: &String) -> Option<String> {
        if host.parse::<Ipv4Addr>().is_ok() {
            return Some(host.parse::<Ipv4Addr>().unwrap().to_string());
        }

        if host.parse::<Ipv6Addr>().is_ok() {
            return Some(host.parse::<Ipv6Addr>().unwrap().to_string());
        }

        return None;
    }

    fn parse_request(uri: String) -> Result<(String, u16)> {
        let uri = uri.parse::<Uri>().unwrap();
        info!("uri: {:?}", uri.to_string());

        let host = uri.host().ok_or(pingora_core::Error::explain(
            InternalError,
            "Could not parse host",
        ))?;

        let port = match uri.port_u16() {
            Some(p) => p,
            None => match uri.scheme_str() {
                // TODO Match other protocols
                Some("https") => 443,
                _ => 80,
            },
        };

        Ok((host.to_string(), port))
    }

    pub fn domain_is_blocked(domain: &str) -> bool {
        let blocked_domains = vec!["squid"];
        return blocked_domains.iter().any(|d| domain.contains(d));
    }

    pub fn gen_error_response(code: u16, len: usize) -> ResponseHeader {
        let mut resp = ResponseHeader::build(code, Some(2)).unwrap();
        resp.insert_header(header::CONTENT_LENGTH, len).unwrap();
        resp.insert_header(header::CACHE_CONTROL, "private, no-store")
            .unwrap();
        resp
    }
}

