// Copyright 2024 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{env, fs};

use async_trait::async_trait;
use log::info;
use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair, SanType};
use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_proxy::fwd_proxy::HttpFwdProxy;

#[cfg(feature = "openssl_derived")]
use pingora_core::tls::ext;
#[cfg(feature = "openssl_derived")]
use pingora_core::tls::pkey::{PKey, Private};
#[cfg(feature = "openssl_derived")]
use pingora_core::tls::ssl::NameType;
#[cfg(feature = "openssl_derived")]
use pingora_core::tls::x509::X509;

struct DynamicCert {
    cert: Certificate,
}

impl DynamicCert {
    fn new(cert: &str, key: &str) -> Box<Self> {
        let cert_bytes = fs::read(cert).unwrap();
        let key_bytes = fs::read(key).unwrap();

        let cert_str = String::from_utf8(cert_bytes).unwrap();
        let key_str = String::from_utf8(key_bytes).unwrap();

        let key_pair = KeyPair::from_pem(&key_str.to_string()).unwrap();
        let ca_cert_params = CertificateParams::from_ca_cert_pem(&cert_str.to_string(), key_pair).unwrap();
        let cert = Certificate::from_params(ca_cert_params).unwrap();

        Box::new(DynamicCert { cert })
    }
}

#[cfg(feature = "openssl_derived")]
fn signed_cert_with_ca(ca_cert: &Certificate, dn_name: String) -> (X509, PKey<Private>) {
    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, dn_name.clone());

    let mut params = CertificateParams::default();
    params.distinguished_name = dn;
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365 * 20);
    params.subject_alt_names = vec![
        SanType::DnsName(dn_name.clone()),
        SanType::DnsName(String::from("localhost")),
        SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
        SanType::IpAddress(std::net::IpAddr::V6(std::net::Ipv6Addr::new(
            0, 0, 0, 0, 0, 0, 0, 1,
        ))),
    ];
    let cert = Certificate::from_params(params).unwrap();
    let cert_signed = cert.serialize_pem_with_signer(&ca_cert).unwrap();

    let x509 = X509::from_pem(cert_signed.as_bytes()).unwrap();
    let pkey = PKey::private_key_from_pem(cert.serialize_private_key_pem().as_bytes()).unwrap();

    return (x509, pkey);
}

#[cfg(feature = "openssl_derived")]
#[async_trait]
impl pingora_core::listeners::TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut pingora_core::tls::ssl::SslRef) {
        let dn_name = ssl.servername(NameType::HOST_NAME).unwrap();
        info!("SNI for cert gen {:?}", dn_name);

        let (cert, key) = signed_cert_with_ca(&self.cert, String::from(dn_name));
        ext::ssl_use_certificate(ssl, &cert).unwrap();
        ext::ssl_use_private_key(ssl, &*key).unwrap();
    }
}


// RUST_LOG=INFO cargo run --package pingora-proxy --example fwd_proxy_example --features openssl
fn main() {
    env_logger::init();

    // Set up server, read command line arguments
    let mut my_server = Server::new(Opt::default()).unwrap();
    my_server.bootstrap();

    // Reverse proxy with TLS inspection: port 6189
    let mut proxy = pingora_proxy::http_proxy_service(&my_server.configuration, HttpFwdProxy());

    let mut tls_settings;
    #[cfg(feature = "openssl_derived")]
    {
        let cert_path = format!("{}/tests/keys/tls.crt", env!("CARGO_MANIFEST_DIR"));
        let key_path = format!("{}/tests/keys/tls.key", env!("CARGO_MANIFEST_DIR"));
        let dynamic_cert = DynamicCert::new(&cert_path, &key_path);
        tls_settings = pingora_core::listeners::tls::TlsSettings::with_callbacks(dynamic_cert).unwrap();
    }
    #[cfg(not(feature = "any_tls"))]
    {
        tls_settings = TlsSettings;
    }

    tls_settings.enable_h2();
    proxy.add_tcp_with_upgrade("0.0.0.0:6189", None, tls_settings);

    my_server.add_service(proxy);

    my_server.run_forever();
}
