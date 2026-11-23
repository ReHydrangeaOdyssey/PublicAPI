use axum::{Extension, Router};
use axum_server::{
    accept::Accept,
    tls_rustls::{RustlsAcceptor, RustlsConfig},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{future::Future, io, net::SocketAddr, pin::Pin, sync::Arc};
use tokio::net::TcpStream;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    PublicApi,
    GameServer,
    Coordinator,
    Operator,
    DiscordBot,
}

#[derive(Clone, Debug)]
pub struct Peer {
    pub role: Role,
    pub instance_id: Option<String>,
}

#[derive(serde::Deserialize)]
pub struct PeerCertificate {
    pub certificate: String,
    pub role: Role,
    pub instance_id: Option<String>,
}

#[derive(Clone)]
pub struct AuthenticatedAcceptor {
    tls: RustlsAcceptor,
    peers: Arc<Vec<(CertificateDer<'static>, Peer)>>,
}

impl Accept<TcpStream, Router> for AuthenticatedAcceptor {
    type Stream = <RustlsAcceptor as Accept<TcpStream, Router>>::Stream;
    type Service = Router;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Router)>> + Send>>;
    fn accept(&self, stream: TcpStream, service: Router) -> Self::Future {
        let future = self.tls.accept(stream, service);
        let peers = self.peers.clone();
        Box::pin(async move {
            let (stream, service) = future.await?;
            let connection = stream.get_ref().1;
            if connection.alpn_protocol() != Some(b"h2") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "HTTP/2 required",
                ));
            }
            let certificate = connection
                .peer_certificates()
                .and_then(|chain| chain.first())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "client certificate required",
                    )
                })?;
            // Pin only after rustls has verified the certificate chain and possession of its key.
            let peer = peers
                .iter()
                .find(|(pinned, _)| pinned == certificate)
                .map(|(_, peer)| peer.clone())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "unknown service certificate",
                    )
                })?;
            Ok((stream, service.layer(Extension(peer))))
        })
    }
}

pub async fn tls_config(cert: &str, key: &str, ca: Option<&str>) -> Result<RustlsConfig, Error> {
    let certificates = CertificateDer::pem_slice_iter(&tokio::fs::read(cert).await?)
        .collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(&tokio::fs::read(key).await?)?;
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if let Some(ca) = ca {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(&tokio::fs::read(ca).await?) {
            roots.add(certificate?)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(certificates, key)?
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(config)))
}

pub async fn serve_internal(
    address: SocketAddr,
    app: Router,
    config: RustlsConfig,
    entries: Vec<PeerCertificate>,
) -> Result<(), Error> {
    if entries.is_empty() {
        return Err("service certificate allowlist is empty".into());
    }
    let mut peers = Vec::new();
    for entry in entries {
        let pem = tokio::fs::read(entry.certificate).await?;
        let certificate = CertificateDer::from_pem_slice(&pem)?;
        if peers.iter().any(|(existing, _)| existing == &certificate) {
            return Err("duplicate service certificate".into());
        }
        if entry.role == Role::GameServer
            && entry.instance_id.as_ref().is_none_or(|id| id.is_empty())
        {
            return Err("GameServer certificate requires instance identity".into());
        }
        peers.push((
            certificate,
            Peer {
                role: entry.role,
                instance_id: entry.instance_id,
            },
        ));
    }
    let acceptor = AuthenticatedAcceptor {
        tls: RustlsAcceptor::new(config),
        peers: Arc::new(peers),
    };
    axum_server::bind(address)
        .acceptor(acceptor)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

pub async fn internal_client(ca: &str, identity: &str) -> Result<reqwest::Client, Error> {
    let ca = reqwest::Certificate::from_pem(&tokio::fs::read(ca).await?)?;
    let identity = reqwest::Identity::from_pem(&tokio::fs::read(identity).await?)?;
    Ok(reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca)
        .identity(identity)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .max_tls_version(reqwest::tls::Version::TLS_1_3)
        .https_only(true)
        .http2_prior_knowledge()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}
