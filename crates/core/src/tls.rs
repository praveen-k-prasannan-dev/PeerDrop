//! Mutual TLS 1.3 configuration built from a device's self-signed [`Identity`].
//!
//! Milestone 3 only: the verifier here accepts whatever certificate the peer
//! presents ("trust anyone once"), so we can prove the rustls plumbing - cert
//! generation, mutual auth, an actual encrypted byte stream - works end to end
//! before Milestone 4 adds real trust-on-first-use pinning + PIN pairing.

use crate::identity::Identity;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use std::sync::Arc;

#[derive(Debug)]
struct TrustAnyoneOnce {
    provider: Arc<CryptoProvider>,
}

fn tls12_unsupported() -> rustls::Error {
    rustls::Error::General("TLS 1.2 is not supported; PeerDrop requires TLS 1.3".into())
}

impl ServerCertVerifier for TrustAnyoneOnce {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls12_unsupported())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for TrustAnyoneOnce {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(tls12_unsupported())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A mutual-TLS client config that presents `identity` and accepts any peer certificate.
pub fn client_config_trust_anyone(identity: &Identity) -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(TrustAnyoneOnce { provider: provider.clone() });

    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported by the ring provider")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(vec![identity.cert_der.clone()], identity.key_der.clone_key())
        .expect("identity cert/key are valid for client auth");

    Arc::new(config)
}

/// A mutual-TLS server config that presents `identity` and accepts any peer certificate.
pub fn server_config_trust_anyone(identity: &Identity) -> Arc<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(TrustAnyoneOnce { provider: provider.clone() });

    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("TLS 1.3 is supported by the ring provider")
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![identity.cert_der.clone()], identity.key_der.clone_key())
        .expect("identity cert/key are valid for server use");

    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    fn test_identity(device_id: &str) -> Identity {
        let CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![format!("{device_id}.local")]).unwrap();
        Identity {
            cert_der: cert.der().clone(),
            key_der: rustls::pki_types::PrivateKeyDer::Pkcs8(
                rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
            ),
        }
    }
    use rcgen::CertifiedKey;

    /// Proves the mutual-TLS plumbing works end to end: two independently generated
    /// identities complete a TLS 1.3 handshake over loopback and exchange a message.
    #[tokio::test]
    async fn client_and_server_exchange_a_message_over_mutual_tls() {
        let server_identity = test_identity("server-device");
        let client_identity = test_identity("client-device");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(server_config_trust_anyone(&server_identity));

        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            tls.write_all(b"pong").await.unwrap();
            tls.shutdown().await.unwrap();
            buf[..n].to_vec()
        });

        let connector = TlsConnector::from(client_config_trust_anyone(&client_identity));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        tls.write_all(b"ping").await.unwrap();

        let mut reply = [0u8; 64];
        let n = tls.read(&mut reply).await.unwrap();
        tls.shutdown().await.unwrap();

        let received_by_server = server.await.unwrap();
        assert_eq!(&received_by_server, b"ping");
        assert_eq!(&reply[..n], b"pong");
    }
}
