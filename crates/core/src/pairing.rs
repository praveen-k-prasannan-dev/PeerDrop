//! One-time PIN pairing over an already-established (but not yet trusted) TLS
//! connection. See docs/PROTOCOL.md for the design rationale.
//!
//! The PIN is derived from both sides' raw TLS certificates via HKDF, so a
//! MITM presenting different certificates to each side makes each side
//! compute a *different* PIN - the human "do these match?" confirmation is
//! what actually detects that, not a network-guessable secret. Trust is only
//! persisted once *both* sides have locally confirmed and exchanged that
//! confirmation over the connection.

use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const PAIRING_HKDF_SALT: &[u8] = b"peerdrop-pairing-v1";
const MAX_FRAME_LEN: u32 = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed pairing message: {0}")]
    Malformed(#[from] serde_json::Error),
    #[error("frame too large ({0} bytes)")]
    FrameTooLarge(u32),
    #[error("connection closed before pairing completed")]
    ConnectionClosed,
    #[error("peer sent an unexpected message")]
    UnexpectedMessage,
    #[error("timed out waiting for the peer")]
    TimedOut,
    #[error("device has no reachable address")]
    NoAddress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum PairingMessage {
    Hello { device_id: String, device_name: String, os: String },
    Confirmed,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct LocalIdentity {
    pub device_id: String,
    pub device_name: String,
    pub os: String,
}

#[derive(Debug, Clone)]
pub struct PeerHello {
    pub device_id: String,
    pub device_name: String,
    pub os: String,
}

async fn write_frame<S: tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    msg: &PairingMessage,
) -> Result<(), PairingError> {
    let bytes = serde_json::to_vec(msg)?;
    let len = bytes.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Result<PairingMessage, PairingError> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            PairingError::ConnectionClosed
        } else {
            PairingError::Io(e)
        }
    })?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_LEN {
        return Err(PairingError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;
    Ok(serde_json::from_slice(&buf)?)
}

/// Exchange device introductions over the connection. Both sides call this;
/// order doesn't matter since each write/read pair is independent.
pub async fn exchange_hello<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    local: &LocalIdentity,
) -> Result<PeerHello, PairingError> {
    write_frame(
        stream,
        &PairingMessage::Hello {
            device_id: local.device_id.clone(),
            device_name: local.device_name.clone(),
            os: local.os.clone(),
        },
    )
    .await?;

    match read_frame(stream).await? {
        PairingMessage::Hello { device_id, device_name, os } => Ok(PeerHello { device_id, device_name, os }),
        _ => Err(PairingError::UnexpectedMessage),
    }
}

/// Derives the 6-digit PIN both sides should display. Order-independent: it's the
/// same value regardless of which side is the TLS client vs. server.
pub fn derive_pin(cert_a_der: &[u8], cert_b_der: &[u8]) -> u32 {
    let (first, second) = if cert_a_der <= cert_b_der {
        (cert_a_der, cert_b_der)
    } else {
        (cert_b_der, cert_a_der)
    };
    let mut ikm = Vec::with_capacity(first.len() + second.len());
    ikm.extend_from_slice(first);
    ikm.extend_from_slice(second);

    let hk = Hkdf::<Sha256>::new(Some(PAIRING_HKDF_SALT), &ikm);
    let mut okm = [0u8; 4];
    hk.expand(b"pin", &mut okm)
        .expect("4-byte output is within HKDF-SHA256's valid length range");
    u32::from_be_bytes(okm) % 1_000_000
}

/// Sends this side's confirm/reject decision, then waits (with `timeout`) for the
/// peer's. Pairing should only be treated as successful if this returns `Ok(true)`.
pub async fn confirm_and_wait_for_peer<S>(
    stream: &mut S,
    locally_confirmed: bool,
    timeout: std::time::Duration,
) -> Result<bool, PairingError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    write_frame(
        stream,
        if locally_confirmed { &PairingMessage::Confirmed } else { &PairingMessage::Rejected },
    )
    .await?;

    if !locally_confirmed {
        return Ok(false);
    }

    match tokio::time::timeout(timeout, read_frame(stream)).await {
        Ok(Ok(PairingMessage::Confirmed)) => Ok(true),
        Ok(Ok(_)) => Ok(false),
        Ok(Err(_)) => Ok(false),
        Err(_) => Err(PairingError::TimedOut),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_pin_is_order_independent_and_in_range() {
        let cert_a = b"certificate-bytes-a";
        let cert_b = b"certificate-bytes-b";
        let pin_ab = derive_pin(cert_a, cert_b);
        let pin_ba = derive_pin(cert_b, cert_a);
        assert_eq!(pin_ab, pin_ba);
        assert!(pin_ab < 1_000_000);
    }

    #[test]
    fn derive_pin_differs_for_different_cert_pairs() {
        let cert_a = b"certificate-bytes-a";
        let cert_b = b"certificate-bytes-b";
        let cert_c = b"certificate-bytes-c";
        assert_ne!(derive_pin(cert_a, cert_b), derive_pin(cert_a, cert_c));
    }

    #[tokio::test]
    async fn exchange_hello_over_a_duplex_stream() {
        let (mut a, mut b) = tokio::io::duplex(1024);

        let local_a = LocalIdentity {
            device_id: "device-a".into(),
            device_name: "A's Mac".into(),
            os: "macos".into(),
        };
        let local_b = LocalIdentity {
            device_id: "device-b".into(),
            device_name: "B's PC".into(),
            os: "windows".into(),
        };

        let (hello_from_b, hello_from_a) =
            tokio::join!(exchange_hello(&mut a, &local_a), exchange_hello(&mut b, &local_b));

        let hello_from_b = hello_from_b.unwrap();
        let hello_from_a = hello_from_a.unwrap();
        assert_eq!(hello_from_b.device_id, "device-b");
        assert_eq!(hello_from_a.device_id, "device-a");
    }

    #[tokio::test]
    async fn both_sides_confirming_yields_success_on_both() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let (result_a, result_b) = tokio::join!(
            confirm_and_wait_for_peer(&mut a, true, std::time::Duration::from_secs(1)),
            confirm_and_wait_for_peer(&mut b, true, std::time::Duration::from_secs(1)),
        );
        assert!(result_a.unwrap());
        assert!(result_b.unwrap());
    }

    #[tokio::test]
    async fn one_side_rejecting_fails_pairing_on_both() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        let (result_a, result_b) = tokio::join!(
            confirm_and_wait_for_peer(&mut a, true, std::time::Duration::from_secs(1)),
            confirm_and_wait_for_peer(&mut b, false, std::time::Duration::from_secs(1)),
        );
        assert!(!result_a.unwrap());
        assert!(!result_b.unwrap());
    }
}
