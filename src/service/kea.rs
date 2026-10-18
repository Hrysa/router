use std::{net::Ipv4Addr, path::Path, time::Duration};

use serde_json::{json, Value};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

const SOCKET: &str = "/run/kea/kea-dhcp4.sock";
const MAX_RESPONSE: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("lease no longer exists")]
    NotFound,
    #[error("Kea lease deletion requires the lease_cmds hook. Install libdhcp_lease_cmds.so in a supported Kea hooks directory, then Apply DHCP configuration.")]
    Unsupported,
    #[error("Kea control socket is unavailable; check that Kea is running with the saved configuration applied")]
    Unavailable,
    #[error(
        "Kea lease deletion timed out; its outcome is unknown. Refresh leases before retrying."
    )]
    Timeout,
    #[error("Kea rejected lease deletion: {0}")]
    Rejected(String),
    #[error("Kea returned an invalid lease deletion response; refresh leases before retrying")]
    InvalidResponse,
}

pub async fn delete_lease(address: Ipv4Addr) -> Result<(), LeaseError> {
    delete_lease_at(Path::new(SOCKET), address, Duration::from_secs(5)).await
}

async fn delete_lease_at(
    socket: &Path,
    address: Ipv4Addr,
    timeout: Duration,
) -> Result<(), LeaseError> {
    tokio::time::timeout(timeout, async {
        let mut stream = UnixStream::connect(socket)
            .await
            .map_err(|_| LeaseError::Unavailable)?;
        let command =
            json!({"command": "lease4-del", "arguments": {"ip-address": address.to_string()}});
        stream
            .write_all(command.to_string().as_bytes())
            .await
            .map_err(|_| LeaseError::Unavailable)?;
        let mut response = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = stream
                .read(&mut buffer)
                .await
                .map_err(|_| LeaseError::InvalidResponse)?;
            if count == 0 || response.len() + count > MAX_RESPONSE {
                return Err(LeaseError::InvalidResponse);
            }
            response.extend_from_slice(&buffer[..count]);
            match serde_json::from_slice::<Value>(&response) {
                Ok(value) => return check_response(&value),
                Err(error) if error.is_eof() => continue,
                Err(_) => return Err(LeaseError::InvalidResponse),
            }
        }
    })
    .await
    .map_err(|_| LeaseError::Timeout)?
}

fn check_response(value: &Value) -> Result<(), LeaseError> {
    // A direct Unix control socket returns an object, unlike the HTTP agent.
    match value.get("result").and_then(Value::as_i64) {
        Some(0) => Ok(()),
        Some(2) => Err(LeaseError::Unsupported),
        Some(3) => Err(LeaseError::NotFound),
        Some(_) => Err(LeaseError::Rejected(
            value["text"].as_str().unwrap_or("unspecified error").into(),
        )),
        None => Err(LeaseError::InvalidResponse),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn sends_delete_command_and_handles_fragmented_reply_without_waiting_for_eof() {
        let directory = std::env::temp_dir().join(format!("routerd-kea-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = Vec::new();
            let mut bytes = [0; 1024];
            loop {
                let count = stream.read(&mut bytes).await.unwrap();
                assert_ne!(count, 0);
                command.extend_from_slice(&bytes[..count]);
                if let Ok(value) = serde_json::from_slice::<Value>(&command) {
                    assert_eq!(
                        value,
                        json!({"command":"lease4-del", "arguments":{"ip-address":"192.0.2.1"}})
                    );
                    break;
                }
            }
            stream.write_all(br#"{"result":"#).await.unwrap();
            tokio::task::yield_now().await;
            stream.write_all(br#"0,"text":"deleted"}"#).await.unwrap();
            // Keep the server side open until the client has parsed the response.
            let _ = stream.read(&mut bytes).await;
        });
        delete_lease_at(
            &socket,
            "192.0.2.1".parse().unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failures_are_never_reported_as_success() {
        assert!(matches!(
            check_response(&json!({"result":2})),
            Err(LeaseError::Unsupported)
        ));
        assert!(matches!(
            check_response(&json!({"result":3})),
            Err(LeaseError::NotFound)
        ));
        assert!(matches!(
            check_response(&json!({"result":1,"text":"failed"})),
            Err(LeaseError::Rejected(_))
        ));
        assert!(matches!(
            check_response(&json!({"text":"ok"})),
            Err(LeaseError::InvalidResponse)
        ));
    }

    #[tokio::test]
    async fn missing_socket_and_timeout_fail() {
        let directory = std::env::temp_dir().join(format!("routerd-kea-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).unwrap();
        let socket = directory.join("control.sock");
        let address = "192.0.2.1".parse().unwrap();
        assert!(matches!(
            delete_lease_at(&socket, address, Duration::from_secs(1)).await,
            Err(LeaseError::Unavailable)
        ));
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(matches!(
            delete_lease_at(&socket, address, Duration::from_millis(20)).await,
            Err(LeaseError::Timeout)
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
