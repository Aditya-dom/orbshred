use std::net::UdpSocket;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{error, info, warn};
use anyhow::{Context, Result};
use futures::StreamExt;
use chrono::{DateTime, TimeZone, Utc};
use ed25519_dalek::Signer;

use crate::config::JitoConfig;
use crate::registry::{ShredEvent, SlotEvent, SourceId};
use crate::shred::parse_shred_key;

pub mod proto {
    // shared must be declared as a sibling so generated code resolves super::shared::Socket
    pub mod shared {
        #![allow(dead_code)]
        tonic::include_proto!("shared");
    }
    pub mod shredstream {
        #![allow(dead_code)]
        tonic::include_proto!("shredstream");
    }
    pub mod auth {
        tonic::include_proto!("auth");
    }
}

use proto::auth::auth_service_client::AuthServiceClient;
use proto::auth::{GenerateAuthChallengeRequest, GenerateAuthTokensRequest, RefreshAccessTokenRequest, Role};
use proto::shredstream::shredstream_client::ShredstreamClient;
use proto::shredstream::shredstream_proxy_client::ShredstreamProxyClient;
use proto::shredstream::{Heartbeat, SubscribeEntriesRequest};
use proto::shared::Socket;

struct TokenPair {
    access_token: String,
    access_expires_at: DateTime<Utc>,
    refresh_token: String,
    refresh_expires_at: DateTime<Utc>,
}

/// Run Jito ShredStream integration. Three independent sub-modes:
///
/// **Direct block engine** (`block_engine_url` + `auth_keypair_path`):
///   Authenticates with Jito's block engine using an Ed25519 keypair,
///   sends periodic heartbeats, and receives raw UDP shreds on `udp_bind_addr`.
///   No separate proxy process needed. Produces shred-level events.
///
/// **Proxy UDP** (`proxy_udp_addr`):
///   Listens for raw shreds forwarded by an already-running
///   jito-shredstream-proxy (--dest-ip-ports). Produces shred-level events.
///
/// **Proxy gRPC entries** (`proxy_grpc_addr`):
///   Connects to proxy's --grpc-service-port, calls SubscribeEntries.
///   Produces slot-level events (entry granularity, not raw shreds).
pub async fn run(
    config: JitoConfig,
    shred_source_id: SourceId,
    entry_source_id: SourceId,
    shred_tx: mpsc::UnboundedSender<ShredEvent>,
    slot_tx: mpsc::UnboundedSender<SlotEvent>,
    cancel: CancellationToken,
) -> Result<()> {
    // Direct block engine mode
    if !config.block_engine_url.is_empty() {
        let cfg = config.clone();
        let tx = shred_tx.clone();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = run_direct_mode(cfg, tx, cancel_clone, shred_source_id).await {
                error!("Jito direct mode error: {:#}", e);
            }
        });
    }

    // Proxy UDP forwarding mode
    if !config.proxy_udp_addr.is_empty() {
        let addr = config.proxy_udp_addr.clone();
        let tx = shred_tx.clone();
        let cancel_clone = cancel.clone();
        tokio::task::spawn_blocking(move || {
            udp_listener(&addr, tx, cancel_clone, shred_source_id, "Jito proxy UDP");
        });
    }

    // Proxy gRPC entries mode
    if !config.proxy_grpc_addr.is_empty() {
        let addr = config.proxy_grpc_addr.clone();
        let cancel_clone = cancel.clone();
        tokio::spawn(async move {
            loop {
                if cancel_clone.is_cancelled() { break; }
                match run_grpc_entries(&addr, &slot_tx, &cancel_clone, entry_source_id).await {
                    Ok(()) => break,
                    Err(e) => {
                        warn!("Jito gRPC entries error: {:#}, reconnecting...", e);
                        tokio::select! {
                            _ = tokio::time::sleep(Duration::from_secs(2)) => {}
                            _ = cancel_clone.cancelled() => { break; }
                        }
                    }
                }
            }
            info!("Jito proxy gRPC entries listener stopped");
        });
    }

    Ok(())
}

async fn run_direct_mode(
    config: JitoConfig,
    shred_tx: mpsc::UnboundedSender<ShredEvent>,
    cancel: CancellationToken,
    shred_source_id: SourceId,
) -> Result<()> {
    let keypair = load_keypair(&config.auth_keypair_path)
        .context("Failed to load Jito auth keypair")?;

    let channel = Channel::from_shared(config.block_engine_url.clone())?
        .tls_config(ClientTlsConfig::new().with_native_roots())
        .context("Failed to configure TLS for Jito block engine")?
        .connect()
        .await
        .context("Failed to connect to Jito block engine")?;

    info!("Jito direct: connected to {}", config.block_engine_url);

    let tokens = authenticate(channel.clone(), &keypair).await
        .context("Jito authentication failed")?;

    info!("Jito direct: authenticated as {}", bs58_pubkey(&keypair));

    // Start UDP listener for incoming shreds
    if !config.udp_bind_addr.is_empty() {
        let addr = config.udp_bind_addr.clone();
        let tx = shred_tx.clone();
        let cancel_clone = cancel.clone();
        tokio::task::spawn_blocking(move || {
            udp_listener(&addr, tx, cancel_clone, shred_source_id, "Jito direct UDP");
        });
    } else {
        warn!("Jito direct mode: udp_bind_addr not set — shreds will be sent by Jito but not captured");
    }

    let socket = Socket {
        ip: config.public_ip.clone(),
        port: port_from_addr(&config.udp_bind_addr),
    };

    run_heartbeat_loop(channel, keypair, tokens, socket, config.desired_regions, cancel).await;
    Ok(())
}

fn udp_listener(
    bind_addr: &str,
    tx: mpsc::UnboundedSender<ShredEvent>,
    cancel: CancellationToken,
    source: SourceId,
    label: &str,
) {
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(e) => { error!("{}: bind failed on {}: {}", label, bind_addr, e); return; }
    };
    socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
    info!("{} listener started on {}", label, bind_addr);
    let mut buf = vec![0u8; 1280];
    loop {
        if cancel.is_cancelled() { break; }
        match socket.recv_from(&mut buf) {
            Ok((len, _)) => {
                let received_at = Instant::now();
                if let Some(key) = parse_shred_key(&buf[..len]) {
                    let _ = tx.send(ShredEvent { source, key, received_at });
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                   || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => { warn!("{} recv error: {}", label, e); }
        }
    }
    info!("{} listener stopped", label);
}

async fn authenticate(channel: Channel, keypair: &[u8; 64]) -> Result<TokenPair> {
    let pubkey = &keypair[32..64];
    let secret: &[u8; 32] = keypair[0..32].try_into()?;
    let mut client = AuthServiceClient::new(channel);

    // Step 1: request a challenge
    let server_challenge = client
        .generate_auth_challenge(GenerateAuthChallengeRequest {
            role: Role::ShredstreamSubscriber as i32,
            pubkey: pubkey.to_vec(),
        })
        .await?
        .into_inner()
        .challenge;

    // Step 2: construct full challenge string: "<base58_pubkey>-<server_challenge>"
    // This is the exact format used by jito-shredstream-proxy.
    let pubkey_b58 = bs58::encode(pubkey).into_string();
    let full_challenge = format!("{}-{}", pubkey_b58, server_challenge);

    // Sign the UTF-8 bytes of the full challenge string
    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret);
    let signature: ed25519_dalek::Signature = signing_key.sign(full_challenge.as_bytes());

    // Step 3: exchange signature for tokens
    let resp = client
        .generate_auth_tokens(GenerateAuthTokensRequest {
            challenge: full_challenge,      // full "<pubkey>-<challenge>" string
            client_pubkey: pubkey.to_vec(),
            signed_challenge: signature.to_bytes().to_vec(),
        })
        .await?
        .into_inner();

    let access = resp.access_token.context("missing access_token in response")?;
    let refresh = resp.refresh_token.context("missing refresh_token in response")?;

    Ok(TokenPair {
        access_token: access.value,
        access_expires_at: proto_ts_to_datetime(access.expires_at_utc),
        refresh_token: refresh.value,
        refresh_expires_at: proto_ts_to_datetime(refresh.expires_at_utc),
    })
}

async fn run_heartbeat_loop(
    channel: Channel,
    keypair: [u8; 64],
    mut tokens: TokenPair,
    socket: Socket,
    regions: Vec<String>,
    cancel: CancellationToken,
) {
    loop {
        if cancel.is_cancelled() { break; }

        // Refresh access token if it expires within 60s
        if (tokens.access_expires_at - Utc::now()) < chrono::Duration::seconds(60) {
            match try_refresh(channel.clone(), &tokens, &keypair).await {
                Ok(new_tokens) => {
                    info!("Jito: access token refreshed");
                    tokens = new_tokens;
                }
                Err(e) => warn!("Jito token refresh failed: {:#}", e),
            }
        }

        // Send heartbeat
        let mut client = ShredstreamClient::new(channel.clone());
        let bearer = format!("Bearer {}", tokens.access_token);
        let mut req = tonic::Request::new(Heartbeat {
            socket: Some(socket.clone()),
            regions: regions.clone(),
        });
        if let Ok(v) = bearer.parse() {
            req.metadata_mut().insert("authorization", v);
        }

        let ttl_ms = match client.send_heartbeat(req).await {
            Ok(resp) => {
                let ttl = resp.into_inner().ttl_ms as u64;
                info!("Jito heartbeat OK, ttl={}ms, regions={:?}", ttl, regions);
                ttl
            }
            Err(e) => {
                warn!("Jito heartbeat error: {}", e);
                1000
            }
        };

        // Re-heartbeat at half the TTL, minimum 500ms
        let wait = Duration::from_millis(ttl_ms / 2).max(Duration::from_millis(500));
        tokio::select! {
            _ = tokio::time::sleep(wait) => {}
            _ = cancel.cancelled() => { break; }
        }
    }
    info!("Jito heartbeat loop stopped");
}

async fn try_refresh(channel: Channel, tokens: &TokenPair, keypair: &[u8; 64]) -> Result<TokenPair> {
    // If refresh token itself is expiring, re-authenticate from scratch
    if (tokens.refresh_expires_at - Utc::now()) < chrono::Duration::seconds(60) {
        info!("Jito: refresh token expiring, re-authenticating");
        return authenticate(channel, keypair).await;
    }

    let mut client = AuthServiceClient::new(channel);
    let resp = client
        .refresh_access_token(RefreshAccessTokenRequest {
            refresh_token: tokens.refresh_token.clone(),
        })
        .await?
        .into_inner();

    let access = resp.access_token.context("missing access_token in refresh response")?;
    Ok(TokenPair {
        access_token: access.value,
        access_expires_at: proto_ts_to_datetime(access.expires_at_utc),
        refresh_token: tokens.refresh_token.clone(),
        refresh_expires_at: tokens.refresh_expires_at,
    })
}

async fn run_grpc_entries(
    addr: &str,
    tx: &mpsc::UnboundedSender<SlotEvent>,
    cancel: &CancellationToken,
    source_id: SourceId,
) -> anyhow::Result<()> {
    let channel = Channel::from_shared(addr.to_string())?.connect().await?;
    let mut client = ShredstreamProxyClient::new(channel);
    info!("Jito gRPC entries: connected to {}", addr);

    let response = client.subscribe_entries(SubscribeEntriesRequest {}).await?;
    let mut stream = response.into_inner();

    loop {
        let msg = tokio::select! {
            msg = stream.next() => msg,
            _ = cancel.cancelled() => None,
        };
        match msg {
            Some(Ok(entry)) => {
                let _ = tx.send(SlotEvent {
                    source: source_id,
                    slot: entry.slot,
                    received_at: Instant::now(),
                });
            }
            Some(Err(e)) => return Err(e.into()),
            None => break,
        }
    }
    Ok(())
}

/// Load a Solana keypair from a JSON file (array of 64 bytes).
/// Bytes 0..32 = Ed25519 secret seed, 32..64 = public key.
fn load_keypair(path: &str) -> Result<[u8; 64]> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read keypair file: {}", path))?;
    let bytes: Vec<u8> = serde_json::from_str(&text)
        .context("Keypair file must be a JSON array of 64 integers")?;
    if bytes.len() != 64 {
        anyhow::bail!("Keypair must be exactly 64 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn proto_ts_to_datetime(ts: Option<prost_types::Timestamp>) -> DateTime<Utc> {
    ts.and_then(|t| {
        chrono::Utc.timestamp_opt(t.seconds, t.nanos as u32).single()
    })
    .unwrap_or_default()
}

fn port_from_addr(addr: &str) -> i64 {
    addr.rsplit(':').next().and_then(|p| p.parse().ok()).unwrap_or(20000)
}

/// Base58 encode the public key portion of a keypair for log display.
fn bs58_pubkey(keypair: &[u8; 64]) -> String {
    bs58::encode(&keypair[32..64]).into_string()
}
