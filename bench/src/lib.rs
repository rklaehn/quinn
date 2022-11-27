use std::{
    convert::TryInto,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    str::FromStr,
    sync::Arc, io::Cursor,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::Keypair;
use quinn_proto::{transport_parameters::TransportParameters, ConnectionId, Side, TransportError, crypto::{Session, Keys, HeaderKey, PacketKey, KeyPair, ExportKeyingMaterialError, UnsupportedVersion}, TransportErrorCode};
use rand::rngs::OsRng;
use rustls::RootCertStore;
use tokio::runtime::{Builder, Runtime};
use tracing::trace;

pub mod stats;

#[derive(Debug)]
struct PlaintextKey;

impl HeaderKey for PlaintextKey {
    #[tracing::instrument(level = "info", skip(packet))]
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        println!("decrypting packet {} {}", pn_offset, packet.len());
    }

    #[tracing::instrument(level = "info", skip(packet))]
    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        println!("encrypting packet {} {}", pn_offset, packet.len());
    }

    #[tracing::instrument(level = "info")]
    fn sample_size(&self) -> usize {
        0
    }
}

impl PacketKey for PlaintextKey {

    #[tracing::instrument(level = "info", skip(buf))]
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        println!("encrypting packet {} {} {}", packet, buf.len(), header_len);
    }

    #[tracing::instrument(level = "info", skip(payload))]
    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut bytes::BytesMut,
    ) -> Result<(), quinn_proto::crypto::CryptoError> {
        println!("decrypting packet {} {} {}", packet, header.len(), payload.len());
        Ok(())
    }

    #[tracing::instrument(level = "info")]
    fn tag_len(&self) -> usize {
        0
    }

    #[tracing::instrument(level = "info")]
    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    #[tracing::instrument(level = "info")]
    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
    Data,
}

#[derive(Debug)]
struct NoCryptoSession {
    state: State,
    side: Side,
    transport_parameters: TransportParameters,
    remote_transport_parameters: Option<TransportParameters>,
}

impl NoCryptoSession {
    fn new(side: Side, transport_parameters: TransportParameters) -> Self {
        Self {
            state: State::Initial,
            side,
            transport_parameters,
            remote_transport_parameters: None,
        }
    }
}

fn connection_refused(reason: &str) -> TransportError {
    TransportError {
        code: TransportErrorCode::CONNECTION_REFUSED,
        frame: None,
        reason: reason.to_string(),
    }
}

impl Session for NoCryptoSession {
    #[tracing::instrument(level = "info")]
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        println!("initial_keys: dst_cid={:?}, side={:?}", dst_cid, side);
        Keys {
            header: KeyPair {
                local: Box::new(PlaintextKey),
                remote: Box::new(PlaintextKey),
            },
            packet: KeyPair {
                local: Box::new(PlaintextKey),
                remote: Box::new(PlaintextKey),
            }
        }
    }

    #[tracing::instrument(level = "info")]
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        println!("next_1rtt_keys");
        None
    }

    #[tracing::instrument(level = "info")]
    fn read_handshake(&mut self, handshake: &[u8]) -> Result<bool, TransportError> {
        println!("read_handshake: buf={:?}", handshake);
        tracing::trace!("read_handshake {:?} {:?}", self.state, self.side);
        match (self.state, self.side) {
            (State::Initial, Side::Server) => {
                // protocol identifier
                if !handshake.is_empty() {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let mut transport_parameters = handshake;
                self.remote_transport_parameters = Some(TransportParameters::read(
                    Side::Server,
                    &mut Cursor::new(&mut transport_parameters),
                )?);
                self.state = State::ZeroRtt;
                Ok(true)
            }
            (State::Handshake, Side::Client) => {
                // e
                if handshake.len() != 0 {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let mut transport_parameters = handshake;
                self.remote_transport_parameters = Some(TransportParameters::read(
                    Side::Client,
                    &mut Cursor::new(&mut transport_parameters),
                )?);
                self.state = State::OneRtt;
                Ok(true)
            }
            _ => Err(TransportError {
                code: TransportErrorCode::CONNECTION_REFUSED,
                frame: None,
                reason: "unexpected crypto frame".to_string(),
            }),
        }
    }

    #[tracing::instrument(level = "info")]
    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        println!("write_handshake: buf={:?}", buf);
        None
    }

    #[tracing::instrument(level = "info")]
    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        println!("handshake_data");
        None
    }

    #[tracing::instrument(level = "info")]
    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        println!("peer_identity");
        None
    }

    #[tracing::instrument(level = "info")]
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        println!("early_crypto");
        Some((Box::new(PlaintextKey), Box::new(PlaintextKey)))
    }

    #[tracing::instrument(level = "info")]
    fn early_data_accepted(&self) -> Option<bool> {
        println!("early_data_accepted");
        Some(true)
    }

    #[tracing::instrument(level = "info")]
    fn is_handshaking(&self) -> bool {
        self.state != State::Data
    }

    #[tracing::instrument(level = "info")]
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, quinn_proto::TransportError> {
        println!("transport_parameters");
        Ok(None)
    }

    #[tracing::instrument(level = "info")]
    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        println!("is_valid_retry: orig_dst_cid={:?}, header={:?}, payload={:?}", orig_dst_cid, header, payload);
        false
    }

    #[tracing::instrument(level = "info")]
    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        println!("export_keying_material: output={:?}, label={:?}, context={:?}", output, label, context);
        Ok(())
    }
}

#[derive(Debug)]
struct NoCryptoServerConfig;

impl quinn_proto::crypto::ServerConfig for NoCryptoServerConfig {

    #[tracing::instrument(level = "info")]
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, UnsupportedVersion> {
        println!("server initial_keys");
        Ok(Keys {
            header: KeyPair {
                local: Box::new(PlaintextKey),
                remote: Box::new(PlaintextKey),
            },
            packet: KeyPair {
                local: Box::new(PlaintextKey),
                remote: Box::new(PlaintextKey),
            }
        })
    }

    #[tracing::instrument(level = "info")]
    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        [0; 16]
    }

    #[tracing::instrument(level = "info")]
    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        println!("server start_session");
        Box::new(NoCryptoSession::new(Side::Server, params.clone()))
    }
}

#[derive(Debug)]
struct NoCryptoClientConfig;

impl quinn_proto::crypto::ClientConfig for NoCryptoClientConfig {

    #[tracing::instrument(level = "info")]
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, quinn::ConnectError> {
        println!("client start_session");
        Ok(Box::new(NoCryptoSession::new(Side::Client, params.clone())))
    }
}

pub fn configure_tracing_subscriber() {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    println!("{:?}", filter);
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_env_filter(filter)
            .finish(),
    )
    .unwrap();
}

/// Creates a server endpoint which runs on the given runtime
pub fn server_endpoint(
    rt: &tokio::runtime::Runtime,
    cert: rustls::Certificate,
    key: rustls::PrivateKey,
    keypair: ed25519_dalek::Keypair,
    opt: &Opt,
) -> (SocketAddr, quinn::Endpoint) {
    let cert_chain = vec![cert];
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key).unwrap();
    server_config.transport = Arc::new(transport_config(opt));
    server_config.crypto = Arc::new(NoCryptoServerConfig);
    server_config.crypto = Arc::new(quinn_noise::NoiseConfig::from(quinn_noise::NoiseServerConfig {
        keypair,
        keylogger: None,
        psk: None,
        supported_protocols: vec![b"bench".to_vec()]
    }));

    let endpoint = {
        let _guard = rt.enter();
        quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
        )
        .unwrap()
    };
    let server_addr = endpoint.local_addr().unwrap();
    (server_addr, endpoint)
}

/// Create a client endpoint and client connection
pub async fn connect_client(
    server_addr: SocketAddr,
    server_cert: rustls::Certificate,
    remote_public_key: ed25519_dalek::PublicKey,
    opt: Opt,
) -> Result<(quinn::Endpoint, quinn::Connection)> {
    let endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0)).unwrap();
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let mut roots = RootCertStore::empty();
    roots.add(&server_cert)?;
    let crypto = rustls::ClientConfig::builder()
        .with_cipher_suites(&[opt.cipher.as_rustls()])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    
    let crypto = quinn_noise::NoiseConfig::from(quinn_noise::NoiseClientConfig {
        remote_public_key,
        alpn: b"bench".to_vec(),
        keypair,
        psk: None,
        keylogger: None,
    });

    // let mut client_config = quinn::ClientConfig::new(Arc::new(NoCryptoClientConfig));
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(transport_config(&opt)));

    let connection = endpoint
        .connect_with(client_config, server_addr, "localhost")
        .unwrap()
        .await
        .context("unable to connect")?;
    trace!("connected");

    Ok((endpoint, connection))
}

pub async fn drain_stream(stream: &mut quinn::RecvStream, read_unordered: bool) -> Result<usize> {
    let mut read = 0;

    if read_unordered {
        while let Some(chunk) = stream.read_chunk(usize::MAX, false).await? {
            read += chunk.bytes.len();
        }
    } else {
        // These are 32 buffers, for reading approximately 32kB at once
        #[rustfmt::skip]
        let mut bufs = [
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
            Bytes::new(), Bytes::new(), Bytes::new(), Bytes::new(),
        ];

        while let Some(n) = stream.read_chunks(&mut bufs[..]).await? {
            read += bufs.iter().take(n).map(|buf| buf.len()).sum::<usize>();
        }
    }

    Ok(read)
}

pub async fn send_data_on_stream(stream: &mut quinn::SendStream, stream_size: u64) -> Result<()> {
    const DATA: &[u8] = &[0xAB; 1024 * 1024];
    let bytes_data = Bytes::from_static(DATA);

    let full_chunks = stream_size / (DATA.len() as u64);
    let remaining = (stream_size % (DATA.len() as u64)) as usize;

    for _ in 0..full_chunks {
        stream
            .write_chunk(bytes_data.clone())
            .await
            .context("failed sending data")?;
    }

    if remaining != 0 {
        stream
            .write_chunk(bytes_data.slice(0..remaining))
            .await
            .context("failed sending data")?;
    }

    stream.finish().await.context("failed finishing stream")?;

    Ok(())
}

pub fn rt() -> Runtime {
    Builder::new_current_thread().enable_all().build().unwrap()
}

pub fn transport_config(opt: &Opt) -> quinn::TransportConfig {
    // High stream windows are chosen because the amount of concurrent streams
    // is configurable as a parameter.
    let mut config = quinn::TransportConfig::default();
    config.max_concurrent_uni_streams(opt.max_streams.try_into().unwrap());
    config
}

#[derive(Parser, Debug, Clone, Copy)]
#[clap(name = "bulk")]
pub struct Opt {
    /// The total number of clients which should be created
    #[clap(long = "clients", short = 'c', default_value = "1")]
    pub clients: usize,
    /// The total number of streams which should be created
    #[clap(long = "streams", short = 'n', default_value = "1")]
    pub streams: usize,
    /// The amount of concurrent streams which should be used
    #[clap(long = "max_streams", short = 'm', default_value = "1")]
    pub max_streams: usize,
    /// Number of bytes to transmit from server to client
    ///
    /// This can use SI prefixes for sizes. E.g. 1M will transfer 1MiB, 10GiB
    /// will transfer 10GiB.
    #[clap(long, default_value = "1G", parse(try_from_str = parse_byte_size))]
    pub download_size: u64,
    /// Number of bytes to transmit from client to server
    ///
    /// This can use SI prefixes for sizes. E.g. 1M will transfer 1MiB, 10GiB
    /// will transfer 10GiB.
    #[clap(long, default_value = "0", parse(try_from_str = parse_byte_size))]
    pub upload_size: u64,
    /// Show connection stats the at the end of the benchmark
    #[clap(long = "stats")]
    pub stats: bool,
    /// Whether to use the unordered read API
    #[clap(long = "unordered")]
    pub read_unordered: bool,
    /// Allows to configure the desired cipher suite
    ///
    /// Valid options are: aes128, aes256, chacha20
    #[clap(long = "cipher", default_value = "aes128")]
    pub cipher: CipherSuite,
}

fn parse_byte_size(s: &str) -> Result<u64, ParseIntError> {
    let s = s.trim();

    let multiplier = match s.chars().last() {
        Some('T') => 1024 * 1024 * 1024 * 1024,
        Some('G') => 1024 * 1024 * 1024,
        Some('M') => 1024 * 1024,
        Some('k') => 1024,
        _ => 1,
    };

    let s = if multiplier != 1 {
        &s[..s.len() - 1]
    } else {
        s
    };

    let base: u64 = u64::from_str(s)?;

    Ok(base * multiplier)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CipherSuite {
    Aes128,
    Aes256,
    Chacha20,
}

impl CipherSuite {
    pub fn as_rustls(self) -> rustls::SupportedCipherSuite {
        match self {
            CipherSuite::Aes128 => rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::Aes256 => rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
            CipherSuite::Chacha20 => rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        }
    }
}

impl FromStr for CipherSuite {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aes128" => Ok(CipherSuite::Aes128),
            "aes256" => Ok(CipherSuite::Aes256),
            "chacha20" => Ok(CipherSuite::Chacha20),
            _ => Err(anyhow::anyhow!("Unknown cipher suite {}", s)),
        }
    }
}
