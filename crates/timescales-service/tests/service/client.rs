//! `SignedClient` against real listeners: plain HTTP (profile local) and
//! mutual TLS 1.3 with pinned peers.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{FromRef, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum_server::tls_rustls::RustlsConfig;
use timescales_core::crypto::Keypair;
use timescales_core::{DecodeError, Encode};
use timescales_service::wire::{MessageKind, ReplayGuard, WireError};
use timescales_service::{
    ClientError, ENVELOPE_CONTENT_TYPE, EnvelopeAuth, SignedClient, TlsConfig, VerifiedEnvelope,
    sealed_response, sealed_response_with_status,
};

use crate::common::{Identity, identity, identity_valid, key, seal, write_file};

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// The calling service (the node) and the called one (an enclave host).
fn node() -> Keypair {
    key(4)
}

fn enclave() -> Arc<Keypair> {
    Arc::new(key(5))
}

#[derive(Clone)]
struct App {
    auth: EnvelopeAuth,
    signer: Arc<Keypair>,
    canned: Arc<Vec<u8>>,
}

impl FromRef<App> for EnvelopeAuth {
    fn from_ref(app: &App) -> Self {
        app.auth.clone()
    }
}

fn envelope(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, ENVELOPE_CONTENT_TYPE)], bytes).into_response()
}

async fn echo(State(app): State<App>, env: VerifiedEnvelope) -> Response {
    let mut body = env.body;
    body.reverse();
    sealed_response(
        MessageKind::ExecuteReady,
        &*app.signer,
        env.sender,
        now_ms(),
        body,
    )
}

async fn conflict(_: VerifiedEnvelope) -> StatusCode {
    StatusCode::CONFLICT
}

/// A member's answer to a second announcement: 409 with the digest it holds.
async fn refuse(State(app): State<App>, env: VerifiedEnvelope) -> Response {
    sealed_response_with_status(
        StatusCode::CONFLICT,
        MessageKind::ErrorResponse,
        &*app.signer,
        env.sender,
        now_ms(),
        vec![0xd1; 32],
    )
}

/// The same refusal signed by someone other than the peer.
async fn refuse_as_stranger(env: VerifiedEnvelope) -> Response {
    sealed_response_with_status(
        StatusCode::CONFLICT,
        MessageKind::ErrorResponse,
        &key(7),
        env.sender,
        now_ms(),
        vec![0xd1; 32],
    )
}

async fn slow(State(app): State<App>, env: VerifiedEnvelope) -> Response {
    tokio::time::sleep(Duration::from_secs(3)).await;
    sealed_response(
        MessageKind::Empty,
        &*app.signer,
        env.sender,
        now_ms(),
        Vec::new(),
    )
}

async fn garbage(_: VerifiedEnvelope) -> Response {
    envelope(vec![0xff; 200])
}

async fn stranger(env: VerifiedEnvelope) -> Response {
    sealed_response(
        MessageKind::Empty,
        &key(7),
        env.sender,
        now_ms(),
        Vec::new(),
    )
}

async fn misaddressed(State(app): State<App>, _: VerifiedEnvelope) -> Response {
    sealed_response(
        MessageKind::Empty,
        &*app.signer,
        key(9).public(),
        now_ms(),
        Vec::new(),
    )
}

async fn canned(State(app): State<App>, _: VerifiedEnvelope) -> Response {
    envelope(app.canned.to_vec())
}

async fn trailing(State(app): State<App>, env: VerifiedEnvelope) -> Response {
    let mut bytes = seal(
        MessageKind::Empty,
        &app.signer,
        env.sender,
        now_ms(),
        Vec::new(),
    )
    .to_bytes();
    bytes.push(0);
    envelope(bytes)
}

fn app() -> Router {
    let node = node().public();
    let signer = enclave();
    let fixed = seal(
        MessageKind::ExecuteReady,
        &signer,
        node,
        now_ms(),
        vec![1, 2, 3],
    )
    .to_bytes();
    let state = App {
        auth: EnvelopeAuth {
            me: signer.public(),
            allowed: Arc::new(move |sender: &[u8; 32], _| *sender == node),
            replay: Arc::new(ReplayGuard::new(1000, 60_000)),
            skew_ms: 30_000,
            now_ms: Arc::new(now_ms),
        },
        signer,
        canned: Arc::new(fixed),
    };
    Router::new()
        .route("/echo", post(echo))
        .route("/conflict", post(conflict))
        .route("/refuse", post(refuse))
        .route("/refuse-as-stranger", post(refuse_as_stranger))
        .route("/slow", post(slow))
        .route("/garbage", post(garbage))
        .route("/stranger", post(stranger))
        .route("/misaddressed", post(misaddressed))
        .route("/canned", post(canned))
        .route("/trailing", post(trailing))
        .with_state(state)
}

async fn plain_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app()).await.unwrap() });
    format!("http://{addr}")
}

async fn tls_server(tls: &TlsConfig) -> String {
    let config = timescales_service::tls::server_config(tls).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = axum_server::tls_rustls::from_tcp_rustls(
        listener,
        RustlsConfig::from_config(Arc::new(config)),
    )
    .unwrap();
    tokio::spawn(async move { server.serve(app().into_make_service()).await.unwrap() });
    format!("https://{addr}")
}

fn client(peer: [u8; 32], tls: Option<TlsConfig>, timeout: Duration) -> SignedClient {
    SignedClient::new(Arc::new(node()), peer, tls, timeout).unwrap()
}

#[tokio::test]
async fn signed_client_round_trip_over_http() {
    let base = plain_server().await;
    let c = client(enclave().public(), None, Duration::from_secs(10));
    let reply = c
        .call(
            &format!("{base}/echo"),
            MessageKind::ExecuteRequest,
            b"hello".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(
        reply,
        VerifiedEnvelope {
            sender: enclave().public(),
            kind: MessageKind::ExecuteReady,
            body: b"olleh".to_vec(),
        }
    );
    // Each call is a fresh envelope, so the server's replay guard passes it.
    let again = c
        .call(
            &format!("{base}/echo"),
            MessageKind::ExecuteRequest,
            b"hello".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(again.body, b"olleh");
}

#[tokio::test]
async fn signed_client_checks_the_response() {
    let base = plain_server().await;
    let c = client(enclave().public(), None, Duration::from_secs(10));
    let call = |path: &'static str| {
        let c = &c;
        let url = format!("{base}{path}");
        async move { c.call(&url, MessageKind::ExecuteRequest, vec![1; 10]).await }
    };

    assert!(matches!(
        call("/conflict").await,
        Err(ClientError::Status(409))
    ));
    match call("/refuse").await {
        Err(ClientError::Refused { status, envelope }) => {
            assert_eq!(status, 409);
            assert_eq!(envelope.sender, enclave().public());
            assert_eq!(envelope.kind, MessageKind::ErrorResponse);
            assert_eq!(envelope.body, vec![0xd1; 32]);
        }
        other => panic!("expected a signed refusal, got {other:?}"),
    }
    // A refusal body that does not verify is only a status.
    assert!(matches!(
        call("/refuse-as-stranger").await,
        Err(ClientError::Status(409))
    ));
    assert!(matches!(call("/stranger").await, Err(ClientError::Peer)));
    assert!(matches!(
        call("/misaddressed").await,
        Err(ClientError::Wire(WireError::Audience))
    ));
    assert!(matches!(
        call("/garbage").await,
        Err(ClientError::Wire(WireError::Version(0xff)))
    ));
    assert!(matches!(
        call("/trailing").await,
        Err(ClientError::Wire(WireError::Decode(
            DecodeError::TrailingBytes(1)
        )))
    ));
    // The same response twice is a replay.
    assert_eq!(call("/canned").await.unwrap().body, vec![1, 2, 3]);
    assert!(matches!(
        call("/canned").await,
        Err(ClientError::Wire(WireError::Replay))
    ));
    // A request addressed to another identity is refused by the server.
    let wrong_audience = client(key(6).public(), None, Duration::from_secs(10));
    assert!(matches!(
        wrong_audience
            .call(
                &format!("{base}/echo"),
                MessageKind::ExecuteRequest,
                vec![1]
            )
            .await,
        Err(ClientError::Status(403))
    ));
    let unreachable = c
        .call(
            "http://127.0.0.1:9/echo",
            MessageKind::ExecuteRequest,
            vec![],
        )
        .await;
    assert!(
        matches!(unreachable, Err(ClientError::Transport(_))),
        "{unreachable:?}"
    );
}

#[tokio::test]
async fn signed_client_times_out() {
    let base = plain_server().await;
    let c = client(enclave().public(), None, Duration::from_millis(300));
    let result = c
        .call(&format!("{base}/slow"), MessageKind::ExecuteRequest, vec![])
        .await;
    assert!(matches!(result, Err(ClientError::Timeout)), "{result:?}");
}

#[tokio::test]
async fn signed_client_scheme_rules() {
    let dir = tempfile::tempdir().unwrap();
    let me = identity(dir.path(), "node");
    let peer = identity(dir.path(), "enclave");
    let plain = client(enclave().public(), None, Duration::from_secs(1));
    let result = plain
        .call("https://127.0.0.1:1/echo", MessageKind::Empty, vec![])
        .await;
    assert!(
        matches!(result, Err(ClientError::Tls(ref m)) if m.contains("needs a [tls]")),
        "{result:?}"
    );
    let tls = client(
        enclave().public(),
        Some(me.tls(&[&peer])),
        Duration::from_secs(1),
    );
    let result = tls
        .call("http://127.0.0.1:1/echo", MessageKind::Empty, vec![])
        .await;
    assert!(
        matches!(result, Err(ClientError::Tls(ref m)) if m.contains("plain http")),
        "{result:?}"
    );
    let result = plain
        .call("ftp://127.0.0.1/echo", MessageKind::Empty, vec![])
        .await;
    assert!(
        matches!(result, Err(ClientError::Transport(_))),
        "{result:?}"
    );
}

#[tokio::test]
async fn mutual_tls_with_pinned_peers() {
    let dir = tempfile::tempdir().unwrap();
    let node_id = identity(dir.path(), "node");
    let enclave_id = identity(dir.path(), "enclave");
    let base = tls_server(&enclave_id.tls(&[&node_id])).await;
    let url = format!("{base}/echo");

    let c = client(
        enclave().public(),
        Some(node_id.tls(&[&enclave_id])),
        Duration::from_secs(10),
    );
    let reply = c
        .call(&url, MessageKind::ExecuteRequest, b"tls".to_vec())
        .await
        .unwrap();
    assert_eq!(reply.body, b"slt");

    // The client refuses a server whose key it did not pin...
    let other = identity(dir.path(), "other");
    let c = client(
        enclave().public(),
        Some(node_id.tls(&[&other])),
        Duration::from_secs(10),
    );
    let result = c.call(&url, MessageKind::ExecuteRequest, vec![1]).await;
    assert!(
        matches!(result, Err(ClientError::Transport(ref m)) if m.contains("ApplicationVerificationFailure")),
        "{result:?}"
    );

    //... and the server refuses a client it did not pin, even one that
    // pins the server.
    let c = client(
        enclave().public(),
        Some(other.tls(&[&enclave_id])),
        Duration::from_secs(10),
    );
    let result = c.call(&url, MessageKind::ExecuteRequest, vec![1]).await;
    assert!(
        matches!(result, Err(ClientError::Transport(ref m)) if m.contains("AccessDenied")),
        "{result:?}"
    );
}

#[tokio::test]
async fn certificates_outside_their_validity_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let node_id = identity(dir.path(), "node");
    for (name, from, to, why) in [
        ("expired", (2001, 1, 1), (2002, 1, 1), "Expired"),
        ("future", (3000, 1, 1), (3001, 1, 1), "NotValidYet"),
    ] {
        let server_id = identity_valid(dir.path(), name, from, to);
        let base = tls_server(&server_id.tls(&[&node_id])).await;
        let c = client(
            enclave().public(),
            Some(node_id.tls(&[&server_id])),
            Duration::from_secs(10),
        );
        let result = c
            .call(
                &format!("{base}/echo"),
                MessageKind::ExecuteRequest,
                vec![1],
            )
            .await;
        assert!(
            matches!(result, Err(ClientError::Transport(ref m)) if m.contains(why)),
            "{name}: {result:?}"
        );
    }
}

#[test]
fn tls_setup_refuses_open_keys_and_missing_pins() {
    let dir = tempfile::tempdir().unwrap();
    let me = identity(dir.path(), "node");
    let peer: Identity = identity(dir.path(), "enclave");

    let no_pins = me.tls(&[]);
    let err = SignedClient::new(
        Arc::new(node()),
        [0; 32],
        Some(no_pins.clone()),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(
        matches!(err, ClientError::Tls(ref m) if m.contains("no pinned peer")),
        "{err:?}"
    );
    assert!(timescales_service::tls::server_config(&no_pins).is_err());

    let open_key = write_file(
        dir.path(),
        "open.key",
        &std::fs::read(&me.key_file).unwrap(),
        0o644,
    );
    let open = TlsConfig {
        key_file: open_key,
        ..me.tls(&[&peer])
    };
    let err = SignedClient::new(
        Arc::new(node()),
        [0; 32],
        Some(open.clone()),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(
        matches!(err, ClientError::Tls(ref m) if m.contains("accessible by group or others")),
        "{err:?}"
    );
    assert!(timescales_service::tls::server_config(&open).is_err());

    let no_cert = TlsConfig {
        cert_file: write_file(dir.path(), "empty.crt", b"", 0o644),
        ..me.tls(&[&peer])
    };
    assert!(matches!(
        timescales_service::tls::server_config(&no_cert),
        Err(ClientError::Tls(ref m)) if m.contains("no certificate")
    ));
    assert!(timescales_service::tls::spki_sha256(b"not a certificate").is_err());
}
