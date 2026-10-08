//! The `VerifiedEnvelope` extractor: the prefix is
//! checked before a single body byte is read, then the signature, the clock
//! skew and the replay guard.
//!
//! "Before the body is read" is shown with a body that delivers the prefix
//! and then never ends: a request refused on its prefix answers at once,
//! while one whose prefix passes waits for the body.

use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use futures::StreamExt;
use timescales_core::Encode;
use timescales_service::wire::{
    EnvelopePrefix, MessageKind, PREFIX_LEN, SignedEnvelope, WIRE_VERSION,
};
use timescales_service::{ENVELOPE_CONTENT_TYPE, EnvelopeAuth, VerifiedEnvelope};
use tower::ServiceExt;

use crate::common::{NOW, SKEW, auth, dealer, key, member, seal};

async fn handler(env: VerifiedEnvelope) -> String {
    format!(
        "{}:{:?}:{}",
        hex::encode(env.sender),
        env.kind,
        hex::encode(env.body)
    )
}

fn router(auth: EnvelopeAuth) -> Router {
    Router::new()
        .route("/krc/v1/shares", post(handler))
        .with_state(auth)
}

fn request(body: Body, content_length: Option<usize>) -> Request<Body> {
    let mut builder =
        Request::post("/krc/v1/shares").header(header::CONTENT_TYPE, ENVELOPE_CONTENT_TYPE);
    if let Some(len) = content_length {
        builder = builder.header(header::CONTENT_LENGTH, len);
    }
    builder.body(body).unwrap()
}

fn whole(bytes: Vec<u8>) -> Request<Body> {
    let len = bytes.len();
    request(Body::from(bytes), Some(len))
}

/// The prefix, and then a body that never arrives.
fn stalled(prefix: [u8; PREFIX_LEN]) -> Request<Body> {
    let stream = futures::stream::iter([Ok::<_, std::io::Error>(Bytes::copy_from_slice(&prefix))])
        .chain(futures::stream::pending());
    request(Body::from_stream(stream), None)
}

async fn send(router: &Router, req: Request<Body>) -> Response {
    tokio::time::timeout(Duration::from_secs(10), router.clone().oneshot(req))
        .await
        .expect("the extractor waited for a body it should not have read")
        .unwrap()
}

async fn text(response: Response) -> String {
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

fn share(body: Vec<u8>) -> SignedEnvelope {
    seal(
        MessageKind::ShareDelivery,
        &dealer(),
        member().public(),
        NOW,
        body,
    )
}

fn prefix_of(env: &SignedEnvelope) -> [u8; PREFIX_LEN] {
    env.prefix().to_bytes()
}

#[tokio::test]
async fn a_valid_envelope_reaches_the_handler() {
    let r = router(auth(16));
    let env = share(vec![0xab; 40]);
    let response = send(&r, whole(env.to_bytes())).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        text(response).await,
        format!(
            "{}:ShareDelivery:{}",
            hex::encode(dealer().public()),
            "ab".repeat(40)
        )
    );
    // Delivered in small pieces and without a length, it is the same.
    let bytes = share(vec![0xcd; 300]).to_bytes();
    let pieces: Vec<Result<Bytes, std::io::Error>> = bytes
        .chunks(7)
        .map(|c| Ok(Bytes::copy_from_slice(c)))
        .collect();
    let response = send(
        &r,
        request(Body::from_stream(futures::stream::iter(pieces)), None),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_stalled_body_after_a_valid_prefix_is_waited_for() {
    // The control for every "refused before the body" test below.
    let r = router(auth(16));
    let pending = tokio::time::timeout(
        Duration::from_millis(300),
        r.clone().oneshot(stalled(prefix_of(&share(vec![1; 40])))),
    )
    .await;
    assert!(
        pending.is_err(),
        "a valid prefix must lead to reading the body"
    );
}

#[tokio::test]
async fn signed_envelope_extractor_prefix() {
    let r = router(auth(16));
    let env = share(vec![7; 40]);

    let mut bad_version = prefix_of(&env);
    bad_version[0] = WIRE_VERSION + 1;
    let response = send(&r, stalled(bad_version)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text(response).await.contains("version"));

    // The media type is checked before anything is read.
    let no_type = Request::post("/krc/v1/shares")
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .body(Body::from(env.to_bytes()))
        .unwrap();
    assert_eq!(
        send(&r, no_type).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );

    // Shorter than a prefix, declared or actual.
    let bytes = env.to_bytes();
    assert_eq!(
        send(&r, whole(bytes[..60].to_vec())).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&r, request(Body::from(bytes[..60].to_vec()), None))
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    // A body that is cut short, too long, or disagrees with its length.
    assert_eq!(
        send(
            &r,
            request(Body::from(bytes[..bytes.len() - 1].to_vec()), None)
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(
        send(&r, whole(longer.clone())).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(&r, request(Body::from(longer), None)).await.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        send(
            &r,
            request(Body::from(bytes.clone()), Some(bytes.len() + 1))
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );

    // A prefix that passes, with a forged signature.
    let mut forged = bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        send(&r, whole(forged)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // A body changed under a valid signature.
    let mut tampered = bytes.clone();
    tampered[PREFIX_LEN] ^= 1;
    assert_eq!(
        send(&r, whole(tampered)).await.status(),
        StatusCode::UNAUTHORIZED
    );
    // The original still goes through: refusals consumed nothing.
    assert_eq!(send(&r, whole(bytes)).await.status(), StatusCode::OK);
}

#[tokio::test]
async fn signed_envelope_extractor_skew() {
    let r = router(auth(16));
    for issued_at in [NOW - SKEW - 1, NOW + SKEW + 1] {
        let env = seal(
            MessageKind::ShareDelivery,
            &dealer(),
            member().public(),
            issued_at,
            vec![1; 8],
        );
        let response = send(&r, whole(env.to_bytes())).await;
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "issued at {issued_at}"
        );
        assert!(text(response).await.contains("skew"));
    }
    for issued_at in [NOW - SKEW, NOW + SKEW] {
        let env = seal(
            MessageKind::ShareDelivery,
            &dealer(),
            member().public(),
            issued_at,
            vec![1; 8],
        );
        assert_eq!(
            send(&r, whole(env.to_bytes())).await.status(),
            StatusCode::OK,
            "issued at {issued_at}"
        );
    }
}

#[tokio::test]
async fn signed_envelope_extractor_replay() {
    let r = router(auth(16));
    let env = share(vec![3; 40]);
    // A forged copy first: it fails on the signature and is not remembered.
    let mut forged = env.to_bytes();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        send(&r, whole(forged)).await.status(),
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        send(&r, whole(env.to_bytes())).await.status(),
        StatusCode::OK
    );
    let replayed = send(&r, whole(env.to_bytes())).await;
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);
    assert!(text(replayed).await.contains("replay"));
    // Another envelope with the same body is a new request.
    assert_eq!(
        send(&r, whole(share(vec![3; 40]).to_bytes()))
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn signed_envelope_extractor_replay_full() {
    let r = router(auth(2));
    let first = share(vec![1; 8]);
    assert_eq!(
        send(&r, whole(first.to_bytes())).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        send(&r, whole(share(vec![2; 8]).to_bytes())).await.status(),
        StatusCode::OK
    );
    // Full: a new envelope is refused (fails closed)...
    let full = send(&r, whole(share(vec![3; 8]).to_bytes())).await;
    assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(full.headers()[header::RETRY_AFTER], "1");
    //... and no live entry was evicted to make room.
    assert_eq!(
        send(&r, whole(first.to_bytes())).await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn signed_envelope_extractor_audience() {
    let r = router(auth(16));
    let elsewhere = seal(
        MessageKind::ShareDelivery,
        &dealer(),
        key(9).public(),
        NOW,
        vec![1; 40],
    );
    let response = send(&r, stalled(prefix_of(&elsewhere))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(text(response).await.contains("another party"));
    assert_eq!(
        send(&r, whole(elsewhere.to_bytes())).await.status(),
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn signed_envelope_extractor_kind() {
    let r = router(auth(16));
    // An allowed sender, but a kind it may not send.
    let release = seal(
        MessageKind::ReleaseRequest,
        &dealer(),
        member().public(),
        NOW,
        vec![1; 40],
    );
    let response = send(&r, stalled(prefix_of(&release))).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(text(response).await.contains("sender not allowed"));
    // A kind it may send, from a sender that is not allowed.
    let stranger = seal(
        MessageKind::ShareDelivery,
        &key(8),
        member().public(),
        NOW,
        vec![1; 40],
    );
    assert_eq!(
        send(&r, stalled(prefix_of(&stranger))).await.status(),
        StatusCode::FORBIDDEN
    );
    // A kind that does not exist.
    let mut unknown = prefix_of(&share(vec![1; 40]));
    unknown[1] = 99;
    let response = send(&r, stalled(unknown)).await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(text(response).await.contains("kind 99"));
    // The second allowed kind passes.
    let query = seal(
        MessageKind::AnnouncementQuery,
        &dealer(),
        member().public(),
        NOW,
        vec![2; 40],
    );
    assert_eq!(
        send(&r, whole(query.to_bytes())).await.status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn signed_envelope_extractor_size() {
    let r = router(auth(16));
    let max = MessageKind::ShareDelivery.max_body();
    // A prefix that announces one byte more than the kind allows is
    // refused before any of it is read.
    let at_limit = share(vec![5; max]);
    let mut over = at_limit.prefix();
    over.body_len = u32::try_from(max + 1).unwrap();
    let response = send(&r, stalled(over.to_bytes())).await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let mut huge = at_limit.prefix();
    huge.body_len = u32::MAX;
    assert_eq!(
        send(&r, stalled(huge.to_bytes())).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Each kind has its own limit: an empty kind allows no body at all.
    let mut empty = EnvelopePrefix {
        kind: MessageKind::Empty,
        ..at_limit.prefix()
    };
    empty.body_len = 1;
    assert_eq!(
        send(&r, stalled(empty.to_bytes())).await.status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Exactly at the limit is accepted.
    assert_eq!(
        send(&r, whole(at_limit.to_bytes())).await.status(),
        StatusCode::OK
    );
}
