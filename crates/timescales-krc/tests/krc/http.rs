//! The member's `/krc/v1` API over real HTTP on a loopback listener:
//! signed envelopes both ways, the prefix checked before the body, replay
//! refusal, signed refusals, and the public policy and identity routes.

#![allow(clippy::unwrap_used)]

use super::common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use rand_core::OsRng;
use timescales_core::crypto::Keypair;
use timescales_core::{Decode, Encode, EpochId, Hash32};
use timescales_krc::member::{Member, router};
use timescales_service::wire::{
    AnnouncementQuery, AnnouncementReply, ChallengeRequest, ChallengeResponse, EpochKeyAck,
    MessageKind, ReleasePolicyStatement, ReleaseRefusal, ReleaseResponse, SignedEnvelope,
};
use timescales_service::{ClientError, HttpLimits, SignedClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const E: u64 = 5;

struct Served {
    _dir: tempfile::TempDir,
    chain: Chain,
    committee: Committee,
    member: Arc<Member>,
    addr: SocketAddr,
    enclave: Enclave,
}

async fn serve() -> Served {
    let dir = tempfile::tempdir().unwrap();
    let committee = committee(market_address(), 3, 2, 1);
    let file = dir.path().join("committee.bin");
    committee.write(&file);
    let enclave = Enclave::new(1);
    let mut market = market_account(committee.digest(), &[enclave.executor.public()]);
    market.last_committed = E - 1;
    market.last_settled = E - 1;
    let chain = Chain::new(market);
    let cfg = member_config(dir.path(), 1, file);
    let member = Arc::new(open_member(dir.path(), cfg, 1, chain.krc()));
    let limits = HttpLimits {
        max_body_bytes: MessageKind::ReleaseRequest.max_envelope_len(),
        request_timeout: Duration::from_secs(10),
        max_concurrency: 16,
        per_caller_rps: 1000,
        per_caller_burst: 1000,
    };
    let app = router(Arc::clone(&member), limits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Served {
        _dir: dir,
        chain,
        committee,
        member,
        addr,
        enclave,
    }
}

impl Served {
    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    fn client(&self, key: Keypair) -> SignedClient {
        SignedClient::new(
            Arc::new(key),
            self.member.identity().public(),
            None,
            Duration::from_secs(10),
        )
        .unwrap()
    }
}

/// Sends `request` and reads the answer until the server closes or two
/// seconds pass. Returns the status and the body.
async fn raw(addr: SocketAddr, request: &[u8]) -> (u16, Vec<u8>) {
    let mut s = TcpStream::connect(addr).await.unwrap();
    s.write_all(request).await.unwrap();
    let mut out = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
    let text = String::from_utf8_lossy(&out);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = out
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or_else(Vec::new, |i| out[i + 4..].to_vec());
    (status, body)
}

fn post(path: &str, content_length: usize, body: &[u8]) -> Vec<u8> {
    let mut r = format!(
        "POST {path} HTTP/1.1\r\nHost: member\r\nContent-Type: application/vnd.timescales.envelope\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    r.extend_from_slice(body);
    r
}

fn get(path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: member\r\nConnection: close\r\n\r\n").into_bytes()
}

#[tokio::test]
async fn shares_and_announcement_queries_travel_in_signed_envelopes() {
    let s = serve().await;
    let dealer = s.client(dealer_key());
    let d = deal(&s.committee, E);
    let env = dealer
        .call(
            &s.url("/krc/v1/shares"),
            MessageKind::ShareDelivery,
            d.deliveries[0].to_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(env.kind, MessageKind::EpochKeyAck);
    let ack = EpochKeyAck::decode_exact(&env.body).unwrap();
    ack.verify(
        &d.announcement.digest(),
        &s.committee.desc.members[0].identity,
    )
    .unwrap();

    // A second announcement: 409, signed, naming what the member holds.
    let second = deal(&s.committee, E);
    match dealer
        .call(
            &s.url("/krc/v1/shares"),
            MessageKind::ShareDelivery,
            second.deliveries[0].to_bytes(),
        )
        .await
    {
        Err(ClientError::Refused { status, envelope }) => {
            assert_eq!(status, 409);
            assert_eq!(envelope.kind, MessageKind::AnnouncementReply);
            let (held, held_ack) = AnnouncementReply::decode_exact(&envelope.body)
                .unwrap()
                .0
                .unwrap();
            assert_eq!(held.digest(), d.announcement.digest());
            assert_eq!(held_ack, ack);
        }
        other => panic!("expected a signed 409, got {other:?}"),
    }

    let reply = dealer
        .call(
            &s.url("/krc/v1/announcements"),
            MessageKind::AnnouncementQuery,
            AnnouncementQuery {
                market: market_address(),
                epoch: EpochId(E),
            }
            .to_bytes(),
        )
        .await
        .unwrap();
    let held = AnnouncementReply::decode_exact(&reply.body)
        .unwrap()
        .0
        .unwrap();
    assert_eq!(held.0, d.announcement);
    let none = dealer
        .call(
            &s.url("/krc/v1/announcements"),
            MessageKind::AnnouncementQuery,
            AnnouncementQuery {
                market: market_address(),
                epoch: EpochId(E + 1),
            }
            .to_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(AnnouncementReply::decode_exact(&none.body).unwrap().0, None);
}

#[tokio::test]
async fn only_configured_dealers_deliver_shares() {
    let s = serve().await;
    let stranger = s.client(Keypair::from_seed([0x77; 32]));
    let d = deal(&s.committee, E);
    match stranger
        .call(
            &s.url("/krc/v1/shares"),
            MessageKind::ShareDelivery,
            d.deliveries[0].to_bytes(),
        )
        .await
    {
        Err(ClientError::Status(403)) => {}
        other => panic!("expected 403, got {other:?}"),
    }
    assert!(
        s.member
            .announcement(market_address(), EpochId(E))
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn challenge_and_release_over_http() {
    let s = serve().await;
    let d = deal(&s.committee, E);
    s.member
        .accept_share(dealer_key().public(), d.deliveries[0].clone())
        .await
        .unwrap();
    s.chain.update_market(|m| m.last_committed = E);
    let batch = revealed_batch(&d.announcement);
    s.chain.put_batch(&batch);

    let enclave = s.client(Keypair::from_seed(*s.enclave.executor.seed()));
    let env = enclave
        .call(
            &s.url("/krc/v1/challenge"),
            MessageKind::ChallengeRequest,
            ChallengeRequest {
                market: market_address(),
                epoch: EpochId(E),
                executor: s.enclave.id(),
            }
            .to_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(env.kind, MessageKind::ChallengeResponse);
    let c = ChallengeResponse::decode_exact(&env.body).unwrap();
    assert_eq!((c.member, c.epoch), (1, EpochId(E)));

    let market = s.chain.market.lock().clone();
    let req = release_request(
        &s.enclave,
        header(&market, &batch, Hash32([1; 32])),
        &d.announcement,
        1,
        3,
        c.nonce,
        MEASUREMENT,
    );
    let env = enclave
        .call(
            &s.url("/krc/v1/release"),
            MessageKind::ReleaseRequest,
            req.to_bytes(),
        )
        .await
        .unwrap();
    assert_eq!(env.kind, MessageKind::ReleaseResponse);
    let ReleaseResponse::Share(share) = ReleaseResponse::decode_exact(&env.body).unwrap() else {
        panic!("expected a share");
    };
    let plain = open_released(&s.enclave, &req.header, &share);
    assert_eq!(plain[1..], d.shares[0].value.to_bytes());

    // A malformed request is refused with a signed answer, status 200.
    let env = enclave
        .call(
            &s.url("/krc/v1/release"),
            MessageKind::ReleaseRequest,
            vec![1, 2, 3],
        )
        .await
        .unwrap();
    assert_eq!(
        ReleaseResponse::decode_exact(&env.body).unwrap(),
        ReleaseResponse::refused(ReleaseRefusal::BadRequest, "BadRequest")
    );

    // A refused challenge carries the signed refusal under an error status.
    let client = s.client(Keypair::from_seed([0x55; 32]));
    match client
        .call(
            &s.url("/krc/v1/challenge"),
            MessageKind::ChallengeRequest,
            ChallengeRequest {
                market: market_address(),
                epoch: EpochId(E),
                executor: timescales_core::ExecutorId(Keypair::from_seed([0x55; 32]).public()),
            }
            .to_bytes(),
        )
        .await
    {
        Err(ClientError::Refused { status, envelope }) => {
            assert_eq!(status, 403);
            assert_eq!(
                ReleaseResponse::decode_exact(&envelope.body).unwrap(),
                ReleaseResponse::refused(ReleaseRefusal::NotRegistered, "NotRegistered")
            );
        }
        other => panic!("expected a signed refusal, got {other:?}"),
    }
}

#[tokio::test]
async fn the_prefix_is_judged_before_the_body_is_read() {
    let s = serve().await;
    // A share delivery from a key that is not a dealer, announcing the
    // largest body its kind allows. Only the 94-byte prefix is sent.
    let stranger = Keypair::from_seed([0x66; 32]);
    let body = vec![0u8; MessageKind::ShareDelivery.max_body()];
    let env = SignedEnvelope::seal(
        MessageKind::ShareDelivery,
        &stranger,
        s.member.identity().public(),
        now_ms(),
        &mut OsRng,
        body,
    );
    let bytes = env.to_bytes();
    let (status, _) = raw(
        s.addr,
        &post(
            "/krc/v1/shares",
            bytes.len(),
            &bytes[..timescales_service::wire::PREFIX_LEN],
        ),
    )
    .await;
    assert_eq!(status, 403);

    // A body longer than the kind allows is refused from its prefix too.
    let dealer = dealer_key();
    let mut prefix = SignedEnvelope::seal(
        MessageKind::AnnouncementQuery,
        &dealer,
        s.member.identity().public(),
        now_ms(),
        &mut OsRng,
        vec![0; 40],
    )
    .prefix();
    prefix.body_len = 1 << 20;
    let (status, _) = raw(
        s.addr,
        &post(
            "/krc/v1/announcements",
            94 + (1 << 20) + 64,
            &prefix.to_bytes(),
        ),
    )
    .await;
    assert_eq!(status, 413);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

#[tokio::test]
async fn a_replayed_envelope_is_refused() {
    let s = serve().await;
    let env = SignedEnvelope::seal(
        MessageKind::AnnouncementQuery,
        &dealer_key(),
        s.member.identity().public(),
        now_ms(),
        &mut OsRng,
        AnnouncementQuery {
            market: market_address(),
            epoch: EpochId(E),
        }
        .to_bytes(),
    )
    .to_bytes();
    let request = post("/krc/v1/announcements", env.len(), &env);
    assert_eq!(raw(s.addr, &request).await.0, 200);
    assert_eq!(raw(s.addr, &request).await.0, 401);
    // Addressed to another member.
    let other = SignedEnvelope::seal(
        MessageKind::AnnouncementQuery,
        &dealer_key(),
        [9; 32],
        now_ms(),
        &mut OsRng,
        vec![0; 40],
    )
    .to_bytes();
    assert_eq!(
        raw(s.addr, &post("/krc/v1/announcements", other.len(), &other))
            .await
            .0,
        403
    );
}

#[tokio::test]
async fn policy_and_identity_are_public() {
    let s = serve().await;
    let (status, body) = raw(s.addr, &get("/krc/v1/policy")).await;
    assert_eq!(status, 200);
    let statement = ReleasePolicyStatement::decode_exact(&body).unwrap();
    statement
        .verify(&s.committee.desc.members[0].identity)
        .unwrap();
    assert_eq!(statement.market, market_address());
    assert_eq!(statement.member, 1);
    let (status, body) = raw(
        s.addr,
        &get(&format!("/krc/v1/policy?market={}", b58(&market_address()))),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, statement.to_bytes());
    let (status, _) = raw(
        s.addr,
        &get(&format!("/krc/v1/policy?market={}", b58(&[1; 32]))),
    )
    .await;
    assert_eq!(status, 404);

    let (status, body) = raw(s.addr, &get("/krc/v1/identity")).await;
    assert_eq!(status, 200);
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("\"index\":1"), "{text}");
    assert!(text.contains(&s.committee.digest().to_hex()), "{text}");
    assert!(text.contains("\"simulated\""), "{text}");
}
