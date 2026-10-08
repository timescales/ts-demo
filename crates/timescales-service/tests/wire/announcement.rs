use timescales_auction::{epoch_binding, terms_digest};
use timescales_core::crypto::{Hasher, domain};
use timescales_core::{Decode, DecodeError, Encode, EpochId, Hash32, Tick};
use timescales_service::wire::{AnnouncementFields, EpochAnnouncement, RelayRefusal, WireError};

use crate::common::{EPOCH, MARKET, envelope, header_v2, keypair, params};

fn fields() -> AnnouncementFields {
    AnnouncementFields {
        market: MARKET,
        epoch: EPOCH,
        opens_at_ms: 1_800_000_000_000,
        cutoff_ms: 1_800_000_002_000,
        band: params().band(Tick(1_000)).unwrap(),
        price_commitment: Hash32([1; 32]),
        key_digest: Hash32([2; 32]),
        committee_digest: Hash32([3; 32]),
    }
}

#[test]
fn announcements_are_signed_by_the_relay() {
    let relay = keypair(11);
    let a = EpochAnnouncement::sign(fields(), &relay);
    assert_eq!(a.version, EpochAnnouncement::VERSION);
    assert_eq!(a.relay, relay.public());
    assert!(a.verify().is_ok());
    let bytes = a.to_bytes();
    assert_eq!(bytes.len(), EpochAnnouncement::ENCODED_LEN);
    assert_eq!(bytes.len(), 273);
    assert_eq!(
        a.signing_digest(),
        Hasher::new(domain::EPOCH_ANNOUNCEMENT)
            .chain(&bytes[..273 - 64])
            .finalize()
    );
}

#[test]
fn every_announced_term_is_signed() {
    let a = EpochAnnouncement::sign(fields(), &keypair(11));
    let mut changes = Vec::new();
    let mut x = a;
    x.epoch = EpochId(EPOCH.0 + 1);
    changes.push(x);
    let mut x = a;
    x.cutoff_ms += 1;
    changes.push(x);
    let mut x = a;
    x.band = params().band(Tick(1_001)).unwrap();
    changes.push(x);
    let mut x = a;
    x.key_digest.0[0] ^= 1;
    changes.push(x);
    let mut x = a;
    x.committee_digest.0[0] ^= 1;
    changes.push(x);
    let mut x = a;
    x.relay = keypair(12).public();
    changes.push(x);
    for changed in changes {
        assert!(matches!(changed.verify(), Err(WireError::BadSignature)));
    }
    let mut v2 = a;
    v2.version = 2;
    assert!(matches!(v2.verify(), Err(WireError::Version(2))));
}

#[test]
fn the_binding_and_terms_match_the_auction_and_the_header() {
    let a = EpochAnnouncement::sign(fields(), &keypair(11));
    let binding = epoch_binding(&a.price_commitment, &a.key_digest, &a.committee_digest);
    assert_eq!(a.binding(), binding);
    assert_eq!(
        binding,
        Hasher::new(domain::EPOCH_BINDING)
            .chain(&[[1u8; 32], [2; 32], [3; 32]].concat())
            .finalize()
    );
    assert_eq!(a.terms_digest(), terms_digest(&a.band, &binding));

    // The program checks terms_digest over header v2 bytes [63..119]: band
    // and epoch binding.
    let envelopes: Vec<_> = (0..3).map(envelope).collect();
    let header = header_v2(&envelopes, a.binding()).to_bytes();
    assert_eq!(
        a.terms_digest(),
        Hasher::new(domain::EPOCH_TERMS)
            .chain(&header[63..119])
            .finalize()
    );
}

#[test]
fn the_announcement_codec_round_trips_and_refuses_bad_input() {
    let a = EpochAnnouncement::sign(fields(), &keypair(11));
    let bytes = a.to_bytes();
    let back = EpochAnnouncement::decode_exact(&bytes).unwrap();
    assert_eq!(back, a);
    assert!(back.verify().is_ok());

    let mut bad = bytes.clone();
    bad[0] = 0;
    assert_eq!(
        EpochAnnouncement::decode_exact(&bad),
        Err(DecodeError::InvalidValue("EpochAnnouncement.version"))
    );
    // The band follows version, market, epoch, opens_at and cutoff: lo > hi.
    let band_at = 1 + 32 + 8 + 8 + 8;
    let mut bad = bytes.clone();
    bad[band_at..band_at + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        EpochAnnouncement::decode_exact(&bad),
        Err(DecodeError::InvalidValue("PriceBand"))
    );
    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        EpochAnnouncement::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
    assert!(matches!(
        EpochAnnouncement::decode_exact(&bytes[..272]),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}

#[test]
fn refusal_codes_are_numbered_from_one() {
    assert_eq!(
        [
            RelayRefusal::BATCH_FULL,
            RelayRefusal::INTAKE_PAUSED,
            RelayRefusal::QUOTA_EXCEEDED,
            RelayRefusal::EPOCH_CLOSED
        ],
        [1, 2, 3, 4]
    );
}

#[test]
fn refusals_are_signed_evidence() {
    let relay = keypair(11);
    let r = RelayRefusal::sign(
        MARKET,
        EPOCH,
        envelope(4).digest(),
        3,
        1_800_000_001_000,
        &relay,
    );
    assert_eq!(r.relay, relay.public());
    assert!(r.verify().is_ok());
    let bytes = r.to_bytes();
    assert_eq!(bytes.len(), RelayRefusal::ENCODED_LEN);
    assert_eq!(bytes.len(), 177);
    assert_eq!(
        r.signing_digest(),
        Hasher::new(domain::RELAY_REFUSAL)
            .chain(&bytes[..177 - 64])
            .finalize()
    );
    let back = RelayRefusal::decode_exact(&bytes).unwrap();
    assert_eq!(back, r);
    assert!(back.verify().is_ok());

    let mut code = r;
    code.code = 4;
    assert!(matches!(code.verify(), Err(WireError::BadSignature)));
    let mut at = r;
    at.at_ms += 1;
    assert!(matches!(at.verify(), Err(WireError::BadSignature)));
    let mut digest = r;
    digest.envelope_digest.0[31] ^= 1;
    assert!(matches!(digest.verify(), Err(WireError::BadSignature)));

    let mut long = bytes.clone();
    long.push(0);
    assert_eq!(
        RelayRefusal::decode_exact(&long),
        Err(DecodeError::TrailingBytes(1))
    );
    assert!(matches!(
        RelayRefusal::decode_exact(&bytes[..176]),
        Err(DecodeError::UnexpectedEof { .. })
    ));
}
