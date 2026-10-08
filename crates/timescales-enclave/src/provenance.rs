//! The provenance check: who submitted each envelope.
//!
//! Every grant is parsed with the SIWS ABNF and must name one of the
//! market's session domains, this deployment's program and chain, this
//! market (or all markets), and carry the wallet's strict Ed25519
//! signature over its exact text. A `signMessage` grant passes only where
//! the configuration allows it. An envelope is admitted for the grant's
//! wallet when the grant passed and the session key it authorises signed
//! the envelope's submission. The executor then runs a Place or Cancel
//! only if the intent's trader is that wallet, so an intent signature
//! phished on another site is useless without the same wallet's grant.
//!
//! Grants are not checked against the current time: the node checked their
//! lifetime when each envelope was submitted, before the batch was cut.

use timescales_core::crypto::{Hasher, Signature, domain, verify_digest};
use timescales_core::intent::SealedEnvelope;
use timescales_core::{Encode, TraderId};
use timescales_service::wire::{
    ChainId, GrantMethod, GrantRecord, Provenance, ProvenanceEntry, SessionGrant,
    parse_session_message,
};

/// What a grant must name besides its signature.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GrantRules<'a> {
    pub domains: &'a [String],
    pub program: [u8; 32],
    pub chain_id: ChainId,
    pub market: [u8; 32],
    pub allow_sign_message: bool,
}

/// The admission vector and how many submitted envelopes failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Admission {
    /// One entry per envelope: the wallet whose session submitted it.
    pub admission: Vec<Option<TraderId>>,
    /// Envelopes that named a grant but did not authenticate.
    pub rejected: u32,
}

/// The digest a session key signs to submit `envelope` (the relay's
/// `Submission::digest` with the session key as trader and no masked
/// encoding, which header version 2 forbids).
pub(crate) fn submission_digest(
    envelope: &SealedEnvelope,
    session_key: &[u8; 32],
) -> timescales_core::Hash32 {
    Hasher::new(domain::RELAY_SUBMISSION)
        .chain(&envelope.to_bytes())
        .chain(session_key)
        .finalize()
}

/// The grant, if it passes every rule.
fn check_grant(g: &GrantRecord, rules: &GrantRules<'_>) -> Option<SessionGrant> {
    if g.method == GrantMethod::SignMessage && !rules.allow_sign_message {
        return None;
    }
    let grant = parse_session_message(&g.text).ok()?;
    let ok = rules.domains.contains(&grant.domain)
        && grant.program == rules.program
        && grant.chain_id == rules.chain_id
        && grant.market.is_none_or(|m| m == rules.market)
        && crate::ed25519::verify_strict(&grant.wallet, g.text.as_bytes(), &g.signature.0);
    ok.then_some(grant)
}

fn session_signed(
    envelope: &SealedEnvelope,
    session_key: &[u8; 32],
    signature: &Signature,
) -> bool {
    verify_digest(
        session_key,
        &submission_digest(envelope, session_key),
        signature,
    )
    .is_ok()
}

/// `admission[i] = Some(wallet)` for every envelope `i` whose grant passes
/// and whose session signature verifies. `None` for cover and failures.
/// `provenance.entries` has one entry per envelope (the decoder checks it).
pub(crate) fn admit(
    envelopes: &[SealedEnvelope],
    provenance: &Provenance,
    rules: &GrantRules<'_>,
) -> Admission {
    let grants: Vec<Option<SessionGrant>> = provenance
        .grants
        .iter()
        .map(|g| check_grant(g, rules))
        .collect();
    let mut rejected = 0u32;
    let admission = envelopes
        .iter()
        .zip(&provenance.entries)
        .map(|(env, entry)| {
            if entry.grant == ProvenanceEntry::NO_GRANT {
                return None;
            }
            let grant = usize::try_from(entry.grant)
                .ok()
                .and_then(|i| grants.get(i))
                .and_then(Option::as_ref);
            let wallet = grant
                .filter(|g| session_signed(env, &g.session_key, &entry.session_signature))
                .map(|g| TraderId(g.wallet));
            if wallet.is_none() {
                rejected = rejected.saturating_add(1);
            }
            wallet
        })
        .collect();
    Admission {
        admission,
        rejected,
    }
}

#[cfg(test)]
mod tests {
    use timescales_core::crypto::{Keypair, hash};
    use timescales_core::{EpochId, MarketId, OrderCommitment};
    use timescales_service::wire::{SESSION_STATEMENT, render_session_message};

    use super::*;
    use crate::testing::sign_message;

    const MARKET: [u8; 32] = [0x4d; 32];
    const PROGRAM: [u8; 32] = [0x50; 32];

    fn domains() -> Vec<String> {
        vec!["app.example".to_owned()]
    }

    fn rules(domains: &[String]) -> GrantRules<'_> {
        GrantRules {
            domains,
            program: PROGRAM,
            chain_id: ChainId::Devnet,
            market: MARKET,
            allow_sign_message: false,
        }
    }

    fn grant_text(
        wallet: &Keypair,
        session: &Keypair,
        edit: impl FnOnce(&mut SessionGrant),
    ) -> String {
        let mut g = SessionGrant {
            domain: "app.example".to_owned(),
            wallet: wallet.public(),
            statement: SESSION_STATEMENT.to_owned(),
            uri: "https://app.example".to_owned(),
            chain_id: ChainId::Devnet,
            nonce: [1; 16],
            issued_at_ms: 1_700_000_000_000,
            expires_at_ms: 1_700_003_600_000,
            not_before_ms: None,
            session_key: session.public(),
            program: PROGRAM,
            market: Some(MARKET),
        };
        edit(&mut g);
        render_session_message(&g)
    }

    fn envelope(i: u8) -> SealedEnvelope {
        SealedEnvelope {
            version: 1,
            market: MarketId(7),
            epoch: EpochId(3),
            commitment: OrderCommitment(hash(b"test/commitment", &[i]).0),
            ephemeral: [i; 32],
            ciphertext: [i; timescales_core::intent::CIPHERTEXT_LEN],
        }
    }

    /// One envelope per grant text, each submitted by that grant's session.
    fn check(texts: &[(String, GrantMethod)], allow_sign_message: bool) -> Admission {
        let wallet_seed = [7u8; 32];
        let session = Keypair::from_seed([8; 32]);
        let envelopes: Vec<SealedEnvelope> = (0..texts.len())
            .map(|i| envelope(u8::try_from(i).unwrap()))
            .collect();
        let grants = texts
            .iter()
            .map(|(text, method)| GrantRecord {
                text: text.clone(),
                signature: Signature(sign_message(&wallet_seed, text.as_bytes())),
                method: *method,
            })
            .collect();
        let entries = envelopes
            .iter()
            .enumerate()
            .map(|(i, env)| ProvenanceEntry {
                grant: u32::try_from(i).unwrap(),
                session_signature: session.sign_digest(&submission_digest(env, &session.public())),
            })
            .collect();
        let domains = domains();
        let rules = GrantRules {
            allow_sign_message,
            ..rules(&domains)
        };
        admit(&envelopes, &Provenance { grants, entries }, &rules)
    }

    #[test]
    fn each_grant_rule_is_enforced() {
        let wallet = Keypair::from_seed([7; 32]);
        let session = Keypair::from_seed([8; 32]);
        let ok = grant_text(&wallet, &session, |_| {});
        let texts = vec![
            (ok.clone(), GrantMethod::SignIn),
            (
                grant_text(&wallet, &session, |g| g.domain = "other.example".into()),
                GrantMethod::SignIn,
            ),
            (
                grant_text(&wallet, &session, |g| g.program = [1; 32]),
                GrantMethod::SignIn,
            ),
            (
                grant_text(&wallet, &session, |g| g.chain_id = ChainId::Mainnet),
                GrantMethod::SignIn,
            ),
            (
                grant_text(&wallet, &session, |g| g.market = Some([2; 32])),
                GrantMethod::SignIn,
            ),
            (
                grant_text(&wallet, &session, |g| g.market = None),
                GrantMethod::SignIn,
            ),
            (ok.clone(), GrantMethod::SignMessage),
        ];
        let a = check(&texts, false);
        let w = Some(TraderId(wallet.public()));
        assert_eq!(a.admission, vec![w, None, None, None, None, w, None]);
        assert_eq!(a.rejected, 5);
        // signMessage grants pass where the configuration allows them.
        let a = check(&[(ok, GrantMethod::SignMessage)], true);
        assert_eq!(a.admission, vec![w]);
    }

    #[test]
    fn a_signature_by_another_wallet_or_session_fails() {
        let wallet = Keypair::from_seed([7; 32]);
        let session = Keypair::from_seed([8; 32]);
        let text = grant_text(&wallet, &session, |_| {});
        let env = envelope(0);
        let domains = domains();
        let entry = |key: &Keypair| ProvenanceEntry {
            grant: 0,
            session_signature: key.sign_digest(&submission_digest(&env, &session.public())),
        };
        let forged = GrantRecord {
            text: text.clone(),
            signature: Signature(sign_message(&[9; 32], text.as_bytes())),
            method: GrantMethod::SignIn,
        };
        let a = admit(
            std::slice::from_ref(&env),
            &Provenance {
                grants: vec![forged],
                entries: vec![entry(&session)],
            },
            &rules(&domains),
        );
        assert_eq!(a.admission, vec![None]);
        let real = GrantRecord {
            text: text.clone(),
            signature: Signature(sign_message(&[7; 32], text.as_bytes())),
            method: GrantMethod::SignIn,
        };
        let a = admit(
            std::slice::from_ref(&env),
            &Provenance {
                grants: vec![real],
                entries: vec![entry(&Keypair::from_seed([10; 32]))],
            },
            &rules(&domains),
        );
        assert_eq!(a.admission, vec![None]);
        assert_eq!(a.rejected, 1);
        // Cover traffic names no grant and is not a rejection.
        let a = admit(
            std::slice::from_ref(&env),
            &Provenance {
                grants: vec![],
                entries: vec![ProvenanceEntry {
                    grant: ProvenanceEntry::NO_GRANT,
                    session_signature: Signature([0; 64]),
                }],
            },
            &rules(&domains),
        );
        assert_eq!(a.admission, vec![None]);
        assert_eq!(a.rejected, 0);
    }
}
