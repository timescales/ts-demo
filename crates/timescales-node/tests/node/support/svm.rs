//! The settlement program in LiteSVM behind `LiteSvmRpc`, with real SPL
//! mints, vaults and token accounts created through the Token program.
//!
//! The node's manifest does not name `litesvm`, so the `LiteSVM` value is
//! built through the constructor `LiteSvmRpc::new` takes, the way
//! `LiteSVM::new` builds it.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use timescales_chain::program::{Ix, TOKEN_PROGRAM};
use timescales_chain::{
    BoxFuture, FileSigner, JournalError, Landed, LiteSvmConfig, LiteSvmRpc, SolanaRpc, TxJournal,
    TxOp, TxOutcome, TxRecord, TxSender, TxSigner,
};
use timescales_core::crypto::{Keypair, hash};
use zeroize::Zeroizing;

pub const PROGRAM: &str = "FDQqHeaCY2iG9kbjkGGJngY2rgend8dW4JjfXmCQytQL";
pub const START_SLOT: u64 = 1_000;
pub const SLOT_TIME: Duration = Duration::from_millis(400);

pub fn program() -> [u8; 32] {
    timescales_chain::program::decode_base58(PROGRAM).unwrap()
}

/// Builds the value `LiteSvmRpc::new` takes as `LiteSVM::new` would:
/// mainnet features, builtins, sysvars, the SPL programs and precompiles.
fn basic_svm<S: Default>(_new: fn(S, LiteSvmConfig) -> LiteSvmRpc, f: impl FnOnce(S) -> S) -> S {
    f(S::default())
}

pub fn cluster() -> LiteSvmConfig {
    LiteSvmConfig {
        confirmed_lag: 1,
        finalized_lag: 32,
        slot_time: Some(SLOT_TIME),
        blockhash_validity: 150,
        ..LiteSvmConfig::default()
    }
}

/// LiteSVM with the settlement program loaded, at `START_SLOT`.
pub fn new_svm() -> Arc<LiteSvmRpc> {
    let so = timescales_chain::settlement_program_so();
    assert!(
        so.is_file(),
        "settlement program not found at {}; run scripts/build-program.sh",
        so.display()
    );
    let svm = basic_svm(LiteSvmRpc::new, |s| {
        s.with_mainnet_features()
            .with_builtins()
            .with_lamports(1_000_000_000_000_000)
            .with_sysvars()
            .with_feature_accounts()
            .with_default_programs()
            .with_precompiles()
            .with_sigverify(true)
            .with_blockhash_check(true)
    });
    let rpc = LiteSvmRpc::new(svm, cluster());
    rpc.with_svm(|s| s.add_program_from_file(program(), &so))
        .unwrap();
    rpc.warp_slot(START_SLOT);
    Arc::new(rpc)
}

/// A Solana signer and the same key as a core `Keypair`.
pub fn key(seed: [u8; 32]) -> (Arc<dyn TxSigner>, Keypair) {
    let kp = Keypair::from_seed(seed);
    let mut bytes = Zeroizing::new([0u8; 64]);
    bytes[..32].copy_from_slice(&seed);
    bytes[32..].copy_from_slice(&kp.public());
    (Arc::new(FileSigner::from_bytes(bytes).unwrap()), kp)
}

pub fn seed(label: &str, n: u64) -> [u8; 32] {
    hash(
        b"timescales/node-test/key",
        &[label.as_bytes(), &n.to_le_bytes()].concat(),
    )
    .0
}

pub fn airdrop(svm: &LiteSvmRpc, to: [u8; 32], lamports: u64) {
    let landed = svm.with_svm(|s| s.airdrop(&to.into(), lamports).is_ok());
    assert!(landed, "airdrop failed");
}

/// An in-memory journal for the harness's own transactions.
#[derive(Default)]
pub struct MemJournal {
    rows: Mutex<Vec<(TxRecord, Option<TxOutcome>)>>,
}

impl TxJournal for MemJournal {
    fn before_send(&self, rec: TxRecord) -> BoxFuture<'_, Result<i64, JournalError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock();
            rows.push((rec, None));
            Ok(i64::try_from(rows.len()).unwrap())
        })
    }

    fn resolved(&self, id: i64, outcome: TxOutcome) -> BoxFuture<'_, Result<(), JournalError>> {
        Box::pin(async move {
            let mut rows = self.rows.lock();
            let i = usize::try_from(id - 1).unwrap();
            rows[i].1 = Some(outcome);
            Ok(())
        })
    }

    fn pending(&self) -> BoxFuture<'_, Result<Vec<TxRecord>, JournalError>> {
        Box::pin(async move { Ok(Vec::new()) })
    }

    fn last_landed_slot(&self) -> BoxFuture<'_, Result<u64, JournalError>> {
        Box::pin(async move {
            Ok(self
                .rows
                .lock()
                .iter()
                .filter_map(|(_, o)| match o {
                    Some(TxOutcome::Landed { slot } | TxOutcome::Failed { slot, .. }) => {
                        Some(*slot)
                    }
                    _ => None,
                })
                .max()
                .unwrap_or(0))
        })
    }
}

pub async fn send(
    sender: &TxSender,
    ixs: Vec<Ix>,
    payer: &Arc<dyn TxSigner>,
    extra: Vec<Arc<dyn TxSigner>>,
) -> Landed {
    sender
        .send(TxOp::Admin, ixs, payer.clone(), extra)
        .await
        .unwrap()
}

/// Creates a Token-owned account of `space` bytes at `new`.
pub async fn create_token_owned(
    rpc: &Arc<dyn SolanaRpc>,
    payer: &Arc<dyn TxSigner>,
    new: &Arc<dyn TxSigner>,
    space: usize,
) -> Ix {
    let rent = rpc.minimum_balance_for_rent_exemption(space).await.unwrap();
    timescales_chain::program::system::create_account(
        &payer.address(),
        &new.address(),
        rent,
        u64::try_from(space).unwrap(),
        &TOKEN_PROGRAM,
    )
}

/// A classic mint with `authority`, 6 decimals.
pub async fn mint(
    rpc: &Arc<dyn SolanaRpc>,
    sender: &TxSender,
    authority: &Arc<dyn TxSigner>,
    mint: Arc<dyn TxSigner>,
) {
    let create = create_token_owned(
        rpc,
        authority,
        &mint,
        timescales_chain::program::spl::MINT_LEN,
    )
    .await;
    let init = timescales_chain::program::spl::initialize_mint2(
        &mint.address(),
        &authority.address(),
        None,
        6,
    );
    send(sender, vec![create, init], authority, vec![mint]).await;
}

/// A token account of `mint` owned by `owner`, holding `amount` minted by
/// `authority`.
pub async fn token_account(
    rpc: &Arc<dyn SolanaRpc>,
    sender: &TxSender,
    authority: &Arc<dyn TxSigner>,
    mint: [u8; 32],
    owner: [u8; 32],
    account: Arc<dyn TxSigner>,
    amount: u64,
) {
    let create = create_token_owned(
        rpc,
        authority,
        &account,
        timescales_chain::program::spl::TOKEN_ACCOUNT_LEN,
    )
    .await;
    let init =
        timescales_chain::program::spl::initialize_account3(&account.address(), &mint, &owner);
    let mut ixs = vec![create, init];
    if amount > 0 {
        ixs.push(timescales_chain::program::spl::mint_to(
            &mint,
            &account.address(),
            &authority.address(),
            amount,
        ));
    }
    send(sender, ixs, authority, vec![account]).await;
}
