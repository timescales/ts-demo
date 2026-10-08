//! Legacy transactions built from `crate::program::Ix`, their wire bytes,
//! and the conversion of a cluster's transaction error into
//! [`TxErrorDetail`], shared by every provider so that each reports the same
//! detail for the same error.

use std::sync::Arc;

use crate::program::{ClientError, Ix};
use serde_json::Value;
use solana_address::Address as SolAddress;
use solana_hash::Hash;
use solana_instruction::{AccountMeta, Instruction};
use solana_message::Message;

use crate::{Address, TxError, TxErrorDetail, TxSigner};

pub(crate) fn instruction(ix: &Ix) -> Instruction {
    Instruction {
        program_id: SolAddress::from(ix.program),
        accounts: ix
            .accounts
            .iter()
            .map(|m| AccountMeta {
                pubkey: SolAddress::from(m.key),
                is_signer: m.signer,
                is_writable: m.writable,
            })
            .collect(),
        data: ix.data.clone(),
    }
}

/// Compiles `ixs` into a legacy message paid for by `payer`.
pub(crate) fn compile(ixs: &[Ix], payer: &Address, blockhash: &[u8; 32]) -> Message {
    let ixs: Vec<Instruction> = ixs.iter().map(instruction).collect();
    Message::new_with_blockhash(
        &ixs,
        Some(&SolAddress::from(*payer)),
        &Hash::new_from_array(*blockhash),
    )
}

/// The bytes every signer signs.
pub(crate) fn message_bytes(message: &Message) -> Result<Vec<u8>, TxError> {
    bincode::serialize(message)
        .map_err(|_| TxError::Build(ClientError::InvalidArgument("message does not serialize")))
}

/// The accounts that must sign `message`, in signature order.
pub(crate) fn required_signers(message: &Message) -> Vec<Address> {
    let n = usize::from(message.header.num_required_signatures);
    message
        .account_keys
        .iter()
        .take(n)
        .map(|k| k.to_bytes())
        .collect()
}

/// A signed transaction: its wire bytes and first (identifying) signature.
#[derive(Debug)]
pub(crate) struct Signed {
    pub(crate) wire: Vec<u8>,
    pub(crate) signature: [u8; 64],
}

/// Signs `message` with the signer of each required signature.
pub(crate) fn sign(message: &Message, signers: &[Arc<dyn TxSigner>]) -> Result<Signed, TxError> {
    let bytes = message_bytes(message)?;
    let mut signatures = Vec::new();
    for key in required_signers(message) {
        let signer = signers
            .iter()
            .find(|s| s.address() == key)
            .ok_or(TxError::Build(ClientError::InvalidArgument(
                "no signer for a required signature",
            )))?;
        signatures.push(signer.sign(&bytes));
    }
    let signature = *signatures
        .first()
        .ok_or(TxError::Build(ClientError::InvalidArgument(
            "transaction without a signature",
        )))?;
    Ok(Signed {
        wire: assemble(&signatures, &bytes),
        signature,
    })
}

/// The transaction with all-zero signatures, for a simulation that skips
/// signature verification.
pub(crate) fn unsigned(message: &Message) -> Result<Vec<u8>, TxError> {
    let bytes = message_bytes(message)?;
    let n = usize::from(message.header.num_required_signatures);
    Ok(assemble(&vec![[0u8; 64]; n], &bytes))
}

/// `short_vec(signatures) || message`.
fn assemble(signatures: &[[u8; 64]], message: &[u8]) -> Vec<u8> {
    let mut wire = Vec::with_capacity(3 + 64 * signatures.len() + message.len());
    put_short_vec_len(&mut wire, signatures.len());
    for s in signatures {
        wire.extend_from_slice(s);
    }
    wire.extend_from_slice(message);
    wire
}

/// Solana's compact-u16 length prefix.
fn put_short_vec_len(out: &mut Vec<u8>, mut n: usize) {
    loop {
        let low = (n & 0x7f).to_le_bytes()[0];
        n >>= 7;
        if n == 0 {
            out.push(low);
            return;
        }
        out.push(low | 0x80);
    }
}

/// The first signature of a serialized transaction (its id).
#[cfg_attr(
    not(any(
        feature = "rpc-client",
        feature = "rpc-minimal",
        feature = "test-util",
        feature = "litesvm"
    )),
    allow(dead_code)
)]
pub(crate) fn first_signature(wire: &[u8]) -> Option<[u8; 64]> {
    let (&count, rest) = wire.split_first()?;
    if count == 0 || count & 0x80 != 0 {
        return None;
    }
    rest.first_chunk::<64>().copied()
}

/// The [`TxErrorDetail`] of a transaction error as the RPC encodes it:
/// `"BlockhashNotFound"`, `{"InstructionError":[2,{"Custom":6014}]}`,
/// `{"InsufficientFundsForRent":{"account_index":0}}`.
#[cfg_attr(
    not(any(feature = "rpc-client", feature = "rpc-minimal", feature = "litesvm")),
    allow(dead_code)
)]
pub(crate) fn error_detail(err: &Value) -> TxErrorDetail {
    let instruction = err
        .get("InstructionError")
        .and_then(Value::as_array)
        .filter(|a| a.len() == 2);
    let ix_index = instruction
        .and_then(|a| a[0].as_u64())
        .and_then(|i| u8::try_from(i).ok());
    let custom = instruction
        .and_then(|a| a[1].get("Custom"))
        .and_then(Value::as_u64)
        .and_then(|c| u32::try_from(c).ok());
    let message = match err {
        Value::String(name) => name.clone(),
        other => other.to_string(),
    };
    TxErrorDetail {
        ix_index,
        custom,
        message,
    }
}

impl TxErrorDetail {
    /// The transaction referenced a blockhash the node does not know or
    /// that has expired.
    pub(crate) fn blockhash_not_found(&self) -> bool {
        self.message == "BlockhashNotFound"
    }

    /// The node already processed a transaction with this signature.
    pub(crate) fn already_processed(&self) -> bool {
        self.message == "AlreadyProcessed"
    }

    /// An instruction may have run out of compute units. Older runtimes
    /// report `ComputationalBudgetExceeded`. Current ones report a program
    /// that exhausts the meter as `ProgramFailedToComplete`, which a status
    /// (without logs) cannot tell apart from other aborts, so it counts.
    pub(crate) fn budget_exceeded(&self) -> bool {
        self.ix_index.is_some()
            && (self.message.contains("\"ComputationalBudgetExceeded\"")
                || self.message.contains("\"ProgramFailedToComplete\""))
    }

    /// An instruction ran out of compute units, as far as `logs` (of a
    /// simulation or preflight) show.
    pub(crate) fn out_of_units(&self, logs: &[String]) -> bool {
        self.ix_index.is_some()
            && (self.message.contains("\"ComputationalBudgetExceeded\"")
                || (self.message.contains("\"ProgramFailedToComplete\"")
                    && logs.iter().any(|l| l.contains("exceeded CUs meter"))))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use solana_keypair::Keypair;
    use solana_signer::Signer;
    use solana_transaction::Transaction;

    use super::*;

    struct Key(Keypair);

    impl TxSigner for Key {
        fn address(&self) -> Address {
            self.0.pubkey().to_bytes()
        }

        fn sign(&self, message: &[u8]) -> [u8; 64] {
            self.0.sign_message(message).into()
        }
    }

    fn key(seed: u8) -> Arc<dyn TxSigner> {
        Arc::new(Key(Keypair::new_from_array([seed; 32])))
    }

    fn two_signer_ixs(payer: &Address, other: &Address) -> Vec<Ix> {
        vec![
            crate::program::compute_budget::set_limit(10_000),
            crate::program::system::transfer(payer, other, 5),
            crate::program::system::transfer(other, &[7; 32], 1),
        ]
    }

    #[test]
    fn wire_bytes_equal_the_sdk_serialization() {
        let (payer, other) = (key(1), key(2));
        let ixs = two_signer_ixs(&payer.address(), &other.address());
        let message = compile(&ixs, &payer.address(), &[9; 32]);
        let signed = sign(&message, &[other.clone(), payer.clone()]).unwrap();

        let sdk_ixs: Vec<Instruction> = ixs.iter().map(instruction).collect();
        let mut tx =
            Transaction::new_with_payer(&sdk_ixs, Some(&SolAddress::from(payer.address())));
        tx.message.recent_blockhash = Hash::new_from_array([9; 32]);
        let bytes = bincode::serialize(&tx.message).unwrap();
        tx.signatures = [1u8, 2]
            .map(|seed| Keypair::new_from_array([seed; 32]).sign_message(&bytes))
            .to_vec();
        assert_eq!(signed.wire, bincode::serialize(&tx).unwrap());
        assert_eq!(signed.signature, <[u8; 64]>::from(tx.signatures[0]));
        assert_eq!(first_signature(&signed.wire), Some(signed.signature));
        assert_eq!(
            signed.wire.len(),
            crate::program::legacy_tx_size(&ixs, &payer.address(), 2)
        );
        let blank = unsigned(&message).unwrap();
        assert_eq!(blank.len(), signed.wire.len());
        assert_eq!(blank[1..129], [0u8; 128]);
        assert_eq!(blank[129..], signed.wire[129..]);
    }

    #[test]
    fn a_missing_signer_is_a_build_error() {
        let (payer, other) = (key(1), key(2));
        let message = compile(
            &two_signer_ixs(&payer.address(), &other.address()),
            &payer.address(),
            &[9; 32],
        );
        assert_eq!(
            sign(&message, &[payer]).unwrap_err(),
            TxError::Build(ClientError::InvalidArgument(
                "no signer for a required signature"
            ))
        );
    }

    #[test]
    fn short_vec_lengths() {
        for (n, bytes) in [
            (0usize, vec![0u8]),
            (0x7f, vec![0x7f]),
            (0x80, vec![0x80, 0x01]),
            (0x3fff, vec![0xff, 0x7f]),
            (0x4000, vec![0x80, 0x80, 0x01]),
        ] {
            let mut out = Vec::new();
            put_short_vec_len(&mut out, n);
            assert_eq!(out, bytes, "{n}");
        }
    }

    #[test]
    fn error_details_from_rpc_json() {
        let custom = error_detail(&json!({"InstructionError": [2, {"Custom": 6014}]}));
        assert_eq!(
            custom,
            TxErrorDetail {
                ix_index: Some(2),
                custom: Some(6014),
                message: r#"{"InstructionError":[2,{"Custom":6014}]}"#.into(),
            }
        );
        let budget = error_detail(&json!({"InstructionError": [0, "ComputationalBudgetExceeded"]}));
        assert!(budget.budget_exceeded() && budget.out_of_units(&[]));
        assert_eq!((budget.ix_index, budget.custom), (Some(0), None));
        let incomplete = error_detail(&json!({"InstructionError": [2, "ProgramFailedToComplete"]}));
        assert!(incomplete.budget_exceeded());
        assert!(!incomplete.out_of_units(&["Program x failed: panicked".into()]));
        assert!(incomplete.out_of_units(&[
            "Program x consumed 12694 of 12694 compute units".into(),
            "Program x failed: exceeded CUs meter at BPF instruction".into(),
        ]));
        let blockhash = error_detail(&json!("BlockhashNotFound"));
        assert!(blockhash.blockhash_not_found());
        assert_eq!(blockhash.ix_index, None);
        let rent = error_detail(&json!({"InsufficientFundsForRent": {"account_index": 0}}));
        assert_eq!(
            rent.message,
            r#"{"InsufficientFundsForRent":{"account_index":0}}"#
        );
        assert!(!rent.budget_exceeded() && !rent.already_processed());
        assert!(error_detail(&json!("AlreadyProcessed")).already_processed());
    }

    #[test]
    fn sdk_errors_serialize_to_the_rpc_json() {
        use solana_transaction::{InstructionError, TransactionError};
        let e = TransactionError::InstructionError(3, InstructionError::Custom(6001));
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v, json!({"InstructionError": [3, {"Custom": 6001}]}));
        assert_eq!(error_detail(&v).custom, Some(6001));
        let v = serde_json::to_value(TransactionError::BlockhashNotFound).unwrap();
        assert!(error_detail(&v).blockhash_not_found());
    }
}
