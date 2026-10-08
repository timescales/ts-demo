//! Unsigned legacy transactions for a multisig to sign (`--unsigned`).
//!
//! The admin key of a production market is a multisig, so governance
//! commands do not sign: they print the transaction with empty signature
//! slots, base64-encoded, plus the message bytes the signers sign. The
//! message is compiled the way `solana_message::Message::new` compiles one:
//! the fee payer first, then writable signers, read-only signers, writable
//! and read-only non-signers, each group in ascending key order, programs
//! as read-only non-signers.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use base64::Engine;
use serde_json::{Value, json};
use timescales_chain::program::Ix;

use crate::util::{Key, b58};

#[derive(Clone, Copy, Debug, Default)]
struct KeyMeta {
    signer: bool,
    writable: bool,
}

/// A compiled legacy message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Message {
    pub(crate) num_required_signatures: u8,
    pub(crate) num_readonly_signed: u8,
    pub(crate) num_readonly_unsigned: u8,
    pub(crate) keys: Vec<Key>,
    pub(crate) blockhash: [u8; 32],
    /// `(program index, account indices, data)`.
    pub(crate) instructions: Vec<(u8, Vec<u8>, Vec<u8>)>,
}

pub(crate) fn compile(ixs: &[Ix], payer: &Key, blockhash: &[u8; 32]) -> Result<Message> {
    let mut metas: BTreeMap<Key, KeyMeta> = BTreeMap::new();
    for ix in ixs {
        metas.entry(ix.program).or_default();
        for m in &ix.accounts {
            let e = metas.entry(m.key).or_default();
            e.signer |= m.signer;
            e.writable |= m.writable;
        }
    }
    metas.remove(payer);
    let group = |signer: bool, writable: bool| -> Vec<Key> {
        metas
            .iter()
            .filter(|(_, m)| m.signer == signer && m.writable == writable)
            .map(|(k, _)| *k)
            .collect()
    };
    let writable_signers = group(true, true);
    let readonly_signers = group(true, false);
    let writable = group(false, true);
    let readonly = group(false, false);
    let count = |n: usize| u8::try_from(n).map_err(|_| anyhow::anyhow!("too many accounts"));
    let num_required_signatures = count(1 + writable_signers.len() + readonly_signers.len())?;
    let num_readonly_signed = count(readonly_signers.len())?;
    let num_readonly_unsigned = count(readonly.len())?;
    let mut keys = vec![*payer];
    keys.extend(writable_signers);
    keys.extend(readonly_signers);
    keys.extend(writable);
    keys.extend(readonly);
    if keys.len() > 256 {
        bail!("too many accounts for one transaction");
    }
    let index = |k: &Key| -> Result<u8> {
        let i = keys
            .iter()
            .position(|x| x == k)
            .ok_or_else(|| anyhow::anyhow!("account missing from the key list"))?;
        Ok(u8::try_from(i)?)
    };
    let instructions = ixs
        .iter()
        .map(|ix| {
            Ok((
                index(&ix.program)?,
                ix.accounts
                    .iter()
                    .map(|m| index(&m.key))
                    .collect::<Result<_>>()?,
                ix.data.clone(),
            ))
        })
        .collect::<Result<_>>()?;
    Ok(Message {
        num_required_signatures,
        num_readonly_signed,
        num_readonly_unsigned,
        keys,
        blockhash: *blockhash,
        instructions,
    })
}

/// Solana's compact-u16 length prefix.
fn put_short_len(out: &mut Vec<u8>, mut n: usize) {
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

impl Message {
    /// The bytes every signer signs.
    pub(crate) fn serialize(&self) -> Vec<u8> {
        let mut out = vec![
            self.num_required_signatures,
            self.num_readonly_signed,
            self.num_readonly_unsigned,
        ];
        put_short_len(&mut out, self.keys.len());
        for k in &self.keys {
            out.extend_from_slice(k);
        }
        out.extend_from_slice(&self.blockhash);
        put_short_len(&mut out, self.instructions.len());
        for (program, accounts, data) in &self.instructions {
            out.push(*program);
            put_short_len(&mut out, accounts.len());
            out.extend_from_slice(accounts);
            put_short_len(&mut out, data.len());
            out.extend_from_slice(data);
        }
        out
    }

    pub(crate) fn signers(&self) -> &[Key] {
        &self.keys[..usize::from(self.num_required_signatures)]
    }

    /// The transaction with all-zero signatures.
    pub(crate) fn unsigned_transaction(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_short_len(&mut out, usize::from(self.num_required_signatures));
        for _ in 0..self.num_required_signatures {
            out.extend_from_slice(&[0u8; 64]);
        }
        out.extend_from_slice(&self.serialize());
        out
    }
}

/// What `--unsigned` prints: the transaction, its message and the signers
/// it needs, plus a readable form of each instruction.
pub(crate) fn unsigned_json(
    what: &str,
    ixs: &[Ix],
    payer: &Key,
    blockhash: &[u8; 32],
) -> Result<Value> {
    let message = compile(ixs, payer, blockhash)?;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    Ok(json!({
        "action": what,
        "transaction_base64": b64(&message.unsigned_transaction()),
        "message_base64": b64(&message.serialize()),
        "recent_blockhash": b58(blockhash),
        "fee_payer": b58(payer),
        "signers": message.signers().iter().map(b58).collect::<Vec<_>>(),
        "instructions": ixs.iter().map(|ix| json!({
            "program": b58(&ix.program),
            "accounts": ix.accounts.iter().map(|m| json!({
                "key": b58(&m.key), "signer": m.signer, "writable": m.writable,
            })).collect::<Vec<_>>(),
            "data_hex": hex::encode(&ix.data),
        })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use timescales_chain::program::Meta;

    use super::*;

    #[test]
    fn orders_accounts_like_the_solana_compiler() {
        let program = [9u8; 32];
        let ix = Ix {
            program,
            accounts: vec![
                Meta::r([5; 32], false),
                Meta::w([4; 32], false),
                Meta::r([3; 32], true),
                Meta::w([2; 32], true),
                Meta::r([1; 32], true),
            ],
            data: vec![1, 2, 3],
        };
        let payer = [8u8; 32];
        let m = compile(&[ix], &payer, &[7; 32]).unwrap();
        assert_eq!(
            m.keys,
            vec![payer, [2; 32], [1; 32], [3; 32], [4; 32], [5; 32], program]
        );
        assert_eq!(
            (
                m.num_required_signatures,
                m.num_readonly_signed,
                m.num_readonly_unsigned
            ),
            (4, 2, 2)
        );
        assert_eq!(
            m.instructions,
            vec![(6, vec![5, 4, 3, 1, 2], vec![1, 2, 3])]
        );
        assert_eq!(m.signers(), &[payer, [2; 32], [1; 32], [3; 32]]);
    }

    #[test]
    fn a_payer_named_in_an_instruction_is_listed_once() {
        let payer = [1u8; 32];
        let ix = Ix {
            program: [2; 32],
            accounts: vec![Meta::r(payer, true), Meta::w([3; 32], false)],
            data: vec![],
        };
        let m = compile(&[ix], &payer, &[0; 32]).unwrap();
        assert_eq!(m.keys, vec![payer, [3; 32], [2; 32]]);
        assert_eq!(m.num_required_signatures, 1);
    }

    #[test]
    fn serializes_the_legacy_wire_format() {
        let ix = Ix {
            program: [2; 32],
            accounts: vec![Meta::w([3; 32], false)],
            data: vec![0xaa; 130],
        };
        let m = compile(&[ix], &[1; 32], &[4; 32]).unwrap();
        let bytes = m.serialize();
        assert_eq!(&bytes[..4], &[1, 0, 1, 3]);
        assert_eq!(&bytes[4..36], &[1; 32]);
        let tail = &bytes[4 + 96 + 32..];
        // One instruction: program 2, one account (index 1), 130 data
        // bytes, whose length takes two compact-u16 bytes.
        assert_eq!(&tail[..6], &[1, 2, 1, 1, 0x82, 0x01]);
        assert_eq!(tail.len(), 6 + 130);
        let tx = m.unsigned_transaction();
        assert_eq!(tx[0], 1);
        assert_eq!(&tx[1..65], &[0; 64]);
        assert_eq!(&tx[65..], &bytes[..]);
    }
}
