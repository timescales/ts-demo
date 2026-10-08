//! Timelocked governance changes and their payload encoding, shared by
//! `ProposeChange` and the market's pending-change slot.

use timescales_core::Hash32;

use crate::program::{ClientError, Key, MAX_EXECUTORS};

/// Longest payload the market's pending slot holds.
pub(crate) const MAX_PAYLOAD: usize = 262;

/// A timelocked governance change. The kind byte is the variant order,
/// starting at 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GovernanceChange {
    SetRelay(Key),
    SetExecutors {
        keys: Vec<Key>,
        quorum: u8,
    },
    SetCommitteeDigest(Hash32),
    SetAdmin(Key),
    SetTimings {
        beacon_delay_slots: u16,
        exec_timeout_slots: u64,
        settle_timeout_slots: u64,
    },
    SetTimelock(u64),
}

/// A proposed change and the slot from which it may be applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingChange {
    pub eta_slot: u64,
    pub change: GovernanceChange,
}

impl GovernanceChange {
    pub const SET_RELAY: u8 = 1;
    pub const SET_EXECUTORS: u8 = 2;
    pub const SET_COMMITTEE_DIGEST: u8 = 3;
    pub const SET_ADMIN: u8 = 4;
    pub const SET_TIMINGS: u8 = 5;
    pub const SET_TIMELOCK: u8 = 6;

    pub fn kind(&self) -> u8 {
        match self {
            Self::SetRelay(_) => Self::SET_RELAY,
            Self::SetExecutors { .. } => Self::SET_EXECUTORS,
            Self::SetCommitteeDigest(_) => Self::SET_COMMITTEE_DIGEST,
            Self::SetAdmin(_) => Self::SET_ADMIN,
            Self::SetTimings { .. } => Self::SET_TIMINGS,
            Self::SetTimelock(_) => Self::SET_TIMELOCK,
        }
    }

    /// Relay, executor, committee and timing changes apply only while no
    /// batch is in flight. Once one is due, `CommitBatch` fails with
    /// `ChangeDue` until it is applied.
    pub fn between_batches(&self) -> bool {
        matches!(
            self,
            Self::SetRelay(_)
                | Self::SetExecutors { .. }
                | Self::SetCommitteeDigest(_)
                | Self::SetTimings { .. }
        )
    }

    /// The  payload: `relay32`, `n u8 || key32xn || quorum u8`, `digest32`,
    /// `admin32`, `beacon_delay u16 || exec_timeout u64 || settle_timeout u64`
    /// or `slots u64`.
    pub fn payload(&self) -> Result<Vec<u8>, ClientError> {
        let mut out = Vec::new();
        match self {
            Self::SetRelay(k) | Self::SetAdmin(k) => out.extend_from_slice(k),
            Self::SetCommitteeDigest(d) => out.extend_from_slice(d.as_bytes()),
            Self::SetExecutors { keys, quorum } => {
                if keys.len() > MAX_EXECUTORS {
                    return Err(ClientError::TooManyExecutors);
                }
                out.push(u8::try_from(keys.len()).map_err(|_| ClientError::TooManyExecutors)?);
                for k in keys {
                    out.extend_from_slice(k);
                }
                out.push(*quorum);
            }
            Self::SetTimings {
                beacon_delay_slots,
                exec_timeout_slots,
                settle_timeout_slots,
            } => {
                out.extend_from_slice(&beacon_delay_slots.to_le_bytes());
                out.extend_from_slice(&exec_timeout_slots.to_le_bytes());
                out.extend_from_slice(&settle_timeout_slots.to_le_bytes());
            }
            Self::SetTimelock(slots) => out.extend_from_slice(&slots.to_le_bytes()),
        }
        Ok(out)
    }

    /// Parses a payload of `kind`. The length must be exact. Only the
    /// encoding is checked here, not the bounds the program enforces.
    pub fn decode(kind: u8, payload: &[u8]) -> Result<Self, ClientError> {
        let key = |p: &[u8]| -> Result<Key, ClientError> {
            p.try_into().map_err(|_| ClientError::Malformed)
        };
        match kind {
            Self::SET_RELAY => Ok(Self::SetRelay(key(payload)?)),
            Self::SET_ADMIN => Ok(Self::SetAdmin(key(payload)?)),
            Self::SET_COMMITTEE_DIGEST => Ok(Self::SetCommitteeDigest(Hash32(key(payload)?))),
            Self::SET_EXECUTORS => {
                let (&n, rest) = payload.split_first().ok_or(ClientError::Malformed)?;
                let n = usize::from(n);
                if n > MAX_EXECUTORS || rest.len() != 32 * n + 1 {
                    return Err(ClientError::Malformed);
                }
                let (keys, quorum) = rest.split_at(32 * n);
                let (keys, _) = keys.as_chunks::<32>();
                Ok(Self::SetExecutors {
                    keys: keys.to_vec(),
                    quorum: quorum[0],
                })
            }
            Self::SET_TIMINGS => {
                let b: &[u8; 18] = payload.try_into().map_err(|_| ClientError::Malformed)?;
                let (delay, timeouts) = b.split_at(2);
                let (exec, settle) = timeouts.split_at(8);
                Ok(Self::SetTimings {
                    beacon_delay_slots: u16::from_le_bytes([delay[0], delay[1]]),
                    exec_timeout_slots: u64_le(exec)?,
                    settle_timeout_slots: u64_le(settle)?,
                })
            }
            Self::SET_TIMELOCK => Ok(Self::SetTimelock(u64_le(payload)?)),
            _ => Err(ClientError::Malformed),
        }
    }
}

fn u64_le(b: &[u8]) -> Result<u64, ClientError> {
    Ok(u64::from_le_bytes(
        b.try_into().map_err(|_| ClientError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn every_kind() -> Vec<GovernanceChange> {
        vec![
            GovernanceChange::SetRelay([1; 32]),
            GovernanceChange::SetExecutors {
                keys: (0..8u8).map(|i| [i + 10; 32]).collect(),
                quorum: 5,
            },
            GovernanceChange::SetExecutors {
                keys: vec![],
                quorum: 0,
            },
            GovernanceChange::SetCommitteeDigest(Hash32([3; 32])),
            GovernanceChange::SetAdmin([4; 32]),
            GovernanceChange::SetTimings {
                beacon_delay_slots: 0x0102,
                exec_timeout_slots: 0x0304,
                settle_timeout_slots: 0x0506,
            },
            GovernanceChange::SetTimelock(u64::MAX),
        ]
    }

    #[test]
    fn payloads_round_trip_and_fit_the_pending_slot() {
        for c in every_kind() {
            let p = c.payload().unwrap();
            assert!(p.len() <= MAX_PAYLOAD);
            assert_eq!(GovernanceChange::decode(c.kind(), &p).unwrap(), c);
            let mut long = p.clone();
            long.push(0);
            assert_eq!(
                GovernanceChange::decode(c.kind(), &long),
                Err(ClientError::Malformed)
            );
            if !p.is_empty() {
                assert_eq!(
                    GovernanceChange::decode(c.kind(), &p[..p.len() - 1]),
                    Err(ClientError::Malformed)
                );
            }
        }
    }

    #[test]
    fn executor_sets_are_bounded() {
        let nine = GovernanceChange::SetExecutors {
            keys: vec![[1; 32]; 9],
            quorum: 1,
        };
        assert_eq!(nine.payload(), Err(ClientError::TooManyExecutors));
        let mut p = vec![9u8];
        p.extend_from_slice(&[1u8; 32 * 9]);
        p.push(1);
        assert_eq!(
            GovernanceChange::decode(GovernanceChange::SET_EXECUTORS, &p),
            Err(ClientError::Malformed)
        );
    }

    #[test]
    fn unknown_kinds_are_malformed() {
        for kind in [0u8, 7, 255] {
            assert_eq!(
                GovernanceChange::decode(kind, &[0; 32]),
                Err(ClientError::Malformed)
            );
        }
    }

    #[test]
    fn between_batch_kinds() {
        let kinds: Vec<u8> = every_kind()
            .iter()
            .filter(|c| c.between_batches())
            .map(GovernanceChange::kind)
            .collect();
        assert_eq!(kinds, [1, 2, 2, 3, 5]);
    }
}
