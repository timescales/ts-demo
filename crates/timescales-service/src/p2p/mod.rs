//! Message transport for simulations.
//!
//! Components that talk to each other in one process (relay replicas in the
//! demo and the tests) do so through [`Endpoint`]s on a [`Network`]. The
//! in-memory network delivers through Tokio channels and can drop, delay and
//! partition traffic deterministically (seeded), which the partition
//! and failure tests rely on.
//!
//! Nothing here authenticates a peer: any holder of the [`Network`] can
//! register an unused node id and send under it, and messages carry no proof
//! of origin. The relay uses this transport only behind its
//! `simulation` feature (gossip between replicas). The services never
//! replicate a relay over it, and their internal links are signed envelopes
//! over mutual TLS instead.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::cast_possible_truncation))]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use thiserror::Error;
use tokio::runtime::Handle;
use tokio::sync::mpsc;

pub type NodeId = u32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub from: NodeId,
    pub to: NodeId,
    pub topic: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum P2pError {
    #[error("unknown node {0}")]
    UnknownNode(NodeId),
    #[error("node {0} already has an endpoint")]
    DuplicateNode(NodeId),
    #[error("message exceeds {0} bytes")]
    TooLarge(usize),
    #[error("delayed delivery needs a Tokio runtime")]
    NoRuntime,
}

/// Upper bound on a single message. Bounds memory per queued message.
pub const MAX_MESSAGE: usize = 1 << 20;
/// Per-endpoint queue bound. Senders see backpressure beyond it.
pub const QUEUE: usize = 4096;

#[derive(Clone, Debug, Default)]
pub struct Faults {
    /// Nodes in different groups cannot reach each other. Nodes not listed
    /// in any group can reach everyone.
    pub partitions: Vec<BTreeSet<NodeId>>,
    /// Probability in parts per million that a message is dropped.
    pub drop_ppm: u32,
    pub delay: Duration,
    /// Nodes that receive nothing and whose sends vanish.
    pub crashed: BTreeSet<NodeId>,
}

impl Faults {
    fn reachable(&self, a: NodeId, b: NodeId) -> bool {
        if self.crashed.contains(&a) || self.crashed.contains(&b) {
            return false;
        }
        let ga = self.partitions.iter().position(|g| g.contains(&a));
        let gb = self.partitions.iter().position(|g| g.contains(&b));
        match (ga, gb) {
            (Some(x), Some(y)) => x == y,
            _ => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NetStats {
    pub sent: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub bytes: u64,
}

struct Inner {
    nodes: BTreeMap<NodeId, mpsc::Sender<Message>>,
    faults: Faults,
    rng: ChaCha20Rng,
    stats: NetStats,
}

#[derive(Clone)]
pub struct Network {
    inner: Arc<Mutex<Inner>>,
}

impl core::fmt::Debug for Network {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Network")
            .field("stats", &self.stats())
            .finish()
    }
}

impl Network {
    pub fn new(seed: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                nodes: BTreeMap::new(),
                faults: Faults::default(),
                rng: ChaCha20Rng::seed_from_u64(seed),
                stats: NetStats::default(),
            })),
        }
    }

    /// Every critical section below is a single map update, counter bump or
    /// RNG draw, so a panic elsewhere cannot leave `Inner` half-written. A
    /// poisoned lock is safe to keep using. Dropping writes or misreporting
    /// errors on poisoning would be worse.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Register node `id`. Ids are unique while their endpoint is alive.
    /// Dropping the endpoint frees the id.
    pub fn endpoint(&self, id: NodeId) -> Result<Endpoint, P2pError> {
        let mut g = self.lock();
        if g.nodes.contains_key(&id) {
            return Err(P2pError::DuplicateNode(id));
        }
        let (tx, rx) = mpsc::channel(QUEUE);
        g.nodes.insert(id, tx);
        Ok(Endpoint {
            id,
            net: self.clone(),
            rx,
        })
    }

    pub fn set_faults(&self, f: Faults) {
        self.lock().faults = f;
    }

    pub fn partition(&self, groups: Vec<BTreeSet<NodeId>>) {
        self.lock().faults.partitions = groups;
    }

    pub fn heal(&self) {
        let mut g = self.lock();
        g.faults.partitions.clear();
        g.faults.crashed.clear();
    }

    pub fn crash(&self, id: NodeId) {
        self.lock().faults.crashed.insert(id);
    }

    pub fn stats(&self) -> NetStats {
        self.lock().stats
    }

    pub fn nodes(&self) -> Vec<NodeId> {
        self.lock().nodes.keys().copied().collect()
    }

    fn route(&self, msg: Message) -> Result<(), P2pError> {
        if msg.payload.len() > MAX_MESSAGE {
            return Err(P2pError::TooLarge(MAX_MESSAGE));
        }
        let (tx, delay, runtime) = {
            let mut g = self.lock();
            let tx = g
                .nodes
                .get(&msg.to)
                .cloned()
                .ok_or(P2pError::UnknownNode(msg.to))?;
            let delay = g.faults.delay;
            // Checked before anything is counted, so a refused send leaves
            // the statistics alone.
            let runtime = if delay.is_zero() {
                None
            } else {
                Some(Handle::try_current().map_err(|_| P2pError::NoRuntime)?)
            };
            g.stats.sent = g.stats.sent.saturating_add(1);
            g.stats.bytes = g.stats.bytes.saturating_add(msg.payload.len() as u64);
            let drop_ppm = g.faults.drop_ppm;
            let dropped = !g.faults.reachable(msg.from, msg.to)
                || (drop_ppm > 0 && g.rng.gen_range(0..1_000_000) < drop_ppm);
            if dropped {
                g.stats.dropped = g.stats.dropped.saturating_add(1);
                return Ok(());
            }
            g.stats.delivered = g.stats.delivered.saturating_add(1);
            (tx, delay, runtime)
        };
        match runtime {
            // A full queue drops rather than blocking the sender. The
            // receiver is overloaded and the protocol must cope with loss.
            None => {
                let _ = tx.try_send(msg);
            }
            Some(runtime) => {
                runtime.spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = tx.send(msg).await;
                });
            }
        }
        Ok(())
    }

    fn unregister(&self, id: NodeId) {
        self.lock().nodes.remove(&id);
    }
}

#[derive(Debug)]
pub struct Endpoint {
    id: NodeId,
    net: Network,
    rx: mpsc::Receiver<Message>,
}

impl Endpoint {
    pub fn id(&self) -> NodeId {
        self.id
    }

    pub fn send(&self, to: NodeId, topic: u16, payload: Vec<u8>) -> Result<(), P2pError> {
        self.net.route(Message {
            from: self.id,
            to,
            topic,
            payload,
        })
    }

    /// Send to every other node currently registered.
    pub fn broadcast(&self, topic: u16, payload: &[u8]) -> Result<(), P2pError> {
        for to in self.net.nodes() {
            if to != self.id {
                self.send(to, topic, payload.to_vec())?;
            }
        }
        Ok(())
    }

    /// Next message, or `None` once every sender is gone. Cancellation
    /// safe: dropping the future loses no message.
    pub async fn recv(&mut self) -> Option<Message> {
        self.rx.recv().await
    }

    pub fn try_recv(&mut self) -> Option<Message> {
        self.rx.try_recv().ok()
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.net.unregister(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delivers_and_partitions() {
        let net = Network::new(1);
        let a = net.endpoint(1).unwrap();
        let mut b = net.endpoint(2).unwrap();
        let mut c = net.endpoint(3).unwrap();
        a.broadcast(7, b"hi").unwrap();
        assert_eq!(b.recv().await.unwrap().payload, b"hi");
        assert_eq!(c.recv().await.unwrap().payload, b"hi");
        net.partition(vec![[1].into(), [2, 3].into()]);
        a.send(2, 7, b"lost".to_vec()).unwrap();
        assert!(b.try_recv().is_none());
        net.heal();
        a.send(2, 7, b"back".to_vec()).unwrap();
        assert_eq!(b.recv().await.unwrap().payload, b"back");
        assert_eq!(net.stats().dropped, 1);
    }

    #[tokio::test]
    async fn drops_are_seeded() {
        let run = |seed| async move {
            let net = Network::new(seed);
            let a = net.endpoint(1).unwrap();
            let mut b = net.endpoint(2).unwrap();
            net.set_faults(Faults {
                drop_ppm: 500_000,
                ..Faults::default()
            });
            for i in 0..100u8 {
                a.send(2, 0, vec![i]).unwrap();
            }
            let mut got = Vec::new();
            while let Some(m) = b.try_recv() {
                got.push(m.payload[0]);
            }
            got
        };
        assert_eq!(run(3).await, run(3).await);
        assert_ne!(run(3).await.len(), 100);
    }

    #[tokio::test(start_paused = true)]
    async fn delay_applies() {
        let net = Network::new(1);
        let a = net.endpoint(1).unwrap();
        let mut b = net.endpoint(2).unwrap();
        net.set_faults(Faults {
            delay: Duration::from_millis(50),
            ..Faults::default()
        });
        a.send(2, 0, vec![1]).unwrap();
        assert!(b.try_recv().is_none());
        tokio::time::advance(Duration::from_millis(60)).await;
        assert!(b.recv().await.is_some());
    }

    #[test]
    fn oversized_message_refused() {
        let net = Network::new(1);
        let a = net.endpoint(1).unwrap();
        let _b = net.endpoint(2).unwrap();
        assert_eq!(
            a.send(2, 0, vec![0; MAX_MESSAGE + 1]),
            Err(P2pError::TooLarge(MAX_MESSAGE))
        );
    }
}
