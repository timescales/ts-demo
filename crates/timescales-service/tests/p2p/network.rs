//! Endpoint registration and delivery edge cases.

#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use timescales_service::p2p::{Faults, MAX_MESSAGE, NetStats, Network, P2pError};

#[test]
fn node_ids_are_unique_while_their_endpoint_lives() {
    let net = Network::new(1);
    let a = net.endpoint(1).unwrap();
    assert_eq!(net.endpoint(1).unwrap_err(), P2pError::DuplicateNode(1));
    assert_eq!(net.nodes(), vec![1]);

    drop(a);
    assert!(net.nodes().is_empty());
    let mut again = net.endpoint(1).unwrap();
    let b = net.endpoint(2).unwrap();
    b.send(1, 3, vec![7]).unwrap();
    assert_eq!(again.try_recv().unwrap().payload, vec![7]);
}

#[test]
fn sending_to_a_dropped_endpoint_fails() {
    let net = Network::new(1);
    let a = net.endpoint(1).unwrap();
    drop(net.endpoint(2).unwrap());
    assert_eq!(a.send(2, 0, vec![1]), Err(P2pError::UnknownNode(2)));
    // Nobody else is registered, so a broadcast reaches no one.
    assert_eq!(a.broadcast(0, b"x"), Ok(()));
    assert_eq!(net.stats(), NetStats::default());
}

#[test]
fn delayed_delivery_without_a_runtime_is_an_error() {
    let net = Network::new(1);
    let a = net.endpoint(1).unwrap();
    let mut b = net.endpoint(2).unwrap();
    net.set_faults(Faults {
        delay: Duration::from_millis(5),
        ..Faults::default()
    });
    assert_eq!(a.send(2, 0, vec![1]), Err(P2pError::NoRuntime));
    assert_eq!(net.stats(), NetStats::default(), "nothing counted");
    assert!(b.try_recv().is_none());

    net.set_faults(Faults::default());
    a.send(2, 0, vec![2]).unwrap();
    assert_eq!(b.try_recv().unwrap().payload, vec![2]);
}

#[test]
fn crashed_nodes_neither_send_nor_receive() {
    let net = Network::new(1);
    let a = net.endpoint(1).unwrap();
    let mut b = net.endpoint(2).unwrap();
    net.crash(2);
    a.send(2, 0, vec![1]).unwrap();
    b.send(1, 0, vec![1]).unwrap();
    assert!(b.try_recv().is_none());
    let s = net.stats();
    assert_eq!((s.sent, s.delivered, s.dropped, s.bytes), (2, 0, 2, 2));

    net.heal();
    a.send(2, 0, vec![9]).unwrap();
    assert_eq!(b.try_recv().unwrap().payload, vec![9]);
}

/// Every `P2pError` variant comes out of a real path. The match has no
/// wildcard arm, so a new variant does not compile until it is named here,
/// and the comparison then fails until a case produces it.
#[test]
fn every_error_variant_is_produced() {
    fn variant(e: &P2pError) -> &'static str {
        match e {
            P2pError::UnknownNode(_) => "UnknownNode",
            P2pError::DuplicateNode(_) => "DuplicateNode",
            P2pError::TooLarge(_) => "TooLarge",
            P2pError::NoRuntime => "NoRuntime",
        }
    }
    let net = Network::new(1);
    let a = net.endpoint(1).unwrap();
    let mut errors = vec![
        a.send(9, 0, vec![1]).unwrap_err(),
        net.endpoint(1).unwrap_err(),
        a.send(1, 0, vec![0; MAX_MESSAGE + 1]).unwrap_err(),
    ];
    net.set_faults(Faults {
        delay: Duration::from_millis(1),
        ..Faults::default()
    });
    errors.push(a.send(1, 0, vec![1]).unwrap_err());

    let produced: BTreeSet<&str> = errors.iter().map(variant).collect();
    let all = ["UnknownNode", "DuplicateNode", "TooLarge", "NoRuntime"];
    assert_eq!(produced, all.into_iter().collect::<BTreeSet<_>>());
}
