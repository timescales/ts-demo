//! Band-indexed encoding of an order as a field vector.
//!
//! ```text
//! [ u_(g, j) for g in 0..4, j in 0..=K ]  [ b_0.. b_(B-1) ]
//! ```
//!
//! * `g` is the (role, side) group: maker-buy, maker-sell, taker-buy,
//!   taker-sell.
//! * `j < K` is the band slot of the order's limit. `j = K` means "cannot
//!   trade in this band".
//! * `u` is one-hot over all `4(K+1)` positions.
//! * `b_l` are the bits of the quantity (`B = max_order_lots_log2`).
//!
//! With this encoding, everything the auction needs from a single order is
//! a *public* linear function of its vector: the side, role and book, the
//! limit's eligibility at any price, the collateral reservation per lot,
//! and the quantity. The only multiplications are by the quantity. That is
//! what makes the MPC auction `O(nK)` multiplications instead of a sort.
//!
//! The band must be known when the trader encodes, so in Timescales the band is
//! fixed when the epoch opens.

use crate::ExecutorError;
use rand_core::{CryptoRng, RngCore};
use timescales_core::identity::TraderKey;
use timescales_core::intent::{FieldBytes, MaskedBody, MaskedIntent, MaskedPlace};
use timescales_core::{BookId, EpochId, FlowMode, Order, OrderCommitment, PriceBand, Role, Side};

use crate::mpc::field::Fp;

pub const GROUPS: [(Role, Side); 4] = [
    (Role::Maker, Side::Buy),
    (Role::Maker, Side::Sell),
    (Role::Taker, Side::Buy),
    (Role::Taker, Side::Sell),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    /// Band ticks `K`.
    pub ticks: u32,
    /// Quantity bits `B`.
    pub qty_bits: u32,
}

impl Layout {
    pub fn new(band: &PriceBand, qty_bits: u8) -> Self {
        Self {
            ticks: band.ticks(),
            qty_bits: u32::from(qty_bits),
        }
    }

    pub fn stride(&self) -> usize {
        self.ticks as usize + 1
    }

    pub fn onehot_len(&self) -> usize {
        4 * self.stride()
    }

    pub fn len(&self) -> usize {
        self.onehot_len() + self.qty_bits as usize
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Position of `(group, slot)`. `None` is the "cannot trade" column.
    pub fn pos(&self, group: usize, slot: Option<u32>) -> usize {
        group * self.stride() + slot.map_or(self.ticks as usize, |s| s as usize)
    }

    pub fn bit_pos(&self, l: u32) -> usize {
        self.onehot_len() + l as usize
    }

    pub fn group_of(role: Role, side: Side) -> usize {
        GROUPS.iter().position(|g| *g == (role, side)).unwrap_or(0)
    }

    /// Groups whose orders sit on `side` of `book`.
    pub fn groups_for(flow: FlowMode, book: BookId, side: Side) -> Vec<usize> {
        (0..4)
            .filter(|&g| GROUPS[g].1 == side && BookId::route(flow, GROUPS[g].0, side) == book)
            .collect()
    }

    /// Plaintext vector for `order` with `remaining` quantity encoding.
    pub fn encode(&self, order: &Order, band: &PriceBand) -> Vec<Fp> {
        let mut x = vec![Fp::ZERO; self.len()];
        x[self.pos(Self::group_of(order.role, order.side), order.slot(band))] = Fp::ONE;
        for l in 0..self.qty_bits {
            if (order.quantity.0 >> l) & 1 == 1 {
                x[self.bit_pos(l)] = Fp::ONE;
            }
        }
        x
    }
}

/// Mask source as seen by a trader (in a deployment: a request to the
/// committee over an authenticated channel).
pub trait MaskSource {
    /// A fresh mask block of `len` values for `owner`'s order in `epoch`.
    fn masks(
        &mut self,
        owner: timescales_core::TraderId,
        epoch: EpochId,
        len: usize,
    ) -> Result<(u64, Vec<Fp>), ExecutorError>;
}

/// Trader side: encode, mask and sign a placement.
pub fn try_mask_order<M: MaskSource>(
    masks: &mut M,
    key: &TraderKey,
    order: &Order,
    commitment: OrderCommitment,
    band: &PriceBand,
    layout: &Layout,
    epoch: EpochId,
) -> Result<MaskedIntent, ExecutorError> {
    let x = layout.encode(order, band);
    let (offset, r) = masks.masks(order.trader, epoch, x.len())?;
    if r.len() != x.len() {
        return Err(ExecutorError::Unavailable(
            "mask source returned a block of another length".into(),
        ));
    }
    let values = x
        .iter()
        .zip(&r)
        .map(|(xi, ri)| FieldBytes((*xi - *ri).value()))
        .collect();
    let body = MaskedBody::Place(MaskedPlace {
        trader: order.trader,
        nonce: order.nonce,
        valid_from: order.valid_from,
        expires_at: order.expires_at,
        mask_offset: offset,
        values,
    });
    Ok(MaskedIntent::sign(
        key,
        order.market,
        epoch,
        commitment,
        body,
    ))
}

/// [`try_mask_order`] for callers that cannot handle a refused mask request.
///
/// # Panics
///
/// If the mask source refuses the request.
pub fn mask_order<M: MaskSource>(
    masks: &mut M,
    key: &TraderKey,
    order: &Order,
    commitment: OrderCommitment,
    band: &PriceBand,
    layout: &Layout,
    epoch: EpochId,
) -> MaskedIntent {
    match try_mask_order(masks, key, order, commitment, band, layout, epoch) {
        Ok(m) => m,
        Err(e) => panic!("mask request refused: {e}"),
    }
}

/// Fresh salt helper kept here so client code does not need the core crypto.
pub fn random_bytes<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use timescales_core::*;

    #[test]
    fn layout_positions_are_disjoint_and_dense() {
        let band = PriceBand {
            lo: Tick(10),
            hi: Tick(14),
            reference: Tick(12),
        };
        let l = Layout::new(&band, 8);
        assert_eq!(l.len(), 4 * 6 + 8);
        let mut seen = std::collections::BTreeSet::new();
        for g in 0..4 {
            for s in (0..5).map(Some).chain([None]) {
                assert!(seen.insert(l.pos(g, s)));
            }
        }
        assert_eq!(seen.len(), l.onehot_len());
    }

    #[test]
    fn groups_route_like_books() {
        let a = Layout::groups_for(FlowMode::DualFlow, BookId::MakerAskTakerBid, Side::Buy);
        assert_eq!(a, vec![Layout::group_of(Role::Taker, Side::Buy)]);
        let s = Layout::groups_for(FlowMode::SingleBook, BookId::Single, Side::Sell);
        assert_eq!(s.len(), 2);
    }
}
