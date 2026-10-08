//! Orders, fills and clearing results.

use crate::encoding::{Decode, DecodeError, Encode, Reader, put_u8};
use crate::ids::{OrderCommitment, TraderId};
use crate::market::{FlowMode, PriceBand};
use crate::units::{EpochId, Lots, MarketId, Tick};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Side {
    Buy = 0,
    Sell = 1,
}

/// Liquidity role. Only meaningful in dual-flow markets, where makers and
/// takers are cleared in separate books.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Role {
    Maker = 0,
    Taker = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum OrderKind {
    /// Executes only at or better than `limit`.
    Limit = 0,
    /// Executes at any price inside the batch's price band. The band is the
    /// only price protection a market order gets.
    Market = 1,
}

/// One of the independent call auctions run in each batch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum BookId {
    /// Single-book markets: all buys against all sells.
    Single = 0,
    /// Dual flow: maker asks against taker bids.
    MakerAskTakerBid = 1,
    /// Dual flow: maker bids against taker asks.
    MakerBidTakerAsk = 2,
}

impl BookId {
    pub const DUAL: [BookId; 2] = [BookId::MakerAskTakerBid, BookId::MakerBidTakerAsk];

    /// Book an order with this role and side participates in.
    pub fn route(flow: FlowMode, role: Role, side: Side) -> BookId {
        match flow {
            FlowMode::SingleBook => BookId::Single,
            FlowMode::DualFlow => match (role, side) {
                (Role::Maker, Side::Sell) | (Role::Taker, Side::Buy) => BookId::MakerAskTakerBid,
                (Role::Maker, Side::Buy) | (Role::Taker, Side::Sell) => BookId::MakerBidTakerAsk,
            },
        }
    }

    pub fn books(flow: FlowMode) -> &'static [BookId] {
        match flow {
            FlowMode::SingleBook => &[BookId::Single],
            FlowMode::DualFlow => &Self::DUAL,
        }
    }
}

/// Plaintext order. Only ever visible inside an executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Order {
    pub market: MarketId,
    pub trader: TraderId,
    /// Per-trader unique value. With `trader` it names the order.
    pub nonce: u64,
    pub side: Side,
    pub role: Role,
    pub kind: OrderKind,
    /// Limit tick. Must be zero for market orders so the encoding is canonical.
    pub limit: Tick,
    pub quantity: Lots,
    /// First batch the order may participate in.
    pub valid_from: EpochId,
    /// Last batch the order may participate in (inclusive).
    pub expires_at: EpochId,
}

impl Order {
    /// Limit used for matching: market buys accept any price, market sells
    /// accept zero. The band then caps both.
    pub fn effective_limit(&self) -> Tick {
        match (self.kind, self.side) {
            (OrderKind::Limit, _) => self.limit,
            (OrderKind::Market, Side::Buy) => Tick::MAX,
            (OrderKind::Market, Side::Sell) => Tick::ZERO,
        }
    }

    pub fn book(&self, flow: FlowMode) -> BookId {
        BookId::route(flow, self.role, self.side)
    }

    /// Band slot this order occupies, or `None` if it cannot trade anywhere
    /// in the band.
    pub fn slot(&self, band: &PriceBand) -> Option<u32> {
        band.slot(self.side, self.effective_limit())
    }

    pub fn is_live_at(&self, epoch: EpochId) -> bool {
        self.valid_from <= epoch && epoch <= self.expires_at
    }
}

/// An execution against one order at the uniform clearing price of its book.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Fill {
    pub commitment: OrderCommitment,
    pub trader: TraderId,
    pub book: BookId,
    pub side: Side,
    pub role: Role,
    pub quantity: Lots,
    pub tick: Tick,
}

/// Outcome of one book's call auction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClearingPrice {
    pub book: BookId,
    pub tick: Tick,
    /// Matched volume. Zero means the book did not trade. `tick` is still
    /// the deterministic rule's output so the receipt is total.
    pub volume: Lots,
}

impl Encode for Side {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for Side {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(Side::Buy),
            1 => Ok(Side::Sell),
            tag => Err(DecodeError::InvalidTag { ty: "Side", tag }),
        }
    }
}

impl Encode for Role {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for Role {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(Role::Maker),
            1 => Ok(Role::Taker),
            tag => Err(DecodeError::InvalidTag { ty: "Role", tag }),
        }
    }
}

impl Encode for OrderKind {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for OrderKind {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(OrderKind::Limit),
            1 => Ok(OrderKind::Market),
            tag => Err(DecodeError::InvalidTag {
                ty: "OrderKind",
                tag,
            }),
        }
    }
}

impl Encode for BookId {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, *self as u8);
    }
}

impl Decode for BookId {
    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8()? {
            0 => Ok(BookId::Single),
            1 => Ok(BookId::MakerAskTakerBid),
            2 => Ok(BookId::MakerBidTakerAsk),
            tag => Err(DecodeError::InvalidTag { ty: "BookId", tag }),
        }
    }
}

impl Encode for Order {
    fn encode(&self, out: &mut Vec<u8>) {
        self.market.encode(out);
        self.trader.encode(out);
        self.nonce.encode(out);
        self.side.encode(out);
        self.role.encode(out);
        self.kind.encode(out);
        self.limit.encode(out);
        self.quantity.encode(out);
        self.valid_from.encode(out);
        self.expires_at.encode(out);
    }
}

impl Decode for Order {
    const MIN_ENCODED_LEN: usize = Order::ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let order = Order {
            market: MarketId::decode(r)?,
            trader: TraderId::decode(r)?,
            nonce: r.u64()?,
            side: Side::decode(r)?,
            role: Role::decode(r)?,
            kind: OrderKind::decode(r)?,
            limit: Tick::decode(r)?,
            quantity: Lots::decode(r)?,
            valid_from: EpochId::decode(r)?,
            expires_at: EpochId::decode(r)?,
        };
        if order.kind == OrderKind::Market && order.limit != Tick::ZERO {
            return Err(DecodeError::InvalidValue("market order with nonzero limit"));
        }
        Ok(order)
    }
}

impl Order {
    /// Encoded size in bytes. Constant. Used to size fixed envelopes.
    pub const ENCODED_LEN: usize = 8 + 32 + 8 + 1 + 1 + 1 + 8 + 8 + 8 + 8;
}

impl Fill {
    pub const ENCODED_LEN: usize = 32 + 32 + 1 + 1 + 1 + 8 + 8;
}

impl Encode for Fill {
    fn encode(&self, out: &mut Vec<u8>) {
        self.commitment.encode(out);
        self.trader.encode(out);
        self.book.encode(out);
        self.side.encode(out);
        self.role.encode(out);
        self.quantity.encode(out);
        self.tick.encode(out);
    }
}

impl Decode for Fill {
    const MIN_ENCODED_LEN: usize = Fill::ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Fill {
            commitment: OrderCommitment::decode(r)?,
            trader: TraderId::decode(r)?,
            book: BookId::decode(r)?,
            side: Side::decode(r)?,
            role: Role::decode(r)?,
            quantity: Lots::decode(r)?,
            tick: Tick::decode(r)?,
        })
    }
}

impl ClearingPrice {
    pub const ENCODED_LEN: usize = 1 + 8 + 8;
}

impl Encode for ClearingPrice {
    fn encode(&self, out: &mut Vec<u8>) {
        self.book.encode(out);
        self.tick.encode(out);
        self.volume.encode(out);
    }
}

impl Decode for ClearingPrice {
    const MIN_ENCODED_LEN: usize = ClearingPrice::ENCODED_LEN;

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(ClearingPrice {
            book: BookId::decode(r)?,
            tick: Tick::decode(r)?,
            volume: Lots::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Order {
        Order {
            market: MarketId(1),
            trader: TraderId([9; 32]),
            nonce: 42,
            side: Side::Buy,
            role: Role::Taker,
            kind: OrderKind::Limit,
            limit: Tick(1000),
            quantity: Lots(5),
            valid_from: EpochId(3),
            expires_at: EpochId(4),
        }
    }

    #[test]
    fn order_roundtrip_and_len() {
        let o = sample();
        let b = o.to_bytes();
        assert_eq!(b.len(), Order::ENCODED_LEN);
        assert_eq!(Order::decode_exact(&b), Ok(o));
    }

    #[test]
    fn fixed_lengths_match_the_encoding() {
        let f = Fill {
            commitment: OrderCommitment([1; 32]),
            trader: TraderId([2; 32]),
            book: BookId::Single,
            side: Side::Sell,
            role: Role::Maker,
            quantity: Lots(3),
            tick: Tick(4),
        };
        assert_eq!(f.to_bytes().len(), Fill::ENCODED_LEN);
        assert_eq!(Fill::decode_exact(&f.to_bytes()), Ok(f));
        let c = ClearingPrice {
            book: BookId::Single,
            tick: Tick(9),
            volume: Lots(1),
        };
        assert_eq!(c.to_bytes().len(), ClearingPrice::ENCODED_LEN);
        assert_eq!(<Order as Decode>::MIN_ENCODED_LEN, Order::ENCODED_LEN);
        assert_eq!(<Fill as Decode>::MIN_ENCODED_LEN, Fill::ENCODED_LEN);
        assert_eq!(
            <ClearingPrice as Decode>::MIN_ENCODED_LEN,
            ClearingPrice::ENCODED_LEN
        );
    }

    #[test]
    fn market_order_requires_zero_limit() {
        let mut o = sample();
        o.kind = OrderKind::Market;
        assert!(Order::decode_exact(&o.to_bytes()).is_err());
        o.limit = Tick::ZERO;
        assert!(Order::decode_exact(&o.to_bytes()).is_ok());
    }

    #[test]
    fn dual_flow_routing_pairs_makers_with_takers() {
        use BookId::*;
        let f = FlowMode::DualFlow;
        assert_eq!(BookId::route(f, Role::Maker, Side::Sell), MakerAskTakerBid);
        assert_eq!(BookId::route(f, Role::Taker, Side::Buy), MakerAskTakerBid);
        assert_eq!(BookId::route(f, Role::Maker, Side::Buy), MakerBidTakerAsk);
        assert_eq!(BookId::route(f, Role::Taker, Side::Sell), MakerBidTakerAsk);
        assert_eq!(
            BookId::route(FlowMode::SingleBook, Role::Maker, Side::Sell),
            Single
        );
    }
}
