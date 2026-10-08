/**
 * Domain-separation tags (`crates/timescales-core/src/crypto/hash.rs`): the 23 v1
 * tags and the 17 added for production. Never reuse a tag for a new
 * purpose. `SEAL_KDF` is a raw HKDF info prefix, not an `H` tag.
 */
export const DOMAIN = Object.freeze({
  ORDER_COMMITMENT: 'timescales/v1/order-commitment',
  ENVELOPE_COMMITMENT: 'timescales/v1/envelope-commitment',
  INTENT_SIGNATURE: 'timescales/v1/intent-signature',
  PRIORITY_KEY: 'timescales/v1/priority-key',
  BATCH_SEED: 'timescales/v1/batch-seed',
  BATCH_HEADER: 'timescales/v1/batch-header',
  MERKLE_LEAF: 'timescales/v1/merkle-leaf',
  MERKLE_NODE: 'timescales/v1/merkle-node',
  RECEIPT: 'timescales/v1/execution-receipt',
  OUTCOME: 'timescales/v1/execution-outcome',
  TRACE: 'timescales/v1/execution-trace',
  SETTLEMENT: 'timescales/v1/settlement',
  ATTESTATION_REPORT: 'timescales/v1/attestation-report',
  REPORT_DATA: 'timescales/v1/report-data',
  KEY_RELEASE: 'timescales/v1/key-release',
  MEASUREMENT: 'timescales/v1/measurement',
  PRICE_COMMITMENT: 'timescales/v1/price-commitment',
  TLS_ATTESTATION: 'timescales/v1/tls-attestation',
  TLS_CHUNK: 'timescales/v1/tls-chunk',
  PROOF: 'timescales/v1/execution-proof',
  RELAY_SUBMISSION: 'timescales/v1/relay-submission',
  SEAL_KDF: 'timescales/v1/seal',
  MARKET_PARAMS: 'timescales/v1/market-params',
  RPC_ENVELOPE: 'timescales/v1/rpc-envelope',
  COMMITTEE: 'timescales/v1/krc-committee',
  EPOCH_KEY: 'timescales/v1/epoch-key',
  KRC_SHARE: 'timescales/v1/krc-share',
  REPORT_DATA_V2: 'timescales/v1/report-data-v2',
  EXECUTOR_REGISTRATION: 'timescales/v1/executor-registration',
  EPOCH_TERMS: 'timescales/v1/epoch-terms',
  EPOCH_ANNOUNCEMENT: 'timescales/v1/epoch-announcement',
  RECEIPT_COSIGN: 'timescales/v1/receipt-cosign',
  SESSION: 'timescales/v1/session',
  EPOCH_SEED: 'timescales/v1/epoch-seed',
  EPOCH_BINDING: 'timescales/v1/epoch-binding',
  MARKET_ID: 'timescales/v1/market-id',
  RELEASE_POLICY: 'timescales/v1/release-policy',
  EPOCH_KEY_ACK: 'timescales/v1/epoch-key-ack',
  RELAY_REFUSAL: 'timescales/v1/relay-refusal',
  SESSION_NONCE: 'timescales/v1/session-nonce',
} as const);

export type DomainName = keyof typeof DOMAIN;
