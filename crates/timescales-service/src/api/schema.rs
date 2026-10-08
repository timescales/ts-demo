//! The JSON Schema of the public API (draft 2020-12).
//!
//! Every request, response, stream frame, problem and problem detail is a
//! definition under `$defs`, named after its type, next to the encodings
//! (`U64`, `I64`, `Num`, `TimeMs`, `Hex32`, `Hex64`, `Hex`, `B58`, `B64`).
//! The schema describes what the node sends: an optional field (`x?`) may be
//! absent, a nullable one (`x: T | null`) is always present.

use schemars::generate::SchemaSettings;
use serde_json::{Map, Value, json};

use crate::api::{
    Artifacts, B58, B58Sig, B64, BadRequestDetails, BatchFullDetails, ClientMessage,
    CreateSessionRequest, CurrentEpoch, DecodeFailedDetails, DuplicateCommitmentDetails,
    EpochClosedDetails, EpochDetail, EpochKey, EpochSummary, ErrorCode, ExecutorRegistration, Hex,
    Hex32, Hex64, I64, Info, IntakePausedDetails, Items, Leaves, MarketDetail, MarketSummary,
    NotYetAvailableDetails, Page, ParkedItem, PolicyStatementView, Problem, QuotaExceededDetails,
    RateLimitedDetails, RetractRequest, RetractResult, ServerFrame, Session, SessionNonce, Status,
    StreamEvent, SubmitBatchRequest, SubmitItemResult, SubmitRequest, SubmitResult, TapeRow, Time,
    U64, WalletNotEligibleDetails,
};

/// `$id` of the schema document.
pub const SCHEMA_ID: &str = "urn:timescales:api:v1";

/// Definitions of what clients send. They alone refuse unknown fields
/// (`additionalProperties: false`). Every body the node sends may gain
/// fields within v1.
pub const REQUESTS: [&str; 5] = [
    "CreateSessionRequest",
    "SubmitRequest",
    "SubmitBatchRequest",
    "RetractRequest",
    "ClientMessage",
];

/// Largest `Num`: JSON numbers are allowed for values below 2^31.
pub const NUM_MAX: u64 = (1 << 31) - 1;
/// Largest `TimeMs`: Unix milliseconds stay below 2^53.
pub const TIME_MS_MAX: u64 = (1 << 53) - 1;

/// The schema document.
pub fn schema() -> Value {
    let mut generator = SchemaSettings::draft2020_12()
        .for_serialize()
        .into_generator();
    macro_rules! define {
        ($($ty:ty),* $(,)?) => {$(
            generator.subschema_for::<$ty>();
        )*};
    }
    define!(
        U64,
        I64,
        Hex32,
        Hex64,
        Hex,
        B58,
        B58Sig,
        B64,
        Info,
        Status,
        Time,
        Items<MarketSummary>,
        MarketDetail,
        CurrentEpoch,
        EpochKey,
        Page<EpochSummary>,
        EpochDetail,
        Leaves,
        Artifacts,
        Items<PolicyStatementView>,
        Page<TapeRow>,
        Items<ExecutorRegistration>,
        SessionNonce,
        CreateSessionRequest,
        Session,
        SubmitRequest,
        SubmitBatchRequest,
        SubmitResult,
        Items<SubmitItemResult>,
        Items<ParkedItem>,
        RetractRequest,
        RetractResult,
        ClientMessage,
        ServerFrame,
        StreamEvent,
        Problem,
        ErrorCode,
        BadRequestDetails,
        DecodeFailedDetails,
        WalletNotEligibleDetails,
        NotYetAvailableDetails,
        EpochClosedDetails,
        DuplicateCommitmentDetails,
        BatchFullDetails,
        QuotaExceededDetails,
        RateLimitedDetails,
        IntakePausedDetails,
    );
    let mut defs = generator.take_definitions(true);
    for (name, def) in defs.iter_mut() {
        name_integers(def);
        drop_null_from_optional(def);
        if !REQUESTS.contains(&name.as_str()) {
            allow_unknown_fields(def);
        }
    }
    defs.insert(
        "Num".into(),
        json!({
            "description": "JSON number below 2^31: counts, indices and u8 to u32 fields.",
            "type": "integer",
            "minimum": 0,
            "maximum": NUM_MAX,
        }),
    );
    defs.insert(
        "TimeMs".into(),
        json!({
            "description": "Unix time in milliseconds as a JSON number below 2^53.",
            "type": "integer",
            "minimum": 0,
            "maximum": TIME_MS_MAX,
        }),
    );
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        "title": "Timescales public API v1",
        "description": "Bodies of timescales-node's /v1 REST endpoints and of the /v1/stream WebSocket. Generated from crates/timescales-service, do not edit.",
        "$defs": defs,
    })
}

/// Replaces the integer schemas schemars derives with references to the
/// named kinds. Every plain `u64` of a DTO is a `TimeMs` (protocol u64s are
/// `U64` strings) and every narrower unsigned integer is a `Num`, so the
/// derived `format` decides which.
fn name_integers(v: &mut Value) {
    match v {
        Value::Object(o) => {
            if let Some(replacement) = integer_ref(o) {
                *v = replacement;
                return;
            }
            for child in o.values_mut() {
                name_integers(child);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(name_integers),
        _ => {}
    }
}

/// schemars lets every `Option` be `null`. A property the node omits when
/// it has no value (`x?: T`) is never `null` on the wire, so only
/// required properties (`x: T | null`) keep the `null` alternative.
fn drop_null_from_optional(v: &mut Value) {
    match v {
        Value::Object(o) => {
            let required: Vec<Value> = o
                .get("required")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if let Some(Value::Object(props)) = o.get_mut("properties") {
                for (name, prop) in props.iter_mut() {
                    if !required.contains(&Value::String(name.clone())) {
                        drop_null(prop);
                    }
                }
            }
            for child in o.values_mut() {
                drop_null_from_optional(child);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(drop_null_from_optional),
        _ => {}
    }
}

/// schemars closes the object of each externally tagged variant
/// (`{ "ok":... }`). A response object stays open.
fn allow_unknown_fields(v: &mut Value) {
    match v {
        Value::Object(o) => {
            if o.get("additionalProperties") == Some(&Value::Bool(false)) {
                o.remove("additionalProperties");
            }
            for child in o.values_mut() {
                allow_unknown_fields(child);
            }
        }
        Value::Array(a) => a.iter_mut().for_each(allow_unknown_fields),
        _ => {}
    }
}

fn drop_null(schema: &mut Value) {
    let Value::Object(o) = schema else { return };
    let null = json!({ "type": "null" });
    if let Some(Value::Array(any)) = o.get("anyOf")
        && any.len() == 2
        && any.contains(&null)
    {
        let other = any.iter().find(|s| **s != null).cloned();
        o.remove("anyOf");
        if let Some(Value::Object(other)) = other {
            o.extend(other);
        }
    } else if let Some(Value::Array(types)) = o.get("type")
        && types.len() == 2
        && types.contains(&json!("null"))
    {
        let other = types.iter().find(|t| **t != json!("null")).cloned();
        if let Some(t) = other {
            o.insert("type".into(), t);
        }
    }
}

fn integer_ref(o: &Map<String, Value>) -> Option<Value> {
    let nullable = match o.get("type")? {
        Value::String(t) if t == "integer" => false,
        Value::Array(types) if types == &[json!("integer"), json!("null")] => true,
        _ => return None,
    };
    let kind = match o.get("format")?.as_str()? {
        "uint64" => "TimeMs",
        "uint32" | "uint16" | "uint8" => "Num",
        _ => return None,
    };
    let reference = json!({ "$ref": format!("#/$defs/{kind}") });
    let mut out: Map<String, Value> = o
        .iter()
        .filter(|(k, _)| !matches!(k.as_str(), "type" | "format" | "minimum" | "maximum"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if nullable {
        out.insert("anyOf".into(), json!([reference, { "type": "null" }]));
    } else {
        out.insert("$ref".into(), reference["$ref"].clone());
    }
    Some(Value::Object(out))
}
