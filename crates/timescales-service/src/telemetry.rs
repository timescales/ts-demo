//! Logging (and, with feature `otlp`, trace export) for every service.
//!
//! JSON logs are one object per line: `ts`, `level`, `target`,
//! `service`, then the fields of every span the event is in (outermost
//! first, so `market`, `epoch`, `phase`,... of the enclosing spans), then
//! the event's own fields (`message`,...). Wallets are logged only as
//! [`wallet_tag`].

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use timescales_core::crypto::{Hasher, domain};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, MakeWriter};
use tracing_subscriber::layer::{Context, Layer, Layered, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    Json,
    Pretty,
}

/// The `[telemetry]` table every service shares.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    pub log_format: LogFormat,
    pub log_filter: String,
    /// The OTLP/HTTP traces URL, used as given (for example
    /// `http://127.0.0.1:4318/v1/traces`). Empty disables OTLP export
    /// (feature `otlp`).
    #[serde(default)]
    pub otlp_endpoint: String,
    #[serde(default)]
    pub service_name: Option<String>,
}

/// Keeps exporters alive. Flushes on drop.
#[non_exhaustive]
pub struct TelemetryGuard {
    #[cfg(feature = "otlp")]
    tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl fmt::Debug for TelemetryGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetryGuard").finish_non_exhaustive()
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        #[cfg(feature = "otlp")]
        if let Some(provider) = self.tracer_provider.take()
            && let Err(e) = provider.shutdown()
        {
            eprintln!("flushing traces failed: {e}");
        }
    }
}

#[derive(Debug, Error)]
pub enum TelemetryError {
    #[error("invalid log filter: {0}")]
    Filter(String),
    #[error("telemetry already initialised")]
    AlreadyInitialised,
    #[error("OTLP exporter: {0}")]
    Otlp(String),
}

type Base = Layered<EnvFilter, Registry>;

/// Installs the global subscriber: `cfg.log_filter` (an `EnvFilter`
/// directive), JSON or pretty lines on stdout, and OTLP export when
/// `cfg.otlp_endpoint` is set. `cfg.service_name` overrides `service`.
///
/// OTLP export needs the `otlp` feature and must be started inside the
/// tokio runtime that will carry the exports. Drop the guard while that
/// runtime still runs, so the last spans are flushed. Without the feature
/// a non-empty endpoint is an error rather than silently ignored.
pub fn init_telemetry(
    cfg: &TelemetryConfig,
    service: &'static str,
) -> Result<TelemetryGuard, TelemetryError> {
    let filter =
        EnvFilter::try_new(&cfg.log_filter).map_err(|e| TelemetryError::Filter(e.to_string()))?;
    let name = cfg
        .service_name
        .clone()
        .unwrap_or_else(|| service.to_owned());
    let lines: Box<dyn Layer<Base> + Send + Sync> = match cfg.log_format {
        LogFormat::Json => Box::new(json_layer(name.clone(), std::io::stdout)),
        LogFormat::Pretty => Box::new(tracing_subscriber::fmt::layer().pretty()),
    };

    #[cfg(feature = "otlp")]
    let (tracer_provider, traces) = if cfg.otlp_endpoint.is_empty() {
        (None, None)
    } else {
        let provider = otlp::provider(&cfg.otlp_endpoint, &name)?;
        let layer = otlp::layer(&provider, service);
        (Some(provider), Some(layer))
    };
    #[cfg(not(feature = "otlp"))]
    if !cfg.otlp_endpoint.is_empty() {
        return Err(TelemetryError::Otlp(
            "this build has no OTLP exporter (feature `otlp`)".to_owned(),
        ));
    }

    let subscriber = tracing_subscriber::registry().with(filter).with(lines);
    #[cfg(feature = "otlp")]
    let subscriber = subscriber.with(traces);
    subscriber
        .try_init()
        .map_err(|_| TelemetryError::AlreadyInitialised)?;
    Ok(TelemetryGuard {
        #[cfg(feature = "otlp")]
        tracer_provider,
    })
}

/// `hex(H(SESSION, "tag" || wallet))[..8]`: a log label that does not name
/// the wallet.
pub fn wallet_tag(wallet: &[u8; 32]) -> String {
    let digest = Hasher::new(domain::SESSION)
        .chain(b"tag")
        .chain(wallet)
        .finalize();
    hex::encode(&digest.0[..4])
}

/// The JSON line format, written to `writer`.
pub(crate) fn json_layer<S, W>(service: String, writer: W) -> impl Layer<S> + Send + Sync
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    SpanFieldsLayer.and_then(
        tracing_subscriber::fmt::layer()
            .event_format(JsonLines { service })
            .with_writer(writer),
    )
}

/// A span's fields as JSON, kept in the span's extensions.
#[derive(Default)]
struct SpanFields(BTreeMap<String, Value>);

/// Records span fields as JSON values for [`JsonLines`].
struct SpanFieldsLayer;

impl<S> Layer<S> for SpanFieldsLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = SpanFields::default();
        attrs.record(&mut JsonVisitor(&mut fields.0));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(fields);
        }
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id)
            && let Some(fields) = span.extensions_mut().get_mut::<SpanFields>()
        {
            values.record(&mut JsonVisitor(&mut fields.0));
        }
    }
}

struct JsonVisitor<'a>(&'a mut BTreeMap<String, Value>);

impl Visit for JsonVisitor<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().to_owned(), Value::String(format!("{value:?}")));
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.0
            .insert(field.name().to_owned(), Value::String(value.to_owned()));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), Value::Bool(value));
    }

    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().to_owned(), Value::from(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.0
            .insert(field.name().to_owned(), Value::String(value.to_string()));
    }
}

struct JsonLines {
    service: String,
}

fn push_json(line: &mut String, key: &str, value: &Value) -> fmt::Result {
    line.push_str(&serde_json::to_string(key).map_err(|_| fmt::Error)?);
    line.push(':');
    line.push_str(&serde_json::to_string(value).map_err(|_| fmt::Error)?);
    Ok(())
}

impl<S, N> FormatEvent<S, N> for JsonLines
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let mut ts = String::new();
        SystemTime.format_time(&mut Writer::new(&mut ts))?;
        let meta = event.metadata();
        let mut fields = BTreeMap::new();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                if let Some(span_fields) = span.extensions().get::<SpanFields>() {
                    fields.extend(span_fields.0.iter().map(|(k, v)| (k.clone(), v.clone())));
                }
            }
        }
        event.record(&mut JsonVisitor(&mut fields));

        let leading = [
            ("ts", ts),
            ("level", meta.level().as_str().to_lowercase()),
            ("target", meta.target().to_owned()),
            ("service", self.service.clone()),
        ];
        let mut line = String::from("{");
        for (i, (k, v)) in leading.iter().enumerate() {
            if i > 0 {
                line.push(',');
            }
            push_json(&mut line, k, &Value::String(v.clone()))?;
        }
        // A field never replaces one of the leading keys.
        for (k, v) in fields
            .iter()
            .filter(|(k, _)| !leading.iter().any(|(l, _)| l == k))
        {
            line.push(',');
            push_json(&mut line, k, v)?;
        }
        line.push('}');
        writeln!(writer, "{line}")
    }
}

#[cfg(feature = "otlp")]
mod otlp {
    //! OTLP/HTTP span export. The SDK's batch processor runs its exports on
    //! a plain thread, while the exporter's HTTP client needs the tokio
    //! runtime. [`OnRuntime`] runs each export as a task on the runtime
    //! that initialised telemetry.

    use std::sync::Arc;
    use std::time::Duration;

    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
    use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData};
    use tokio::runtime::Handle;
    use tracing::Subscriber;
    use tracing_subscriber::Layer;
    use tracing_subscriber::registry::LookupSpan;

    use super::TelemetryError;

    pub(super) fn provider(
        endpoint: &str,
        service: &str,
    ) -> Result<SdkTracerProvider, TelemetryError> {
        let runtime = Handle::try_current().map_err(|_| {
            TelemetryError::Otlp("OTLP export must be started inside the tokio runtime".to_owned())
        })?;
        // The exporter builds its own reqwest client.
        crate::tls::install_default_provider();
        let exporter = SpanExporter::builder()
            .with_http()
            .with_endpoint(endpoint)
            .build()
            .map_err(|e| TelemetryError::Otlp(e.to_string()))?;
        Ok(SdkTracerProvider::builder()
            .with_batch_exporter(OnRuntime {
                inner: Arc::new(exporter),
                runtime,
            })
            .with_resource(
                Resource::builder()
                    .with_service_name(service.to_owned())
                    .build(),
            )
            .build())
    }

    pub(super) fn layer<S>(provider: &SdkTracerProvider, service: &'static str) -> impl Layer<S>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        tracing_opentelemetry::layer().with_tracer(provider.tracer(service))
    }

    #[derive(Debug)]
    struct OnRuntime {
        inner: Arc<SpanExporter>,
        runtime: Handle,
    }

    impl opentelemetry_sdk::trace::SpanExporter for OnRuntime {
        fn export(&self, batch: Vec<SpanData>) -> impl Future<Output = OTelSdkResult> + Send {
            let inner = Arc::clone(&self.inner);
            let task = self.runtime.spawn(async move { inner.export(batch).await });
            async move {
                task.await
                    .unwrap_or_else(|e| Err(OTelSdkError::InternalFailure(e.to_string())))
            }
        }

        fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
            self.inner.shutdown_with_timeout(timeout)
        }

        fn force_flush(&self) -> OTelSdkResult {
            self.inner.force_flush()
        }

        fn set_resource(&mut self, resource: &Resource) {
            // Called while the provider is built, before any export holds
            // a reference.
            if let Some(inner) = Arc::get_mut(&mut self.inner) {
                inner.set_resource(resource);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    use super::*;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The raw lines written while `f` runs.
    fn capture(f: impl FnOnce()) -> Vec<String> {
        let out = Capture::default();
        let subscriber =
            tracing_subscriber::registry().with(json_layer("timescales-node".into(), out.clone()));
        tracing::subscriber::with_default(subscriber, f);
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        text.lines().map(str::to_owned).collect()
    }

    #[test]
    fn json_lines_carry_the_d10_fields() {
        let tag = wallet_tag(&[7; 32]);
        let lines = capture(|| {
            let epoch = tracing::info_span!("epoch", market = "4dbe", epoch = 12u64);
            let _e = epoch.enter();
            let phase = tracing::info_span!("phase", phase = "sealed", op = tracing::field::Empty);
            let _p = phase.enter();
            phase.record("op", "post");
            tracing::warn!(wallet_tag = %tag, attempts = 3, "receipt check failed");
        });
        assert_eq!(lines.len(), 1);
        let raw = &lines[0];
        let at = |key: &str| raw.find(&format!("\"{key}\":")).unwrap();
        assert!(raw.starts_with("{\"ts\":\""), "{raw}");
        assert!(
            at("ts") < at("level") && at("level") < at("target") && at("target") < at("service")
        );
        assert!(at("service") < at("epoch"), "{raw}");
        let line: serde_json::Value = serde_json::from_str(raw).unwrap();
        assert_eq!(line["level"], "warn");
        assert_eq!(line["service"], "timescales-node");
        assert_eq!(line["target"], "timescales_service::telemetry::tests");
        assert_eq!(line["market"], "4dbe");
        assert_eq!(line["epoch"], 12);
        assert_eq!(line["phase"], "sealed");
        assert_eq!(line["op"], "post");
        assert_eq!(line["attempts"], 3);
        assert_eq!(line["wallet_tag"], tag);
        assert_eq!(line["message"], "receipt check failed");
        let ts = line["ts"].as_str().unwrap();
        assert!(ts.ends_with('Z') && ts.contains('T'), "{ts}");
    }

    #[test]
    fn an_event_field_never_replaces_a_leading_key() {
        let lines = capture(|| tracing::info!(service = "spoofed", level = "none", "x"));
        assert_eq!(lines[0].matches("\"service\":").count(), 1, "{}", lines[0]);
        let line: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(line["service"], "timescales-node");
        assert_eq!(line["level"], "info");
    }

    #[test]
    fn wallet_tags_are_eight_hex_digits_and_stable() {
        let a = wallet_tag(&[1; 32]);
        assert_eq!(a.len(), 8);
        assert!(
            a.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        assert_eq!(a, wallet_tag(&[1; 32]));
        assert_ne!(a, wallet_tag(&[2; 32]));
        let digest =
            timescales_core::crypto::hash(domain::SESSION, &[b"tag".as_slice(), &[1; 32]].concat());
        assert_eq!(a, hex::encode(&digest.0[..4]));
    }

    #[test]
    fn a_bad_filter_is_refused_before_anything_is_installed() {
        let cfg = TelemetryConfig {
            log_format: LogFormat::Json,
            log_filter: "info,[=bad".into(),
            otlp_endpoint: String::new(),
            service_name: None,
        };
        assert!(matches!(
            init_telemetry(&cfg, "t"),
            Err(TelemetryError::Filter(_))
        ));
    }

    #[cfg(not(feature = "otlp"))]
    #[test]
    fn an_otlp_endpoint_without_the_feature_is_refused() {
        let cfg = TelemetryConfig {
            log_format: LogFormat::Json,
            log_filter: "info".into(),
            otlp_endpoint: "http://127.0.0.1:4318".into(),
            service_name: None,
        };
        assert!(matches!(
            init_telemetry(&cfg, "t"),
            Err(TelemetryError::Otlp(_))
        ));
    }
}
