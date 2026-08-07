//! OpenTelemetry bootstrap for radian-rs network functions.
//!
//! [`init_telemetry`] wires the `tracing` subscriber every NF already logs through
//! to an OpenTelemetry pipeline: spans (and the log events inside them) are
//! exported over **OTLP/HTTP** to a collector, and the W3C `traceparent` /
//! `baggage` propagators are installed globally so trace context crosses the SBI
//! (outbound injection and inbound extraction live in `sbi-core`).
//!
//! Jaeger ingests OTLP natively — to see traces locally:
//!
//! ```sh
//! docker run --rm -p 16686:16686 -p 4318:4318 jaegertracing/all-in-one
//! # ... run the NFs, then browse http://localhost:16686
//! ```
//!
//! Configuration (environment):
//! - `OTEL_EXPORTER_OTLP_ENDPOINT` — collector base URL (default
//!   `http://localhost:4318`).
//! - `RADIAN_OTEL=off` (or `0`/`false`) — disable export; console logging only.
//! - `RUST_LOG` — console log filter, as before. Span export is filtered
//!   independently (`info` and up) so a quiet console doesn't drop traces.

use opentelemetry::global;
use opentelemetry::propagation::TextMapCompositePropagator;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer, fmt};

/// The installed provider, kept so [`shutdown_telemetry`] can flush it.
static PROVIDER: std::sync::OnceLock<SdkTracerProvider> = std::sync::OnceLock::new();

fn console_filter() -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))
}

fn otel_disabled() -> bool {
    std::env::var("RADIAN_OTEL")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "0" | "off" | "false"))
        .unwrap_or(false)
}

/// Initialise console logging **and** OpenTelemetry trace export for `service`
/// (the OTel `service.name`, e.g. `"amf"`). Falls back to console-only logging
/// when export is disabled or the exporter cannot be built. Idempotent across
/// NFs sharing a process (tests): the first initialisation wins.
pub fn init_telemetry(service: &str) {
    if otel_disabled() {
        let _ = tracing_subscriber::registry()
            .with(fmt::layer().with_filter(console_filter()))
            .try_init();
        return;
    }

    // The exporter's reqwest client is built with `rustls-no-provider` (the
    // workspace-wide reqwest build) and panics without a default crypto
    // provider. Idempotent — sbi-core installs the same ring provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let exporter = match opentelemetry_otlp::SpanExporter::builder().with_http().build() {
        Ok(exporter) => exporter,
        Err(e) => {
            let _ = tracing_subscriber::registry()
                .with(fmt::layer().with_filter(console_filter()))
                .try_init();
            tracing::warn!("OTLP span exporter unavailable — console logging only: {e}");
            return;
        }
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::AlwaysOn)
        .with_resource(Resource::builder().with_service_name(service.to_string()).build())
        .build();

    // W3C TraceContext + Baggage — what SBI peers inject/extract.
    global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));
    global::set_tracer_provider(provider.clone());

    let tracer = provider.tracer("radian-rs");
    let _ = tracing_subscriber::registry()
        .with(fmt::layer().with_filter(console_filter()))
        .with(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
        )
        .try_init();
    let _ = PROVIDER.set(provider);
}

/// Flush and shut down the trace pipeline (call at orderly exit — spans batched
/// but not yet exported would otherwise be lost). No-op when export is off.
pub fn shutdown_telemetry() {
    if let Some(provider) = PROVIDER.get() {
        let _ = provider.force_flush();
        let _ = provider.shutdown();
    }
}
