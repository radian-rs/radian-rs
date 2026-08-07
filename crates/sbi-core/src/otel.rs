//! W3C trace-context propagation across the SBI.
//!
//! Outbound: [`Traced::traced`] injects the current span's `traceparent` /
//! `baggage` headers into a `reqwest` request, so the receiving NF joins the
//! caller's trace. Inbound: [`trace_requests`] is an axum middleware that
//! extracts those headers and runs the handler inside a server span — every
//! SBI server mounted through [`crate::run`]/[`crate::tls::serve`] gets it
//! automatically. Both are no-ops (empty context, unexported spans) when the
//! process hasn't installed an OpenTelemetry provider
//! (`common::init_telemetry`).

use opentelemetry::global;
use opentelemetry::propagation::{Extractor, Injector};
use tracing::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;

struct HeaderInjector<'a>(&'a mut http::HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::try_from(key),
            http::header::HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

struct HeaderExtractor<'a>(&'a http::HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

/// Outbound half: `client.post(url).traced().json(..).send()` propagates the
/// active trace to the peer NF.
pub trait Traced {
    /// Inject the current span's W3C `traceparent`/`baggage` into this request.
    fn traced(self) -> Self;
}

impl Traced for reqwest::RequestBuilder {
    fn traced(self) -> Self {
        let cx = tracing::Span::current().context();
        let mut headers = http::HeaderMap::new();
        global::get_text_map_propagator(|prop| {
            prop.inject_context(&cx, &mut HeaderInjector(&mut headers))
        });
        self.headers(headers)
    }
}

/// Inbound half: continue the remote trace (or start one) around each SBI
/// request. Handler logs land inside the span, so they carry the trace id.
pub async fn trace_requests(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let parent = global::get_text_map_propagator(|prop| {
        prop.extract(&HeaderExtractor(req.headers()))
    });
    let span = tracing::info_span!(
        "sbi_request",
        otel.name = %format!("{} {}", req.method(), req.uri().path()),
        otel.kind = "server",
        http.request.method = %req.method(),
        url.path = %req.uri().path(),
    );
    let _ = span.set_parent(parent);
    next.run(req).instrument(span).await
}

/// Wrap an SBI router with [`trace_requests`] — applied by the server runners.
pub(crate) fn traced_router(app: axum::Router) -> axum::Router {
    app.layer(axum::middleware::from_fn(trace_requests))
}
