//! Server-Sent Events endpoint.
//!
//! One long-lived `GET /events` connection per browser tab. The handler
//! subscribes to the same broadcast the `WebEventSink` writes to, and
//! re-encodes each `WebEvent` as an `event: <name>\ndata: <json>\n\n` line.
//! SSE is the right tool here over WebSocket: the events are one-way
//! (server → client), the format is dead simple, and `EventSource` on the
//! browser side handles reconnection for free.

use axum::extract::State;
use axum::response::sse::{Event, Sse};
use k7s_deps::futures::stream::Stream;
use std::convert::Infallible;

use k7s_core::core::events::WebEvent;

use super::state::{SessionToken, WebState};

/// `GET /events` — open an SSE stream and forward this connection's emits.
pub async fn events_handler(
    State(state): State<WebState>,
    session: axum::extract::Extension<SessionToken>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.session_for(&session).event_tx.subscribe();

    let stream = k7s_deps::async_stream::stream! {
        loop {
            match rx.recv().await {
                Ok(WebEvent { name, data }) => {
                    // Serialize once for the wire. SSE itself doesn't care
                    // about the format — the browser just hands `data` to
                    // the EventSource listener as a string and we JSON-parse
                    // it on the front end.
                    let payload = k7s_deps::serde_json::to_string(&data)
                        .unwrap_or_else(|_| "null".to_string());
                    yield Ok(Event::default().event(name).data(payload));
                }
                // A receiver that fell behind (broadcast returns Lagged) just
                // misses events; the next emit will re-sync state. Don't tear
                // down the stream over it.
                Err(k7s_deps::tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                // No senders (manager torn down) — the connection is done.
                Err(k7s_deps::tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    };

    Sse::new(stream)
}
