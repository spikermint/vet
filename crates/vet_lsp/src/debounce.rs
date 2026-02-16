//! Debounced document scanning.
//!
//! Only triggers a scan after typing stops for the debounce delay.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tower_lsp::lsp_types::Url;
use tracing::debug;

use crate::uri::filename_from_uri;

const DEBOUNCE_DELAY: Duration = Duration::from_millis(300);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A document that is ready to be scanned after the debounce delay.
#[derive(Debug, Clone)]
pub struct ScanRequest {
    /// The document URI to scan.
    pub uri: Url,
    /// The full text content at the time the scan was scheduled.
    pub content: String,
}

/// Handle for scheduling debounced document scans.
#[derive(Debug, Clone)]
pub struct Debouncer {
    /// Channel sender for submitting scan requests to the debounce worker.
    tx: mpsc::UnboundedSender<ScanRequest>,
}

impl Debouncer {
    /// Queues a document for scanning after the debounce delay elapses.
    pub fn schedule(&self, uri: Url, content: String) {
        debug!("Debounce: queued {}", filename_from_uri(&uri));
        let _ = self.tx.send(ScanRequest { uri, content });
    }
}

struct PendingDocument {
    content: String,
    last_change: Instant,
}

/// Spawns the debounce worker and returns the debouncer handle and ready-scan receiver.
pub fn spawn() -> (Debouncer, mpsc::UnboundedReceiver<ScanRequest>) {
    let (request_tx, request_rx) = mpsc::unbounded_channel();
    let (ready_tx, ready_rx) = mpsc::unbounded_channel();

    tokio::spawn(debounce_worker(request_rx, ready_tx));

    (Debouncer { tx: request_tx }, ready_rx)
}

async fn debounce_worker(
    mut requests: mpsc::UnboundedReceiver<ScanRequest>,
    ready: mpsc::UnboundedSender<ScanRequest>,
) {
    let mut pending: HashMap<Url, PendingDocument> = HashMap::new();

    loop {
        // Wait for either a new message or the poll interval
        match tokio::time::timeout(POLL_INTERVAL, requests.recv()).await {
            Ok(Some(request)) => {
                // New change arrived, update pending state and reset timer
                pending.insert(
                    request.uri,
                    PendingDocument {
                        content: request.content,
                        last_change: Instant::now(),
                    },
                );
            }
            Ok(None) => {
                // Channel closed, shutdown
                debug!("Debounce: worker shutting down");
                break;
            }
            Err(_) => {}
        }

        let now = Instant::now();
        let ready_uris: Vec<Url> = pending
            .iter()
            .filter(|(_, doc)| now.duration_since(doc.last_change) >= DEBOUNCE_DELAY)
            .map(|(uri, _)| uri.clone())
            .collect();

        for uri in ready_uris {
            if let Some(doc) = pending.remove(&uri) {
                debug!("Debounce: {} ready for scan", filename_from_uri(&uri));

                let _ = ready.send(ScanRequest {
                    uri,
                    content: doc.content,
                });
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "tests use expect for clearer failure messages")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn debouncer_coalesces_rapid_changes() {
        let (debouncer, mut ready) = spawn();
        let uri = Url::parse("file:///test.rs").unwrap();

        // Simulate rapid typing
        debouncer.schedule(uri.clone(), "a".into());
        debouncer.schedule(uri.clone(), "ab".into());
        debouncer.schedule(uri.clone(), "abc".into());

        // Wait for debounce
        tokio::time::sleep(Duration::from_millis(400)).await;

        // Should only receive one scan request with final content
        let request = ready.recv().await.expect("should receive scan request");
        assert_eq!(request.uri, uri);
        assert_eq!(request.content, "abc");

        // No more pending
        assert!(ready.try_recv().is_err());
    }

    #[tokio::test]
    async fn debouncer_handles_multiple_documents() {
        let (debouncer, mut ready) = spawn();
        let uri_a = Url::parse("file:///a.rs").unwrap();
        let uri_b = Url::parse("file:///b.rs").unwrap();

        debouncer.schedule(uri_a.clone(), "content a".into());
        debouncer.schedule(uri_b.clone(), "content b".into());

        tokio::time::sleep(Duration::from_millis(400)).await;

        // Should receive both
        let mut received = vec![];
        while let Ok(req) = ready.try_recv() {
            received.push(req.uri);
        }

        assert!(received.contains(&uri_a));
        assert!(received.contains(&uri_b));
    }

    #[tokio::test]
    async fn debouncer_resets_on_new_change() {
        let (debouncer, mut ready) = spawn();
        let uri = Url::parse("file:///test.rs").unwrap();

        debouncer.schedule(uri.clone(), "first".into());

        // Wait less than debounce delay
        tokio::time::sleep(Duration::from_millis(200)).await;

        // New change resets timer
        debouncer.schedule(uri.clone(), "second".into());

        // Wait less than debounce delay again
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Should not have received anything yet
        assert!(ready.try_recv().is_err());

        // Wait for full debounce
        tokio::time::sleep(Duration::from_millis(200)).await;

        let request = ready.recv().await.expect("should receive scan request");
        assert_eq!(request.content, "second");
    }
}
