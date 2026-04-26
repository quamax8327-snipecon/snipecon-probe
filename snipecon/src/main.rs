use reqwest::blocking::Client;
use serde_json::json;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ingest_url = env::var("INGEST_URL")
        .unwrap_or_else(|_| "https://snipecon.space/functions/ingest".to_string());
    let probe_id = env::var("PROBE_ID")
        .unwrap_or_else(|_| "probe-unknown".to_string());

    let client = Client::new();
    println!("[SnipeCon] Courier starting... probe_id={} endpoint={}", probe_id, ingest_url);

    loop {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

        let body = json!({
            "probe_id": probe_id,
            "event_type": "heartbeat",
            "severity": 1,
            "timestamp": ts,
            "payload": { "status": "active", "msg": "Desktop Probe Online" }
        });

        match client.post(&ingest_url).json(&body).send() {
            Ok(res) => println!("[SnipeCon] Heartbeat sent | Status: {}", res.status()),
            Err(e) => eprintln!("[SnipeCon] Connection error: {}", e),
        }

        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
