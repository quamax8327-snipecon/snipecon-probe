use reqwest::blocking::Client;
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const INGEST_URL: &str = "https://snipecon.space/api/v1/ingest";
const PROBE_ID: &str = "probe-9rded3m"; 

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();
    println!("[SnipeCon] Courier starting... Monitoring kernel events.");

    // This loop sends a heartbeat to your dashboard every 60 seconds
    loop {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        let body = json!({
            "probe_id": PROBE_ID,
            "event_type": "heartbeat",
            "severity": 1,
            "timestamp": ts,
            "payload": { "status": "active", "msg": "Desktop Probe Online" }
        });

        match client.post(INGEST_URL).json(&body).send() {
            Ok(res) => println!("[SnipeCon] Heartbeat sent | Status: {}", res.status()),
            Err(e) => eprintln!("[SnipeCon] Connection error: {}", e),
        }

        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
