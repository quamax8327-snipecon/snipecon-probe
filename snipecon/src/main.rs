use aya::maps::HashMap;
use aya::programs::SchedClassifier;
use aya::Ebpf;
use reqwest::blocking::Client;
use serde_json::json;
use std::env;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ingest_url = env::var("INGEST_URL")
        .unwrap_or_else(|_| "https://snipecon.space/functions/ingest".to_string());
    let probe_id = env::var("PROBE_ID")
        .unwrap_or_else(|_| "probe-unknown".to_string());
    let iface = env::var("SNIPECON_IFACE")
        .unwrap_or_else(|_| "wlp7s0".to_string());

    println!("[SnipeCon] Courier starting...");
    println!("[SnipeCon]   probe_id = {}", probe_id);
    println!("[SnipeCon]   endpoint = {}", ingest_url);
    println!("[SnipeCon]   iface    = {}", iface);

    // ── Load eBPF object ───────────────────────────────────────────────────
    let ebpf_path = Path::new("/usr/local/bin/libsnipecon_ebpf.so");
    let mut bpf = Ebpf::load_file(ebpf_path)
        .map_err(|e| format!("Failed to load eBPF object at {}: {}", ebpf_path.display(), e))?;

    // ── Attach SchedClassifier (TC egress) ────────────────────────────────
    let program: &mut SchedClassifier = bpf
        .program_mut("snipecon_probe")
        .ok_or("BPF program 'snipecon_probe' not found")?
        .try_into()?;

    program.load()?;
    program.attach(&iface, aya::programs::tc::TcAttachType::Egress)?;
    println!("[SnipeCon] eBPF SchedClassifier attached on {} (egress)", iface);


    // ── Heartbeat loop ─────────────────────────────────────────────────────
    let client = Client::new();
    loop {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let body = json!({
            "probe_id": probe_id,
            "event_type": "heartbeat",
            "severity": 1,
            "timestamp": ts,
            "payload": { "status": "active", "iface": iface }
        });

        match client.post(&ingest_url).json(&body).send() {
            Ok(res) => println!("[SnipeCon] Heartbeat sent | {}", res.status()),
            Err(e)  => eprintln!("[SnipeCon] Connection error: {}", e),
        }

        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
