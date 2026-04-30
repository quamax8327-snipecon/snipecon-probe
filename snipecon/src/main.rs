use aya::maps::AsyncPerfEventArray;
use aya::programs::SchedClassifier;
use aya::Bpf;
use bytes::BytesMut;
use log::{info, warn};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION};
use reqwest::Client;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sysinfo::System;
use tokio::sync::Mutex;
use tokio::time::sleep;

const INGEST_URL: &str = "https://snipecon.space/functions/ingest";
const ACTIVE_BLACKLIST_URL: &str = "https://snipecon.space/functions/getActiveBlacklist";
const PROBE_ID: &str = "probe-uowhmue";
const AGENT_BEARER_TOKEN: &str = "probe-uowhmue";
const IFACE: &str = "wlp7s0";
const STATE_FILE: &str = "/var/lib/snipecon/system_state.json";
const BATCH_LIMIT: usize = 50;
const BATCH_INTERVAL_SECS: u64 = 5;
const HEARTBEAT_INTERVAL_SECS: u64 = 10;
const CONFIG_PATHS: [&str; 8] = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/fstab",
];
const PACKAGE_LOGS: [&str; 6] = [
    "/var/log/apt/history.log",
    "/var/log/apt/term.log",
    "/var/log/dpkg.log",
    "/var/log/dnf.log",
    "/var/log/yum.log",
    "/var/log/pacman.log",
];

#[derive(serde::Serialize, serde::Deserialize, Default, Clone)]
struct SystemState {
    os: String,
    kernel: String,
    config_mtimes: HashMap<String, u64>,
    package_log_sizes: HashMap<String, u64>,
}

fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn file_mtime(path: &str) -> u64 {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn file_size(path: &str) -> u64 {
    fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

fn load_state() -> SystemState {
    fs::read_to_string(STATE_FILE)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default()
}

fn save_state(state: &SystemState) {
    if let Some(parent) = Path::new(STATE_FILE).parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(content) = serde_json::to_string_pretty(state) {
        let _ = fs::write(STATE_FILE, content);
    }
}

fn build_event(event_type: &str, severity: u8, message: String, payload: serde_json::Value) -> serde_json::Value {
    json!({
        "probe_id": PROBE_ID,
        "event_type": event_type,
        "severity": severity,
        "timestamp": now_ts(),
        "log_message": message,
        "payload": payload,
    })
}

async fn post_event(client: &Client, event_type: &str, severity: u8, message: String, payload: serde_json::Value) {
    let body = build_event(event_type, severity, message, payload);

    if let Err(error) = client.post(INGEST_URL).json(&body).send().await {
        warn!("[SnipeCon] failed to send {} event: {}", event_type, error);
    }
}

fn shell_for_command(command: &str) -> Option<&'static str> {
    match command {
        "restart_agent" => Some("sudo systemctl restart snipecon"),
        "sync_rules" => Some("sudo systemctl reload snipecon || sudo systemctl restart snipecon"),
        "refresh_metadata" => Some("systemctl status snipecon --no-pager >/dev/null"),
        "diagnostics" => Some("journalctl -u snipecon -n 80 --no-pager"),
        "deploy_update" => Some("sudo systemctl restart snipecon"),
        "pause_protection" => Some("sudo tc qdisc del dev wlp7s0 clsact || true"),
        "resume_protection" => Some("sudo systemctl restart snipecon"),
        _ => None,
    }
}

async fn execute_pending_command(client: &Client, command: &str) {
    let Some(shell_command) = shell_for_command(command) else {
        warn!("[SnipeCon] unknown command from dashboard: {}", command);
        return;
    };

    info!("[SnipeCon] executing dashboard command: {}", command);
    match Command::new("/bin/sh").args(["-lc", shell_command]).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            post_event(
                client,
                "terminal_activity",
                if output.status.success() { 3 } else { 7 },
                format!("Dashboard command executed: {}", command),
                json!({ "command": command, "shell": shell_command, "success": output.status.success(), "stdout": stdout, "stderr": stderr }),
            ).await;
        }
        Err(error) => {
            warn!("[SnipeCon] failed to execute dashboard command {}: {}", command, error);
        }
    }
}

async fn handle_ingest_response(client: &Client, response: reqwest::Response) {
    match response.json::<serde_json::Value>().await {
        Ok(body) => {
            if let Some(commands) = body["commands"].as_array() {
                for command in commands.iter().filter_map(|item| item["type"].as_str()) {
                    execute_pending_command(client, command).await;
                }
            }
        }
        Err(error) => warn!("[SnipeCon] failed to parse ingest response: {}", error),
    }
}

async fn flush_event_batch(client: &Client, buffer: &Arc<Mutex<Vec<serde_json::Value>>>) {
    let batch = {
        let mut locked = buffer.lock().await;
        if locked.is_empty() {
            return;
        }
        std::mem::take(&mut *locked)
    };

    let batch_len = batch.len();
    if let Err(error) = client.post(INGEST_URL).json(&batch).send().await {
        warn!("[SnipeCon] failed to send kernel batch of {} events: {}", batch_len, error);
    } else {
        info!("[SnipeCon] sent kernel batch of {} events", batch_len);
    }
}

async fn enqueue_kernel_event(client: &Client, buffer: &Arc<Mutex<Vec<serde_json::Value>>>, event_type: &str, severity: u8, message: String, payload: serde_json::Value) {
    let should_flush = {
        let mut locked = buffer.lock().await;
        locked.push(build_event(event_type, severity, message, payload));
        locked.len() >= BATCH_LIMIT
    };

    if should_flush {
        flush_event_batch(client, buffer).await;
    }
}

async fn poll_active_blacklist(client: Client) {
    let mut applied = HashSet::<String>::new();

    loop {
        match client.get(ACTIVE_BLACKLIST_URL).send().await {
            Ok(response) => {
                match response.json::<serde_json::Value>().await {
                    Ok(body) => {
                        if let Some(ips) = body["ips"].as_array() {
                            info!("Checking Blacklist... Found {} IPs", ips.len());
                            for ip in ips.iter().filter_map(|value| value.as_str()) {
                                if applied.contains(ip) {
                                    continue;
                                }

                                match Command::new("/usr/bin/sudo")
                                    .args(["/usr/sbin/ufw", "insert", "1", "deny", "from", ip])
                                    .output()
                                {
                                    Ok(output) if output.status.success() => {
                                        applied.insert(ip.to_string());
                                        info!("[SnipeCon] blocked active blacklist IP via ufw: {}", ip);
                                    }
                                    Ok(output) => {
                                        let stderr = String::from_utf8_lossy(&output.stderr);
                                        warn!("[SnipeCon] ufw failed for {}: {}", ip, stderr.trim());
                                    }
                                    Err(error) => {
                                        warn!("[SnipeCon] failed to execute ufw for {}: {}", ip, error);
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => warn!("[SnipeCon] failed to parse active blacklist response: {}", error),
                }
            }
            Err(error) => warn!("[SnipeCon] failed to fetch active blacklist: {}", error),
        }

        sleep(Duration::from_secs(60)).await;
    }
}

async fn audit_system_changes(client: &Client, state: &mut SystemState) {
    let current_os = System::name().unwrap_or_else(|| "unknown".to_string());
    let current_kernel = System::kernel_version().unwrap_or_default();

    if !state.os.is_empty() && (state.os != current_os || state.kernel != current_kernel) {
        post_event(
            client,
            "os_kernel_update",
            7,
            format!("OS/kernel changed: {} / {} -> {} / {}", state.os, state.kernel, current_os, current_kernel),
            json!({ "old_os": state.os, "old_kernel": state.kernel, "new_os": current_os, "new_kernel": current_kernel }),
        ).await;
    }
    state.os = current_os;
    state.kernel = current_kernel;

    for path in CONFIG_PATHS {
        let current_mtime = file_mtime(path);
        let previous_mtime = state.config_mtimes.get(path).copied().unwrap_or(0);
        if previous_mtime > 0 && current_mtime > previous_mtime {
            post_event(
                client,
                "config_changed",
                6,
                format!("Critical config changed: {}", path),
                json!({ "path": path, "previous_mtime": previous_mtime, "current_mtime": current_mtime }),
            ).await;
        }
        if current_mtime > 0 {
            state.config_mtimes.insert(path.to_string(), current_mtime);
        }
    }

    for path in PACKAGE_LOGS {
        let current_size = file_size(path);
        let previous_size = state.package_log_sizes.get(path).copied().unwrap_or(0);
        if previous_size > 0 && current_size > previous_size {
            post_event(
                client,
                "package_activity",
                4,
                format!("Package manager log changed: {}", path),
                json!({ "path": path, "previous_size": previous_size, "current_size": current_size }),
            ).await;
        }
        if current_size > 0 {
            state.package_log_sizes.insert(path.to_string(), current_size);
        }
    }

    save_state(state);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let probe_id = "probe-uowhmue";
    let mut sys = System::new_all();
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", AGENT_BEARER_TOKEN))?);
    headers.insert(HeaderName::from_static("x-probe-id"), HeaderValue::from_str(probe_id)?);
    let client = Client::builder().default_headers(headers).build()?;
    let mut state = load_state();
    let kernel_buffer = Arc::new(Mutex::new(Vec::<serde_json::Value>::new()));

    info!("[SnipeCon-XDR] Initializing Full System Awareness...");
    info!("[SnipeCon] Identifying as: {}", probe_id);
    tokio::spawn(poll_active_blacklist(client.clone()));

    let batch_client = client.clone();
    let batch_buffer = kernel_buffer.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(BATCH_INTERVAL_SECS)).await;
            flush_event_batch(&batch_client, &batch_buffer).await;
        }
    });

    let ebpf_path = Path::new("/usr/local/bin/libsnipecon_ebpf.so");
    let mut bpf = Bpf::load_file(ebpf_path)?;

    let program: &mut SchedClassifier = bpf
        .program_mut("snipecon_probe")
        .ok_or("BPF program 'snipecon_probe' not found")?
        .try_into()?;

    program.load()?;
    program.attach(IFACE, aya::programs::tc::TcAttachType::Egress)?;
    program.attach(IFACE, aya::programs::tc::TcAttachType::Ingress)?;

    let events_map = bpf.take_map("EVENTS").ok_or("Perf event map 'EVENTS' not found")?;
    let mut events = AsyncPerfEventArray::try_from(events_map)?;

    for cpu_id in aya::util::online_cpus().map_err(|_| "Failed to get online CPUs")? {
        let mut buf = events.open(cpu_id, None)?;
        let client_clone = client.clone();
        let buffer_clone = kernel_buffer.clone();

        tokio::spawn(async move {
            let mut buffers = (0..10).map(|_| BytesMut::with_capacity(4096)).collect::<Vec<_>>();
            loop {
                if let Ok(events_data) = buf.read_events(&mut buffers).await {
                    for _ in 0..events_data.read {
                        enqueue_kernel_event(
                            &client_clone,
                            &buffer_clone,
                            "network",
                            2,
                            "Kernel-level traffic detected".to_string(),
                            json!({ "source": format!("CPU_{}_EVENT", cpu_id) }),
                        ).await;
                    }
                }
            }
        });
    }

    loop {
        sys.refresh_all();
        audit_system_changes(&client, &mut state).await;

        let heartbeat = json!({
            "probe_id": PROBE_ID,
            "event_type": "heartbeat",
            "severity": 1,
            "timestamp": now_ts(),
            "payload": {
                "status": "active",
                "version": "1.1.0",
                "os": System::name().unwrap_or_else(|| "unknown".to_string()),
                "kernel": System::kernel_version().unwrap_or_default(),
                "cpu_usage": sys.global_cpu_info().cpu_usage(),
                "mem_used": sys.used_memory(),
                "uptime": System::uptime(),
                "iface": IFACE
            }
        });

        match client.post(INGEST_URL).json(&heartbeat).send().await {
            Ok(response) => handle_ingest_response(&client, response).await,
            Err(error) => warn!("[SnipeCon] heartbeat failed: {}", error),
        }
        sleep(Duration::from_secs(HEARTBEAT_INTERVAL_SECS)).await;
    }
}
