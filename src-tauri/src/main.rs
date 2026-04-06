#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

// ── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct DnsResult {
    addresses: Vec<String>,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PortResult {
    port: u16,
    service: String,
    open: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct SslResult {
    valid: bool,
    days_remaining: Option<i64>,
    subject: Option<String>,
    issuer: Option<String>,
    expires: Option<String>,
    error: Option<String>,
}

// ── Common ports ──────────────────────────────────────────────────────────────

const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (80, "HTTP"),
    (110, "POP3"),
    (143, "IMAP"),
    (443, "HTTPS"),
    (445, "SMB"),
    (587, "SMTP/TLS"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1433, "MSSQL"),
    (3306, "MySQL"),
    (3389, "RDP"),
    (5432, "Postgres"),
    (6379, "Redis"),
    (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"),
];

// ── Commands ──────────────────────────────────────────────────────────────────

#[tauri::command]
async fn check_dns(host: String) -> DnsResult {
    match tokio::net::lookup_host(format!("{}:0", host)).await {
        Ok(addrs) => {
            let mut seen = std::collections::HashSet::new();
            let addresses: Vec<String> = addrs
                .filter(|a| a.is_ipv4())
                .map(|a| a.ip().to_string())
                .filter(|ip| seen.insert(ip.clone()))
                .collect();

            if addresses.is_empty() {
                DnsResult {
                    addresses: vec![],
                    error: Some("No IPv4 addresses found".to_string()),
                }
            } else {
                DnsResult {
                    addresses,
                    error: None,
                }
            }
        }
        Err(e) => DnsResult {
            addresses: vec![],
            error: Some(e.to_string()),
        },
    }
}

#[tauri::command]
async fn check_ports(host: String) -> Vec<PortResult> {
    // Resolve once, scan IP directly for all ports.
    let ip = match tokio::net::lookup_host(format!("{}:80", &host)).await {
        Ok(mut addrs) => addrs
            .find(|a| a.is_ipv4())
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| host.clone()),
        Err(_) => host.clone(),
    };

    let handles: Vec<_> = COMMON_PORTS
        .iter()
        .map(|&(port, service)| {
            let ip = ip.clone();
            let service = service.to_string();
            tokio::spawn(async move {
                let addr = format!("{}:{}", ip, port);
                let open = tokio::time::timeout(
                    Duration::from_secs(2),
                    tokio::net::TcpStream::connect(&addr),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
                PortResult { port, service, open }
            })
        })
        .collect();

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(r) = handle.await {
            results.push(r);
        }
    }
    results.sort_by_key(|r| r.port);
    results
}

#[tauri::command]
async fn check_ssl(host: String) -> SslResult {
    // SSL requires SNI — doesn't work with bare IPs.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return SslResult {
            valid: false,
            days_remaining: None,
            subject: None,
            issuer: None,
            expires: None,
            error: Some("SSL check requires a domain name, not a bare IP".to_string()),
        };
    }

    let addr: SocketAddr =
        match tokio::net::lookup_host(format!("{}:443", &host)).await {
            Ok(mut addrs) => match addrs.find(|a| a.is_ipv4()) {
                Some(a) => a,
                None => {
                    return SslResult {
                        valid: false,
                        days_remaining: None,
                        subject: None,
                        issuer: None,
                        expires: None,
                        error: Some("DNS resolution failed (no IPv4 record)".to_string()),
                    }
                }
            },
            Err(e) => {
                return SslResult {
                    valid: false,
                    days_remaining: None,
                    subject: None,
                    issuer: None,
                    expires: None,
                    error: Some(format!("DNS error: {}", e)),
                }
            }
        };

    let host_clone = host.clone();

    tokio::task::spawn_blocking(move || {
        use openssl::ssl::{SslConnector, SslMethod};

        let connector = match SslConnector::builder(SslMethod::tls()) {
            Ok(b) => b.build(),
            Err(e) => {
                return SslResult {
                    valid: false,
                    days_remaining: None,
                    subject: None,
                    issuer: None,
                    expires: None,
                    error: Some(format!("SSL init: {}", e)),
                }
            }
        };

        let tcp = match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
            Ok(s) => s,
            Err(e) => {
                return SslResult {
                    valid: false,
                    days_remaining: None,
                    subject: None,
                    issuer: None,
                    expires: None,
                    error: Some(format!("TCP connect: {}", e)),
                }
            }
        };

        let ssl_stream = match connector.connect(&host_clone, tcp) {
            Ok(s) => s,
            Err(e) => {
                return SslResult {
                    valid: false,
                    days_remaining: None,
                    subject: None,
                    issuer: None,
                    expires: None,
                    error: Some(format!("TLS handshake: {}", e)),
                }
            }
        };

        let cert = match ssl_stream.ssl().peer_certificate() {
            Some(c) => c,
            None => {
                return SslResult {
                    valid: false,
                    days_remaining: None,
                    subject: None,
                    issuer: None,
                    expires: None,
                    error: Some("No certificate presented".to_string()),
                }
            }
        };

        let not_after = cert.not_after();
        let expires_str = not_after.to_string();

        // days_from_now(0) = now; diff returns (other - self) in days
        let days_remaining = openssl::asn1::Asn1Time::days_from_now(0)
            .ok()
            .and_then(|now| now.diff(not_after).ok())
            .map(|diff| diff.days as i64);

        let valid = days_remaining.map(|d| d >= 0).unwrap_or(false);

        let subject = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string());

        let issuer = cert
            .issuer_name()
            .entries_by_nid(openssl::nid::Nid::ORGANIZATIONNAME)
            .next()
            .and_then(|e| e.data().as_utf8().ok())
            .map(|s| s.to_string());

        SslResult {
            valid,
            days_remaining,
            subject,
            issuer,
            expires: Some(expires_str),
            error: None,
        }
    })
    .await
    .unwrap_or_else(|e| SslResult {
        valid: false,
        days_remaining: None,
        subject: None,
        issuer: None,
        expires: None,
        error: Some(format!("Task error: {}", e)),
    })
}

// ── Ping & latency ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct PingResult {
    success: bool,
    avg_ms: Option<f64>,
    packet_loss: Option<u8>,
    requires_root: bool,
    error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LatencyResult {
    ms: Option<u64>,
    port: Option<u16>,
    error: Option<String>,
}

#[tauri::command]
async fn check_ping(host: String) -> PingResult {
    let host_clone = host.clone();
    tokio::task::spawn_blocking(move || {
        let output = std::process::Command::new("ping")
            .args(["-c", "3", "-W", "2", &host_clone])
            .output();

        match output {
            Err(e) => PingResult {
                success: false,
                avg_ms: None,
                packet_loss: None,
                requires_root: false,
                error: Some(format!("ping not found: {}", e)),
            },
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
                let stdout = String::from_utf8_lossy(&out.stdout);

                if stderr.contains("operation not permitted")
                    || stderr.contains("permission denied")
                {
                    return PingResult {
                        success: false,
                        avg_ms: None,
                        packet_loss: None,
                        requires_root: true,
                        error: Some(
                            "ICMP requires elevated privileges on this system".to_string(),
                        ),
                    };
                }

                // Parse "X% packet loss"
                let loss: Option<u8> = stdout
                    .lines()
                    .find(|l| l.contains("packet loss"))
                    .and_then(|l| {
                        let pct = l.split('%').next()?;
                        pct.split_whitespace().last()?.parse().ok()
                    });

                // Parse "rtt min/avg/max/mdev = X/AVG/X/X ms"
                let avg: Option<f64> = stdout
                    .lines()
                    .find(|l| l.starts_with("rtt") || l.starts_with("round-trip"))
                    .and_then(|l| l.split('=').nth(1))
                    .and_then(|stats| stats.trim().split('/').nth(1))
                    .and_then(|s| s.parse().ok());

                PingResult {
                    success: out.status.success() && loss.map(|l| l < 100).unwrap_or(false),
                    avg_ms: avg,
                    packet_loss: loss,
                    requires_root: false,
                    error: if out.status.success() {
                        None
                    } else {
                        Some(String::from_utf8_lossy(&out.stderr).trim().to_string())
                    },
                }
            }
        }
    })
    .await
    .unwrap_or_else(|e| PingResult {
        success: false,
        avg_ms: None,
        packet_loss: None,
        requires_root: false,
        error: Some(format!("Task error: {}", e)),
    })
}

#[tauri::command]
async fn check_latency(host: String) -> LatencyResult {
    // Try port 80 first, then 443.
    for port in [80u16, 443] {
        let addr = match tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            Ok(mut a) => match a.find(|x| x.is_ipv4()) {
                Some(a) => a,
                None => continue,
            },
            Err(_) => continue,
        };
        let start = std::time::Instant::now();
        if tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false)
        {
            return LatencyResult {
                ms: Some(start.elapsed().as_millis() as u64),
                port: Some(port),
                error: None,
            };
        }
    }
    LatencyResult {
        ms: None,
        port: None,
        error: Some("No response on port 80 or 443".to_string()),
    }
}

// ── MAC via ARP ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct MacResult {
    mac: Option<String>,
    is_local: bool,
    /// Human-readable note when MAC can't be shown
    note: Option<String>,
}

fn is_private_ip(ip: &str) -> bool {
    if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
        return addr.is_private() || addr.is_loopback() || addr.is_link_local();
    }
    false
}

#[tauri::command]
async fn check_mac(host: String) -> MacResult {
    // Resolve to IPv4 first.
    let ip = match tokio::net::lookup_host(format!("{}:0", &host)).await {
        Ok(mut a) => match a.find(|x| x.is_ipv4()) {
            Some(a) => a.ip().to_string(),
            None => {
                return MacResult {
                    mac: None,
                    is_local: false,
                    note: Some("Could not resolve host".to_string()),
                }
            }
        },
        Err(_) => {
            return MacResult {
                mac: None,
                is_local: false,
                note: Some("DNS resolution failed".to_string()),
            }
        }
    };

    if !is_private_ip(&ip) {
        return MacResult {
            mac: None,
            is_local: false,
            note: Some("Remote host — MAC not visible beyond local network".to_string()),
        };
    }

    // Read ARP table from /proc/net/arp
    // Format: IP address  HW type  Flags  HW address        Mask  Device
    let arp = match std::fs::read_to_string("/proc/net/arp") {
        Ok(s) => s,
        Err(e) => {
            return MacResult {
                mac: None,
                is_local: true,
                note: Some(format!("Cannot read ARP table: {}", e)),
            }
        }
    };

    for line in arp.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == ip {
            let mac = cols[3].to_string();
            // ARP entries with MAC 00:00:00:00:00:00 are incomplete
            if mac == "00:00:00:00:00:00" {
                return MacResult {
                    mac: None,
                    is_local: true,
                    note: Some("ARP entry incomplete — try pinging the host first".to_string()),
                };
            }
            return MacResult {
                mac: Some(mac),
                is_local: true,
                note: None,
            };
        }
    }

    MacResult {
        mac: None,
        is_local: true,
        note: Some("Not in ARP table — host may be unreachable or not yet contacted".to_string()),
    }
}

// ── Network scanner ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SubnetInfo {
    interface: String,
    local_ip: String,
    prefix_len: u8,
    scan_count: usize, // IPs that will be scanned
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct NetworkHost {
    ip: String,
    hostname: Option<String>,
    mac: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScanProgress {
    scanned: usize,
    total: usize,
}

fn ip_to_u32(ip: &str) -> Option<u32> {
    let p: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if p.len() != 4 { return None; }
    Some(u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
}

fn u32_to_ip(n: u32) -> String {
    let b = n.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

// Returns IPs to scan for a given local IP + prefix.
// Subnets larger than /24 are capped to the /24 containing the local IP.
fn subnet_ips(local_ip: &str, prefix_len: u8) -> Vec<String> {
    let effective = prefix_len.max(24);
    let host = match ip_to_u32(local_ip) { Some(h) => h, None => return vec![] };
    let mask = if effective == 32 { u32::MAX } else { !((1u32 << (32 - effective)) - 1) };
    let network = host & mask;
    let broadcast = network | !mask;
    (network + 1..broadcast).map(u32_to_ip).collect()
}

#[tauri::command]
async fn get_subnets() -> Vec<SubnetInfo> {
    let output = match tokio::task::spawn_blocking(|| {
        std::process::Command::new("ip")
            .args(["-o", "-4", "addr", "show"])
            .output()
    })
    .await
    {
        Ok(Ok(o)) => o,
        _ => return vec![],
    };

    let mut subnets = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let iface = parts[1].trim_end_matches(':');
        if iface == "lo" { continue; }

        if let Some(idx) = parts.iter().position(|&p| p == "inet") {
            if let Some(cidr) = parts.get(idx + 1) {
                if let Some((ip, prefix_str)) = cidr.split_once('/') {
                    if let Ok(prefix_len) = prefix_str.parse::<u8>() {
                        if prefix_len <= 30 {
                            let scan_count = subnet_ips(ip, prefix_len).len();
                            subnets.push(SubnetInfo {
                                interface: iface.to_string(),
                                local_ip: ip.to_string(),
                                prefix_len,
                                scan_count,
                            });
                        }
                    }
                }
            }
        }
    }
    subnets
}

fn arp_table() -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 && cols[3] != "00:00:00:00:00:00" {
                map.insert(cols[0].to_string(), cols[3].to_string());
            }
        }
    }
    map
}

fn reverse_lookup(ip: &str) -> Option<String> {
    let out = std::process::Command::new("getent")
        .args(["hosts", ip])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    // Format: "1.2.3.4  hostname.local hostname"
    s.split_whitespace().nth(1).map(|s| s.to_string())
}

#[tauri::command]
async fn scan_network(
    local_ip: String,
    prefix_len: u8,
    app: tauri::AppHandle,
) -> usize {
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use tauri::Emitter;

    let ips = subnet_ips(&local_ip, prefix_len);
    let total = ips.len();
    let scanned = Arc::new(AtomicUsize::new(0));
    let semaphore = Arc::new(tokio::sync::Semaphore::new(60));

    let mut handles = Vec::new();

    for ip in ips {
        let sem = semaphore.clone();
        let scanned = scanned.clone();
        let app = app.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            // TCP probe: first hit on any of these ports → host is alive
            let probe_ports = [22u16, 80, 443, 8080, 8443, 53, 21, 25, 3306, 5432];
            let alive = {
                let ip_ref = &ip;
                let mut found = false;
                for &port in &probe_ports {
                    if tokio::time::timeout(
                        Duration::from_millis(400),
                        tokio::net::TcpStream::connect(format!("{}:{}", ip_ref, port)),
                    )
                    .await
                    .map(|r| r.is_ok())
                    .unwrap_or(false)
                    {
                        found = true;
                        break;
                    }
                }
                found
            };

            let done = scanned.fetch_add(1, Ordering::Relaxed) + 1;
            let _ = app.emit("scan-progress", ScanProgress { scanned: done, total });

            if alive {
                // Enrich: hostname + MAC (blocking calls)
                let ip_c = ip.clone();
                let (hostname, mac) = tokio::task::spawn_blocking(move || {
                    let hostname = reverse_lookup(&ip_c);
                    let mac = arp_table().get(&ip_c).cloned();
                    (hostname, mac)
                })
                .await
                .unwrap_or((None, None));

                let _ = app.emit("host-found", NetworkHost { ip, hostname, mac });
            }
        }));
    }

    for h in handles { let _ = h.await; }
    let _ = app.emit("scan-complete", total);
    total
}

// ── Ping streaming ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PingLine {
    line: String,
    is_reply: bool,
    is_timeout: bool,
    is_stats: bool,
    requires_root: bool,
}

#[tauri::command]
async fn run_ping(host: String, count: u32, app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Emitter;
    use tokio::io::AsyncBufReadExt;

    // count = 0 means continuous (-c not passed, user must stop manually)
    let mut args: Vec<String> = Vec::new();
    if count > 0 {
        args.push("-c".into());
        args.push(count.to_string());
    }
    args.push(host.clone());

    let mut child = tokio::process::Command::new("ping")
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start ping: {}", e))?;

    // Check stderr first line for permission error
    let stderr_handle = child.stderr.take();
    let app_err = app.clone();
    if let Some(stderr) = stderr_handle {
        tokio::spawn(async move {
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            if let Ok(Some(line)) = lines.next_line().await {
                let lower = line.to_lowercase();
                if lower.contains("operation not permitted") || lower.contains("permission denied") {
                    let _ = app_err.emit("ping-line", PingLine {
                        line: "ICMP ping requires elevated privileges on this system.".into(),
                        is_reply: false, is_timeout: false, is_stats: false, requires_root: true,
                    });
                }
            }
        });
    }

    if let Some(stdout) = child.stdout.take() {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let is_reply   = line.contains("bytes from") || line.contains("icmp_seq");
            let is_timeout = line.contains("Request timeout") || line.contains("no answer");
            let is_stats   = line.contains("packets transmitted") || line.contains("round-trip") || line.contains("rtt");
            let _ = app.emit("ping-line", PingLine {
                line: line.clone(), is_reply, is_timeout, is_stats, requires_root: false,
            });
        }
    }

    let _ = child.wait().await;
    let _ = app.emit("ping-done", ());
    Ok(())
}

#[tauri::command]
async fn stop_ping() -> Result<(), String> {
    // Ping is stopped from the frontend by killing the process via the done event;
    // actual process kill is handled by dropping the child — we signal via event.
    Ok(())
}

// ── DNS Records ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct DnsRecordsResult {
    a:     Vec<String>,
    mx:    Vec<String>,
    ns:    Vec<String>,
    txt:   Vec<String>,
    cname: Vec<String>,
    error: Option<String>,
}

#[tauri::command]
async fn check_dns_records(host: String) -> DnsRecordsResult {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::proto::rr::RecordType;
    use hickory_resolver::TokioAsyncResolver;

    // Prefer system resolv.conf; fall back to Google DNS
    let (cfg, opts) = hickory_resolver::system_conf::read_system_conf()
        .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));

    let resolver = TokioAsyncResolver::tokio(cfg, opts);

    // No trailing dot — let hickory handle FQDN normalisation
    let fqdn = host.trim_end_matches('.').to_string();

    let mut first_err: Option<String> = None;

    let a: Vec<String> = match resolver.ipv4_lookup(fqdn.as_str()).await {
        Ok(r)  => r.iter().map(|ip| ip.to_string()).collect(),
        Err(e) => { first_err.get_or_insert(e.to_string()); vec![] }
    };

    let mx: Vec<String> = match resolver.mx_lookup(fqdn.as_str()).await {
        Ok(r)  => r.iter().map(|mx| format!("{} {}", mx.preference(), mx.exchange())).collect(),
        Err(e) => { first_err.get_or_insert(e.to_string()); vec![] }
    };

    let ns: Vec<String> = match resolver.ns_lookup(fqdn.as_str()).await {
        Ok(r)  => r.iter().map(|n| n.0.to_string()).collect(),
        Err(e) => { first_err.get_or_insert(e.to_string()); vec![] }
    };

    let txt: Vec<String> = match resolver.txt_lookup(fqdn.as_str()).await {
        Ok(r)  => r.iter()
            .map(|t| t.iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join(""))
            .collect(),
        Err(e) => { first_err.get_or_insert(e.to_string()); vec![] }
    };

    let cname: Vec<String> = match resolver.lookup(fqdn.as_str(), RecordType::CNAME).await {
        Ok(r)  => r.iter()
            .filter_map(|rdata| {
                use hickory_resolver::proto::rr::RData;
                if let RData::CNAME(c) = rdata { Some(c.0.to_string()) } else { None }
            })
            .collect(),
        Err(e) => { first_err.get_or_insert(e.to_string()); vec![] }
    };

    // If everything is empty and we have an error, report it
    let error = if a.is_empty() && mx.is_empty() && ns.is_empty() && txt.is_empty() && cname.is_empty() {
        first_err
    } else {
        None
    };

    DnsRecordsResult { a, mx, ns, txt, cname, error }
}

// ── HTTP Check ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Clone)]
struct RedirectStep {
    url: String,
    status: u16,
}

#[derive(Debug, Serialize, Deserialize)]
struct HttpResult {
    final_url: String,
    status: u16,
    redirects: Vec<RedirectStep>,
    headers: Vec<(String, String)>,
    response_ms: u64,
    error: Option<String>,
}

#[tauri::command]
async fn check_http(url: String) -> HttpResult {
    // Prepend https:// if no scheme given
    let start_url = if url.starts_with("http://") || url.starts_with("https://") {
        url.clone()
    } else {
        format!("https://{}", url)
    };

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(false)
        .build()
    {
        Ok(c) => c,
        Err(e) => return HttpResult {
            final_url: start_url, status: 0, redirects: vec![],
            headers: vec![], response_ms: 0, error: Some(e.to_string()),
        },
    };

    let mut current = start_url.clone();
    let mut redirects: Vec<RedirectStep> = Vec::new();
    let timer = std::time::Instant::now();

    loop {
        let resp = match client.get(&current).send().await {
            Ok(r) => r,
            Err(e) => return HttpResult {
                final_url: current, status: 0, redirects,
                headers: vec![], response_ms: timer.elapsed().as_millis() as u64,
                error: Some(e.to_string()),
            },
        };

        let status = resp.status().as_u16();

        if (300..400).contains(&(status as i32)) {
            let location = resp.headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            redirects.push(RedirectStep { url: current.clone(), status });

            if location.is_empty() || redirects.len() >= 10 { break; }

            // Handle relative redirects
            current = if location.starts_with("http") {
                location
            } else {
                format!("{}/{}", current.trim_end_matches('/'), location.trim_start_matches('/'))
            };
            continue;
        }

        let headers: Vec<(String, String)> = resp.headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("?").to_string()))
            .collect();

        return HttpResult {
            final_url: current,
            status,
            redirects,
            headers,
            response_ms: timer.elapsed().as_millis() as u64,
            error: None,
        };
    }

    HttpResult {
        final_url: current, status: 0, redirects,
        headers: vec![], response_ms: timer.elapsed().as_millis() as u64,
        error: Some("Too many redirects or no final destination".to_string()),
    }
}

// ── Whois ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct WhoisResult {
    raw: String,
    error: Option<String>,
}

#[tauri::command]
async fn check_whois(host: String) -> WhoisResult {
    let host_clone = host.clone();
    tokio::task::spawn_blocking(move || {
        match std::process::Command::new("whois").arg(&host_clone).output() {
            Ok(o) => WhoisResult {
                raw: String::from_utf8_lossy(&o.stdout).to_string(),
                error: None,
            },
            Err(e) => WhoisResult {
                raw: String::new(),
                error: Some(format!("`whois` not found — install: sudo dnf install whois  ({})", e)),
            },
        }
    })
    .await
    .unwrap_or_else(|e| WhoisResult { raw: String::new(), error: Some(e.to_string()) })
}

// ── Traceroute ────────────────────────────────────────────────────────────────

#[tauri::command]
async fn run_traceroute(host: String, app: tauri::AppHandle) -> Result<(), String> {
    use tauri::Emitter;
    use tokio::io::AsyncBufReadExt;

    // Prefer traceroute; fall back to tracepath (no root needed)
    let (cmd, args): (&str, Vec<String>) =
        if std::path::Path::new("/usr/bin/traceroute").exists()
            || std::path::Path::new("/bin/traceroute").exists()
        {
            ("traceroute", vec!["-m".into(), "30".into(), host.clone()])
        } else {
            ("tracepath", vec!["-m".into(), "30".into(), host.clone()])
        };

    let mut child = tokio::process::Command::new(cmd)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not start {}: {}", cmd, e))?;

    if let Some(stdout) = child.stdout.take() {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = app.emit("traceroute-line", line);
        }
    }

    let _ = child.wait().await;
    let _ = app.emit("traceroute-done", ());
    Ok(())
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            use tauri::Manager;
            if let Some(win) = app.get_webview_window("main") {
                let icon_bytes: &[u8] = include_bytes!("../icons/icon.png");
                if let Ok(img) = tauri::image::Image::from_bytes(icon_bytes) {
                    let _ = win.set_icon(img);
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            check_dns,
            check_ports,
            check_ssl,
            check_ping,
            check_latency,
            check_mac,
            get_subnets,
            scan_network,
            run_ping,
            stop_ping,
            check_dns_records,
            check_http,
            check_whois,
            run_traceroute,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
