use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

// ── ANSI colours ─────────────────────────────────────────────────────────────

const GREEN:  &str = "\x1b[38;2;63;185;80m";
const RED:    &str = "\x1b[38;2;248;81;73m";
const YELLOW: &str = "\x1b[38;2;210;153;34m";
const BLUE:   &str = "\x1b[38;2;88;166;255m";
const DIM:    &str = "\x1b[2m";
const BOLD:   &str = "\x1b[1m";
const RESET:  &str = "\x1b[0m";

fn ok(s: &str)   -> String { format!("{GREEN}✔{RESET}  {s}") }
fn fail(s: &str) -> String { format!("{RED}✘{RESET}  {s}") }
fn warn(s: &str) -> String { format!("{YELLOW}!{RESET}  {s}") }

fn header(s: &str) {
    println!("\n{BOLD}{BLUE}{s}{RESET}");
    println!("{DIM}{}{RESET}", "─".repeat(s.len()));
}

// ── DNS ───────────────────────────────────────────────────────────────────────

async fn check_dns(host: &str) -> Vec<String> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let (cfg, opts) = hickory_resolver::system_conf::read_system_conf()
        .unwrap_or_else(|_| (ResolverConfig::default(), ResolverOpts::default()));
    let resolver = TokioAsyncResolver::tokio(cfg, opts);

    // If it's an IP address, do a reverse lookup (PTR)
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        return match resolver.reverse_lookup(std::net::IpAddr::V4(ip)).await {
            Ok(r) => r.iter().map(|n| n.to_string().trim_end_matches('.').to_string()).collect(),
            Err(_) => vec![],
        };
    }

    match resolver.ipv4_lookup(host).await {
        Ok(r) => r.iter().map(|ip| ip.to_string()).collect(),
        Err(_) => vec![],
    }
}

// ── Ports ─────────────────────────────────────────────────────────────────────

const PORTS: &[(u16, &str)] = &[
    (21, "FTP"), (22, "SSH"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (443, "HTTPS"),
    (445, "SMB"), (587, "SMTP/TLS"), (993, "IMAPS"), (995, "POP3S"),
    (1433, "MSSQL"), (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"),
    (6379, "Redis"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"), (27017, "MongoDB"),
];

async fn check_ports(host: &str) -> Vec<(u16, &'static str, bool)> {
    let mut handles = vec![];
    let host = host.to_string();

    for &(port, service) in PORTS {
        let h = host.clone();
        handles.push(tokio::spawn(async move {
            let open = tokio::task::spawn_blocking(move || {
                let addr_str = format!("{}:{}", h, port);
                match addr_str.parse::<SocketAddr>() {
                    Ok(addr) => TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok(),
                    Err(_) => {
                        // hostname — resolve via ToSocketAddrs
                        use std::net::ToSocketAddrs;
                        match addr_str.to_socket_addrs() {
                            Ok(mut addrs) => addrs.next()
                                .map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok())
                                .unwrap_or(false),
                            Err(_) => false,
                        }
                    }
                }
            }).await.unwrap_or(false);
            (port, service, open)
        }));
    }

    let mut results = vec![];
    for h in handles {
        if let Ok(r) = h.await { results.push(r); }
    }
    results.sort_by_key(|r| r.0);
    results
}

async fn check_ports_list(host: &str, ports: &[u16]) -> Vec<(u16, &'static str, bool)> {
    let mut handles = vec![];
    let host = host.to_string();
    for &port in ports {
        let h = host.clone();
        handles.push(tokio::spawn(async move {
            let open = tokio::task::spawn_blocking(move || {
                use std::net::ToSocketAddrs;
                let addr_str = format!("{}:{}", h, port);
                match addr_str.to_socket_addrs() {
                    Ok(mut addrs) => addrs.next()
                        .map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(2)).is_ok())
                        .unwrap_or(false),
                    Err(_) => false,
                }
            }).await.unwrap_or(false);
            (port, "", open)
        }));
    }
    let mut results = vec![];
    for h in handles {
        if let Ok(r) = h.await { results.push(r); }
    }
    results.sort_by_key(|r| r.0);
    results
}

// ── SSL ───────────────────────────────────────────────────────────────────────

struct SslInfo {
    valid: bool,
    days:  Option<i64>,
    subject: String,
    issuer:  String,
    error:   Option<String>,
}

fn check_ssl(host: &str) -> SslInfo {
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use std::net::TcpStream as StdTcp;

    let addr = format!("{}:443", host);
    let stream = match StdTcp::connect(&addr as &str) {
        Ok(s) => s,
        Err(e) => return SslInfo { valid: false, days: None, subject: String::new(), issuer: String::new(), error: Some(e.to_string()) },
    };

    let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
    builder.set_verify(SslVerifyMode::PEER);
    let connector = builder.build();

    let ssl_stream = match connector.connect(host, stream) {
        Ok(s) => s,
        Err(e) => return SslInfo { valid: false, days: None, subject: String::new(), issuer: String::new(), error: Some(e.to_string()) },
    };

    let cert = ssl_stream.ssl().peer_certificate().unwrap();
    let not_after = cert.not_after();
    let now = openssl::asn1::Asn1Time::days_from_now(0).unwrap();
    let days = not_after.diff(&now).map(|d| -d.days as i64).ok();

    let subject = cert.subject_name().entries()
        .filter(|e| e.object().nid() == openssl::nid::Nid::COMMONNAME)
        .map(|e| e.data().as_utf8().unwrap().to_string())
        .next().unwrap_or_default();

    let issuer = cert.issuer_name().entries()
        .filter(|e| e.object().nid() == openssl::nid::Nid::ORGANIZATIONNAME)
        .map(|e| e.data().as_utf8().unwrap().to_string())
        .next().unwrap_or_default();

    SslInfo { valid: true, days, subject, issuer, error: None }
}

// ── Ping ──────────────────────────────────────────────────────────────────────

struct PingInfo {
    avg_ms: Option<f64>,
    loss:   Option<f64>,
    error:  Option<String>,
}

fn check_ping(host: &str) -> PingInfo {
    let out = std::process::Command::new("ping")
        .args(["-c", "4", "-W", "2", host])
        .output();

    match out {
        Err(e) => PingInfo { avg_ms: None, loss: None, error: Some(e.to_string()) },
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            if stderr.contains("not permitted") {
                return PingInfo { avg_ms: None, loss: None, error: Some("requires root or cap_net_raw".into()) };
            }
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();

            let avg_ms = stdout.lines()
                .find(|l| l.contains("rtt") || l.contains("round-trip"))
                .and_then(|l| l.split('/').nth(4))
                .and_then(|s| s.trim().parse::<f64>().ok());

            let loss = stdout.lines()
                .find(|l| l.contains("packet loss"))
                .and_then(|l| l.split('%').next())
                .and_then(|s| s.split_whitespace().last())
                .and_then(|s| s.parse::<f64>().ok());

            PingInfo { avg_ms, loss, error: None }
        }
    }
}

// ── Parse port list ("22,80,443" or "8000-8010") ─────────────────────────────

fn parse_ports(s: &str) -> Vec<u16> {
    let mut ports = vec![];
    for part in s.split(',') {
        let p = part.trim();
        if let Some((a, b)) = p.split_once('-') {
            if let (Ok(from), Ok(to)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                for port in from..=to { ports.push(port); }
            }
        } else if let Ok(port) = p.parse::<u16>() {
            ports.push(port);
        }
    }
    ports.sort();
    ports.dedup();
    ports
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Simple arg parsing: netblame-cli [-a] [-p ports] <host>
    let mut show_all   = false;
    let mut custom_ports: Option<Vec<u16>> = None;
    let mut host_arg: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-a" => { show_all = true; }
            "-p" => {
                i += 1;
                if i < args.len() { custom_ports = Some(parse_ports(&args[i])); }
            }
            _ => { host_arg = Some(args[i].clone()); }
        }
        i += 1;
    }

    let host = match host_arg {
        Some(h) => h.trim_end_matches('.').to_string(),
        None => {
            eprintln!("Usage: netblame-cli [-a] [-p 22,80,443] <host>");
            std::process::exit(1);
        }
    };

    println!("\n{BOLD}netblame{RESET}  {DIM}{host}{RESET}");

    // ── DNS ──
    header("DNS");
    let addrs = check_dns(&host).await;
    if addrs.is_empty() {
        println!("{}", fail("no addresses found"));
    } else {
        for (i, addr) in addrs.iter().enumerate() {
            if i == 0 {
                println!("{}  {}", ok(addr), "");
            } else {
                println!("   {DIM}{addr}{RESET}");
            }
        }
    }

    // ── Ports ──
    let port_list = custom_ports.as_deref().unwrap_or(&[]);
    let using_custom = custom_ports.is_some();

    if using_custom {
        header(&format!("PORTS  {DIM}custom{RESET}"));
    } else {
        header("PORTS");
    }

    let ports = if using_custom {
        check_ports_list(&host, port_list).await
    } else {
        check_ports(&host).await
    };

    let open_count  = ports.iter().filter(|p| p.2).count();
    let closed_count = ports.len() - open_count;

    for (port, svc, open) in &ports {
        if *open {
            let label = if svc.is_empty() { format!("{port:<5}") } else { format!("{port:<5} {svc}") };
            println!("{}", ok(&label));
        } else if show_all || using_custom {
            let label = if svc.is_empty() { format!("{port:<5}") } else { format!("{port:<5} {svc}") };
            println!("{}", fail(&label));
        }
    }
    if open_count == 0 {
        println!("{}", warn("no open ports found"));
    }
    if !show_all && !using_custom {
        println!("{DIM}  {closed_count} ports closed / filtered  (use -a to show all){RESET}");
    }

    // ── SSL ──
    header("SSL");
    let ssl = tokio::task::spawn_blocking({
        let h = host.clone();
        move || check_ssl(&h)
    }).await.unwrap();

    if let Some(err) = &ssl.error {
        println!("{}", fail(err));
    } else if ssl.valid {
        let days = ssl.days.unwrap_or(0);
        let status = if days > 30 { ok(&format!("valid  {days} days remaining")) }
                     else if days > 0 { warn(&format!("expiring in {days} days")) }
                     else { fail("expired") };
        println!("{status}");
        if !ssl.subject.is_empty() { println!("{DIM}   CN  {}{RESET}", ssl.subject); }
        if !ssl.issuer.is_empty()  { println!("{DIM}   CA  {}{RESET}", ssl.issuer);  }
    }

    // ── Ping ──
    header("PING");
    let ping = tokio::task::spawn_blocking({
        let h = host.clone();
        move || check_ping(&h)
    }).await.unwrap();

    if let Some(err) = &ping.error {
        println!("{}", warn(err));
    } else {
        let avg  = ping.avg_ms.map(|v| format!("{v:.1} ms")).unwrap_or_else(|| "timeout".into());
        let loss = ping.loss.unwrap_or(100.0);
        let line = format!("{avg}  {loss}% loss");
        if loss == 0.0 { println!("{}", ok(&line)); }
        else if loss < 50.0 { println!("{}", warn(&line)); }
        else { println!("{}", fail(&line)); }
    }

    println!();
}
