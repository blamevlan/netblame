# netblame

A desktop app for debugging network infrastructure — built with Tauri v2 and Rust.

![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)
![Rust](https://img.shields.io/badge/Rust-000000?style=flat&logo=rust&logoColor=white)
![Tauri](https://img.shields.io/badge/Tauri-24C8D8?style=flat&logo=tauri&logoColor=white)

## Features

- **Host Check** DNS resolution, port scan (top 20), SSL certificate validation, ping, latency, MAC address lookup
- **DNS Records** A, MX, NS, TXT, CNAME records via system resolver
- **HTTP/S** Full redirect chain, response headers, response time
- **Ping** Live streaming output with packet loss stats
- **Traceroute** Hop-by-hop streaming output
- **Whois** Raw whois data for any domain or IP
- **Network Scan** Discovers live hosts on your local subnet via ARP + TCP probing

## Installation

**Fedora / RHEL:**
```bash
sudo dnf install netblame-*.x86_64.rpm
```

After installation, netblame appears in your application menu.

> Tested on Fedora. A `.deb` package is also produced by the build but has not been tested on Debian/Ubuntu.

## Build from source

Requirements: [Rust](https://rustup.rs), [Tauri CLI v2](https://tauri.app/start/create-project/)

```bash
git clone https://github.com/blamevlan/netblame.git
cd netblame
cargo tauri build
```

Packages are output to `src-tauri/target/release/bundle/`.

## Notes

- Ping and traceroute require raw socket permissions. If ping shows no results, run with `sudo` or set the capability:
  ```bash
  sudo setcap cap_net_raw+ep $(which ping)
  ```
- Network scan only works on local subnets (private IP ranges).
- MAC address lookup only available for hosts on the same network segment.

## License

MIT
