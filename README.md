# netblame

netblame is a small Linux desktop tool for everyday network troubleshooting. I started it because I wanted the checks I use most often in one place instead of jumping between several commands and browser tools.

Current version: **0.1.0**

The project is still early. Fedora is the main tested platform at the moment. The build also produces a Debian package, but I have not tested that package on Debian or Ubuntu yet.

## What it does

- hostname resolution and DNS lookups
- common or custom TCP port checks
- TLS certificate checks
- HTTP and HTTPS redirect and header inspection
- ping and traceroute with live output
- whois lookups
- local subnet discovery
- a small CLI for quick host checks

## CLI

The repository also includes `netblame-cli`.

```text
netblame-cli github.com

DNS       ✔  140.82.121.3
PORTS     ✔  22    SSH
          ✔  80    HTTP
          ✔  443   HTTPS
             17 ports closed / filtered (use -a to show all)
SSL       ✔  valid  58 days remaining
             CN  github.com  ·  CA  Sectigo Limited
PING      ✔  11.0 ms  0% loss
```

A few examples:

```bash
netblame-cli -a github.com
netblame-cli -p 22,80,443 github.com
netblame-cli -p 8000-8010 github.com
```

Build the CLI with:

```bash
cargo build --manifest-path src-tauri/Cargo.toml --bin netblame-cli --release
```

The binary will be in `src-tauri/target/release/`.

## Build the desktop app

You need Rust and the Tauri v2 prerequisites for your distribution.

```bash
git clone https://github.com/blamevlan/netblame.git
cd netblame
cargo tauri build
```

Tauri writes the packages to:

```text
src-tauri/target/release/bundle/
```

If you already built an RPM, you can install it on Fedora with:

```bash
sudo dnf install ./src-tauri/target/release/bundle/rpm/netblame-*.x86_64.rpm
```

## Notes

Ping and traceroute depend on the permissions available to the system tools they call. On systems where raw socket access is restricted, the relevant capability may need to be set explicitly.

Network discovery is intended for local private subnets. MAC address information is only available for devices that are visible on the local network segment.

## License

MIT. See [LICENSE](LICENSE).
