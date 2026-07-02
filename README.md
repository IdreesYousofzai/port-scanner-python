# Port Scanner

A basic multi-threaded TCP port scanner built with Python's `socket` and
`concurrent.futures` libraries. Built as a cybersecurity learning project
covering networking fundamentals, concurrency, and CLI tool design.

---

## ⚠️ Ethical & Legal Disclaimer — READ FIRST

**Only scan hosts and networks that you own, or that you have explicit,
written permission to test.**

Port scanning a system you don't own or have authorization for is illegal
in most jurisdictions, regardless of intent — for example:

- **UK**: the **Computer Misuse Act 1990** makes unauthorised access to a
  computer system a criminal offence, even if no data is changed or stolen
  and even if the scan is "just reconnaissance."
- **US**: the **Computer Fraud and Abuse Act (CFAA)** carries similar
  unauthorised-access provisions.
- Most other countries have equivalent computer misuse laws.

A port scan can also trigger intrusion-detection alerts and be treated as
the first stage of an attack by the target's security team, even on
networks you think are "fair game."

**Safe places to use this tool:**
- `127.0.0.1` / `localhost` — your own machine.
- Your own home network devices (e.g. a router or Raspberry Pi you own),
  ideally after confirming with anyone else on the network.
- Deliberately vulnerable practice environments built for this purpose —
  CTF platforms (Hack The Box, TryHackMe, PicoCTF), or local lab VMs like
  Metasploitable, DVWA, or a self-hosted target.
- Systems where you have **written authorization** (e.g. a pentest
  engagement letter or bug bounty scope).

**Never scan:** employer networks without written sign-off, public Wi-Fi,
university networks, IoT devices you don't own, or any third-party
infrastructure "just to see what happens."

This project is provided for educational purposes — learning how TCP
connections, ports, and services work. The author is not responsible for
any misuse of this tool.

---

## What is a port scan, and what does it reveal?

Every networked device has 65,535 TCP and 65,535 UDP ports. A port scanner
attempts to open a connection to a range of ports on a target and checks
whether the connection succeeds. If it does, something is listening on
that port — usually a specific service (a web server on port 80, SSH on
port 22, a database on port 3306, etc).

This reveals:
- **Which services are running** on a machine, which is the first step
  in both legitimate network administration and in an attacker's
  reconnaissance phase.
- **The attack surface** of a system — every open port is a potential
  entry point, so fewer unnecessary open ports means a smaller attack
  surface.
- **Misconfigurations** — e.g. a database port like 3306 (MySQL) or 5432
  (PostgreSQL) left open to the internet when it should only be reachable
  internally.

This is exactly why port scanning matters for defenders too: knowing what
your own network exposes is the foundation of good security hygiene.

## Legitimate use cases

- **Network administrators** — auditing which services are running on
  servers they manage, verifying firewall rules are working as intended,
  and catching services left open by mistake.
- **Penetration testers** — the reconnaissance phase of an authorized
  security assessment, used to map a client's attack surface before
  deeper testing (always within a signed scope of work).
- **CTF (Capture The Flag) challenges** — competitive hacking challenges
  are explicitly built to be scanned and exploited as a learning exercise.
- **Home lab / self-learning** — understanding your own devices, IoT
  gadgets, or home server setup.

---

## Features

- Pure Python `socket`-based TCP connect scanning (no third-party
  dependencies).
- **Multi-threaded** scanning via `concurrent.futures.ThreadPoolExecutor`
  — scans a full 1–1024 port range in a fraction of the time of a
  sequential scan.
- **Configurable timeout** per connection attempt.
- **Service detection** — a built-in dictionary maps common ports (22,
  80, 443, 3306, etc.) to their typical service names.
- **CLI arguments** for target, port range, timeout, and thread count.
- **Report saving** — optionally write results to a timestamped `.txt`
  report file.

## Requirements

- Python 3.9+
- No external dependencies (standard library only)

## Usage

```bash
# Default: scan localhost, ports 1-1024
python scanner.py

# Scan a specific target and port range
python scanner.py --target 127.0.0.1 --start-port 1 --end-port 1024

# Short flags, custom timeout and thread count
python scanner.py -t 127.0.0.1 -s 1 -e 65535 --timeout 0.3 --threads 200

# Save results to an auto-named, timestamped report
python scanner.py -t 127.0.0.1 --save

# Save results to a specific filename
python scanner.py -t 127.0.0.1 --save my_scan.txt
```

### Arguments

| Flag | Short | Default | Description |
|---|---|---|---|
| `--target` | `-t` | `127.0.0.1` | Target IP address or hostname |
| `--start-port` | `-s` | `1` | First port in the scan range |
| `--end-port` | `-e` | `1024` | Last port in the scan range |
| `--timeout` | | `0.5` | Socket timeout (seconds) per port |
| `--threads` | | `100` | Number of worker threads |
| `--save [FILENAME]` | | off | Save report; auto-timestamps if no filename given |

### Example output

```
Scanning 127.0.0.1 — ports 1-1024 (1024 ports, 100 threads, 0.5s timeout)

[+] Port    22 OPEN   -> SSH
[+] Port    80 OPEN   -> HTTP
[+] Port   443 OPEN   -> HTTPS

--------------------------------------------------
Scan complete in 1.42s. 3 open port(s) found.
--------------------------------------------------
  Port    22  ->  SSH
  Port    80  ->  HTTP
  Port   443  ->  HTTPS

[✓] Report saved to scan_report_20260702_101530.txt
```

## How it works

1. **Socket connect scan**: for each port, `scan_port()` opens a TCP
   socket and calls `connect_ex()` against `(target, port)`. `connect_ex`
   returns `0` on success instead of raising an exception, which is
   faster to check across thousands of ports than wrapping `connect()`
   in `try/except`.
2. **Threading**: `ThreadPoolExecutor` submits one `scan_port` task per
   port and processes results as they complete via `as_completed()`,
   so open ports print as soon as they're found rather than waiting for
   the whole range to finish sequentially.
3. **Service detection**: open ports are looked up in the `COMMON_PORTS`
   dictionary to attach a human-readable label (falls back to
   `"Unknown"` for ports not in the dictionary).
4. **Reporting**: if `--save` is passed, results plus scan metadata
   (target, range, timeout, duration, timestamp) are written to a `.txt`
   file.
