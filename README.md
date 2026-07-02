# Port Sacnner

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
