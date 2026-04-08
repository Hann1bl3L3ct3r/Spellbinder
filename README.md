# Spellbinder: IPv6 MITM with DNS Spoofing or Relay

Spellbinder is a Python-based adversary-in-the-middle (AiTM) tool that emulates the behavior of APT actors leveraging SLAAC and Router Advertisements (RA) to bypass traditional DHCPv6 protections. It enables penetration testers to perform internal network assessments where clients automatically configure IPv6 without needing a DHCP server — a common misconfiguration in enterprise environments.

This tool supports **full DNS spoofing**, **targeted domain spoofing**, and **DNS relaying** (to upstream resolvers such as `8.8.8.8`), with real-time console logging of DNS queries for visibility.

---

## Features

- **SLAAC + RDNSS spoofing** using `radvd`
- **NAT64 support** via `tayga` with auto-derived prefix from user input
- **DNS response hijacking** using `dnsmasq`
- **Three DNS modes:** full spoof, relay, or targeted domain spoofing
- **Live DNS query logging** to the console
- **Full cleanup on exit:** restores iptables rules, dnsmasq.conf, removes TUN interface and assigned IPs
- **Bypasses DHCPv6 protections** by leveraging IPv6 autoconfig behavior
- **Root privilege check** at startup

---

## Requirements

Tested on **Kali Linux** (Debian-based). Install dependencies:

```bash
sudo apt install -y dnsmasq radvd tayga iproute2 net-tools
```

---

## Usage

```bash
sudo python3 spellbinder.py
```

### Interactive Prompts

```
Enter the interface to listen on (default eth0): eth0
Enter the global IPv6 address to assign (e.g., fd00:dead:beef::2): fd00:dead:beef::2
Enter the NAT64 IPv6 address (e.g., fd00:dead:beef::3): fd00:dead:beef::3
Enter the NAT64 IPv4 address (e.g., 192.168.255.1): 192.168.255.1
Select DNS mode: [1] Spoof all to attacker IPv6 (default)  [2] Relay to 8.8.8.8  [3] Targeted spoof: 1
```

> **Note:** The example addresses above use ULA space (`fd00::/8`) for illustration. On real engagements, supply routable IPv6 addresses appropriate for the target network. The `2001:db8::/32` range is reserved for documentation (RFC 3849) and will not route on live networks.

### DNS Modes

| Mode | Description |
|------|-------------|
| **1 — Full Spoof** | All DNS queries resolve to the attacker's IPv6 address. Useful for redirecting all client traffic to an attacker-controlled service. |
| **2 — Relay** | DNS queries are forwarded to an upstream resolver (`8.8.8.8`) while all queries are logged. Maintains legitimate DNS resolution for passive monitoring. |
| **3 — Targeted Spoof** | Specified domains resolve to the attacker's IPv6 address; all other queries are relayed upstream. Ideal for surgical redirection during engagements. |

When selecting mode 3, you will be prompted for a comma-separated list of domains to spoof:

```
Enter domains to spoof (comma-separated, e.g., evil.corp,updates.target.com): updates.target.com,portal.internal
```

---

## How It Works

1. **SLAAC Poisoning** — `radvd` broadcasts Router Advertisement messages with the attacker's IPv6 as the RDNSS (recursive DNS server). Clients on the network auto-configure using the advertised prefix and set the attacker as their DNS resolver.
2. **DNS Interception** — `dnsmasq` handles DNS queries from victims in the selected mode (spoof, relay, or targeted), logging all queries in real time.
3. **NAT64 Translation** — `tayga` creates a NAT64 bridge so IPv6-only victims can still reach IPv4 services, keeping network connectivity intact and reducing detection risk.
4. **Traffic Forwarding** — `iptables` rules route traffic between the NAT64 TUN interface and the target network interface with masquerading.

### Traffic Flow

```
Victim (IPv6 client)
    │
    ├─ Receives RA with attacker RDNSS
    ├─ Auto-configures IPv6 via SLAAC
    │
    ▼
Attacker (dnsmasq)
    │
    ├─ Spoof:    All responses → attacker IPv6
    ├─ Relay:    Forward to upstream, log queries
    ├─ Targeted: Spoof selected domains, relay rest
    │
    ▼
NAT64 (tayga)
    │
    └─ IPv6 ↔ IPv4 translation for connectivity
```

---

## Cleanup

Press `Ctrl+C` to trigger graceful shutdown. The cleanup process:

- Stops dnsmasq, radvd, and tayga
- Restores original iptables (v4 and v6) rules from backup
- Restores the original `/etc/dnsmasq.conf` from backup
- Removes the `nat64` TUN interface and assigned IPv6 address
- Removes the Spellbinder dnsmasq config and temporary DNS log

---

## Notes

- The NAT64 IPv4 address must be valid on the IPv4 subnet (default pool: `192.168.255.0/24`).
- The NAT64 prefix is automatically derived from your routable IPv6 input (e.g., `fd00:dead:beef::2` produces `fd00:dead:beef:FFFF::/96`).
- Must be run as root.
- Designed and tested on Kali Linux (Debian-based).
