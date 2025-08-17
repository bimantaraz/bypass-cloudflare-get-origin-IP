import dns.resolver
import socket
import argparse
import sys
import time
import requests
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed

logo = """
  ________________  ___ _____ 
 /_  __/ ____/ __ \/   /__  / 
  / / / __/ / /_/ / /| | / / 
 / / / /___/ _, _/ ___ |/ /__ 
/_/ /_____/_/ |_/_/  |_/____/ v1.0
         By github.com/bimantaraz
"""

print(colored(logo, "cyan", attrs=["bold"]))

COMMON_SUBDOMAINS = [
    "mail", "ftp", "api", "dev", "staging", "test", "blog", "admin", 
    "portal", "shop", "docs", "support", "vpn", "status", "account", "assets", 
    "cdn", "secure", "images", "files", "backup", "webmail", "pay", 
    "users", "mail2", "dashboard", "chat", "help", "management", "ci", "git", 
    "devops", "cloud", "public", "fileserver", "webdav"
]

class OriginReaper:
    def __init__(self, domain):
        if not domain:
            raise ValueError("Domain cannot be null or empty.")
        self.domain = domain
        self.results = set()
        self.cloudflare_ips = self._fetch_cloudflare_ips()
        print(colored(f"[INFO] Loaded {len(self.cloudflare_ips)} Cloudflare IP ranges.", "cyan", attrs=["bold"]))

    def _fetch_cloudflare_ips(self):
        try:
            v4_response = requests.get("https://www.cloudflare.com/ips-v4", timeout=10)
            v6_response = requests.get("https://www.cloudflare.com/ips-v6", timeout=10)
            v4_response.raise_for_status()
            v6_response.raise_for_status()
            return set(v4_response.text.splitlines() + v6_response.text.splitlines())
        except requests.exceptions.RequestException as e:
            print(colored(f"[ERROR] Could not fetch Cloudflare IP ranges: {e}", "red"))
            return set()

    def _is_cloudflare_ip(self, ip):
        for cidr in self.cloudflare_ips:
            if ip in cidr:
                return True
        try:
            domain_ips = set([str(i[4][0]) for i in socket.getaddrinfo(self.domain, None)])
            for dip in domain_ips:
                for cidr in self.cloudflare_ips:
                    if dip in cidr or any(dip in ip_range for ip_range in self.cloudflare_ips):
                        return True
            return False
        except socket.gaierror:
            return False

    def _add_result(self, ip):
        if ip and ip not in self.results and not self._is_cloudflare_ip(ip):
            print(colored(f"[SUCCESS] Potential Origin IP Found: {ip}", "green", attrs=['bold']))
            self.results.add(ip)

    def scan_subdomains(self):
        print(colored("\n[PHASE 1] Commencing Subdomain Enumeration...", "yellow", attrs=["bold"]))
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_subdomain = {executor.submit(self._resolve_subdomain, subdomain): subdomain for subdomain in COMMON_SUBDOMAINS}
            for future in as_completed(future_to_subdomain):
                future_to_subdomain[future]

    def _resolve_subdomain(self, subdomain):
        target = f"{subdomain}.{self.domain}"
        try:
            answers = dns.resolver.resolve(target, 'A', lifetime=5)
            for rdata in answers:
                ip = str(rdata)
                print(colored(f"  [~] Testing {target} -> {ip}", "magenta"))
                self._add_result(ip)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
        except Exception as e:
            print(colored(f"  [!] Error resolving {target}: {e}", "red"))

    def check_mx_records(self):
        print(colored("\n[PHASE 2] Analyzing MX Records...", "yellow", attrs=["bold"]))
        try:
            answers = dns.resolver.resolve(self.domain, 'MX', lifetime=5)
            for rdata in answers:
                mail_server = str(rdata.exchange).rstrip('.')
                print(colored(f"  [~] Found MX record: {mail_server}", "cyan"))
                try:
                    mail_ips = dns.resolver.resolve(mail_server, 'A', lifetime=5)
                    for ip_data in mail_ips:
                        self._add_result(str(ip_data))
                except Exception as e:
                    print(colored(f"  [!] Could not resolve mail server {mail_server}: {e}", "red"))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print(colored("  [INFO] No MX records found.", "cyan"))

    def run(self):
        print(colored(f"\n--- Initiating Reconnaissance for {self.domain} ---", "white", attrs=["bold"]))
        if not self._is_cloudflare_ip(self.domain):
            print(colored(f"[WARNING] {self.domain} does not appear to be protected by Cloudflare. Direct resolution may be possible.", "magenta"))

        self.scan_subdomains()
        self.check_mx_records()

        print(colored("\n--- Reconnaissance Complete ---", "white", attrs=["bold"]))
        if self.results:
            print(colored("\nFound the following potential origin IPs:", "green", attrs=["bold"]))
            for ip in self.results:
                print(colored(f"  -> {ip}", "green", attrs=['bold']))
        else:
            print(colored("Mission concluded. No origin IPs discovered through these vectors.", "red", attrs=["bold"]))

def main():
    parser = argparse.ArgumentParser(description="OriginReaper - Find origin IPs behind Cloudflare.")
    parser.add_argument("domain", help="The target domain to scan.")
    args = parser.parse_args()

    try:
        reaper = OriginReaper(args.domain)
        reaper.run()
    except Exception as e:
        print(colored(f"\n[FATAL] A critical error occurred: {e}", "red", attrs=['bold']), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
