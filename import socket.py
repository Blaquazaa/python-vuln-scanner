import socket
import concurrent.futures
from datetime import datetime

# A small dictionary of "known" vulnerable service versions for demonstration.
# In a real-world tool, this would be a large database of CVEs.
VULNERABILITY_DB = {
    "SSH-2.0-OpenSSH_7.2p2": "CVE-2016-6210 - User enumeration vulnerability.",
    "Apache/2.4.18": "Potential vulnerabilities in old version. Update to 2.4.50+.",
    "vsFTPd 2.3.4": "Backdoor Command Execution (CVE-2011-2523).",
}

class VulnScanner:
    def __init__(self, target, port_range=(1, 1024)):
        self.target = target
        self.port_range = port_range
        self.open_ports = []
        self.report = []

    def banner_grab(self, s):
        """Attempts to grab the service banner from an open port."""
        try:
            # Set a short timeout for the banner grab
            s.settimeout(2)
            # Some services require a small send to trigger a banner
            s.send(b'Hello\r\n')
            banner = s.recv(1024).decode().strip()
            return banner
        except:
            return None

    def check_vulnerability(self, port, banner):
        """Checks the grabbed banner against our local 'vulnerability' database."""
        if not banner:
            return "No banner detected (Unknown Service)"
        
        for vuln_banner, description in VULNERABILITY_DB.items():
            if vuln_banner in banner:
                return f"CRITICAL: {description}"
        
        return "No known vulnerabilities found in local DB."

    def scan_port(self, port):
        """Scans a single port to check if it is open."""
        try:
            # AF_INET = IPv4, SOCK_STREAM = TCP
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    banner = self.banner_grab(s)
                    vuln_status = self.check_vulnerability(port, banner)
                    return {
                        "port": port,
                        "status": "Open",
                        "banner": banner or "Unknown",
                        "vulnerability": vuln_status
                    }
        except Exception:
            pass
        return None

    def run(self):
        print(f"[*] Starting scan on {self.target} at {datetime.now()}")
        
        # Using ThreadPoolExecutor for faster scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            ports = range(self.port_range[0], self.port_range[1] + 1)
            results = list(executor.map(self.scan_port, ports))

        # Filter out None results (closed ports)
        self.open_ports = [res for res in results if res]
        self.generate_report()

    def generate_report(self):
        print("-" * 50)
        print(f"VULNERABILITY REPORT: {self.target}")
        print("-" * 50)
        if not self.open_ports:
            print("No open ports found.")
        else:
            for item in self.open_ports:
                print(f"Port {item['port']}: {item['status']}")
                print(f"  Service: {item['banner']}")
                print(f"  Vuln:    {item['vulnerability']}\n")
        print("-" * 50)
        print(f"[*] Scan completed at {datetime.now()}")

if __name__ == "__main__":
    # Example target (Localhost for testing)
    target_ip = "127.0.0.1" 
    scanner = VulnScanner(target_ip, port_range=(20, 1000))
    scanner.run()
