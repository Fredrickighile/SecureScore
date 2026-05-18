"""
Network Security Scanner
Uses Nmap to detect open ports and vulnerable services
"""
import nmap
from typing import Dict, List
from ..config import Config

class NetworkScanner:
    """Scans network for security vulnerabilities"""
    
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.vulnerabilities = []
        
    def scan(self, target: str, ports: str = None) -> Dict:
        """
        Scan target for open ports and services
        
        Args:
            target: IP address or domain name
            ports: Port range to scan (default: common ports)
            
        Returns:
            Dict with scan results and vulnerabilities
        """
        if ports is None:
            ports = Config.NMAP_QUICK_PORTS
            
        print(f"[*] Scanning {target} on ports {ports}...")
        
        try:
            # Run Nmap scan
            self.nm.scan(target, ports, arguments='-sV')
            
            results = {
                "target": target,
                "scan_time": self.nm.scanstats()['elapsed'],
                "open_ports": [],
                "vulnerabilities": [],
                "risk_score": 0
            }
            
            # Check if host is up
            if target not in self.nm.all_hosts():
                results["error"] = "Host is down or unreachable"
                return results
            
            # Analyze open ports
            for proto in self.nm[target].all_protocols():
                ports_list = self.nm[target][proto].keys()
                
                for port in ports_list:
                    port_info = self.nm[target][proto][port]
                    
                    if port_info['state'] == 'open':
                        service = {
                            "port": port,
                            "protocol": proto,
                            "service": port_info.get('name', 'unknown'),
                            "version": port_info.get('version', 'unknown'),
                            "state": port_info['state']
                        }
                        results["open_ports"].append(service)
                        
                        # Check for critical vulnerabilities
                        vuln = self._check_port_vulnerability(port, service)
                        if vuln:
                            results["vulnerabilities"].append(vuln)
                            results["risk_score"] += vuln["risk_points"]
            
            print(f"[+] Scan complete. Found {len(results['open_ports'])} open ports")
            return results
            
        except Exception as e:
            return {
                "target": target,
                "error": str(e),
                "open_ports": [],
                "vulnerabilities": [],
                "risk_score": 0
            }
    
    def _check_port_vulnerability(self, port: int, service: Dict) -> Dict:
        """Check if port represents a security vulnerability"""
        
        # RDP exposed (major ransomware entry point)
        if port == 3389:
            return {
                "type": "exposed_rdp",
                "severity": "CRITICAL",
                "port": port,
                "description": "Remote Desktop Protocol (RDP) exposed to internet",
                "impact": "Primary entry point for ransomware attacks",
                "recommendation": "Close port 3389 or restrict to VPN-only access",
                "mitre_attack": "T1021.001",
                "mitre_tactic": "Lateral Movement",
                "mitre_url": "https://attack.mitre.org/techniques/T1021/001/",
                "risk_points": Config.RISK_WEIGHTS["exposed_rdp"]
            }
        
        # SMB exposed (WannaCry, NotPetya vector)
        if port == 445:
            return {
                "type": "exposed_smb",
                "severity": "CRITICAL",
                "port": port,
                "description": "Server Message Block (SMB) exposed to internet",
                "impact": "Used by WannaCry and other ransomware for lateral movement",
                "recommendation": "Block port 445 at firewall level immediately",
                "mitre_attack": "T1021.002",
                "mitre_tactic": "Lateral Movement",
                "mitre_url": "https://attack.mitre.org/techniques/T1021/002/",
                "risk_points": Config.RISK_WEIGHTS["exposed_smb"]
            }
        
        # Database ports (data breach risk)
        if port in [3306, 5432, 1433, 27017]:
            db_names = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}
            return {
                "type": "open_database_port",
                "severity": "HIGH",
                "port": port,
                "mitre_attack": "T1190",
                "mitre_tactic": "Initial Access",
                "mitre_url": "https://attack.mitre.org/techniques/T1190/",
                "description": f"{db_names.get(port, 'Database')} port exposed to internet",
                "impact": "Direct access to database could lead to data breach",
                "recommendation": f"Restrict {db_names.get(port, 'database')} access to localhost or VPN only",
                "risk_points": Config.RISK_WEIGHTS["open_database_port"]
            }
        
        # Telnet (unencrypted remote access)
        if port == 23:
            return {
                "type": "telnet_exposed",
                "severity": "HIGH",
                "port": port,
                "mitre_attack": "T1021",
                "mitre_tactic": "Lateral Movement",
                "mitre_url": "https://attack.mitre.org/techniques/T1021/",
                "description": "Telnet service running (unencrypted)",
                "impact": "Credentials transmitted in plaintext, easily intercepted",
                "recommendation": "Disable Telnet, use SSH (port 22) instead",
                "risk_points": 15
            }
        
        # FTP (unencrypted file transfer)
        if port == 21:
            return {
                "type": "ftp_exposed",
                "severity": "MEDIUM",
                "port": port,
                "mitre_attack": "T1071.002",
                "mitre_tactic": "Command and Control",
                "mitre_url": "https://attack.mitre.org/techniques/T1071/002/",
                "description": "FTP service exposed (unencrypted)",
                "impact": "File transfers not encrypted, credentials at risk",
                "recommendation": "Use SFTP (port 22) or FTPS instead",
                "risk_points": 10
            }
        
        return None

# Test function
if __name__ == "__main__":
    scanner = NetworkScanner()
    result = scanner.scan("scanme.nmap.org")
    print(result)