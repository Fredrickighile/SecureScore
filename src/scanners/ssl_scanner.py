"""
SSL/TLS Security Scanner
Checks certificate validity and encryption strength
"""
import ssl
import socket
from datetime import datetime
from typing import Dict

class SSLScanner:
    """Scans SSL/TLS certificates for security issues"""
    
    def scan(self, target: str, port: int = 443) -> Dict:
        """
        Check SSL certificate and configuration
        
        Args:
            target: Domain name
            port: HTTPS port (default 443)
            
        Returns:
            Dict with SSL analysis results
        """
        print(f"[*] Checking SSL certificate for {target}...")
        
        results = {
            "target": target,
            "port": port,
            "vulnerabilities": [],
            "risk_score": 0,
            "certificate_valid": False
        }
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Extract certificate info
                    results["issuer"] = dict(x[0] for x in cert['issuer'])
                    results["subject"] = dict(x[0] for x in cert['subject'])
                    results["version"] = cert['version']
                    results["serial_number"] = cert['serialNumber']
                    
                    # Check expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    
                    days_until_expiry = (not_after - datetime.now()).days
                    results["expires_in_days"] = days_until_expiry
                    results["expiry_date"] = not_after.strftime('%Y-%m-%d')
                    
                    # Check for vulnerabilities
                    if days_until_expiry < 0:
                        results["vulnerabilities"].append({
                            "type": "expired_cert",
                            "severity": "CRITICAL",
                            "description": "SSL certificate has EXPIRED",
                            "impact": "Browser warnings, connection refused, loss of customer trust",
                            "recommendation": "Renew SSL certificate immediately",
                            "risk_points": 20
                        })
                        results["risk_score"] += 20
                        
                    elif days_until_expiry < 30:
                        results["vulnerabilities"].append({
                            "type": "expiring_soon",
                            "severity": "HIGH",
                            "description": f"SSL certificate expires in {days_until_expiry} days",
                            "impact": "Potential service disruption if not renewed",
                            "recommendation": "Renew SSL certificate within next 7 days",
                            "risk_points": 15
                        })
                        results["risk_score"] += 15
                    
                    # Check protocol version
                    protocol = ssock.version()
                    results["protocol"] = protocol
                    
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        results["vulnerabilities"].append({
                            "type": "weak_ssl",
                            "severity": "HIGH",
                            "description": f"Outdated protocol: {protocol}",
                            "impact": "Vulnerable to POODLE, BEAST attacks",
                            "recommendation": "Upgrade to TLS 1.2 or TLS 1.3",
                            "risk_points": 15
                        })
                        results["risk_score"] += 15
                    
                    results["certificate_valid"] = True
                    print(f"[✓] SSL check complete. Expires in {days_until_expiry} days")
                    
        except ssl.SSLError as e:
            results["vulnerabilities"].append({
                "type": "ssl_error",
                "severity": "CRITICAL",
                "description": f"SSL Error: {str(e)}",
                "impact": "Cannot establish secure connection",
                "recommendation": "Fix SSL configuration",
                "risk_points": 20
            })
            results["risk_score"] += 20
            results["error"] = str(e)
            
        except socket.timeout:
            results["error"] = "Connection timeout"
            
        except Exception as e:
            results["error"] = str(e)
        
        return results

# Test function
if __name__ == "__main__":
    scanner = SSLScanner()
    result = scanner.scan("google.com")
    print(result)