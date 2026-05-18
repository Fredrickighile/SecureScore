"""
Web Application Security Scanner
Detects OWASP Top 10 vulnerabilities
"""
import requests
from urllib.parse import urljoin
from typing import Dict, List
import re

class WebAppScanner:
    """Scans web applications for common vulnerabilities"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecureScore Security Scanner/1.0'
        })
        self.timeout = 10
    
    def scan(self, target: str) -> Dict:
        """
        Scan web application for vulnerabilities
        
        Args:
            target: Base URL of web application
            
        Returns:
            Dict with vulnerability findings
        """
        if not target.startswith('http'):
            target = f"https://{target}"
        
        print(f"[*] Scanning web application: {target}")
        
        results = {
            "target": target,
            "vulnerabilities": [],
            "risk_score": 0,
            "headers_secure": True,
            "security_headers": {}
        }
        
        try:
            # Check security headers
            headers_result = self._check_security_headers(target)
            results["security_headers"] = headers_result["headers"]
            results["vulnerabilities"].extend(headers_result["vulnerabilities"])
            results["risk_score"] += headers_result["risk_score"]
            
            # Check for information disclosure
            info_result = self._check_information_disclosure(target)
            results["vulnerabilities"].extend(info_result["vulnerabilities"])
            results["risk_score"] += info_result["risk_score"]
            
            # Check for common misconfigurations
            config_result = self._check_misconfigurations(target)
            results["vulnerabilities"].extend(config_result["vulnerabilities"])
            results["risk_score"] += config_result["risk_score"]
            
            print(f"[+] Web application scan complete. Found {len(results['vulnerabilities'])} issues")
            
        except requests.exceptions.RequestException as e:
            results["error"] = f"Connection failed: {str(e)}"
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    def _check_security_headers(self, url: str) -> Dict:
        """Check for missing security headers"""
        result = {
            "headers": {},
            "vulnerabilities": [],
            "risk_score": 0
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            headers = response.headers
            
            # Required security headers
            security_headers = {
                'X-Frame-Options': {
                    'severity': 'MEDIUM',
                    'risk': 8,
                    'description': 'Missing X-Frame-Options header',
                    'impact': 'Vulnerable to clickjacking attacks',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'severity': 'MEDIUM',
                    'risk': 6,
                    'description': 'Missing X-Content-Type-Options header',
                    'impact': 'Vulnerable to MIME-type sniffing attacks',
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                },
                'Strict-Transport-Security': {
                    'severity': 'HIGH',
                    'risk': 12,
                    'description': 'Missing HSTS header',
                    'impact': 'Vulnerable to SSL stripping attacks and man-in-the-middle',
                    'recommendation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'severity': 'MEDIUM',
                    'risk': 10,
                    'description': 'Missing Content-Security-Policy header',
                    'impact': 'Vulnerable to XSS and data injection attacks',
                    'recommendation': "Add Content-Security-Policy with appropriate directives"
                },
                'X-XSS-Protection': {
                    'severity': 'LOW',
                    'risk': 4,
                    'description': 'Missing X-XSS-Protection header',
                    'impact': 'Browser XSS filter not enabled',
                    'recommendation': 'Add X-XSS-Protection: 1; mode=block'
                },
                'Referrer-Policy': {
                    'severity': 'LOW',
                    'risk': 3,
                    'description': 'Missing Referrer-Policy header',
                    'impact': 'May leak sensitive URL information',
                    'recommendation': 'Add Referrer-Policy: strict-origin-when-cross-origin'
                }
            }
            
            for header, config in security_headers.items():
                if header in headers:
                    result["headers"][header] = headers[header]
                else:
                    result["vulnerabilities"].append({
                        "type": f"missing_{header.lower().replace('-', '_')}",
                        "severity": config['severity'],
                        "description": config['description'],
                        "impact": config['impact'],
                        "recommendation": config['recommendation'],
                        "risk_points": config['risk']
                    })
                    result["risk_score"] += config['risk']
            
            # Check for insecure cookies
            if 'Set-Cookie' in headers:
                cookies = headers.get('Set-Cookie', '')
                if 'Secure' not in cookies:
                    result["vulnerabilities"].append({
                        "type": "insecure_cookie",
                        "severity": "MEDIUM",
                        "description": "Cookies transmitted without Secure flag",
                        "impact": "Session cookies vulnerable to interception over HTTP",
                        "recommendation": "Add Secure flag to all session cookies",
                        "risk_points": 8
                    })
                    result["risk_score"] += 8
                
                if 'HttpOnly' not in cookies:
                    result["vulnerabilities"].append({
                        "type": "httponly_missing",
                        "severity": "MEDIUM",
                        "description": "Cookies accessible via JavaScript (missing HttpOnly)",
                        "impact": "Vulnerable to XSS cookie theft",
                        "recommendation": "Add HttpOnly flag to session cookies",
                        "risk_points": 7
                    })
                    result["risk_score"] += 7
        
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    def _check_information_disclosure(self, url: str) -> Dict:
        """Check for information disclosure vulnerabilities"""
        result = {
            "vulnerabilities": [],
            "risk_score": 0
        }
        
        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers
            content = response.text
            
            # Check for server version disclosure
            if 'Server' in headers:
                server = headers['Server']
                # Check if version numbers are exposed
                if re.search(r'\d+\.\d+', server):
                    result["vulnerabilities"].append({
                        "type": "server_version_disclosure",
                    "mitre_attack": "T1592",
                    "mitre_tactic": "Reconnaissance",
                    "mitre_url": "https://attack.mitre.org/techniques/T1592/",
                        "severity": "LOW",
                        "description": f"Server version disclosed: {server}",
                        "impact": "Attackers can target known vulnerabilities for this version",
                        "recommendation": "Remove version information from Server header",
                        "risk_points": 4
                    })
                    result["risk_score"] += 4
            
            # Check for technology disclosure in headers
            tech_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            for header in tech_headers:
                if header in headers:
                    result["vulnerabilities"].append({
                        "type": "technology_disclosure",
                        "severity": "LOW",
                        "description": f"Technology stack disclosed: {header}: {headers[header]}",
                        "impact": "Reveals technology stack to potential attackers",
                        "recommendation": f"Remove {header} header",
                        "risk_points": 3
                    })
                    result["risk_score"] += 3
            
            # Check for common backup files
            backup_files = [
                '.git/config',
                '.env',
                'config.php.bak',
                'web.config',
                '.DS_Store',
                'phpinfo.php'
            ]
            
            for backup_file in backup_files:
                try:
                    test_url = urljoin(url, backup_file)
                    test_response = self.session.get(test_url, timeout=5, verify=False)
                    if test_response.status_code == 200:
                        result["vulnerabilities"].append({
                            "type": "exposed_sensitive_file",
                        "mitre_attack": "T1083",
                        "mitre_tactic": "Discovery",
                        "mitre_url": "https://attack.mitre.org/techniques/T1083/",
                            "severity": "HIGH",
                            "description": f"Sensitive file exposed: {backup_file}",
                            "impact": "Configuration files or source code accessible to attackers",
                            "recommendation": f"Remove or restrict access to {backup_file}",
                            "risk_points": 15
                        })
                        result["risk_score"] += 15
                        break  # Don't check all if one is found
                except:
                    pass
        
        except Exception as e:
            pass
        
        return result
    
    def _check_misconfigurations(self, url: str) -> Dict:
        """Check for common misconfigurations"""
        result = {
            "vulnerabilities": [],
            "risk_score": 0
        }
        
        try:
            # Check if directory listing is enabled
            response = self.session.get(url, timeout=self.timeout, verify=False)
            
            if 'Index of /' in response.text or '<title>Directory Listing' in response.text:
                result["vulnerabilities"].append({
                    "type": "directory_listing",
                    "mitre_attack": "T1083",
                    "mitre_tactic": "Discovery",
                    "mitre_url": "https://attack.mitre.org/techniques/T1083/",
                    "severity": "MEDIUM",
                    "description": "Directory listing enabled",
                    "impact": "Attackers can browse server directories and discover sensitive files",
                    "recommendation": "Disable directory listing in web server configuration",
                    "risk_points": 10
                })
                result["risk_score"] += 10
            
            # Check for default pages
            default_pages = ['/phpinfo.php', '/info.php', '/test.php', '/admin', '/phpmyadmin']
            for page in default_pages:
                try:
                    test_url = urljoin(url, page)
                    test_response = self.session.get(test_url, timeout=5, verify=False)
                    if test_response.status_code == 200 and len(test_response.content) > 100:
                        result["vulnerabilities"].append({
                            "type": "default_page_accessible",
                            "severity": "MEDIUM",
                            "description": f"Default/test page accessible: {page}",
                            "impact": "May expose sensitive system information or administrative interfaces",
                            "recommendation": f"Remove or restrict access to {page}",
                            "risk_points": 12
                        })
                        result["risk_score"] += 12
                        break
                except:
                    pass
        
        except Exception as e:
            pass
        
        return result

# Test function
if __name__ == "__main__":
    scanner = WebAppScanner()
    result = scanner.scan("http://testphp.vulnweb.com")
    print(result)