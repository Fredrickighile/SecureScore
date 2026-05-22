"""
Web Application Security Scanner
Detects missing security headers and common misconfigurations
"""
import requests
from urllib.parse import urljoin
from typing import Dict
import re
import warnings
warnings.filterwarnings('ignore')


class WebAppScanner:

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.timeout = 8

    def scan(self, target: str) -> Dict:
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
            headers_result = self._check_security_headers(target)
            results["security_headers"] = headers_result["headers"]
            results["vulnerabilities"].extend(headers_result["vulnerabilities"])
            results["risk_score"] += headers_result["risk_score"]

            if headers_result.get("site_accessible"):
                info_result = self._check_information_disclosure(target)
                results["vulnerabilities"].extend(info_result["vulnerabilities"])
                results["risk_score"] += info_result["risk_score"]

            print(f"[+] Web scan complete. Found {len(results['vulnerabilities'])} issues")

        except Exception as e:
            results["error"] = str(e)

        return results

    def _check_security_headers(self, url: str) -> Dict:
        result = {
            "headers": {},
            "vulnerabilities": [],
            "risk_score": 0,
            "site_accessible": False
        }

        try:
            response = self.session.get(
                url, timeout=self.timeout,
                verify=False, allow_redirects=True
            )

            # Skip header checks if site blocks scanners - avoids false positives
            if response.status_code in [401, 403, 407]:
                print(f"[*] Site returned {response.status_code} - skipping to avoid false positives")
                return result

            if response.status_code >= 500:
                return result

            result["site_accessible"] = True
            headers = response.headers

            security_headers = {
                'X-Frame-Options': {
                    'severity': 'MEDIUM', 'risk': 8,
                    'description': 'Missing X-Frame-Options header',
                    'impact': 'Vulnerable to clickjacking attacks',
                    'recommendation': 'Add X-Frame-Options: DENY or SAMEORIGIN'
                },
                'X-Content-Type-Options': {
                    'severity': 'MEDIUM', 'risk': 6,
                    'description': 'Missing X-Content-Type-Options header',
                    'impact': 'Vulnerable to MIME-type sniffing attacks',
                    'recommendation': 'Add X-Content-Type-Options: nosniff'
                },
                'Strict-Transport-Security': {
                    'severity': 'HIGH', 'risk': 12,
                    'description': 'Missing HSTS header',
                    'impact': 'Vulnerable to SSL stripping attacks and man-in-the-middle',
                    'recommendation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'severity': 'MEDIUM', 'risk': 10,
                    'description': 'Missing Content-Security-Policy header',
                    'impact': 'Vulnerable to XSS and data injection attacks',
                    'recommendation': 'Add Content-Security-Policy with appropriate directives'
                },
                'X-XSS-Protection': {
                    'severity': 'LOW', 'risk': 4,
                    'description': 'Missing X-XSS-Protection header',
                    'impact': 'Browser XSS filter not enabled',
                    'recommendation': 'Add X-XSS-Protection: 1; mode=block'
                },
                'Referrer-Policy': {
                    'severity': 'LOW', 'risk': 3,
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

        except Exception as e:
            result["error"] = str(e)

        return result

    def _check_information_disclosure(self, url: str) -> Dict:
        result = {"vulnerabilities": [], "risk_score": 0}

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            headers = response.headers

            if 'Server' in headers:
                server = headers['Server']
                if re.search(r'\d+\.\d+', server):
                    result["vulnerabilities"].append({
                        "type": "server_version_disclosure",
                        "severity": "LOW",
                        "description": f"Server version disclosed: {server}",
                        "impact": "Attackers can target known vulnerabilities for this version",
                        "recommendation": "Remove version information from Server header",
                        "risk_points": 4
                    })
                    result["risk_score"] += 4

            for header in ['X-Powered-By', 'X-AspNet-Version']:
                if header in headers:
                    result["vulnerabilities"].append({
                        "type": "technology_disclosure",
                        "severity": "LOW",
                        "description": f"Technology disclosed: {header}: {headers[header]}",
                        "impact": "Reveals tech stack to attackers",
                        "recommendation": f"Remove {header} header",
                        "risk_points": 3
                    })
                    result["risk_score"] += 3

            # Only check 2 most critical files with 2s timeout
            for backup_file in ['.env', '.git/config']:
                try:
                    test_url = urljoin(url, backup_file)
                    test_r = self.session.get(test_url, timeout=2, verify=False)
                    if test_r.status_code == 200 and len(test_r.content) > 10:
                        result["vulnerabilities"].append({
                            "type": "exposed_sensitive_file",
                            "severity": "HIGH",
                            "description": f"Sensitive file exposed: {backup_file}",
                            "impact": "Configuration files accessible to attackers",
                            "recommendation": f"Remove or restrict access to {backup_file}",
                            "risk_points": 15
                        })
                        result["risk_score"] += 15
                        break
                except Exception:
                    pass

        except Exception:
            pass

        return result


if __name__ == "__main__":
    scanner = WebAppScanner()
    result = scanner.scan("https://example.com")
    print(result)