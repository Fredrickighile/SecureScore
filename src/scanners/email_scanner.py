"""
Email Security Scanner
Checks SPF, DKIM, and DMARC records to prevent email spoofing
"""
import dns.resolver
from typing import Dict, List

class EmailScanner:
    """Scans email security configurations"""
    
    def scan(self, domain: str) -> Dict:
        """
        Check email security records (SPF, DKIM, DMARC)
        
        Args:
            domain: Domain name to check
            
        Returns:
            Dict with email security analysis
        """
        print(f"[*] Checking email security for {domain}...")
        
        results = {
            "domain": domain,
            "spf_record": None,
            "dmarc_record": None,
            "vulnerabilities": [],
            "risk_score": 0
        }
        
        # Check SPF record
        spf_result = self._check_spf(domain)
        results["spf_record"] = spf_result["record"]
        if spf_result["vulnerability"]:
            results["vulnerabilities"].append(spf_result["vulnerability"])
            results["risk_score"] += spf_result["vulnerability"]["risk_points"]
        
        # Check DMARC record
        dmarc_result = self._check_dmarc(domain)
        results["dmarc_record"] = dmarc_result["record"]
        if dmarc_result["vulnerability"]:
            results["vulnerabilities"].append(dmarc_result["vulnerability"])
            results["risk_score"] += dmarc_result["vulnerability"]["risk_points"]
        
        print(f"[+] Email security check complete. Found {len(results['vulnerabilities'])} issues")
        return results
    
    def _check_spf(self, domain: str) -> Dict:
        """Check SPF (Sender Policy Framework) record"""
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=spf1'):
                    return {
                        "record": txt_record,
                        "vulnerability": None
                    }
            
            # No SPF record found
            return {
                "record": None,
                "vulnerability": {
                    "type": "missing_spf",
                    "severity": "MEDIUM",
                    "description": "No SPF record found",
                    "mitre_attack": "T1566.001",
                    "mitre_tactic": "Initial Access",
                    "mitre_url": "https://attack.mitre.org/techniques/T1566/001/",
                    "impact": "Attackers can spoof emails from your domain",
                    "recommendation": "Add SPF record: 'v=spf1 include:_spf.google.com ~all' (adjust for your email provider)",
                    "risk_points": 8
                }
            }
            
        except dns.resolver.NXDOMAIN:
            return {"record": None, "vulnerability": None}
        except dns.resolver.NoAnswer:
            return {
                "record": None,
                "vulnerability": {
                    "type": "missing_spf",
                    "severity": "MEDIUM",
                    "description": "No SPF record configured",
                    "mitre_attack": "T1566.001",
                    "mitre_tactic": "Initial Access",
                    "mitre_url": "https://attack.mitre.org/techniques/T1566/001/",
                    "impact": "Email spoofing possible",
                    "recommendation": "Configure SPF record in DNS",
                    "risk_points": 8
                }
            }
        except Exception as e:
            return {"record": None, "vulnerability": None}
    
    def _check_dmarc(self, domain: str) -> Dict:
        """Check DMARC (Domain-based Message Authentication) record"""
        try:
            # DMARC records are at _dmarc subdomain
            dmarc_domain = f"_dmarc.{domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            
            for rdata in answers:
                txt_record = str(rdata).strip('"')
                if txt_record.startswith('v=DMARC1'):
                    # Check DMARC policy
                    if 'p=none' in txt_record:
                        return {
                            "record": txt_record,
                            "vulnerability": {
                                "type": "weak_dmarc",
                                "severity": "MEDIUM",
                                "description": "DMARC policy set to 'none' (monitoring only)",
                                "impact": "Emails are not blocked even if they fail authentication",
                                "recommendation": "Change policy to 'quarantine' or 'reject'",
                                "risk_points": 5
                            }
                        }
                    return {
                        "record": txt_record,
                        "vulnerability": None
                    }
            
            # No DMARC record found
            return {
                "record": None,
                "vulnerability": {
                    "type": "missing_dmarc",
                    "severity": "HIGH",
                    "description": "No DMARC record found",
                    "mitre_attack": "T1566.001",
                    "mitre_tactic": "Initial Access",
                    "mitre_url": "https://attack.mitre.org/techniques/T1566/001/",
                    "impact": "No policy for handling failed email authentication - phishing attacks easier",
                    "recommendation": "Add DMARC record: 'v=DMARC1; p=quarantine; rua=mailto:admin@yourdomain.com'",
                    "risk_points": 10
                }
            }
            
        except dns.resolver.NXDOMAIN:
            return {
                "record": None,
                "vulnerability": {
                    "type": "missing_dmarc",
                    "severity": "HIGH",
                    "description": "No DMARC record configured",
                    "mitre_attack": "T1566.001",
                    "mitre_tactic": "Initial Access",
                    "mitre_url": "https://attack.mitre.org/techniques/T1566/001/",
                    "impact": "Domain vulnerable to email spoofing and phishing",
                    "recommendation": "Configure DMARC record in DNS",
                    "risk_points": 10
                }
            }
        except Exception as e:
            return {"record": None, "vulnerability": None}

# Test function
if __name__ == "__main__":
    scanner = EmailScanner()
    result = scanner.scan("google.com")
    print(result)