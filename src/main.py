"""
SecureScore - Ransomware Readiness Assessment Platform
Automated security assessment focused on ransomware prevention for Canadian SMBs
"""
import sys
import json
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.scanners.network_scanner import NetworkScanner
from src.scanners.ssl_scanner import SSLScanner
from src.scanners.email_scanner import EmailScanner
from src.scanners.webapp_scanner import WebAppScanner
from src.utils.risk_calculator import RiskCalculator
from src.config import Config

class SecureScore:
    """
    Main security assessment application
    
    Focuses on ransomware attack surface reduction for Canadian organizations
    by detecting the most common entry points:
    - Exposed RDP/SMB (80% of ransomware attacks)
    - Weak email security (phishing delivery)
    - SSL/TLS vulnerabilities (credential theft)
    - Web application weaknesses (initial access)
    """
    
    def __init__(self):
        self.network_scanner = NetworkScanner()
        self.ssl_scanner = SSLScanner()
        self.email_scanner = EmailScanner()
        self.webapp_scanner = WebAppScanner()
        self.risk_calculator = RiskCalculator()
    
    def scan(self, target: str) -> dict:
        """
        Run comprehensive security assessment
        
        Args:
            target: Domain or IP address to scan
            
        Returns:
            Complete assessment results with ransomware readiness score
        """
        print("\n" + "="*70)
        print("  SECURESCORE - RANSOMWARE READINESS ASSESSMENT")
        print("="*70)
        print(f"Target: {target}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Focus: Canadian Ransomware Attack Surface")
        print("="*70 + "\n")
        
        results = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "network_scan": {},
            "ssl_scan": {},
            "email_scan": {},
            "webapp_scan": {},
            "overall_risk": {},
            "ransomware_readiness": {}
        }
        
        # 1. Network Security Scan - Check for RDP/SMB exposure
        print("\n[1/4] NETWORK SECURITY SCAN")
        print("-" * 70)
        print("Checking for exposed ransomware entry points (RDP, SMB, databases)...")
        results["network_scan"] = self.network_scanner.scan(target)
        
        # 2. SSL/TLS Certificate Scan - Prevent credential theft
        print("\n[2/4] SSL/TLS CERTIFICATE SCAN")
        print("-" * 70)
        print("Validating encryption to prevent man-in-the-middle attacks...")
        results["ssl_scan"] = self.ssl_scanner.scan(target)
        
        # 3. Email Security Scan - Prevent phishing delivery
        print("\n[3/4] EMAIL SECURITY SCAN")
        print("-" * 70)
        print("Checking SPF/DMARC to prevent phishing (primary ransomware delivery)...")
        results["email_scan"] = self.email_scanner.scan(target)
        
        # 4. Web Application Security Scan - Harden web apps
        print("\n[4/4] WEB APPLICATION SECURITY SCAN")
        print("-" * 70)
        print("Scanning for vulnerabilities that enable credential theft...")
        results["webapp_scan"] = self.webapp_scanner.scan(target)
        
        # Calculate Overall Risk Score
        print("\n" + "="*70)
        print("  CALCULATING RANSOMWARE READINESS SCORE...")
        print("="*70)
        
        scan_results = {
            "network": results["network_scan"],
            "ssl": results["ssl_scan"],
            "email": results["email_scan"],
            "webapp": results["webapp_scan"]
        }
        
        results["overall_risk"] = self.risk_calculator.calculate_overall_risk(scan_results)
        
        # Calculate Ransomware-Specific Readiness
        results["ransomware_readiness"] = self._calculate_ransomware_readiness(results)
        
        # Display Results
        self._display_results(results)
        
        # Save Results
        self._save_results(target, results)
        
        # Generate PDF Report
        self._generate_pdf_report(target, results)
        
        return results
    
    def _calculate_ransomware_readiness(self, results: dict) -> dict:
        """
        Calculate ransomware-specific readiness score
        
        Focuses on the 3 primary ransomware attack vectors:
        1. RDP/SMB exposure (direct access)
        2. Phishing susceptibility (email security)
        3. Credential theft risk (SSL + web app vulnerabilities)
        
        Returns:
            Dict with ransomware readiness assessment
        """
        readiness_score = 100  # Start at perfect
        attack_vectors = []
        
        # Check for RDP/SMB exposure (CRITICAL - 80% of ransomware attacks)
        network_vulns = results.get("network_scan", {}).get("vulnerabilities", [])
        has_rdp = any(v.get("type") == "exposed_rdp" for v in network_vulns)
        has_smb = any(v.get("type") == "exposed_smb" for v in network_vulns)
        
        if has_rdp:
            readiness_score -= 40
            attack_vectors.append({
                "vector": "Exposed RDP (Port 3389)",
                "severity": "CRITICAL",
                "likelihood": "80% of ransomware attacks use this",
                "impact": "Direct remote access for attackers",
                "fix": "Close port 3389 or implement VPN-only access"
            })
        
        if has_smb:
            readiness_score -= 35
            attack_vectors.append({
                "vector": "Exposed SMB (Port 445)",
                "severity": "CRITICAL",
                "likelihood": "WannaCry, NotPetya primary vector",
                "impact": "Lateral movement and rapid infection spread",
                "fix": "Block port 445 at firewall level"
            })
        
        # Check email security (phishing = #1 ransomware delivery method)
        email_vulns = results.get("email_scan", {}).get("vulnerabilities", [])
        missing_dmarc = any(v.get("type") == "missing_dmarc" for v in email_vulns)
        missing_spf = any(v.get("type") == "missing_spf" for v in email_vulns)
        
        if missing_dmarc:
            readiness_score -= 15
            attack_vectors.append({
                "vector": "Missing DMARC (Email Spoofing)",
                "severity": "HIGH",
                "likelihood": "90% of ransomware delivered via phishing",
                "impact": "Attackers can send fake emails from your domain",
                "fix": "Configure DMARC policy: p=quarantine or p=reject"
            })
        
        if missing_spf:
            readiness_score -= 10
            attack_vectors.append({
                "vector": "Missing SPF Record",
                "severity": "MEDIUM",
                "likelihood": "Enables email spoofing for phishing",
                "impact": "Employees may trust malicious emails",
                "fix": "Add SPF record to DNS"
            })
        
        # Check SSL/Certificate issues (credential theft)
        ssl_vulns = results.get("ssl_scan", {}).get("vulnerabilities", [])
        if ssl_vulns:
            readiness_score -= 10
            attack_vectors.append({
                "vector": "SSL/TLS Vulnerabilities",
                "severity": "MEDIUM",
                "likelihood": "Enables credential interception",
                "impact": "Stolen credentials used for initial access",
                "fix": "Renew certificates and upgrade to TLS 1.3"
            })
        
        # Determine readiness level
        if readiness_score >= 80:
            readiness_level = "WELL PROTECTED"
            color = "green"
        elif readiness_score >= 60:
            readiness_level = "MODERATE RISK"
            color = "yellow"
        elif readiness_score >= 40:
            readiness_level = "HIGH RISK"
            color = "orange"
        else:
            readiness_level = "CRITICAL RISK"
            color = "red"
        
        return {
            "readiness_score": max(0, readiness_score),
            "readiness_level": readiness_level,
            "color": color,
            "attack_vectors": attack_vectors,
            "can_survive_attack": readiness_score >= 70,
            "estimated_recovery_time": self._estimate_recovery_time(readiness_score),
            "insurance_ready": readiness_score >= 60
        }
    
    def _estimate_recovery_time(self, readiness_score: int) -> str:
        """Estimate recovery time if ransomware hits"""
        if readiness_score >= 80:
            return "< 24 hours (backups likely functional)"
        elif readiness_score >= 60:
            return "2-5 days (moderate recovery capability)"
        elif readiness_score >= 40:
            return "1-2 weeks (significant downtime expected)"
        else:
            return "2+ weeks or total data loss (high risk of business closure)"
    
    def _display_results(self, results: dict):
        """Display comprehensive assessment results"""
        risk = results["overall_risk"]
        ransomware = results["ransomware_readiness"]
        
        print("\n" + "="*70)
        print("  ASSESSMENT RESULTS")
        print("="*70)
        
        # Overall Risk Score
        print(f"\nOVERALL SECURITY RISK: {risk['total_risk_score']}/100 ({risk['risk_level']})")
        print(f"TOTAL VULNERABILITIES: {risk['total_vulnerabilities']}")
        
        if risk['critical_count'] > 0:
            print(f"  - CRITICAL: {risk['critical_count']}")
        if risk['high_count'] > 0:
            print(f"  - HIGH: {risk['high_count']}")
        if risk['medium_count'] > 0:
            print(f"  - MEDIUM: {risk['medium_count']}")
        
        # Ransomware Readiness Score
        print("\n" + "-"*70)
        print("  RANSOMWARE READINESS ASSESSMENT")
        print("-"*70)
        print(f"\nRANSOMWARE READINESS SCORE: {ransomware['readiness_score']}/100")
        print(f"READINESS LEVEL: {ransomware['readiness_level']}")
        print(f"CAN SURVIVE ATTACK: {'YES' if ransomware['can_survive_attack'] else 'NO - HIGH RISK'}")
        print(f"ESTIMATED RECOVERY TIME: {ransomware['estimated_recovery_time']}")
        print(f"CYBER INSURANCE READY: {'YES' if ransomware['insurance_ready'] else 'NO'}")
        
        # Attack Vectors
        if ransomware['attack_vectors']:
            print("\n" + "-"*70)
            print("  RANSOMWARE ATTACK VECTORS DETECTED")
            print("-"*70)
            
            for i, vector in enumerate(ransomware['attack_vectors'], 1):
                print(f"\n{i}. [{vector['severity']}] {vector['vector']}")
                print(f"   Likelihood: {vector['likelihood']}")
                print(f"   Impact: {vector['impact']}")
                print(f"   Fix: {vector['fix']}")
        
        # Top Recommendations
        if risk['recommendations']:
            print("\n" + "-"*70)
            print("  PRIORITY RECOMMENDATIONS")
            print("-"*70)
            for i, rec in enumerate(risk['recommendations'][:5], 1):
                print(f"{i}. {rec}")
        
        print("\n" + "="*70)
        print(f"  Reports saved to: {Config.REPORTS_DIR}")
        print("="*70 + "\n")
    
    def _save_results(self, target: str, results: dict):
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{target.replace('.', '_')}_{timestamp}.json"
        filepath = Config.REPORTS_DIR / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"[+] JSON results saved: {filepath.name}")
    
    def _generate_pdf_report(self, target: str, results: dict):
        """Generate professional PDF report"""
        try:
            from src.reporters.pdf_reporter import PDFReporter
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            pdf_filename = f"ransomware_assessment_{target.replace('.', '_')}_{timestamp}.pdf"
            pdf_path = Config.REPORTS_DIR / pdf_filename
            
            reporter = PDFReporter()
            reporter.generate(results, pdf_path)
            
            print(f"[+] PDF report saved: {pdf_path.name}")
            
        except Exception as e:
            import traceback
            print(f"[!] PDF generation failed: {str(e)}")
            print(f"[!] Full error: {traceback.format_exc()}")
            print("[!] JSON report still available")

def main():
    """CLI entry point"""
    if len(sys.argv) < 2:
        print("\n" + "="*70)
        print("  SecureScore - Ransomware Readiness Assessment")
        print("="*70)
        print("\nUsage: python -m src.main <target>")
        print("\nExamples:")
        print("  python -m src.main google.com")
        print("  python -m src.main 192.168.1.1")
        print("  python -m src.main mycompany.com")
        print("\nWhat it checks:")
        print("  - Exposed RDP/SMB ports (ransomware entry points)")
        print("  - Email security (phishing prevention)")
        print("  - SSL/TLS vulnerabilities (credential theft)")
        print("  - Web application security (initial access)")
        print("\nOutputs:")
        print("  - Ransomware readiness score (0-100)")
        print("  - Professional PDF report")
        print("  - JSON data for automation")
        print("="*70 + "\n")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Run comprehensive assessment
    app = SecureScore()
    results = app.scan(target)
    
    # Exit with code based on ransomware readiness
    readiness = results["ransomware_readiness"]["readiness_score"]
    if readiness < 40:
        sys.exit(2)  # Critical risk
    elif readiness < 70:
        sys.exit(1)  # High risk
    else:
        sys.exit(0)  # Protected

if __name__ == "__main__":
    main()