"""
Ransomware Readiness Calculator
Assesses organization's risk of ransomware attack
"""

class RansomwareCalculator:
    """Calculates ransomware attack risk"""
    
    @staticmethod
    def calculate_readiness(scan_results: dict) -> dict:
        """
        Calculate ransomware readiness score
        
        Args:
            scan_results: All scan results
            
        Returns:
            Ransomware readiness assessment
        """
        readiness_score = 100
        risk_factors = []
        
        # Check network vulnerabilities
        network = scan_results.get('network', {})
        for vuln in network.get('vulnerabilities', []):
            if vuln.get('type') == 'exposed_rdp':
                readiness_score -= 30
                risk_factors.append({
                    'factor': 'RDP Exposed to Internet',
                    'impact': 'Primary ransomware entry point',
                    'severity': 'CRITICAL',
                    'points_deducted': 30
                })
            elif vuln.get('type') == 'exposed_smb':
                readiness_score -= 25
                risk_factors.append({
                    'factor': 'SMB Protocol Exposed',
                    'impact': 'WannaCry/NotPetya attack vector',
                    'severity': 'CRITICAL',
                    'points_deducted': 25
                })
        
        # Check email security (phishing = ransomware delivery)
        email = scan_results.get('email', {})
        for vuln in email.get('vulnerabilities', []):
            if vuln.get('type') == 'missing_dmarc':
                readiness_score -= 15
                risk_factors.append({
                    'factor': 'No Email Authentication (DMARC)',
                    'impact': 'Vulnerable to ransomware phishing emails',
                    'severity': 'HIGH',
                    'points_deducted': 15
                })
            elif vuln.get('type') == 'missing_spf':
                readiness_score -= 10
                risk_factors.append({
                    'factor': 'No Sender Verification (SPF)',
                    'impact': 'Email spoofing enables phishing attacks',
                    'severity': 'MEDIUM',
                    'points_deducted': 10
                })
        
        # Check SSL/TLS (outdated = vulnerable to MITM for ransomware delivery)
        ssl = scan_results.get('ssl', {})
        for vuln in ssl.get('vulnerabilities', []):
            if vuln.get('type') == 'weak_ssl':
                readiness_score -= 12
                risk_factors.append({
                    'factor': 'Outdated Encryption Protocol',
                    'impact': 'Man-in-the-middle ransomware injection',
                    'severity': 'HIGH',
                    'points_deducted': 12
                })
        
        # Check web security headers
        webapp = scan_results.get('webapp', {})
        for vuln in webapp.get('vulnerabilities', []):
            if 'security_header' in vuln.get('type', ''):
                readiness_score -= 5
                risk_factors.append({
                    'factor': 'Missing Security Headers',
                    'impact': 'Web-based ransomware delivery possible',
                    'severity': 'MEDIUM',
                    'points_deducted': 5
                })
        
        # Determine readiness level
        if readiness_score >= 80:
            level = "EXCELLENT"
            color = "green"
            recommendation = "Organization has strong ransomware defenses"
        elif readiness_score >= 60:
            level = "GOOD"
            color = "lightgreen"
            recommendation = "Minor improvements needed to prevent ransomware"
        elif readiness_score >= 40:
            level = "MODERATE"
            color = "orange"
            recommendation = "Significant vulnerabilities - ransomware attack likely"
        elif readiness_score >= 20:
            level = "POOR"
            color = "red"
            recommendation = "Critical gaps - ransomware attack imminent"
        else:
            level = "CRITICAL"
            color = "darkred"
            recommendation = "Immediate action required - multiple attack vectors exposed"
        
        return {
            'readiness_score': max(0, readiness_score),
            'readiness_level': level,
            'color': color,
            'recommendation': recommendation,
            'risk_factors': risk_factors,
            'total_risk_factors': len(risk_factors)
        }