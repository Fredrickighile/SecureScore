"""
Risk Score Calculator
Calculates overall security risk score from scan results
"""
from typing import Dict, List

class RiskCalculator:
    """Calculates and categorizes security risk"""
    
    @staticmethod
    def calculate_overall_risk(scan_results: Dict) -> Dict:
        """
        Calculate overall risk score from all scanners
        
        Args:
            scan_results: Combined results from all scanners
            
        Returns:
            Dict with overall risk assessment
        """
        total_risk = 0
        all_vulnerabilities = []
        
        # Collect all vulnerabilities and sum risk scores
        for scanner_name, result in scan_results.items():
            if isinstance(result, dict) and 'vulnerabilities' in result:
                all_vulnerabilities.extend(result['vulnerabilities'])
                total_risk += result.get('risk_score', 0)
        
        # Categorize risk level
        if total_risk >= 70:
            risk_level = "CRITICAL"
            color = "red"
        elif total_risk >= 50:
            risk_level = "HIGH"
            color = "orange"
        elif total_risk >= 30:
            risk_level = "MEDIUM"
            color = "yellow"
        else:
            risk_level = "LOW"
            color = "green"
        
        # Sort vulnerabilities by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_vulns = sorted(
            all_vulnerabilities,
            key=lambda x: severity_order.get(x.get('severity', 'LOW'), 4)
        )
        
        return {
            "total_risk_score": min(100, total_risk),
            "risk_level": risk_level,
            "color": color,
            "total_vulnerabilities": len(all_vulnerabilities),
            "critical_count": sum(1 for v in all_vulnerabilities if v.get('severity') == 'CRITICAL'),
            "high_count": sum(1 for v in all_vulnerabilities if v.get('severity') == 'HIGH'),
            "medium_count": sum(1 for v in all_vulnerabilities if v.get('severity') == 'MEDIUM'),
            "low_count": sum(1 for v in all_vulnerabilities if v.get('severity') == 'LOW'),
            "vulnerabilities": sorted_vulns,
            "recommendations": RiskCalculator._get_top_recommendations(sorted_vulns)
        }
    
    @staticmethod
    def _get_top_recommendations(vulnerabilities: List[Dict], top_n: int = 5) -> List[str]:
        """Get top priority recommendations"""
        recommendations = []
        for vuln in vulnerabilities[:top_n]:
            if 'recommendation' in vuln:
                recommendations.append(vuln['recommendation'])
        return recommendations

# Test function
if __name__ == "__main__":
    # Mock scan results
    test_results = {
        "network": {
            "vulnerabilities": [
                {"severity": "CRITICAL", "risk_points": 25, "recommendation": "Close RDP port"}
            ],
            "risk_score": 25
        },
        "ssl": {
            "vulnerabilities": [
                {"severity": "HIGH", "risk_points": 15, "recommendation": "Renew SSL certificate"}
            ],
            "risk_score": 15
        }
    }
    
    calculator = RiskCalculator()
    risk = calculator.calculate_overall_risk(test_results)
    print(risk)