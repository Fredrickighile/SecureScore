"""
SecureScore Configuration Management
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    
    # Project Paths
    BASE_DIR = Path(__file__).parent.parent
    REPORTS_DIR = BASE_DIR / "reports"
    DATA_DIR = BASE_DIR / "data"
    LOGS_DIR = BASE_DIR / "logs"
    
    # Scan Configuration
    DEFAULT_SCAN_TIMEOUT = 300
    
    # Nmap Ports
    NMAP_QUICK_PORTS = "21,22,23,25,80,443,445,3306,3389,5900,8080"  # ransomware-critical only
    NMAP_STANDARD_PORTS = "1-1024,1433,1521,3306,3389,5432,5900,8000,8080,8443"
    
    # Risk Scoring Weights
    RISK_WEIGHTS = {
        "exposed_rdp": 25,      # Port 3389
        "exposed_smb": 20,      # Port 445
        "weak_ssl": 15,
        "missing_dmarc": 10,
        "missing_spf": 8,
        "expired_cert": 20,
        "breach_detected": 30,
        "open_database_port": 18,
    }
    
    @classmethod
    def ensure_directories(cls):
        """Create required directories"""
        cls.REPORTS_DIR.mkdir(exist_ok=True)
        cls.DATA_DIR.mkdir(exist_ok=True)
        cls.LOGS_DIR.mkdir(exist_ok=True)

Config.ensure_directories()