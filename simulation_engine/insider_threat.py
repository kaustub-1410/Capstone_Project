"""
Insider Threat Simulator Module — Simulates insider threat actions (privilege abuse,
USB exfiltration, credential theft, financial fraud) and anomalies detection.
"""

import logging
import math
from typing import Dict, List, Set, Optional, Tuple, Any

logger = logging.getLogger(__name__)

class InsiderThreatSimulator:
    """
    Simulates insider activity logs and tracks anomaly score indicators
    (accessing out-of-department servers, unusual login hours, high-volume data exfiltration).
    """

    def __init__(self):
        # Baseline user activity profile template
        # {username: {dept: X, allowed_servers: [...], base_data_volume: float}}
        self.profiles: Dict[str, Dict[str, Any]] = {
            "hr_user": {"dept": "HR", "allowed_servers": ["SRV-HR"], "avg_daily_volume": 10.5},
            "finance_user": {"dept": "Finance", "allowed_servers": ["SRV-FIN"], "avg_daily_volume": 25.0},
            "eng_user": {"dept": "Engineering", "allowed_servers": ["SRV-ENG", "SRV-GIT"], "avg_daily_volume": 50.0}
        }
        self.security_alerts: List[Dict[str, Any]] = []

    def log_activity(self, username: str, accessed_server: str, data_volume_mb: float, is_working_hours: bool = True) -> float:
        """
        Logs user activity and calculates an anomaly score.
        Score ranges from 0.0 (perfectly normal) to 1.0 (highly anomalous).
        If score exceeds 0.7, a security alert is triggered.
        """
        profile = self.profiles.get(username)
        if not profile:
            logger.warning(f"Unknown user logged activity: {username}")
            return 1.0
            
        anomaly_score = 0.0
        
        # 1. Access anomaly: target server not in profile
        if accessed_server not in profile["allowed_servers"]:
            anomaly_score += 0.4
            
        # 2. Time anomaly: outside working hours
        if not is_working_hours:
            anomaly_score += 0.2
            
        # 3. Volume anomaly: data transferred exceeds average by a margin
        avg_vol = profile["avg_daily_volume"]
        if data_volume_mb > avg_vol * 3:
            # Scale log ratio
            anomaly_score += min(0.4, 0.1 * (data_volume_mb / avg_vol))

        anomaly_score = min(1.0, round(anomaly_score, 2))
        
        if anomaly_score >= 0.6:
            alert = {
                "user": username,
                "server": accessed_server,
                "volume": data_volume_mb,
                "score": anomaly_score,
                "alert_type": "Insider_Threat_Anomaly"
            }
            self.security_alerts.append(alert)
            logger.warning(f"Insider Anomaly Alert triggered for '{username}': score={anomaly_score}")
            
        return anomaly_score

    def simulate_usb_exfiltration(self, username: str, host_id: str, file_list: List[str]) -> bool:
        """Simulates an insider copying files to a USB drive."""
        logger.warning(f"Insider '{username}' performed USB file transfer on host '{host_id}': exfiltrating {len(file_list)} files.")
        alert = {
            "user": username,
            "host": host_id,
            "files": file_list,
            "alert_type": "USB_Data_Exfiltration",
            "score": 0.95
        }
        self.security_alerts.append(alert)
        return True

    def simulate_financial_fraud(self, username: str, amount_usd: float) -> bool:
        """Simulates an insider modifying accounting database records to transfer funds."""
        logger.critical(f"Insider '{username}' modified ledger table: initiated unauthorized transfer of ${amount_usd:.2f}")
        alert = {
            "user": username,
            "amount": amount_usd,
            "alert_type": "Financial_Fraud_Transaction",
            "score": 0.99
        }
        self.security_alerts.append(alert)
        return True
