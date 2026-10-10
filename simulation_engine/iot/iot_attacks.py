"""
IoT Attacks Module — Simulates Modbus protocol hijacking, Mirai default credential scans,
and malicious firmware flashing.
"""

import logging
from typing import Dict, Any, List
from simulation_engine.iot.iot_simulator import IoTSimulator

logger = logging.getLogger(__name__)

class IoTAttackSimulator:
    """
    Executes industrial control system (ICS) and IoT-focused attacks against an IoTSimulator instance.
    """

    def __init__(self):
        self.iot = IoTSimulator()

    def execute_modbus_hijack(self, target_register: int, malicious_value: int) -> bool:
        """
        Exploits lack of authentication in Modbus TCP to directly overwrite PLC register values.
        """
        logger.info(f"Initiating Modbus TCP register hijack on register: {target_register}")
        success = self.iot.write_modbus_register(target_register, malicious_value)
        return success

    def execute_mirai_scan_compromise(self, target_device_id: str) -> bool:
        """
        Simulates Mirai-style brute force scan.
        Attempts connection using a dictionary of insecure default credentials.
        """
        logger.info(f"Executing default credential scan on IoT device: {target_device_id}")
        dev = self.iot.devices.get(target_device_id)
        if not dev:
            return False
            
        defaults = dev["default_credentials"]
        # Standard Mirai default credential list snippet
        wordlist = [
            {"username": "root", "password": "root"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "support", "password": "support"}
        ]
        
        for cred in wordlist:
            if cred["username"] == defaults["username"] and cred["password"] == defaults["password"]:
                logger.warning(f"Device '{target_device_id}' compromised via default credentials! Host joined Mirai botnet.")
                return True
                
        return False

    def execute_malicious_firmware_flash(self, target_device_id: str, payload_name: str) -> bool:
        """
        Attempts to update device firmware with a malicious image.
        Uses default credentials to bypass firmware verification.
        """
        dev = self.iot.devices.get(target_device_id)
        if not dev:
            return False
            
        defaults = dev["default_credentials"]
        success = self.iot.flash_firmware(target_device_id, payload_name, defaults)
        return success
