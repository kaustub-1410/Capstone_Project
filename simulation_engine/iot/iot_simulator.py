"""
IoT Security Simulator — Models Programmable Logic Controllers (PLCs),
cameras, routers, medical devices, SCADA, Modbus, and OPC-UA protocols.
"""

import logging
from typing import Dict, List, Set, Optional, Any

logger = logging.getLogger(__name__)

class IoTSimulator:
    """
    Simulates industrial control system (ICS) and Internet of Things (IoT) hardware,
    registers, and insecure default protocols.
    """

    def __init__(self):
        # PLC holding registers (Modbus addresses)
        self.plc_registers: Dict[int, int] = {
            1001: 50,  # Centrifuge speed (RPM)
            1002: 1,   # Cooling valve status (0=Closed, 1=Open)
            1003: 120  # Chamber pressure (PSI)
        }
        self.devices: Dict[str, Dict[str, Any]] = {
            "PLC-01": {
                "type": "plc",
                "firmware_version": "v1.4",
                "default_credentials": {"username": "admin", "password": "password"},
                "modbus_enabled": True
            },
            "CAM-01": {
                "type": "camera",
                "firmware_version": "v0.9-beta",
                "default_credentials": {"username": "admin", "password": "admin"},
                "modbus_enabled": False
            }
        }
        self.scada_online = True

    def read_modbus_register(self, register_address: int) -> Optional[int]:
        """Simulates Modbus TCP read request (unauthenticated)."""
        val = self.plc_registers.get(register_address)
        if val is not None:
            logger.info(f"Modbus read address {register_address}: value={val}")
            return val
        return None

    def write_modbus_register(self, register_address: int, value: int) -> bool:
        """Simulates Modbus TCP write request (unauthenticated, typical of classic Modbus)."""
        if register_address in self.plc_registers:
            self.plc_registers[register_address] = value
            logger.warning(f"Modbus write address {register_address}: updated to value={value}")
            
            # Simple safety check: check for physical limits violation
            if register_address == 1001 and value > 100:
                logger.critical("Centrifuge speed exceeds safety threshold! SCADA alarm triggered.")
            return True
        return False

    def flash_firmware(self, device_id: str, firmware_image: str, credentials: Dict[str, str]) -> bool:
        """Simulates flashing firmware on IoT devices, requiring administrator authentication."""
        dev = self.devices.get(device_id)
        if not dev:
            return False
            
        defaults = dev["default_credentials"]
        if credentials.get("username") == defaults["username"] and credentials.get("password") == defaults["password"]:
            dev["firmware_version"] = f"custom-{firmware_image[:8]}"
            logger.warning(f"Device '{device_id}' firmware updated successfully.")
            return True
            
        logger.warning(f"Failed firmware update attempt on '{device_id}': Authentication failure.")
        return False
