import pytest
from simulation_engine.iot.iot_simulator import IoTSimulator
from simulation_engine.iot.iot_attacks import IoTAttackSimulator

def test_modbus_protocol():
    iot = IoTSimulator()
    
    # Read register
    val = iot.read_modbus_register(1001)
    assert val == 50
    
    # Write register (unauthenticated)
    success = iot.write_modbus_register(1001, 75)
    assert success is True
    assert iot.read_modbus_register(1001) == 75

def test_firmware_flashing():
    iot = IoTSimulator()
    
    # Attempt with bad credentials (should fail)
    success = iot.flash_firmware("CAM-01", "malicious_fw", {"username": "admin", "password": "wrongpassword"})
    assert success is False
    assert iot.devices["CAM-01"]["firmware_version"] == "v0.9-beta"
    
    # Attempt with correct default credentials (should succeed)
    success = iot.flash_firmware("CAM-01", "malicious_fw", {"username": "admin", "password": "admin"})
    assert success is True
    assert "custom-" in iot.devices["CAM-01"]["firmware_version"]

def test_iot_attacks():
    attacker = IoTAttackSimulator()
    
    # 1. Modbus Hijack Centrifuge
    success = attacker.execute_modbus_hijack(1001, 150)
    assert success is True
    
    # 2. Mirai compromise on CAM-01 (default admin/admin)
    compromised = attacker.execute_mirai_scan_compromise("CAM-01")
    assert compromised is True
    
    # Mirai on PLC-01 (default admin/password)
    compromised = attacker.execute_mirai_scan_compromise("PLC-01")
    assert compromised is True

    # 3. Flashing unauthorized firmware
    flash_success = attacker.execute_malicious_firmware_flash("CAM-01", "rootkit.bin")
    assert flash_success is True
