"""Digital Twin environment templates."""

from digital_twin.templates.bank import BankEnvironment
from digital_twin.templates.hospital import HospitalEnvironment
from digital_twin.templates.university import UniversityEnvironment
from digital_twin.templates.manufacturing import ManufacturingEnvironment
from digital_twin.templates.government import GovernmentEnvironment
from digital_twin.templates.cloud_enterprise import CloudEnterpriseEnvironment

__all__ = [
    "BankEnvironment",
    "HospitalEnvironment",
    "UniversityEnvironment",
    "ManufacturingEnvironment",
    "GovernmentEnvironment",
    "CloudEnterpriseEnvironment",
]
