from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime
import uuid

class Credential(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    password_hash: str
    cred_type: str = "password" # password, hash, ssh_key, kerberos_ticket
    privilege_level: str = "user" # user, administrator, domain_admin
    # Active Directory / Kerberos extensions
    ticket_type: Optional[str] = None # TGT, TGS, None
    spn: Optional[str] = None # Service Principal Name for Kerberoasting
    krbtgt_hash: Optional[str] = None # krbtgt hash for Golden Ticket creation
    session_key: Optional[str] = None

class Service(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str # SMB, HTTP, SSH, RDP, LDAP
    port: int
    version: str = "1.0"
    vulnerabilities: List[str] = Field(default_factory=list) # List of Exploit IDs

class Host(BaseModel):
    id: str
    name: str
    ip: str
    os: str # "Windows Server 2022", "Ubuntu 22.04", "Windows 11"
    role: str = "workstation" # workstation, domain_controller, web_server, db_server, file_server
    domain: str = "enterprise.local"
    services: List[Service] = Field(default_factory=list)
    logged_in_users: List[str] = Field(default_factory=list) # Usernames
    compromised: bool = False
    compromised_by: Optional[str] = None # Attacker Agent ID
    isolated: bool = False
    credentials_dumped: bool = False
    # Phase 5 — Digital Twin extensions (all optional, backward compatible)
    department: Optional[str] = None           # Organizational department
    sensitivity_level: Optional[str] = None    # critical, high, medium, low
    asset_value: float = 0.0                   # Estimated USD value for risk calculations
    cloud_provider: Optional[str] = None       # aws, azure, gcp (None = on-premises)
    device_type: Optional[str] = None          # plc, hmi, iot_device, kiosk, atm, etc.

class User(BaseModel):
    id: str
    username: str
    domain: str = "enterprise.local"
    roles: List[str] = Field(default_factory=list) # IT, HR, Finance, Admin
    credentials: List[Credential] = Field(default_factory=list)
    phishing_susceptibility: float = 0.3 # Probability of clicking on phishing email

class Exploit(BaseModel):
    id: str
    name: str
    cve: str
    target_service: str
    privilege_escalation: bool = False
    success_probability: float = 0.7

class TelemetryEvent(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    run_id: uuid.UUID
    host_id: str
    event_type: str # Sysmon_ProcessCreation, Sysmon_NetworkConnection, Auth_Log, IDS_Alert, Auditd_Process
    source: str
    severity: str = "INFO"
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
