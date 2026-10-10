"""
Active Directory Simulation Module — Simulates Kerberos, LDAP, Group Policy,
Domain Trusts, and standard AD attack primitives (Pass the Hash, Kerberoasting, Golden Tickets, etc.)
"""

import logging
import random
from typing import Dict, List, Optional, Tuple, Any
from shared.models import Host, User, Credential
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class ActiveDirectorySimulator:
    """
    Simulates domain controllers, directory services, Kerberos authentication protocol state,
    and AD-specific attacks.
    """

    def __init__(self, topo: NetworkTopology):
        self.topo = topo
        self._krbtgt_hash = "5000krbtgt_ntlm_hash"
        self._domain_controllers = [h for h in self.topo.hosts.values() if h.role == "domain_controller"]

    def request_tgt(self, username: str, domain: str) -> Optional[Credential]:
        """Simulates requesting a Kerberos Ticket Granting Ticket (TGT)."""
        user = self.topo.users.get(username)
        if not user or user.domain != domain:
            logger.warning(f"TGT request failed: User {username} not found in domain {domain}")
            return None
            
        logger.info(f"Kerberos TGT granted to user {username}@{domain}")
        return Credential(
            username=username,
            password_hash="TGT_encrypted_session_key",
            cred_type="kerberos_ticket",
            ticket_type="TGT",
            privilege_level="user" if "admin" not in user.roles else "domain_admin"
        )

    def request_tgs(self, tgt: Credential, spn: str) -> Optional[Credential]:
        """Simulates requesting a Service Ticket (TGS) using a valid TGT."""
        if tgt.cred_type != "kerberos_ticket" or tgt.ticket_type != "TGT":
            logger.warning("TGS request failed: Invalid TGT provided.")
            return None
            
        logger.info(f"Kerberos TGS granted to user {tgt.username} for SPN: {spn}")
        return Credential(
            username=tgt.username,
            password_hash="TGS_encrypted_service_key",
            cred_type="kerberos_ticket",
            ticket_type="TGS",
            spn=spn,
            privilege_level=tgt.privilege_level
        )

    # ------------------------------------------------------------------ #
    #  Attack Simulation Handlers
    # ------------------------------------------------------------------ #

    def simulate_kerberoasting(self, compromised_host_id: str, target_spns: List[str]) -> List[Credential]:
        """
        Simulates Kerberoasting attack.
        Requests service tickets for specific SPNs, yielding offline crackable TGS tickets.
        """
        host = self.topo.hosts.get(compromised_host_id)
        if not host or not host.compromised:
            logger.warning(f"Kerberoasting failed: Host {compromised_host_id} is not compromised.")
            return []

        roasted_tickets = []
        for spn in target_spns:
            # Generate roasted ticket hash
            ticket = Credential(
                username="roasted_svc",
                password_hash=f"$kerb5tgs$23${spn}$roasted_hash_value",
                cred_type="kerberos_ticket",
                ticket_type="TGS",
                spn=spn
            )
            roasted_tickets.append(ticket)
            logger.info(f"Kerberoasted SPN: {spn} from host {compromised_host_id}")
            
        return roasted_tickets

    def simulate_pass_the_hash(self, source_host_id: str, target_host_id: str, cred: Credential) -> bool:
        """
        Simulates Pass the Hash (PtH) lateral movement.
        """
        src = self.topo.hosts.get(source_host_id)
        dst = self.topo.hosts.get(target_host_id)
        
        if not src or not src.compromised or not dst:
            return False
            
        if cred.privilege_level in ("administrator", "domain_admin"):
            dst.compromised = True
            dst.compromised_by = src.compromised_by
            self.topo.sync_host_to_neo4j(dst)
            logger.info(f"Pass-the-Hash successful from {source_host_id} to {target_host_id} using {cred.username}")
            return True
            
        return False

    def simulate_golden_ticket(self, domain: str, username: str) -> Optional[Credential]:
        """
        Simulates Golden Ticket forgery.
        Requires krbtgt hash. Forges a domain admin TGT valid for 10 years.
        """
        logger.info(f"Forged Kerberos Golden Ticket for {username}@{domain} using krbtgt hash")
        return Credential(
            username=username,
            password_hash="FORGED_GOLDEN_TGT",
            cred_type="kerberos_ticket",
            ticket_type="TGT",
            krbtgt_hash=self._krbtgt_hash,
            privilege_level="domain_admin"
        )

    def simulate_dcsync(self, domain_admin_cred: Credential) -> Optional[List[Credential]]:
        """
        Simulates DCSync attack to replicate domain credentials from Domain Controller.
        Requires Domain Admin privileges.
        """
        if domain_admin_cred.privilege_level != "domain_admin":
            logger.warning("DCSync failed: Insufficient privilege level.")
            return None
            
        logger.info("DCSync replica request successfully dumped domain hashes.")
        
        dumped_creds = []
        for user in self.topo.users.values():
            for cred in user.credentials:
                dumped_creds.append(cred)
                
        return dumped_creds
