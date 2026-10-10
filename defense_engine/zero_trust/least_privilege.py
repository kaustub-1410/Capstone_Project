"""
Zero Trust Least Privilege Module — Tracks credential usage and dynamically
reduces privileges to enforce the Principle of Least Privilege.
"""

import logging
from typing import Dict, List, Set, Optional, Any
from shared.models import Credential

logger = logging.getLogger(__name__)

class LeastPrivilegeEngine:
    """
    Monitors access tokens and credential capabilities.
    Dynamically downgrades or revokes stale or unused permissions.
    """

    def __init__(self):
        # Map: credential_id -> active_scopes (list of permissions)
        self.credential_permissions: Dict[str, Set[str]] = {}

    def register_credential(self, cred_id: str, default_permissions: List[str]):
        """Registers a credential and its default privilege scopes."""
        self.credential_permissions[cred_id] = set(default_permissions)

    def revoke_unused_privileges(self, cred_id: str, used_permissions: List[str]) -> List[str]:
        """
        Compares requested scopes with actually utilized permissions,
        revoking any scopes that have not been exercised (JIT privilege scaling).
        """
        scopes = self.credential_permissions.get(cred_id)
        if not scopes:
            return []
            
        unused = scopes - set(used_permissions)
        for perm in unused:
            scopes.remove(perm)
            logger.info(f"LeastPrivilege: Revoked unused scope '{perm}' on credential '{cred_id}'")
            
        return list(unused)

    def verify_permission(self, cred_id: str, required_permission: str) -> bool:
        """Verifies if the credential currently holds the required permission scope."""
        scopes = self.credential_permissions.get(cred_id)
        if not scopes:
            return False
        return required_permission in scopes
