"""
Azure Cloud Security Simulator — Models Azure AD (Entra ID) and Azure storage accounts.
"""

import logging
from typing import Dict, List, Set, Optional, Any

logger = logging.getLogger(__name__)

class AzureSimulator:
    """
    Simulates Azure cloud platform security: Entra ID users, storage account access tokens, and Azure VM policies.
    """

    def __init__(self):
        self.storage_accounts: Dict[str, Dict[str, Any]] = {
            "sa_financials": {"keys": ["Key1_financial_secret", "Key2_financial_secret"], "files": ["ledger.xlsx"]},
            "sa_public": {"keys": ["Key1_public_key"], "files": ["banner.jpg"]}
        }
        self.entra_users: Dict[str, Dict[str, Any]] = {
            "admin@corp.onmicrosoft.com": {"roles": ["Global Administrator"], "mfa_enabled": True},
            "developer@corp.onmicrosoft.com": {"roles": ["Contributor"], "mfa_enabled": False}
        }

    def acquire_sas_token(self, account_name: str, key: str) -> Optional[str]:
        """Simulates acquiring a Shared Access Signature (SAS) token for an Azure Storage Account."""
        sa = self.storage_accounts.get(account_name)
        if sa and key in sa["keys"]:
            logger.info(f"Azure SAS token granted for Storage Account: {account_name}")
            return f"SAS_TOKEN_{account_name}"
        return None

    def read_storage_account(self, account_name: str, sas_token: str) -> Optional[List[str]]:
        """Simulates reading container assets from Azure Storage Accounts."""
        sa = self.storage_accounts.get(account_name)
        if sa and sas_token == f"SAS_TOKEN_{account_name}":
            logger.info(f"Authorized access to Azure Storage Account: {account_name}")
            return sa["files"]
        logger.warning(f"Unauthorized Azure Storage access attempt to: {account_name}")
        return None
