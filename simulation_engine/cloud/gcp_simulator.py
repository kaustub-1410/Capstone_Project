"""
GCP Cloud Security Simulator — Models Google Cloud IAM service accounts and storage buckets.
"""

import logging
from typing import Dict, List, Set, Optional, Any

logger = logging.getLogger(__name__)

class GCPSimulator:
    """
    Simulates Google Cloud Platform (GCP) infrastructure: IAM policies, Service Account keys, and Cloud Storage.
    """

    def __init__(self):
        self.gcs_buckets: Dict[str, Dict[str, Any]] = {
            "gcp-billing": {"public_access": False, "files": ["invoice.pdf"]},
            "gcp-assets": {"public_access": True, "files": ["avatar.png"]}
        }
        self.service_accounts: Dict[str, Dict[str, Any]] = {
            "sa-compute@project.iam.gserviceaccount.com": {"roles": ["roles/compute.admin"]},
            "sa-storage@project.iam.gserviceaccount.com": {"roles": ["roles/storage.objectViewer"]}
        }

    def generate_service_account_key(self, service_account_email: str) -> Optional[str]:
        """Simulates creating a JSON key file for a GCP service account."""
        if service_account_email in self.service_accounts:
            logger.info(f"Generated service account key file for: {service_account_email}")
            return f"GCP_SA_KEY_{service_account_email}"
        return None

    def read_gcs_bucket(self, bucket_name: str, sa_key: Optional[str] = None) -> Optional[List[str]]:
        """Simulates reading object files from GCP Cloud Storage buckets."""
        bucket = self.gcs_buckets.get(bucket_name)
        if not bucket:
            return None
            
        if bucket["public_access"]:
            logger.info(f"Anonymous access to public GCS bucket: {bucket_name}")
            return bucket["files"]
            
        if sa_key:
            # Match service account role permissions
            for email, sa in self.service_accounts.items():
                if f"GCP_SA_KEY_{email}" == sa_key:
                    if "roles/storage.objectViewer" in sa["roles"] or "roles/editor" in sa["roles"]:
                        logger.info(f"Authorized GCS access to: {bucket_name} using key: {email}")
                        return bucket["files"]
                        
        logger.warning(f"Unauthorized GCS access attempt to: {bucket_name}")
        return None
