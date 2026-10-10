"""
Cloud Attacks Module — Simulates attack payloads targeting AWS, Azure, and GCP resources.
Includes Instance Metadata Service (IMDS) SSRF, key compromise, and storage exfiltration.
"""

import logging
from typing import Dict, Any, List, Optional
from simulation_engine.cloud.aws_simulator import AWSSimulator
from simulation_engine.cloud.azure_simulator import AzureSimulator
from simulation_engine.cloud.gcp_simulator import GCPSimulator

logger = logging.getLogger(__name__)

class CloudAttackSimulator:
    """
    Executes and validates cloud attack steps against AWS, Azure, and GCP target environments.
    """

    def __init__(self):
        self.aws = AWSSimulator()
        self.azure = AzureSimulator()
        self.gcp = GCPSimulator()

    def execute_aws_imds_compromise(self, target_role: str, target_bucket: str) -> Optional[List[str]]:
        """
        SSRF attack path: accesses EC2 Instance Metadata Service (IMDS) to exfiltrate
        temporary credentials, and uses them to access files in a private S3 bucket.
        """
        logger.info(f"Executing AWS IMDS credentials exfiltration for role: {target_role}")
        token = self.aws.access_metadata_service(target_role)
        if not token:
            logger.warning("SSRF failed: Unable to acquire IAM credentials.")
            return None
            
        # Access S3 bucket using exfiltrated credentials
        files = self.aws.read_s3_bucket(target_bucket, token=token)
        if files:
            logger.info(f"Successfully exfiltrated {len(files)} files from AWS S3: {target_bucket}")
            return files
        return None

    def execute_azure_sas_abuse(self, account_name: str, compromised_key: str) -> Optional[List[str]]:
        """
        Abuses leaked Azure storage account keys to generate SAS tokens and access container files.
        """
        logger.info(f"Executing Azure storage key abuse for: {account_name}")
        sas_token = self.azure.acquire_sas_token(account_name, compromised_key)
        if not sas_token:
            logger.warning("Leaked key abuse failed: Invalid storage account key.")
            return None
            
        # Download files from Azure Blob Storage container
        files = self.azure.read_storage_account(account_name, sas_token)
        if files:
            logger.info(f"Successfully exfiltrated {len(files)} files from Azure storage: {account_name}")
            return files
        return None

    def execute_gcp_key_leak(self, service_account_email: str, target_bucket: str) -> Optional[List[str]]:
        """
        Uses a compromised GCP service account JSON private key to download files from Google Cloud Storage.
        """
        logger.info(f"Executing GCP Service Account key compromise for: {service_account_email}")
        key = self.gcp.generate_service_account_key(service_account_email)
        if not key:
            logger.warning("Key compromise failed: Invalid service account email.")
            return None
            
        # Download files from GCS bucket
        files = self.gcp.read_gcs_bucket(target_bucket, sa_key=key)
        if files:
            logger.info(f"Successfully exfiltrated {len(files)} files from GCP bucket: {target_bucket}")
            return files
        return None
