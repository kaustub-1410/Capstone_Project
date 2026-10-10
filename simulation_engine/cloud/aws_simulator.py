"""
AWS Cloud Security Simulator — Models AWS IAM roles, EC2, S3, and Lambda resources.
"""

import logging
from typing import Dict, List, Set, Optional, Any

logger = logging.getLogger(__name__)

class AWSSimulator:
    """
    Simulates AWS cloud control plane security: IAM, EC2 metadata service, S3 bucket access, and Lambda.
    """

    def __init__(self):
        self.s3_buckets: Dict[str, Dict[str, Any]] = {
            "enterprise-financials": {"public_access": False, "files": ["Q4_balance.csv", "tax_returns.pdf"]},
            "marketing-public": {"public_access": True, "files": ["logo.png", "brochure.pdf"]}
        }
        self.iam_roles: Dict[str, List[str]] = {
            "EC2-Default-Role": ["s3:Read"],
            "Lambda-Execution-Role": ["iam:CreateAccessKey", "s3:Read", "s3:Write"]
        }

    def access_metadata_service(self, role_name: str) -> Optional[str]:
        """Simulates requesting temporary credentials from the EC2 Instance Metadata Service (IMDS)."""
        if role_name in self.iam_roles:
            logger.info(f"IMDS token retrieved for IAM role: {role_name}")
            return f"AWS_TEMP_TOKEN_{role_name}"
        return None

    def read_s3_bucket(self, bucket_name: str, token: Optional[str] = None) -> Optional[List[str]]:
        """Simulates reading files from an S3 bucket with IAM token authorization."""
        bucket = self.s3_buckets.get(bucket_name)
        if not bucket:
            return None
            
        if bucket["public_access"]:
            logger.info(f"Anonymous access to public S3 bucket: {bucket_name}")
            return bucket["files"]
            
        if token:
            # Simple permission check
            for role, policies in self.iam_roles.items():
                if f"AWS_TEMP_TOKEN_{role}" == token:
                    if "s3:Read" in policies or "s3:*" in policies:
                        logger.info(f"Authorized access to S3 bucket: {bucket_name} using role: {role}")
                        return bucket["files"]
                        
        logger.warning(f"Unauthorized S3 access attempt to: {bucket_name}")
        return None

    def invoke_lambda(self, function_name: str, payload: Dict[str, Any], token: Optional[str] = None) -> Dict[str, Any]:
        """Simulates executing an AWS Lambda serverless function."""
        logger.info(f"Invoking AWS Lambda function: {function_name}")
        return {"status": "success", "result": f"Executed function: {function_name} with payload size: {len(payload)}"}
