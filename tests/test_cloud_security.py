import pytest
from simulation_engine.cloud.aws_simulator import AWSSimulator
from simulation_engine.cloud.azure_simulator import AzureSimulator
from simulation_engine.cloud.gcp_simulator import GCPSimulator
from simulation_engine.cloud.cloud_attacks import CloudAttackSimulator

def test_aws_simulation():
    aws = AWSSimulator()
    
    # Try public S3 bucket
    public_files = aws.read_s3_bucket("marketing-public")
    assert public_files is not None
    assert "logo.png" in public_files
    
    # Try private bucket without token (should fail)
    private_files = aws.read_s3_bucket("enterprise-financials")
    assert private_files is None
    
    # Try private bucket with valid role metadata token
    token = aws.access_metadata_service("EC2-Default-Role")
    assert token is not None
    
    auth_files = aws.read_s3_bucket("enterprise-financials", token=token)
    assert auth_files is not None
    assert "Q4_balance.csv" in auth_files

def test_azure_simulation():
    azure = AzureSimulator()
    
    # Try private Storage Account with key
    sas = azure.acquire_sas_token("sa_financials", "Key1_financial_secret")
    assert sas is not None
    
    files = azure.read_storage_account("sa_financials", sas)
    assert files is not None
    assert "ledger.xlsx" in files

def test_gcp_simulation():
    gcp = GCPSimulator()
    
    key = gcp.generate_service_account_key("sa-storage@project.iam.gserviceaccount.com")
    assert key is not None
    
    files = gcp.read_gcs_bucket("gcp-billing", sa_key=key)
    assert files is not None
    assert "invoice.pdf" in files

def test_cloud_attacks():
    attacker = CloudAttackSimulator()
    
    # 1. AWS IMDS Compromise SSRF
    aws_files = attacker.execute_aws_imds_compromise("EC2-Default-Role", "enterprise-financials")
    assert aws_files is not None
    assert "Q4_balance.csv" in aws_files
    
    # 2. Azure key abuse
    azure_files = attacker.execute_azure_sas_abuse("sa_financials", "Key1_financial_secret")
    assert azure_files is not None
    assert "ledger.xlsx" in azure_files
    
    # 3. GCP Service Account key compromise
    gcp_files = attacker.execute_gcp_key_leak("sa-storage@project.iam.gserviceaccount.com", "gcp-billing")
    assert gcp_files is not None
    assert "invoice.pdf" in gcp_files
