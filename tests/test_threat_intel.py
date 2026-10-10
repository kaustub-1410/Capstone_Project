import pytest
from intelligence.mitre_client import MITREClient
from intelligence.cisa_kev_client import CISAKEVClient
from intelligence.nvd_client import NVDClient
from intelligence.epss_client import EPSSClient
from intelligence.intelligence_aggregator import IntelligenceAggregator

def test_individual_intel_clients():
    # 1. MITRE Client
    mitre = MITREClient()
    tech = mitre.get_technique("T1046")
    assert tech is not None
    assert tech["name"] == "Network Service Discovery"
    assert mitre.sync_latest_feed() is True
    
    # 2. CISA KEV Client
    cisa = CISAKEVClient()
    assert cisa.is_known_exploited("CVE-2017-0144") is True
    assert cisa.is_known_exploited("CVE-2022-XXXX") is False
    assert cisa.get_remediation_guidance("CVE-2017-0144") == "Apply patch"
    
    # 3. NVD Client
    nvd = NVDClient()
    details = nvd.get_cve_details("CVE-2021-44228")
    assert details is not None
    assert details["cvss"] == 10.0
    
    # 4. EPSS Client
    epss = EPSSClient()
    assert epss.get_exploit_probability("CVE-2017-0144") == 0.975
    assert epss.get_exploit_probability("CVE-2029-XXXX") == 0.01

def test_intelligence_aggregator():
    aggregator = IntelligenceAggregator()
    
    # Sync feeds
    assert aggregator.sync_all_feeds() is True
    
    # Aggregate CVE details
    intel = aggregator.aggregate_cve_intelligence("CVE-2017-0144")
    
    assert intel["cve_id"] == "CVE-2017-0144"
    assert intel["cvss"] == 9.8
    assert intel["epss_score"] == 0.975
    assert intel["cisa_kev"] is True
    assert "remediation" in intel
    assert len(intel["mitre_techniques"]) > 0
