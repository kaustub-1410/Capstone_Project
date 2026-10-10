import os
import sys
import json
import csv
import xml.etree.ElementTree as ET
import pytest

# Ensure workspace root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from shared.models import Host, Service, User
from simulation_engine.network import NetworkTopology
from simulation_engine.ingestor import RealWorldIngestor
from defense_engine.real_world_mitigation import RealWorldMitigationRunner
from attack_engine.real_world_scanner import RealWorldScanner
from telemetry_service.file_ingestor import TelemetryFileIngestor

@pytest.fixture
def clean_topo():
    topo = NetworkTopology()
    topo.neo4j_enabled = False
    return topo

def test_asset_csv_ingestion(clean_topo, tmp_path):
    # Create mock assets CSV
    csv_file = tmp_path / "assets.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["id", "name", "ip", "os", "role", "domain"])
        writer.writerow(["HOST-01", "Web Server", "10.0.1.20", "Linux", "web_server", "enterprise.local"])
        writer.writerow(["HOST-02", "SQL Server", "10.0.1.30", "Ubuntu", "db_server", "enterprise.local"])
        
    ingestor = RealWorldIngestor(clean_topo)
    count = ingestor.import_assets_csv(str(csv_file))
    
    assert count == 2
    assert "HOST-01" in clean_topo.hosts
    assert clean_topo.hosts["HOST-01"].ip == "10.0.1.20"
    assert clean_topo.hosts["HOST-01"].role == "web_server"
    assert "HOST-02" in clean_topo.hosts

def test_nessus_csv_ingestion(clean_topo, tmp_path):
    # Add Host to topology first
    host = Host(id="10.0.1.20", name="Target-Host", ip="10.0.1.20", os="Windows", role="workstation")
    clean_topo.add_host(host)
    
    # Create mock Nessus CSV
    nessus_file = tmp_path / "nessus.csv"
    with open(nessus_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Protocol", "CVE", "Name"])
        writer.writerow(["10.0.1.20", "445", "tcp", "CVE-2017-0144", "MS17-010 EternalBlue"])
        writer.writerow(["10.0.1.20", "80", "tcp", "CVE-2021-41773", "Apache Path Traversal"])

    ingestor = RealWorldIngestor(clean_topo)
    count = ingestor.import_nessus_csv(str(nessus_file))
    
    assert count == 2
    target_host = clean_topo.hosts["10.0.1.20"]
    services_dict = {s.port: s for s in target_host.services}
    assert 445 in services_dict
    assert "CVE-2017-0144" in services_dict[445].vulnerabilities
    assert 80 in services_dict
    assert "CVE-2021-41773" in services_dict[80].vulnerabilities

def test_nessus_xml_ingestion(clean_topo, tmp_path):
    # Create mock Nessus XML file content
    nessus_xml = tmp_path / "nessus.nessus"
    xml_content = """<?xml version="1.0" ?>
    <NessusClientData_v2>
      <Report name="Scan Report">
        <ReportHost name="10.0.1.5">
          <HostProperties>
            <tag name="host-ip">10.0.1.5</tag>
            <tag name="operating-system">Windows Server 2022</tag>
          </HostProperties>
          <ReportItem port="445" svc_name="microsoft-ds" protocol="tcp">
            <cve>CVE-2017-0144</cve>
          </ReportItem>
        </ReportHost>
      </Report>
    </NessusClientData_v2>
    """
    with open(nessus_xml, "w", encoding="utf-8") as f:
        f.write(xml_content)
        
    ingestor = RealWorldIngestor(clean_topo)
    count = ingestor.import_nessus_xml(str(nessus_xml))
    
    assert count == 1
    assert "10.0.1.5" in clean_topo.hosts
    target_host = clean_topo.hosts["10.0.1.5"]
    assert len(target_host.services) == 1
    assert target_host.services[0].port == 445
    assert "CVE-2017-0144" in target_host.services[0].vulnerabilities

def test_bloodhound_json_ingestion(clean_topo, tmp_path):
    # Create mock simplified Bloodhound topology
    bh_file = tmp_path / "bh.json"
    bh_data = {
        "nodes": [
            {"id": "DC-01", "name": "DC-01.local", "ip": "10.0.1.2", "role": "domain_controller"},
            {"id": "WS-01", "name": "WS-01.local", "ip": "10.0.3.21", "role": "workstation"}
        ],
        "edges": [
            {"source": "WS-01", "target": "DC-01", "relation": "CONNECTED_TO"}
        ]
    }
    with open(bh_file, "w") as f:
        json.dump(bh_data, f)
        
    ingestor = RealWorldIngestor(clean_topo)
    count = ingestor.import_bloodhound_json(str(bh_file))
    
    assert count == 1
    assert "DC-01" in clean_topo.hosts
    assert "WS-01" in clean_topo.hosts
    assert ("WS-01", "DC-01") in clean_topo.connections

def test_real_world_mitigation():
    runner = RealWorldMitigationRunner(dry_run=True)
    
    # Test quarantine command gen
    res = runner.execute_quarantine_rules(os_type="windows")
    assert "commands" in res
    assert len(res["commands"]) == 2
    assert "AMCDS_QUARANTINE_IN" in res["commands"][0]
    
    res_linux = runner.execute_quarantine_rules(os_type="linux")
    assert "iptables -A INPUT -j DROP" in res_linux["commands"]
    
    # Test Ansible playbook generation
    playbook = runner.generate_ansible_playbook("isolate_host", "WS-01", "10.0.3.21")
    assert "Incident Response - Host Quarantine" in playbook
    assert "win_firewall_rule" in playbook
    assert "iptables" in playbook
    
    # Clean up generated playbook file
    if os.path.exists("contain__WS-01__isolate_host.yml"):
        os.remove("contain__WS-01__isolate_host.yml")

def test_real_world_scanner_inference():
    scanner = RealWorldScanner()
    assert scanner.infer_service_name(80) == "HTTP"
    assert scanner.infer_service_name(445) == "SMB"
    assert scanner.infer_service_name(9999) == "unknown_port_9999"

def test_telemetry_file_ingestion(tmp_path):
    ingestor = TelemetryFileIngestor()
    
    # Test syslog parsing
    syslog_file = tmp_path / "syslog.log"
    syslog_content = (
        "Jun 27 15:30:10 WEB-01 sshd[12345]: Failed password for admin from 10.0.3.25 port 55670 ssh2\n"
        "Jun 27 15:32:00 WEB-01 sshd[12345]: Accepted password for admin from 10.0.3.25 port 55670 ssh2\n"
    )
    with open(syslog_file, "w", encoding="utf-8") as f:
        f.write(syslog_content)
        
    events = ingestor.parse_syslog_file(str(syslog_file))
    assert len(events) == 2
    assert events[0].host_id == "WEB-01"
    assert events[0].severity == "WARNING"
    assert events[1].severity == "INFO"
    assert "Failed password" in events[0].message
    
    # Test Snort alert parsing
    snort_file = tmp_path / "snort.alert"
    snort_content = "[**] [1:1000001:1] SMB Exploit Attempt [**] [Priority: 1] {TCP} 10.0.3.25:55432 -> 10.0.1.2:445\n"
    with open(snort_file, "w", encoding="utf-8") as f:
        f.write(snort_content)
        
    snort_events = ingestor.parse_snort_alert_file(str(snort_file))
    assert len(snort_events) == 1
    assert snort_events[0].host_id == "10.0.1.2"
    assert snort_events[0].severity == "CRITICAL"
    assert snort_events[0].message == "SMB Exploit Attempt"
