import csv
import json
import xml.etree.ElementTree as ET
import logging
from typing import Dict, Any, List
from shared.models import Host, Service, User, Credential
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)

class RealWorldIngestor:
    """Utility class to ingest real enterprise asset lists, vulnerability reports, and Active Directory paths."""
    
    def __init__(self, topology: NetworkTopology):
        self.topology = topology

    def import_assets_csv(self, file_path: str) -> int:
        """
        Imports host metadata from an Asset Inventory CSV file.
        Expected headers: id, name, ip, os, role, domain (optional)
        """
        count = 0
        try:
            with open(file_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    h_id = row.get("id") or row.get("Host ID") or row.get("name")
                    if not h_id:
                        continue
                    
                    host = Host(
                        id=h_id.strip(),
                        name=(row.get("name") or row.get("Host Name") or h_id).strip(),
                        ip=(row.get("ip") or row.get("IP Address") or "127.0.0.1").strip(),
                        os=(row.get("os") or row.get("Operating System") or "Unknown OS").strip(),
                        role=(row.get("role") or row.get("Role") or "workstation").strip().lower(),
                        domain=(row.get("domain") or row.get("Domain") or "enterprise.local").strip(),
                        services=[]
                    )
                    self.topology.add_host(host)
                    count += 1
            logger.info(f"Successfully ingested {count} assets from CSV: {file_path}")
        except Exception as e:
            logger.error(f"Failed to parse assets CSV {file_path}: {e}")
        return count

    def import_nessus_csv(self, file_path: str) -> int:
        """
        Parses a Nessus vulnerability scan report exported as a CSV.
        Expected columns: Host, Port, Protocol, CVE, Name (or similar)
        """
        vuln_count = 0
        try:
            with open(file_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    host_ip_or_name = row.get("Host") or row.get("IP Address") or row.get("ip")
                    if not host_ip_or_name:
                        continue
                    
                    host_ip_or_name = host_ip_or_name.strip()
                    
                    # Find host in topology by IP or Name; if not found, create a basic one
                    host = None
                    for h in self.topology.hosts.values():
                        if h.ip == host_ip_or_name or h.id == host_ip_or_name or h.name == host_ip_or_name:
                            host = h
                            break
                    
                    if not host:
                        host = Host(
                            id=host_ip_or_name,
                            name=host_ip_or_name,
                            ip=host_ip_or_name if "." in host_ip_or_name else "10.0.0.1",
                            os="Unknown OS (Nessus Inferred)",
                            role="workstation"
                        )
                        self.topology.add_host(host)
                    
                    port_str = row.get("Port") or row.get("port")
                    if not port_str:
                        continue
                    
                    try:
                        port = int(port_str.strip())
                    except ValueError:
                        continue
                        
                    # Skip port 0 (general host info vulnerability reports)
                    if port == 0:
                        continue
                    
                    protocol = (row.get("Protocol") or "tcp").strip().upper()
                    cve = row.get("CVE") or row.get("cve")
                    svc_name = row.get("Name") or row.get("Plugin Name") or f"Port_{port}"
                    
                    # Look for existing service on host
                    service = next((s for s in host.services if s.port == port), None)
                    if not service:
                        service = Service(
                            name=svc_name.split(" - ")[0][:15], # Clean name limit
                            port=port,
                            version="1.0"
                        )
                        host.services.append(service)
                    
                    if cve and cve.strip():
                        # Multiple CVEs can be comma-separated or space-separated
                        clean_cves = [c.strip() for c in cve.replace(",", " ").split() if c.strip().upper().startswith("CVE-")]
                        for single_cve in clean_cves:
                            if single_cve not in service.vulnerabilities:
                                service.vulnerabilities.append(single_cve)
                                vuln_count += 1
                                
                    # Sync change back to Neo4j if enabled
                    self.topology.sync_host_to_neo4j(host)
            logger.info(f"Successfully processed Nessus CSV: loaded {vuln_count} vulnerabilities.")
        except Exception as e:
            logger.error(f"Failed to parse Nessus CSV {file_path}: {e}")
        return vuln_count

    def import_nessus_xml(self, file_path: str) -> int:
        """
        Parses a Nessus vulnerability scan report saved as .nessus XML format.
        """
        vuln_count = 0
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Find ReportHost elements
            for rep_host in root.findall(".//ReportHost"):
                hostname = rep_host.get("name")
                
                # Fetch IP and OS tags
                ip_addr = hostname
                os_val = "Unknown OS"
                
                host_properties = rep_host.find("HostProperties")
                if host_properties is not None:
                    for tag in host_properties.findall("tag"):
                        name_attr = tag.get("name")
                        if name_attr == "host-ip":
                            ip_addr = tag.text
                        elif name_attr == "operating-system":
                            os_val = tag.text
                
                # Find or create host
                host = next((h for h in self.topology.hosts.values() if h.ip == ip_addr or h.id == hostname), None)
                if not host:
                    host = Host(
                        id=hostname,
                        name=hostname,
                        ip=ip_addr,
                        os=os_val,
                        role="workstation"
                    )
                    self.topology.add_host(host)
                
                # Find vulnerabilities/services under ReportItem
                for item in rep_host.findall("ReportItem"):
                    port = int(item.get("port"))
                    if port == 0:
                        continue
                    
                    protocol = item.get("protocol")
                    svc_name = item.get("svc_name")
                    
                    service = next((s for s in host.services if s.port == port), None)
                    if not service:
                        service = Service(
                            name=svc_name.upper(),
                            port=port,
                            version="1.0"
                        )
                        host.services.append(service)
                    
                    # Parse CVE tags
                    for cve_tag in item.findall("cve"):
                        cve = cve_tag.text
                        if cve and cve not in service.vulnerabilities:
                            service.vulnerabilities.append(cve)
                            vuln_count += 1
                
                # Sync back to graph
                self.topology.sync_host_to_neo4j(host)
            logger.info(f"Successfully processed Nessus XML: loaded {vuln_count} vulnerabilities.")
        except Exception as e:
            logger.error(f"Failed to parse Nessus XML {file_path}: {e}")
        return vuln_count

    def import_bloodhound_json(self, file_path: str) -> int:
        """
        Parses Active Directory domain relationship models.
        Supports standard BloodHound 'computers' schema, or a custom simplified schema:
        {
          "nodes": [{"id": "DC-01", "label": "Computer", "ip": "10.0.1.2", "role": "domain_controller"}],
          "edges": [{"source": "WS-01", "target": "DC-01", "relation": "CONNECTED_TO"}]
        }
        """
        imported_relations = 0
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                
            # Case 1: Simplified nodes/edges format
            if "nodes" in data and "edges" in data:
                # Add nodes
                for node in data["nodes"]:
                    n_id = node.get("id")
                    if not n_id:
                        continue
                    
                    # Only add if doesn't exist
                    if n_id not in self.topology.hosts:
                        host = Host(
                            id=n_id,
                            name=node.get("name") or n_id,
                            ip=node.get("ip") or "10.0.0.1",
                            os=node.get("os") or "Windows",
                            role=node.get("role") or "workstation"
                        )
                        self.topology.add_host(host)
                
                # Add connections
                for edge in data["edges"]:
                    src = edge.get("source")
                    dst = edge.get("target")
                    if src in self.topology.hosts and dst in self.topology.hosts:
                        self.topology.add_connection(src, dst)
                        imported_relations += 1
            
            # Case 2: Standard Bloodhound Computers JSON format
            elif "data" in data or isinstance(data, list):
                computers_list = data.get("data") if isinstance(data, dict) else data
                for comp in computers_list:
                    props = comp.get("Properties", {})
                    name = props.get("name") or comp.get("ObjectIdentifier")
                    if not name:
                        continue
                    
                    # Simplify name to host ID
                    h_id = name.split(".")[0].upper()
                    
                    if h_id not in self.topology.hosts:
                        host = Host(
                            id=h_id,
                            name=name,
                            ip="10.0.1.1", # placeholder to update via Nessus
                            os=props.get("operating-system") or props.get("os") or "Windows Server",
                            role="domain_controller" if "domaincontroller" in name.lower() else "workstation"
                        )
                        self.topology.add_host(host)
                    
                    # Ingest LocalAdmins or Sessions if available
                    for session in comp.get("Sessions", []):
                        user_username = session.get("User")
                        if user_username:
                            user = User(
                                id=user_username,
                                username=user_username,
                                phishing_susceptibility=0.4
                            )
                            self.topology.add_user(user)
                            # Log user as logged in
                            if user_username not in self.topology.hosts[h_id].logged_in_users:
                                self.topology.hosts[h_id].logged_in_users.append(user_username)
                                
            logger.info(f"Successfully processed BloodHound JSON: imported {imported_relations} relations.")
        except Exception as e:
            logger.error(f"Failed to parse BloodHound JSON {file_path}: {e}")
        return imported_relations
