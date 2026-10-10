from typing import Dict, List, Tuple
from shared.models import Host, Service, User, Credential
from shared.db import get_neo4j_driver
import logging

logger = logging.getLogger(__name__)

class NetworkTopology:
    def __init__(self):
        self.hosts: Dict[str, Host] = {}
        self.users: Dict[str, User] = {}
        self.connections: List[Tuple[str, str]] = [] # List of tuples: (host_id_1, host_id_2)
        self.neo4j_enabled = True

    def add_host(self, host: Host):
        self.hosts[host.id] = host
        self.sync_host_to_neo4j(host)

    def add_user(self, user: User):
        self.users[user.username] = user
        self.sync_user_to_neo4j(user)

    def add_connection(self, host_id_1: str, host_id_2: str):
        if host_id_1 in self.hosts and host_id_2 in self.hosts:
            self.connections.append((host_id_1, host_id_2))
            self.sync_connection_to_neo4j(host_id_1, host_id_2)

    def sync_host_to_neo4j(self, host: Host):
        if not self.neo4j_enabled:
            return
        
        query = """
        MERGE (h:Device {id: $id})
        SET h.name = $name,
            h.ip = $ip,
            h.os = $os,
            h.role = $role,
            h.domain = $domain,
            h.compromised = $compromised,
            h.isolated = $isolated
        """
        try:
            driver = get_neo4j_driver()
            with driver.session() as session:
                session.run(query, 
                            id=host.id, 
                            name=host.name, 
                            ip=host.ip, 
                            os=host.os, 
                            role=host.role, 
                            domain=host.domain, 
                            compromised=host.compromised, 
                            isolated=host.isolated)
                
                # Link services
                for srv in host.services:
                    srv_query = """
                    MERGE (s:Service {id: $srv_id})
                    SET s.name = $srv_name,
                        s.port = $srv_port,
                        s.version = $srv_version
                    WITH s
                    MATCH (h:Device {id: $host_id})
                    MERGE (h)-[:RUNS]->(s)
                    """
                    session.run(srv_query, 
                                srv_id=srv.id, 
                                srv_name=srv.name, 
                                srv_port=srv.port, 
                                srv_version=srv.version, 
                                host_id=host.id)
            driver.close()
        except Exception as e:
            logger.warning(f"Neo4j host sync skipped/failed: {e}")

    def sync_user_to_neo4j(self, user: User):
        if not self.neo4j_enabled:
            return
        
        query = """
        MERGE (u:User {id: $id})
        SET u.username = $username,
            u.domain = $domain,
            u.roles = $roles,
            u.phishing_susceptibility = $phishing_susceptibility
        """
        try:
            driver = get_neo4j_driver()
            with driver.session() as session:
                session.run(query,
                            id=user.id,
                            username=user.username,
                            domain=user.domain,
                            roles=user.roles,
                            phishing_susceptibility=user.phishing_susceptibility)
                
                # Link user credentials
                for cred in user.credentials:
                    cred_query = """
                    MERGE (c:Credential {id: $cred_id})
                    SET c.username = $username,
                        c.cred_type = $cred_type,
                        c.privilege_level = $privilege_level
                    WITH c
                    MATCH (u:User {id: $user_id})
                    MERGE (u)-[:HAS_CREDENTIAL]->(c)
                    """
                    session.run(cred_query,
                                cred_id=cred.id,
                                username=cred.username,
                                cred_type=cred.cred_type,
                                privilege_level=cred.privilege_level,
                                user_id=user.id)
            driver.close()
        except Exception as e:
            logger.warning(f"Neo4j user sync skipped/failed: {e}")

    def sync_connection_to_neo4j(self, host_id_1: str, host_id_2: str):
        if not self.neo4j_enabled:
            return
        
        query = """
        MATCH (h1:Device {id: $id1})
        MATCH (h2:Device {id: $id2})
        MERGE (h1)-[:CONNECTED_TO]-(h2)
        """
        try:
            driver = get_neo4j_driver()
            with driver.session() as session:
                session.run(query, id1=host_id_1, id2=host_id_2)
            driver.close()
        except Exception as e:
            logger.warning(f"Neo4j connection sync skipped/failed: {e}")

    def get_compromised_hosts(self) -> List[Host]:
        return [h for h in self.hosts.values() if h.compromised]

    def reset(self):
        """Clears local topology state."""
        self.hosts.clear()
        self.users.clear()
        self.connections.clear()
        
        # Reset Neo4j representation if connected
        if self.neo4j_enabled:
            try:
                driver = get_neo4j_driver()
                with driver.session() as session:
                    session.run("MATCH (n) DETACH DELETE n")
                driver.close()
                logger.info("Neo4j database topology cleared.")
            except Exception as e:
                logger.warning(f"Neo4j database reset skipped/failed: {e}")
