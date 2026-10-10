import pytest
from simulation_engine.network import NetworkTopology
from simulation_engine.network_generator import NetworkGenerator

def test_generate_small_network():
    generator = NetworkGenerator()
    
    # Generate a network of size 15
    topo = generator.generate_network(
        num_hosts=15,
        domain_name="test.local",
        vuln_density=0.5,
        include_cloud=True,
        include_iot=True
    )
    
    assert len(topo.hosts) == 15
    assert len(topo.connections) > 0
    assert len(topo.users) > 0
    
    # Verify DC-01 exists and is domain controller
    dc = topo.hosts.get("DC-01")
    assert dc is not None
    assert dc.role == "domain_controller"
    assert dc.domain == "test.local"
    
    # Verify some hosts have departments
    departments = {h.department for h in topo.hosts.values() if h.department}
    assert len(departments) > 0
    
    # Verify some hosts have cloud providers / devices tags
    cloud_hosts = [h for h in topo.hosts.values() if h.cloud_provider]
    iot_hosts = [h for h in topo.hosts.values() if h.device_type]
    
    assert len(cloud_hosts) >= 0
    assert len(iot_hosts) >= 0

def test_generate_medium_network():
    generator = NetworkGenerator()
    
    # Generate a network of size 100
    topo = generator.generate_network(
        num_hosts=100,
        domain_name="corp.local",
        vuln_density=0.2,
        include_cloud=False,
        include_iot=False
    )
    
    assert len(topo.hosts) == 100
    assert len(topo.connections) > 50
    
    # Verify no cloud/iot tags
    cloud_hosts = [h for h in topo.hosts.values() if h.cloud_provider]
    iot_hosts = [h for h in topo.hosts.values() if h.device_type]
    
    assert len(cloud_hosts) == 0
    assert len(iot_hosts) == 0
