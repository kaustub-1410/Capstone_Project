"""
Environment Factory — Creates complete enterprise topologies from templates.

Central factory that instantiates digital twin environments by composing
reusable components (departments, AD domains, firewall zones, etc.)
into fully-connected network topologies.

Part of Phase 5: Digital Twin Environments.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple, Type

from shared.models import Host, Service, User
from simulation_engine.network import NetworkTopology

logger = logging.getLogger(__name__)


class EnvironmentTemplate(ABC):
    """
    Abstract base class for digital twin environment templates.

    Each template defines a complete enterprise environment with hosts,
    services, users, and network connections. Templates are composable
    and can be extended or combined.
    """

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description

    @abstractmethod
    def build(self) -> NetworkTopology:
        """
        Build the complete network topology for this environment.

        Returns a fully configured NetworkTopology instance with all
        hosts, services, users, and connections.
        """
        pass

    def get_metadata(self) -> Dict[str, Any]:
        """Return metadata about this environment template."""
        return {
            "name": self.name,
            "description": self.description,
            "template_class": self.__class__.__name__,
        }


class EnvironmentFactory:
    """
    Factory for creating digital twin environments from templates.

    Maintains a registry of available templates and provides
    a unified interface for environment creation.
    """

    def __init__(self):
        self._registry: Dict[str, Type[EnvironmentTemplate]] = {}
        self._auto_register()

    def _auto_register(self) -> None:
        """Auto-register all built-in templates."""
        try:
            from digital_twin.templates.bank import BankEnvironment
            self.register("bank", BankEnvironment)
        except ImportError:
            pass
        try:
            from digital_twin.templates.hospital import HospitalEnvironment
            self.register("hospital", HospitalEnvironment)
        except ImportError:
            pass
        try:
            from digital_twin.templates.university import UniversityEnvironment
            self.register("university", UniversityEnvironment)
        except ImportError:
            pass
        try:
            from digital_twin.templates.manufacturing import ManufacturingEnvironment
            self.register("manufacturing", ManufacturingEnvironment)
        except ImportError:
            pass
        try:
            from digital_twin.templates.government import GovernmentEnvironment
            self.register("government", GovernmentEnvironment)
        except ImportError:
            pass
        try:
            from digital_twin.templates.cloud_enterprise import CloudEnterpriseEnvironment
            self.register("cloud_enterprise", CloudEnterpriseEnvironment)
        except ImportError:
            pass

        logger.info(f"EnvironmentFactory initialized with {len(self._registry)} templates")

    def register(self, name: str, template_class: Type[EnvironmentTemplate]) -> None:
        """Register a new environment template."""
        self._registry[name] = template_class
        logger.debug(f"Registered template: {name}")

    def create(self, template_name: str, **kwargs) -> NetworkTopology:
        """
        Create a network topology from a registered template.

        Args:
            template_name: Name of the registered template
            **kwargs: Additional arguments passed to the template constructor

        Returns:
            Fully configured NetworkTopology
        """
        if template_name not in self._registry:
            available = ", ".join(sorted(self._registry.keys()))
            raise ValueError(
                f"Unknown template '{template_name}'. Available: {available}"
            )

        template_class = self._registry[template_name]
        template = template_class(**kwargs)
        topo = template.build()

        logger.info(
            f"Created '{template_name}' environment: "
            f"{len(topo.hosts)} hosts, {len(topo.connections)} connections, "
            f"{len(topo.users)} users"
        )
        return topo

    def list_templates(self) -> List[Dict[str, Any]]:
        """List all available environment templates."""
        templates = []
        for name, cls in self._registry.items():
            try:
                instance = cls.__new__(cls)
                desc = getattr(instance, 'description', '') if hasattr(instance, 'description') else ''
            except Exception:
                desc = ""
            templates.append({
                "name": name,
                "class": cls.__name__,
                "description": desc,
            })
        return templates

    def get_template_class(self, name: str) -> Optional[Type[EnvironmentTemplate]]:
        """Get the template class by name."""
        return self._registry.get(name)


def add_topology_components(
    topo: NetworkTopology,
    hosts: List[Host],
    users: Optional[List[User]] = None,
    connections: Optional[List[Tuple[str, str]]] = None,
) -> None:
    """
    Helper to add a batch of components to a topology.

    Safely handles duplicates and logs additions.
    """
    for host in hosts:
        if host.id not in topo.hosts:
            topo.add_host(host)

    if users:
        for user in users:
            if user.username not in topo.users:
                topo.add_user(user)

    if connections:
        existing = set((h1, h2) for h1, h2 in topo.connections)
        for h1, h2 in connections:
            if (h1, h2) not in existing and (h2, h1) not in existing:
                if h1 in topo.hosts and h2 in topo.hosts:
                    topo.add_connection(h1, h2)
