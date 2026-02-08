"""
Valence Seed Node - The "phone book" for router discovery.

This package provides the seed node implementation for router discovery
in the Valence network.

Public API:
    - SeedNode: The main seed node class
    - SeedConfig: Configuration for seed nodes
    - RouterRecord: Data model for registered routers
    - HealthStatus, HealthState, HealthMonitor: Health monitoring
    - create_seed_node, run_seed_node: Convenience functions

Example:
    from oro_network.seed import create_seed_node

    node = create_seed_node(host="0.0.0.0", port=8470)
    await node.start()
"""

from oro_network.seed.config import SeedConfig
from oro_network.seed.health import HealthMonitor, HealthState, HealthStatus
from oro_network.seed.peers import SeedPeerManager
from oro_network.seed.reputation import (
    RateLimiter,
    RegistrationEvent,
    ReputationManager,
    ReputationRecord,
)
from oro_network.seed.revocation import SeedRevocationManager, SeedRevocationRecord
from oro_network.seed.router import RouterRecord
from oro_network.seed.seed_node import (
    COUNTRY_TO_CONTINENT,
    SeedNode,
    _secure_random,
    compute_region_score,
    create_seed_node,
    get_continent,
    run_seed_node,
)
from oro_network.seed.sybil import CorrelationDetector, SybilResistance

__all__ = [
    # Main classes
    "SeedNode",
    "SeedConfig",
    "RouterRecord",
    # Health monitoring
    "HealthStatus",
    "HealthState",
    "HealthMonitor",
    # Reputation / rate limiting
    "RegistrationEvent",
    "ReputationRecord",
    "RateLimiter",
    "ReputationManager",
    # Sybil resistance
    "CorrelationDetector",
    "SybilResistance",
    # Revocation
    "SeedRevocationRecord",
    "SeedRevocationManager",
    # Peering
    "SeedPeerManager",
    # Regional routing
    "COUNTRY_TO_CONTINENT",
    "get_continent",
    "compute_region_score",
    # Convenience functions
    "create_seed_node",
    "run_seed_node",
    # Internal (for security tests)
    "_secure_random",
]
