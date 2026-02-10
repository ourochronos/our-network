# our-network

Privacy-preserving P2P networking with onion-routed circuits, seed node discovery, and quality of service for the ourochronos ecosystem.

## Overview

our-network implements the transport layer for Valence's federated architecture. Messages are end-to-end encrypted at the source and relayed through multi-hop onion circuits — routers only know the previous and next hop, never the full path or message content. The system includes decentralized seed nodes for router discovery, contribution-based QoS, and configurable traffic analysis mitigations.

## Install

```bash
pip install our-network
```

Requires `cryptography>=42.0` and `aiohttp>=3.9`.

## Usage

### Discovery

```python
from our_network import create_discovery_client

discovery = create_discovery_client(
    seed_urls=["https://seed1.example.com", "https://seed2.example.com"],
    cache_ttl_seconds=3600,
)

# Find routers (signature-verified, health-ranked)
routers = await discovery.discover_routers(count=5)
```

### Node Client

```python
from our_network import create_node_client

node = await create_node_client(
    node_id="user-123",
    discovery=discovery,
    target_connections=5,
    min_connections=2,
)

# Send message through onion circuit
await node.send_message(message_data, recipient_id)
```

### End-to-End Encryption

```python
from our_network import (
    generate_identity_keypair,
    generate_encryption_keypair,
    encrypt_message,
    decrypt_message,
)

# Ed25519 for signing, X25519 for encryption
identity = generate_identity_keypair()
encryption = generate_encryption_keypair()

ciphertext = encrypt_message(b"belief data", recipient_public_key)
plaintext = decrypt_message(ciphertext, recipient_private_key)
```

### Onion Routing

```python
from our_network import create_onion, peel_onion

# Build layered encryption for a 3-hop circuit
onion = create_onion(payload, circuit_keys=[hop1_key, hop2_key, hop3_key])

# Each router peels one layer
next_payload = peel_onion(onion, hop1_key)
```

### Quality of Service

```python
from our_network import ContributionScore, ContributionDimension, QoSPolicy

score = ContributionScore(node_id="user-123")
score.set_dimension(ContributionDimension.ROUTING_CAPACITY, 0.8)
score.set_dimension(ContributionDimension.UPTIME_RELIABILITY, 0.9)

policy = QoSPolicy()
tier = policy.assign_tier(score.overall)       # PriorityTier enum
priority = policy.compute_priority(score.overall, load_factor=0.7)
```

### Privacy Levels

```python
from our_network import PrivacyLevel, get_recommended_config

# LOW: minimal latency, basic encryption
# MEDIUM: batching + jitter
# HIGH: constant-rate padding
# PARANOID: mix network integration
config = get_recommended_config(PrivacyLevel.HIGH)
```

## API

### Core Crypto

`generate_identity_keypair()`, `generate_encryption_keypair()`, `encrypt_message()`, `decrypt_message()`, `create_onion()`, `peel_onion()`

### Networking

| Class | Description |
|-------|-------------|
| `NodeClient` | User node: multi-router connections, failover, health monitoring |
| `RouterNode` | Relay node: routes encrypted messages without seeing content |
| `SeedNode` | Bootstrap node: router discovery with anti-Sybil measures |
| `DiscoveryClient` | Router discovery with caching and multi-seed fallback |

### QoS

| Class | Description |
|-------|-------------|
| `ContributionScore` | 5-dimension contribution tracking |
| `QoSPolicy` | Dynamic prioritization based on network load |
| `PriorityTier` | CRITICAL, HIGH, NORMAL, LOW, MINIMUM |

### Traffic Analysis Mitigations

`PrivacyLevel`, `BatchingConfig`, `TimingJitterConfig`, `ConstantRateConfig`, `MixNetworkConfig`

## Key Properties

- **End-to-end encryption**: AES-256-GCM with X25519 key exchange
- **Onion routing**: Per-hop keys, routers can't see full path
- **Anti-Sybil**: Proof-of-work registration, reputation scoring, correlation detection
- **IP/ASN diversity**: Prevents eclipse attacks by enforcing diverse connections
- **Connection recovery**: State persistence and automatic failover
- **662 tests** covering routing, discovery, QoS, security, and state recovery

## Development

```bash
# Install with dev dependencies
make dev

# Run linters
make lint

# Run tests
make test

# Run tests with coverage
make test-cov

# Auto-format
make format
```

## State Ownership

Owns connection state, circuit state, router records (at seed nodes), and QoS scores. Node clients can persist connection state for recovery across restarts.

## Part of Valence

This brick is part of the [Valence](https://github.com/ourochronos/valence) knowledge substrate. See [our-infra](https://github.com/ourochronos/our-infra) for ourochronos conventions.

## License

MIT
