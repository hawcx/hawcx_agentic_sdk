# Customer Redis setup

The SDK uses customer-deployed Redis for two purposes:

1. **SessionMaterial substrate** — read by RSV at verify time (and
   written by the CAA). Schema: `haap:session:{u64_session_id:016x}` →
   bincode-serialized `SubstrateMaterial`.
2. **Replay store** — set by RSV after each successful verify; key
   `haap:jti:{jti_ascii}` with TTL = token's `expires_at - now`.

This Redis is **separate** from Hawcx's own Redis (the latter lives
inside the Hawcx SaaS deployment and stores Hawcx-side metadata).

## Three deployment patterns

### Pattern 1 — Local development (Docker Compose)

Use the bundled compose file:

```bash
docker compose -f compose/docker-compose.dev.yml up -d
export HAAP_CUSTOMER_REDIS_URL=redis://localhost:6379
```

The compose file enables AOF persistence and `allkeys-lru` eviction
within a 256 MiB cap. Data persists to a named volume across container
restarts.

### Pattern 2 — Cloud-managed Redis

#### AWS ElastiCache

Cluster mode disabled is sufficient for the typical session-count
ranges. Steps:

1. Create a Redis 7.x replication group via the AWS Console or Terraform:

   ```hcl
   resource "aws_elasticache_replication_group" "haap" {
     replication_group_id = "haap-customer"
     description          = "HAAP customer SessionMaterial substrate"
     engine               = "redis"
     engine_version       = "7.1"
     node_type            = "cache.t4g.small"
     num_cache_clusters   = 2
     parameter_group_name = "default.redis7"
     port                 = 6379
     subnet_group_name    = aws_elasticache_subnet_group.haap.name
     security_group_ids   = [aws_security_group.haap.id]
     at_rest_encryption_enabled = true
     transit_encryption_enabled = true
     auth_token = var.haap_redis_auth_token
   }
   ```

2. Configure security group: ingress 6379/tcp from the MCP host /
   agent runtime hosts only.

3. Connection string with TLS:

   ```bash
   HAAP_CUSTOMER_REDIS_URL=rediss://:${AUTH_TOKEN}@${PRIMARY_ENDPOINT}:6379
   ```

#### GCP Memorystore

1. Create a STANDARD_HA tier instance (Redis 7.x):

   ```bash
   gcloud redis instances create haap-customer \
       --size=1 --region=us-central1 --redis-version=redis_7_0 \
       --tier=STANDARD_HA --transit-encryption-mode=SERVER_AUTHENTICATION
   ```

2. Authorize private VPC network to reach the instance.

3. Connection string:

   ```bash
   HAAP_CUSTOMER_REDIS_URL=rediss://${HOST}:6378
   ```

#### Azure Cache for Redis

1. Create a Standard or Premium tier (Redis 6.x at minimum).
2. Enable "non-SSL port" only if absolutely required for testing;
   prefer the SSL port (default 6380).
3. Connection string:

   ```bash
   HAAP_CUSTOMER_REDIS_URL=rediss://:${ACCESS_KEY}@${HOST}:6380
   ```

#### Redis Cloud (Redis Inc.)

Provision via the Redis Cloud dashboard; copy the connection string
from the database details page directly into `HAAP_CUSTOMER_REDIS_URL`.

### Pattern 3 — Self-hosted production

| Topology | When to use | Operational complexity |
|---|---|---|
| Single instance + AOF | Small deployments, < 10K sessions | Lowest |
| Sentinel | Need automatic failover; single shard suffices | Moderate |
| Cluster | Need horizontal scale beyond one shard | Highest |

For Sentinel and Cluster: standard Redis docs apply. The SDK's
`redis::aio::ConnectionManager` handles connection re-establishment
across primary failovers automatically.

Security for self-hosted:

- Enable ACLs (`requirepass` or Redis 6+ user ACLs).
- TLS termination via stunnel or native Redis TLS (Redis 7+).
- Network isolation: bind to a private interface; firewall the port to
  the MCP host CIDR.

## Operational notes

- **Recommended Redis version**: 7.x. `redis::aio::ConnectionManager`
  works with 6.x as well, but 7.x is what tests and benches target.
- **Memory sizing**: ~1 KB per active session (SubstrateMaterial is
  small + the replay-store entries are tiny). For 100K active sessions
  with 1h average lifetime, 100–200 MiB is plenty.
- **Eviction**: `allkeys-lru` is acceptable since both kinds of keys
  have TTLs anyway. A flushed entry just forces a fresh registration
  for that session (cheap) or rejects a delayed replay (correct fail-closed).
- **Persistence**: AOF recommended for the SessionMaterial keys so
  in-flight sessions survive a Redis restart. RDB-only is sufficient
  if you can tolerate ~30s session-loss on restart.
- **Backup**: not strictly required — all session material is
  ephemeral and the AS + CAA can re-populate it on demand. But AOF
  + nightly RDB snapshots is a reasonable belt-and-braces.

## Verifying the connection

```bash
HAAP_CUSTOMER_REDIS_URL=redis://localhost:6379 \
    cargo run --bin haap-sdk -- substrate-fetch --session-id 0
```

A reachable but empty substrate returns `no session found for 0`.
A network/auth failure returns a clear `redis transport: ...` error.
