# dnsd

An authoritative DNS server configured via HCL files.

[![Renovate enabled](https://img.shields.io/badge/renovate-enabled-brightgreen?logo=renovatebot)](https://renovateapp.com/)
[![Renovate](https://img.shields.io/badge/dependencies-Renovate-blue?logo=renovatebot)](https://github.com/renovatebot/renovate)

## Configuration

Config files live in `etc/dnsd/`. Three kinds of files are scanned:

| Pattern | Purpose |
|---|---|
| `*.hcl` | Variable definitions, records, zones, server config |
| `*.vars.hcl` | Variable value overrides (higher priority than `default`) |
| `dyndns/*.hcl.b64` | Dynamic record payloads (base64-encoded HCL) loaded at startup |

Environment variables prefixed with `DNSD_` take the highest priority (e.g. `DNSD_PORT_OCI=9999`).

### gRPC dynamic updates

You can enable a dynamic submission listener in the `server` block:

```hcl
server {
	dns {
		bind {
			addr = "0.0.0.0"
			port = 53
			query {
				allow = ["192.0.2.0/24", "127.0.0.1", "2001:db8::/32", "::1"]
				deny  = ["192.0.2.254", "2001:db8::dead:beef"]
			}

			transfer {
				allow = ["198.51.100.10", "2001:db8:100::10"]
				deny  = ["198.51.100.254"]
			}
		}

		upstream {
			keepalive {
				interval_seconds = 5
				window_seconds   = 15
				timeout_seconds  = 2
			}

			group "google" {
				domains = ["example.com.", "lab.example.com."]
				weight = 10
				endpoint {
					addr    = "8.8.8.8"
					port    = 53
					percent = 100
				}
			}

			# Use system resolver nameservers from /etc/resolv.conf
			group "system" {
				weight = 20
				endpoint {
					system_resolver = true
					percent         = 100
				}
			}
		}
	}

	grpc {
		addr                 = "127.0.0.1"
		port                 = 50051
		net                  = "tcp"
		authorized_keys_file = "etc/dnsd/authorized_keys"
		allow                = ["127.0.0.1", "::1"]
		deny                 = []
	}

	metrics {
		addr = "127.0.0.1"
		port = 9090
		net  = "tcp"
		path = "/metrics"
		allow = ["127.0.0.1", "::1"]
		deny  = []
	}

	health {
		addr           = "127.0.0.1"
		port           = 8081
		net            = "tcp"
		readiness_path = "/readyz"
		liveness_path  = "/healthz"
		allow          = ["127.0.0.1", "::1"]
		deny           = []
	}
}
```

Dynamic payloads accepted by gRPC are persisted into `dyndns/*.hcl.b64` and immediately applied in memory.
Authentication is done with an SSH signature over the raw HCL payload; the corresponding public key must be present in `authorized_keys_file`.
Keys should be stored in a separate `authorized_keys` file (not inline in HCL config).

### Prometheus metrics

You can enable a dedicated Prometheus endpoint with `server.metrics`.

- `addr`, `port`: listener address for HTTP metrics
- `net`: must be `tcp`
- `path`: HTTP endpoint path (default `/metrics`)
- `allow` / `deny`: required client ACLs (CIDR or single IP, use `[]` when empty)

Exposed metrics include DNS question/response counters and dynamic gRPC submission counters.

### Health checks

`server.health` is required and exposes two HTTP endpoints:

- readiness (`readiness_path`, default `/readyz`): returns `200` when upstreams are available, `503` otherwise
- liveness (`liveness_path`, default `/healthz`): returns `200` when process is alive

`allow` / `deny` are required on `server.health` (same ACL semantics as other listeners).

Each `bind` listens on both UDP and TCP and must define separate ACLs for standard queries and zone transfers.

- `query.allow` / `query.deny`: ACLs for regular DNS queries
- `transfer.allow` / `transfer.deny`: ACLs for AXFR and IXFR requests

Entries accept CIDR prefixes or single IPv4/IPv6 addresses. `allow` and `deny` must both be specified (use `[]` when empty). Evaluation order is always `deny` first, then `allow`. If `allow` is empty, clients are allowed unless explicitly denied. A rejected client receives `REFUSED`.

AXFR and IXFR are served over TCP. IXFR currently falls back to a full zone transfer when the client serial is older than the current SOA serial, and returns the current SOA only when no change is needed.

`endpoint.system_resolver = true` expands to all nameservers from `/etc/resolv.conf`.
You can optionally set `endpoint.port` to override the resolver port for all expanded nameservers.

`group.domains` is optional. When set, that upstream group is only considered for queried names inside those domains.

### ACME DNS-01 challenge server

`server.acme` enables an HTTP API that lets Caddy (or any [libdns](https://github.com/libdns/libdns)-compatible client) present and clean up `_acme-challenge` TXT records for DNS-01 certificate issuance — without writing them to the zone file.

Authentication uses **one token per DNS record** (created via `dnsctl`).

```hcl
acme {
  addr  = "127.0.0.1"   # keep on loopback when Caddy runs on the same host
  port  = 9053
  ttl   = 60            # optional TXT record TTL, default 60 s
	allow = ["127.0.0.1", "::1"]
	deny  = []
}
```

`server.grpc` requires `allow` / `deny` with the same ACL semantics.

**Endpoints**

| Method | Path       | Description                          |
|--------|------------|--------------------------------------|
| POST   | `/present` | Store a challenge TXT value          |
| POST   | `/cleanup` | Remove a challenge TXT value         |
| GET    | `/healthz` | Liveness check                       |

All mutating endpoints require `Authorization: Bearer <token>`.

- Per-record tokens created with `dnsctl acme token create` are scoped to a single `_acme-challenge.<domain>.` FQDN.
- Wildcards are supported by `dnsctl`: `--fqdn '*.example.com.'` produces a token for `_acme-challenge.example.com.`.

**Request body** (`/present` and `/cleanup`):
```json
{ "fqdn": "_acme-challenge.example.com.", "value": "<challenge-token>" }
```

**Per-record token workflow (recommended)**

```sh
# Build client binary (standalone project)
cd ~/dnsctl && go build -o dnsctl .

# Create a token limited to _acme-challenge.example.com.
# (connection settings are read from config file / env vars / flags)
~/dnsctl/dnsctl acme token create --fqdn example.com.

# Wildcard cert token (maps to _acme-challenge.example.com.)
~/dnsctl/dnsctl acme token create --fqdn '*.example.com.'

# List/revoke tokens
~/dnsctl/dnsctl acme token list
~/dnsctl/dnsctl acme token revoke --token <token>
```

**Caddy configuration** (using the [`acme_dns`](https://github.com/caddy-dns/acmedns) module with the per-record token):
```caddy
tls {
  dns acmedns http://127.0.0.1:9053 {
		token <TOKEN_FROM_DNSCTL>
  }
}
```

Full example file: `etc/dnsd/examples/Caddyfile.acme-dnsctl.example`

**Security notes**

- Keep the `token` value secret; treat it like a password.
- Bind `acme.addr` to `127.0.0.1` when Caddy is on the same machine.
- TXT records injected via ACME are ephemeral (in-memory only); they survive server restart only if re-presented.
- Only `_acme-challenge.*` names whose parent zone is served by dnsd are accepted.

### Config examples

Two ready-to-use server config examples are available:

- `etc/dnsd/examples/server.prod.hcl`: bind on 53 with query/transfer ACL examples and weighted Google/Cloudflare groups
- `etc/dnsd/examples/server.lab.hcl`: local lab profile (127.0.0.1:8053) with a single upstream group

### OpenPubkey certificates (OIDC email)

Current auth supports raw SSH public keys from `authorized_keys_file`.
OpenPubkey certificate-based authorization by OIDC email is a good next step and can be added by:

- trusting one or more CA keys,
- validating SSH certificates on submit,
- extracting OIDC-linked email from certificate identity,
- checking that email against an allowlist.

## dnsctl client

`dnsctl` now lives in its own project at `~/dnsctl` with its own README, tests,
and CI workflow.

## Usage

```sh
# Validate config
task validate

# Run server
task run

# Build binary → bin/dnsd
task build

# Build client binary (standalone project)
cd ~/dnsctl && go build -o dnsctl .

# Submit dynamic payload (signed via ssh-agent) via dnsctl
~/dnsctl/dnsctl dyndns submit --file ./update.hcl

# Submit dynamic payload with explicit key
~/dnsctl/dnsctl dyndns submit --file ./update.hcl --ssh-key ~/.ssh/id_ed25519

# Create ACME per-record token
~/dnsctl/dnsctl acme token create --fqdn example.com.

# Create ACME wildcard token (for *.example.com)
~/dnsctl/dnsctl acme token create --fqdn '*.example.com.'

# List / revoke tokens
~/dnsctl/dnsctl acme token list
~/dnsctl/dnsctl acme token revoke --token <token>
```

## Dependencies

Managed by [Renovate](https://github.com/apps/renovate). Covers:
- Go modules (`go.mod`)
- GitHub Actions
- `pkgx.yaml` (`go.dev`, `taskfile.dev`)
