// Minimal, valid dnsd configuration.
//
// This is the smallest configuration that satisfies every check performed by
// `dnsd validate` (server.Validate -> loadConfig + listen/health resolution):
//   - exactly one server block, with a dns bind (query + transfer ACLs) and an
//     upstream group holding at least one endpoint;
//   - a health endpoint with an allow/deny ACL;
//   - at least one zone that references at least one defined record.
// It is also a sane starting point for a real deployment; adjust the addresses,
// ACLs, upstreams and records to suit your environment.

server {
  dns {
    // Serve DNS on the loopback interface, port 8053.
    bind {
      addr = "127.0.0.1"
      port = 8053

      // Who may send ordinary queries to this bind.
      query {
        allow = ["0.0.0.0/0", "::/0"]
        deny  = []
      }

      // Who may request zone transfers (AXFR/IXFR) from this bind.
      transfer {
        allow = ["127.0.0.1", "::1"]
        deny  = []
      }
    }

    // Recursive upstreams used to resolve names not served locally
    // (e.g. SRV additional-section lookups).
    upstream {
      keepalive {
        interval_seconds = 5
        window_seconds   = 15
        timeout_seconds  = 2
      }

      group "default" {
        weight = 10

        endpoint {
          addr        = "9.9.9.9"
          port        = 53
          percent     = 100
          description = "Quad9 public resolver"
        }
      }
    }
  }

  // Readiness/liveness HTTP endpoint.
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

// A single authoritative record and the zone that publishes it.
record "www" {
  type = "A"
  ttl  = 3600
  ip   = "192.0.2.1"
}

zone "example.com." {
  records = ["www"]
}
