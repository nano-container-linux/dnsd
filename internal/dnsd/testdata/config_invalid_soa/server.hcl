server {
  dns {
    bind {
      addr = "127.0.0.1"
      port = 8053
      net  = "udp"
    }

    upstream {
      keepalive {
        interval_seconds = 5
        window_seconds   = 15
        timeout_seconds  = 2
      }

      group "google" {
        weight = 10

        endpoint {
          addr    = "8.8.8.8"
          port    = 53
          percent = 100
        }
      }
    }
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
