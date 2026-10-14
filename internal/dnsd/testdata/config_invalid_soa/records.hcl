record "soa-bad" {
  type  = "SOA"
  ttl   = vars.default_ttl
  mname = "ns1.example.com."
  # rname missing on purpose
  serial  = 1
  refresh = 2
  retry   = 3
  expire  = 4
  minimum = 5
}
