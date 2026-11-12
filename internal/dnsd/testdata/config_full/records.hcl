record "_oci._tcp" {
  type     = "SRV"
  ttl      = vars.default_ttl
  priority = 10
  weight   = 5

  target {
    name = "registry"
    port = 5000
  }
}

record "registry" {
  type = "A"
  ttl  = vars.default_ttl
  ip   = "192.168.64.2"
}

record "v6" {
  type = "AAAA"
  ttl  = vars.default_ttl
  ip6  = "2001:db8::1"
}

record "www" {
  type  = "CNAME"
  ttl   = vars.default_ttl
  cname = "registry"
}

record "txt" {
  type  = "TXT"
  ttl   = vars.default_ttl
  text  = "one"
  texts = ["two", "three"]
}

record "2" {
  type = "PTR"
  ttl  = vars.default_ttl
  ptr  = "registry.example.com."
}

record "mail" {
  type     = "MX"
  ttl      = vars.default_ttl
  exchange = "mxhost"
  priority = 20
}

record "ns-rec" {
  type = "NS"
  ttl  = vars.default_ttl
  ns   = "ns1.example.com."
}

record "soa-rec" {
  type    = "SOA"
  ttl     = vars.default_ttl
  mname   = "ns1.example.com."
  rname   = "hostmaster.example.com."
  serial  = 1
  refresh = 2
  retry   = 3
  expire  = 4
  minimum = 5
}

record "cert-rec" {
  type        = "CERT"
  ttl         = vars.default_ttl
  cert_type   = 1
  key_tag     = 123
  algorithm   = 8
  certificate = "QUJDRA=="
}

record "rp-rec" {
  type     = "RP"
  ttl      = vars.default_ttl
  mbox     = "hostmaster.example.com."
  txtdname = "txt.example.com."
}

record "ssh-rec" {
  type        = "SSHFP"
  ttl         = vars.default_ttl
  algorithm   = 4
  fp_type     = 2
  fingerprint = "abcdef"
}
