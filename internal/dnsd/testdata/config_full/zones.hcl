zone "example.com." {
  records = [
    "_oci._tcp",
    "registry",
    "v6",
    "www",
    "txt",
    "mail",
    "ns-rec",
    "soa-rec",
    "cert-rec",
    "rp-rec",
    "ssh-rec",
  ]
}

zone "0.168.192.in-addr.arpa." {
  records = ["2"]
}
