package dnsd

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func addARecord(runtime *RuntimeConfig, rec RecordConfig, name string, ttl uint32) error {
	ip := net.ParseIP(rec.IP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("record %s has invalid IPv4 address: %s", rec.ID, rec.IP)
	}
	rr := &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   ip.To4(),
	}
	appendAnswer(runtime, dns.TypeA, name, rr)
	return nil
}
