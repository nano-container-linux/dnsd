package dnsd

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

func addAAAARecord(runtime *RuntimeConfig, rec RecordConfig, name string, ttl uint32) error {
	ip := net.ParseIP(rec.IP6)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("record %s has invalid IPv6 address: %s", rec.ID, rec.IP6)
	}
	rr := &dns.AAAA{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl},
		AAAA: ip.To16(),
	}
	appendAnswer(runtime, dns.TypeAAAA, name, rr)
	return nil
}
