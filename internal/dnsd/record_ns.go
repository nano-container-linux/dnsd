package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addNSRecord(runtime *RuntimeConfig, rec RecordConfig, zoneName, name string, ttl uint32) error {
	if strings.TrimSpace(rec.NS) == "" {
		return fmt.Errorf("record %s (NS) requires ns", rec.ID)
	}
	target, err := resolveTarget(rec.NS, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (NS) invalid ns %q: %w", rec.ID, rec.NS, err)
	}
	rr := &dns.NS{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
		Ns:  target,
	}
	appendAnswer(runtime, dns.TypeNS, name, rr)
	return nil
}
