package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addCNAMERecord(runtime *RuntimeConfig, rec RecordConfig, zoneName, name string, ttl uint32) error {
	if strings.TrimSpace(rec.CNAME) == "" {
		return fmt.Errorf("record %s (CNAME) requires cname", rec.ID)
	}
	target, err := resolveTarget(rec.CNAME, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (CNAME) invalid cname %q: %w", rec.ID, rec.CNAME, err)
	}
	rr := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: ttl},
		Target: target,
	}
	appendAnswer(runtime, dns.TypeCNAME, name, rr)
	return nil
}
