package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addPTRRecord(runtime *RuntimeConfig, rec RecordConfig, zoneName, name string, ttl uint32) error {
	if strings.TrimSpace(rec.PTR) == "" {
		return fmt.Errorf("record %s (PTR) requires ptr", rec.ID)
	}
	target, err := resolveTarget(rec.PTR, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (PTR) invalid ptr %q: %w", rec.ID, rec.PTR, err)
	}
	rr := &dns.PTR{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl},
		Ptr: target,
	}
	appendAnswer(runtime, dns.TypePTR, name, rr)
	return nil
}
