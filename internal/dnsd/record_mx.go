package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addMXRecord(runtime *RuntimeConfig, rec RecordConfig, zoneName, name string, ttl uint32) error {
	if strings.TrimSpace(rec.Exchange) == "" {
		return fmt.Errorf("record %s (MX) requires exchange", rec.ID)
	}
	target, err := resolveTarget(rec.Exchange, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (MX) invalid exchange %q: %w", rec.ID, rec.Exchange, err)
	}
	rr := &dns.MX{
		Hdr:        dns.RR_Header{Name: name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: ttl},
		Preference: rec.Priority,
		Mx:         target,
	}
	appendAnswer(runtime, dns.TypeMX, name, rr)
	return nil
}
