package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addSOARecord(runtime *RuntimeConfig, rec RecordConfig, zoneName, name string, ttl uint32) error {
	if strings.TrimSpace(rec.MName) == "" {
		return fmt.Errorf("record %s (SOA) requires mname", rec.ID)
	}
	if strings.TrimSpace(rec.RName) == "" {
		return fmt.Errorf("record %s (SOA) requires rname", rec.ID)
	}
	mname, err := resolveTarget(rec.MName, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (SOA) invalid mname %q: %w", rec.ID, rec.MName, err)
	}
	rname, err := resolveTarget(rec.RName, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (SOA) invalid rname %q: %w", rec.ID, rec.RName, err)
	}
	rr := &dns.SOA{
		Hdr:     dns.RR_Header{Name: name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      mname,
		Mbox:    rname,
		Serial:  rec.Serial,
		Refresh: rec.Refresh,
		Retry:   rec.Retry,
		Expire:  rec.Expire,
		Minttl:  rec.Minimum,
	}
	appendAnswer(runtime, dns.TypeSOA, name, rr)
	return nil
}
