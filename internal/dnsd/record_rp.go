package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addRPRecord(runtime *RuntimeConfig, rec RecordConfig, zoneName, name string, ttl uint32) error {
	if strings.TrimSpace(rec.Mbox) == "" {
		return fmt.Errorf("record %s (RP) requires mbox", rec.ID)
	}
	if strings.TrimSpace(rec.TxtDName) == "" {
		return fmt.Errorf("record %s (RP) requires txtdname", rec.ID)
	}
	mbox, err := resolveTarget(rec.Mbox, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (RP) invalid mbox %q: %w", rec.ID, rec.Mbox, err)
	}
	txtName, err := resolveTarget(rec.TxtDName, zoneName)
	if err != nil {
		return fmt.Errorf("record %s (RP) invalid txtdname %q: %w", rec.ID, rec.TxtDName, err)
	}
	rr := &dns.RP{
		Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeRP, Class: dns.ClassINET, Ttl: ttl},
		Mbox: mbox,
		Txt:  txtName,
	}
	appendAnswer(runtime, dns.TypeRP, name, rr)
	return nil
}
