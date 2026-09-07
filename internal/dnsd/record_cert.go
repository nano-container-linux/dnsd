package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addCERTRecord(runtime *RuntimeConfig, rec RecordConfig, name string, ttl uint32) error {
	if rec.CertType == 0 {
		return fmt.Errorf("record %s (CERT) requires cert_type", rec.ID)
	}
	if rec.Algo == 0 {
		return fmt.Errorf("record %s (CERT) requires algorithm", rec.ID)
	}
	if strings.TrimSpace(rec.Cert) == "" {
		return fmt.Errorf("record %s (CERT) requires certificate", rec.ID)
	}
	rr := &dns.CERT{
		Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeCERT, Class: dns.ClassINET, Ttl: ttl},
		Type:        rec.CertType,
		KeyTag:      rec.KeyTag,
		Algorithm:   rec.Algo,
		Certificate: rec.Cert,
	}
	appendAnswer(runtime, dns.TypeCERT, name, rr)
	return nil
}
