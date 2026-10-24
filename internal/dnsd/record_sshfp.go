package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addSSHFPRecord(runtime *RuntimeConfig, rec RecordConfig, name string, ttl uint32) error {
	if rec.Algo == 0 {
		return fmt.Errorf("record %s (SSHFP) requires algorithm", rec.ID)
	}
	if rec.FPType == 0 {
		return fmt.Errorf("record %s (SSHFP) requires fp_type", rec.ID)
	}
	if strings.TrimSpace(rec.FP) == "" {
		return fmt.Errorf("record %s (SSHFP) requires fingerprint", rec.ID)
	}
	rr := &dns.SSHFP{
		Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeSSHFP, Class: dns.ClassINET, Ttl: ttl},
		Algorithm:   rec.Algo,
		Type:        rec.FPType,
		FingerPrint: rec.FP,
	}
	appendAnswer(runtime, dns.TypeSSHFP, name, rr)
	return nil
}
