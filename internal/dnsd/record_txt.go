package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addTXTRecord(runtime *RuntimeConfig, rec RecordConfig, name string, ttl uint32) error {
	values := make([]string, 0, len(rec.Texts)+1)
	if strings.TrimSpace(rec.Text) != "" {
		values = append(values, rec.Text)
	}
	for _, value := range rec.Texts {
		if strings.TrimSpace(value) != "" {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		return fmt.Errorf("record %s (TXT) requires text or texts", rec.ID)
	}
	rr := &dns.TXT{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: values,
	}
	appendAnswer(runtime, dns.TypeTXT, name, rr)
	return nil
}
