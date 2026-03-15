package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func appendAnswer(runtime *RuntimeConfig, qtype uint16, name string, rr dns.RR) {
	if _, ok := runtime.Answers[qtype]; !ok {
		runtime.Answers[qtype] = map[string][]dns.RR{}
	}
	runtime.Answers[qtype][name] = append(runtime.Answers[qtype][name], rr)
}

func defaultTTL(ttl uint32) uint32 {
	if ttl == 0 {
		return 3600
	}
	return ttl
}

func addRecordAnswers(runtime *RuntimeConfig, rec RecordConfig, zoneName string) error {
	name := fqdnInZone(rec.ID, zoneName)
	ttl := defaultTTL(rec.TTL)

	switch strings.ToUpper(rec.Type) {
	case "A":
		return addARecord(runtime, rec, name, ttl)
	case "AAAA":
		return addAAAARecord(runtime, rec, name, ttl)
	case "SRV":
		return addSRVRecord(runtime, rec, zoneName, name, ttl)
	case "CNAME":
		return addCNAMERecord(runtime, rec, zoneName, name, ttl)
	case "TXT":
		return addTXTRecord(runtime, rec, name, ttl)
	case "PTR":
		return addPTRRecord(runtime, rec, zoneName, name, ttl)
	case "MX":
		return addMXRecord(runtime, rec, zoneName, name, ttl)
	case "NS":
		return addNSRecord(runtime, rec, zoneName, name, ttl)
	case "SOA":
		return addSOARecord(runtime, rec, zoneName, name, ttl)
	case "CERT":
		return addCERTRecord(runtime, rec, name, ttl)
	case "RP":
		return addRPRecord(runtime, rec, zoneName, name, ttl)
	case "SSHFP":
		return addSSHFPRecord(runtime, rec, name, ttl)
	default:
		return fmt.Errorf("record %s has unsupported type: %s", rec.ID, rec.Type)
	}
}
