package dnsd

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

func addSRVRecord(runtime *RuntimeConfig, rec RecordConfig, zoneName, name string, ttl uint32) error {
	type srvResolvedTarget struct {
		Target   string
		Port     uint16
		Priority uint16
		Weight   uint16
	}

	resolvedTargets := make([]srvResolvedTarget, 0, len(rec.Targets))
	for _, targetCfg := range rec.Targets {
		port := rec.Port
		priority := rec.Priority
		weight := rec.Weight
		if targetCfg.Port != nil {
			port = *targetCfg.Port
		}
		if targetCfg.Priority != nil {
			priority = *targetCfg.Priority
		}
		if targetCfg.Weight != nil {
			weight = *targetCfg.Weight
		}
		if port == 0 {
			return fmt.Errorf("record %s (SRV) target %q has invalid port", rec.ID, targetCfg.Name)
		}
		if strings.TrimSpace(targetCfg.Name) == "" {
			return fmt.Errorf("record %s (SRV) target requires name", rec.ID)
		}
		resolvedTargets = append(resolvedTargets, srvResolvedTarget{
			Target:   targetCfg.Name,
			Port:     port,
			Priority: priority,
			Weight:   weight,
		})
	}

	if len(resolvedTargets) == 0 {
		return fmt.Errorf("record %s (SRV) requires at least one target block", rec.ID)
	}

	for _, targetCfg := range resolvedTargets {
		targetFQDN, err := resolveTarget(targetCfg.Target, zoneName)
		if err != nil {
			return fmt.Errorf("record %s (SRV) invalid target %q: %w", rec.ID, targetCfg.Target, err)
		}
		rr := &dns.SRV{
			Hdr:      dns.RR_Header{Name: name, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: ttl},
			Priority: targetCfg.Priority,
			Weight:   targetCfg.Weight,
			Port:     targetCfg.Port,
			Target:   targetFQDN,
		}
		appendAnswer(runtime, dns.TypeSRV, name, rr)
	}

	return nil
}
