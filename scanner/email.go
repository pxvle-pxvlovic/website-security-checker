package main

import(
	"fmt"
	"net"
	"strings"
)

type EmailSecurityResult struct {
	Domain string `json:"domain"`
	Valid bool `json:"valid"`
	HasSPF bool `json:"has_spf"`
	SPFRecord string `json:"spf_record,omitempty"`
	HasDMARC bool `json:"has_dmarc"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
	Issues []string `json:"issues"`
}

func checkEmailSecurity(domain string) (*EmailSecurityResult, error) {
	issues := []string{}

	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return nil, fmt.Errorf("could not look up TXT records for %s: %w", domain, err)
	}

	hasSPF := false
	spfRecord := ""
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			hasSPF = true
			spfRecord = record
			break
		}
	}

	if !hasSPF {
		issues = append(issues, "no SPF record found")
	} else if isWeakSPF(spfRecord) {
		issues = append(issues, "SPF record uses '+all', which allows any server to send mail as this domain")
	}

	dmarcRecords, err := net.LookupTXT("_dmarc." + domain)
	hasDMARC := false
	dmarcPolicy := ""

	if err == nil {
		for _, record := range dmarcRecords {
			if strings.HasPrefix(record, "v=DMARC1") {
				hasDMARC = true
				dmarcPolicy = extractDMARCPolicy(record)
				break
			}
		}
	}

	if !hasDMARC {
		issues = append(issues, "no DMARC record found")
	} else if dmarcPolicy == "none" {
		issues = append(issues, "DMARC policy is 'none', monitoring only, provides no actual protection")
	}

	return &EmailSecurityResult{
		Domain:      domain,
		Valid:       len(issues) == 0,
		HasSPF:      hasSPF,
		SPFRecord:   spfRecord,
		HasDMARC:    hasDMARC,
		DMARCPolicy: dmarcPolicy,
		Issues:      issues,
	}, nil
}

func isWeakSPF(record string) bool {
	return strings.Contains(record, "+all")
}

func extractDMARCPolicy(record string) string {
	parts := strings.Split(record, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			return strings.TrimPrefix(part, "p=")
		}
	}
	return ""
}