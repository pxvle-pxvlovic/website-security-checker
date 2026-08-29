package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"net"
	"strings"
)

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type TLSResult struct {
	Domain string `json:"domain"`
	Valid bool `json:"valid"`
	ExpiresAt time.Time `json:"expires_at"`
	DaysUntilExpiry int `json:"days_until_expiry"`
	ProtocolVersion string `json:"protocol_version"`
	Issuer string `json:"issuer"`
	Issues []string `json:"issues"`
}

type scanRequest struct {
	Domain string `json:"domain"`
}

type HeaderCheck struct {
	Name string `json:"name"`
	Present bool `json:"present"`
	Value string `json:"value,omitempty"`
}

type HeadersResult struct {
	Domain string `json:"domain"`
	Valid bool `json:"valid"`
	Checks []HeaderCheck `json:"checks"`
	Issues []string `json:"issues"`
}

type EmailSecurityResult struct {
	Domain string `json:"domain"`
	Valid bool `json:"valid"`
	HasSPF bool `json:"has_spf"`
	SPFRecord string `json:"spf_record,omitempty"`
	HasDMARC bool `json:"has_dmarc"`
	DMARCPolicy string `json:"dmarc_policy,omitempty"`
	Issues []string `json:"issues"`
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}

func checkTLS(domain string) (*TLSResult, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
		ServerName: domain,
	})
	if err != nil {
		return nil, fmt.Errorf("could not connect to %s: %w", domain, err)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]

	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	issues := []string{}

	if time.Now().After(cert.NotAfter) {
		issues = append(issues, "certificate has expired")
	} else if daysLeft < 14 {
		issues = append(issues, fmt.Sprintf("certificate expires soon (%d days)", daysLeft))
	}

	if err := cert.VerifyHostname(domain); err != nil {
		issues = append(issues, fmt.Sprintf("hostname mismatch: %v", err))
	}

	return &TLSResult{
		Domain: domain,
		Valid: len(issues) == 0,
		ExpiresAt: cert.NotAfter,
		DaysUntilExpiry: daysLeft,
		ProtocolVersion: tlsVersionName(state.Version),
		Issuer: cert.Issuer.CommonName,
		Issues: issues,
	}, nil
}


func tlsHandler(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	result, err := checkTLS(req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func hasSecurityHeader(headers http.Header, name string) bool {
	value := headers.Get(name)
	return value != ""
}

func checkHeaders(domain string) (*HeadersResult, error){
	url := "https://" + domain

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("could not fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	securityHeaders := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
	}

	var checks []HeaderCheck
	issues := []string{}

	for _, headerName := range securityHeaders {
		value := resp.Header.Get(headerName)
		present := hasSecurityHeader(resp.Header, headerName)

		checks = append(checks, HeaderCheck{
			Name: headerName,
			Present: present,
			Value: value,
		})

		if !present {
			issues = append(issues, fmt.Sprintf("missing header: %s", headerName))
		}
	}

	return &HeadersResult{
		Domain: domain,
		Valid: len(issues) == 0,
		Checks: checks,
		Issues: issues,
	}, nil
}

func headersHandler(w http.ResponseWriter, r *http.Request){
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	result, err := checkHeaders(req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func isWeakSPF(record string) bool {
	return strings.Contains(record, "+all")
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

func emailHandler(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	result, err := checkEmailSecurity(req.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func main(){
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/scan/tls", tlsHandler)
	http.HandleFunc("/scan/headers", headersHandler)
	http.HandleFunc("/scan/email", emailHandler)

	log.Println("scanner service listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}