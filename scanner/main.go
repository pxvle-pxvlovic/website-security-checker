package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
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
		present := value != ""

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

func main(){
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/scan/tls", tlsHandler)
	http.HandleFunc("/scan/headers", headersHandler)

	log.Println("scanner service listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}