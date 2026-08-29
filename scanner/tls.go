package main

import (
	"crypto/tls"
	"time"
	"fmt"
)

type TLSResult struct {
	Domain string `json:"domain"`
	Valid bool `json:"valid"`
	ExpiresAt time.Time `json:"expires_at"`
	DaysUntilExpiry int `json:"days_until_expiry"`
	ProtocolVersion string `json:"protocol_version"`
	Issuer string `json:"issuer"`
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