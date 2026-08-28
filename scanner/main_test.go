package main

import "testing"

func TestTlsVersionName(t *testing.T){
	got := tlsVersionName(0x0304)
	want := "TLS 1.3"

	if got != want {
		t.Errorf("tlsVersionName(0x0304) = %q, want %q", got, want)
	}
}

func TestCheckTLS_ValidDomain(t *testing.T){

	result, err := checkTLS("github.com")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected github.com to be valid, go issues: %v", result.Issues)
	}

	if result.ProtocolVersion != "TLS 1.3" {
		t.Errorf("expected TLS 1.3, got %s", result.ProtocolVersion)
	}
}

func TestCheckTLS_InvalidDomain(t *testing.T) {
	_, err := checkTLS("this-domain-should-not-exist-zzz123.invalid")

	if err == nil {
		t.Fatal("expected an error for a nonexistent domain, got nil")
	}
}

func TestCheckTLS_HostnameMismatch(t *testing.T) {
	result, err := checkTLS("wrong.host.badssl.com")

	if err != nil {
		t.Fatalf("expected no error (bad cert isn't a connection failure), got: %v", err)
	}

	if result.Valid {
		t.Error("expected result.Valid to be false for a hostname-mismatched cert")
	}

	if len(result.Issues) == 0 {
		t.Error("expected at least one issue to be reported")
	}
}

func TestCheckHeaders_GoodDomain(t *testing.T) {
	result, err := checkHeaders("github.com")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !result.Valid {
		t.Errorf("expected github.com to have all security headers, got issues: %v", result.Issues)
	}

	if len(result.Checks) != 4 {
		t.Errorf("expected 4 header checks, got %d", len(result.Checks))
	}
}

func TestCheckHeaders_MissingHeaders(t *testing.T) {
	result, err := checkHeaders("example.com")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if result.Valid {
		t.Error("expected example.com to be missing at least one security header")
	}

	if len(result.Issues) == 0 {
		t.Error("expected at least one issue to be reported")
	}
}

func TestCheckHeaders_InvalidDomain(t *testing.T) {
	_, err := checkHeaders("this-domain-should-not-exist-zzz123.invalid")

	if err == nil {
		t.Fatal("expected an error for a nonexistent domain, got nil")
	}
}

func TestCheckEmailSecurity_GoodDomain(t *testing.T) {
	result, err := checkEmailSecurity("github.com")

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !result.HasSPF {
		t.Error("expected github.com to have an SPF record")
	}

	if !result.HasDMARC {
		t.Error("expected github.com to have a DMARC record")
	}

	if !result.Valid {
		t.Errorf("expected github.com to be valid, got issues: %v", result.Issues)
	}
}

func TestExtractDMARCPolicy(t *testing.T) {
	got := extractDMARCPolicy("v=DMARC1; p=quarantine; pct=100")
	want := "quarantine"

	if got != want {
		t.Errorf("extractDMARCPolicy(...) = %q, want %q", got, want)
	}
}