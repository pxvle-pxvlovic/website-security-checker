package main

import "testing"
import "net/http"

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

func TestHasSecurityHeader(t *testing.T){
	headers := http.Header{}
	headers.Set("X-Frame-Options", "deny")
	got := hasSecurityHeader(headers, "X-Frame-Options")
	want := true

	if got != want{
		t.Errorf("hasSecurityHeader(...) = %v, want %v", got, want)
	}
}