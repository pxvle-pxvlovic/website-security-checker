package main

import "testing"

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

func TestIsWeakSPF(t *testing.T) {
    got := isWeakSPF("+all")
    want := true

    if got != want {
        t.Errorf("isWeakSPF(...) = %v, want %v", got, want)
    }
}