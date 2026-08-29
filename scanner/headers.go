package main

import(
	"fmt"
	"net/http"
)

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

func hasSecurityHeader(headers http.Header, name string) bool {
	value := headers.Get(name)
	return value != ""
}