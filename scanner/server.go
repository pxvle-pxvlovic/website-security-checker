package main

import (
	"encoding/json"
	"net/http"
)

func decodeRequest(r *http.Request) (scanRequest, error){
	var req scanRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type scanRequest struct {
	Domain string `json:"domain"`
}

func tlsHandler(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r)
	if err != nil {
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

func headersHandler(w http.ResponseWriter, r *http.Request){
	req, err := decodeRequest(r)
	if err != nil {
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

func emailHandler(w http.ResponseWriter, r *http.Request) {
	req, err := decodeRequest(r) 
	if err != nil {
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

