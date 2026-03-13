// Package siem implements a lightweight Mock SIEM (Security Information and
// Event Management) webhook server that receives Falco alerts over HTTP,
// stores them in an in-memory AlertStore, and exposes a WaitForAlert method
// used by the engine to measure Mean Time To Detect (MTTD).
package siem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// FalcoAlert represents a single alert received from Falco via HTTP webhook.
type FalcoAlert struct {
	Rule         string            `json:"rule"`
	Time         string            `json:"time"`
	Priority     string            `json:"priority"`
	Output       string            `json:"output"`
	OutputFields map[string]string `json:"output_fields"`
	// ReceivedAt is set by the server when the HTTP request arrives.
	ReceivedAt time.Time `json:"-"`
}

// AlertStore is a thread-safe in-memory store for Falco alerts, keyed by rule name.
type AlertStore struct {
	mu     sync.Mutex
	alerts map[string][]FalcoAlert
}

// NewAlertStore initialises an empty AlertStore.
func NewAlertStore() *AlertStore {
	return &AlertStore{
		alerts: make(map[string][]FalcoAlert),
	}
}

// Handler is the HTTP handler for incoming Falco webhook POST requests.
func (s *AlertStore) Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var alert FalcoAlert
	if err := json.NewDecoder(r.Body).Decode(&alert); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}
	alert.ReceivedAt = time.Now()

	s.mu.Lock()
	s.alerts[alert.Rule] = append(s.alerts[alert.Rule], alert)
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// WaitForAlert blocks until an alert matching ruleName arrives or ctx expires.
// It polls every 500ms to avoid busy-spinning.
func (s *AlertStore) WaitForAlert(ctx context.Context, ruleName string) (*FalcoAlert, error) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for Falco alert %q: %w", ruleName, ctx.Err())
		case <-ticker.C:
			s.mu.Lock()
			alerts := s.alerts[ruleName]
			s.mu.Unlock()

			if len(alerts) > 0 {
				a := alerts[len(alerts)-1]
				return &a, nil
			}
		}
	}
}

// Reset clears all stored alerts. Useful between full experiment runs.
func (s *AlertStore) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alerts = make(map[string][]FalcoAlert)
}

// ClearRule removes all stored alerts for a specific rule name.
// Call this before spawning an attacker pod to prevent stale alerts from a
// previous run skewing MTTD calculations for the same rule.
func (s *AlertStore) ClearRule(ruleName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.alerts, ruleName)
}

// ListenAndServe starts the Falco webhook HTTP server on the given address (e.g. ":8080").
// It returns immediately — the server runs in the background.
func ListenAndServe(addr string, store *AlertStore) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/falco", store.Handler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil && err != http.ErrServerClosed {
			fmt.Printf("siem server error: %v\n", err)
		}
	}()
	return nil
}
