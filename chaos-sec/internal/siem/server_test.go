package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHandler_StoresAlert(t *testing.T) {
	store := NewAlertStore()
	ts := httptest.NewServer(http.HandlerFunc(store.Handler))
	defer ts.Close()

	alert := FalcoAlert{
		Rule:     "outbound_connection_not_in_allowlist",
		Priority: "WARNING",
		Output:   "some output",
	}
	body, _ := json.Marshal(alert)
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	store.mu.Lock()
	stored := store.alerts["outbound_connection_not_in_allowlist"]
	store.mu.Unlock()

	if len(stored) != 1 {
		t.Fatalf("expected 1 stored alert, got %d", len(stored))
	}
	if stored[0].Rule != "outbound_connection_not_in_allowlist" {
		t.Errorf("unexpected rule: %q", stored[0].Rule)
	}
	if stored[0].ReceivedAt.IsZero() {
		t.Error("ReceivedAt should be set")
	}
}

func TestWaitForAlert_ReceivesAlert(t *testing.T) {
	store := NewAlertStore()

	// Inject an alert asynchronously after a short delay.
	go func() {
		time.Sleep(200 * time.Millisecond)
		store.mu.Lock()
		store.alerts["test_rule"] = append(store.alerts["test_rule"], FalcoAlert{
			Rule:       "test_rule",
			ReceivedAt: time.Now(),
		})
		store.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	alert, err := store.WaitForAlert(ctx, "test_rule")
	if err != nil {
		t.Fatalf("WaitForAlert returned error: %v", err)
	}
	if alert.Rule != "test_rule" {
		t.Errorf("expected rule %q, got %q", "test_rule", alert.Rule)
	}
}

func TestWaitForAlert_TimesOut(t *testing.T) {
	store := NewAlertStore()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := store.WaitForAlert(ctx, "nonexistent_rule")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestReset_ClearsAlerts(t *testing.T) {
	store := NewAlertStore()
	store.mu.Lock()
	store.alerts["some_rule"] = []FalcoAlert{{Rule: "some_rule"}}
	store.mu.Unlock()

	store.Reset()

	store.mu.Lock()
	count := len(store.alerts)
	store.mu.Unlock()

	if count != 0 {
		t.Errorf("expected 0 alerts after reset, got %d", count)
	}
}
