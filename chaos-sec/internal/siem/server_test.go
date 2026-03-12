package siem

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
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

func TestClearRule_RemovesOnlyTargetRule(t *testing.T) {
	store := NewAlertStore()
	store.mu.Lock()
	store.alerts["rule_a"] = []FalcoAlert{{Rule: "rule_a"}}
	store.alerts["rule_b"] = []FalcoAlert{{Rule: "rule_b"}}
	store.mu.Unlock()

	store.ClearRule("rule_a")

	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.alerts["rule_a"]) != 0 {
		t.Errorf("expected rule_a to be cleared, got %d alerts", len(store.alerts["rule_a"]))
	}
	if len(store.alerts["rule_b"]) != 1 {
		t.Errorf("expected rule_b to be untouched, got %d alerts", len(store.alerts["rule_b"]))
	}
}

func TestHandler_RejectsBadJSON(t *testing.T) {
	store := NewAlertStore()
	ts := httptest.NewServer(http.HandlerFunc(store.Handler))
	defer ts.Close()

	resp, err := http.Post(ts.URL, "application/json", bytes.NewBufferString("not-json"))
	if err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_RejectsGetMethod(t *testing.T) {
	store := NewAlertStore()
	ts := httptest.NewServer(http.HandlerFunc(store.Handler))
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

func TestListenAndServe_StartsServer(t *testing.T) {
	store := NewAlertStore()

	// Find a free port by binding then immediately releasing it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find free port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // Release the port; ListenAndServe will reclaim it.

	if startErr := ListenAndServe(addr, store); startErr != nil {
		t.Fatalf("ListenAndServe returned error: %v", startErr)
	}

	// Give the goroutine a moment to bind.
	time.Sleep(50 * time.Millisecond)

	alert := FalcoAlert{Rule: "siem_test_rule", Priority: "WARNING", Output: "test"}
	body, _ := json.Marshal(alert)
	resp, err := http.Post("http://"+addr+"/falco", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST to SIEM server failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
