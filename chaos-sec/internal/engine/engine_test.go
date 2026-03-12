package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jashdashandi/chaos-sec/internal/experiment"
	"github.com/jashdashandi/chaos-sec/internal/siem"
)

// fakePodRunner implements PodRunner and returns canned results.
type fakePodRunner struct {
	results map[string]experiment.ExperimentResult
	err     error
}

func (f *fakePodRunner) Run(_ context.Context, spec experiment.ExperimentSpec) (experiment.ExperimentResult, error) {
	if f.err != nil {
		return experiment.ExperimentResult{}, f.err
	}
	if r, ok := f.results[spec.Name]; ok {
		return r, nil
	}
	// Default: pass
	return experiment.ExperimentResult{
		Spec:          spec,
		Pass:          true,
		ActualOutcome: spec.ExpectedOutcome,
		StartTime:     time.Now(),
		EndTime:       time.Now(),
	}, nil
}

func TestEngine_AllPass(t *testing.T) {
	specs := []experiment.ExperimentSpec{
		{Name: "exp-a", ExpectedOutcome: "blocked", FalcoRule: "rule_a", Namespace: "test"},
		{Name: "exp-b", ExpectedOutcome: "permitted", FalcoRule: "rule_b", Namespace: "test"},
	}

	runner := &fakePodRunner{}
	store := siem.NewAlertStore()
	eng := New(runner, store)
	eng.AlertWaitTimeout = 100 * time.Millisecond // short timeout for tests

	results := eng.Run(context.Background(), specs)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for _, r := range results {
		if !r.Pass {
			t.Errorf("experiment %q: expected pass=true, got false", r.Spec.Name)
		}
	}
}

func TestEngine_FailedExperiment(t *testing.T) {
	specs := []experiment.ExperimentSpec{
		{Name: "failing-exp", ExpectedOutcome: "blocked", Namespace: "test"},
	}

	runner := &fakePodRunner{
		results: map[string]experiment.ExperimentResult{
			"failing-exp": {
				Spec:          specs[0],
				Pass:          false,
				ActualOutcome: "permitted", // policy failed open
				StartTime:     time.Now(),
				EndTime:       time.Now(),
			},
		},
	}

	eng := New(runner, nil) // nil SIEM — MTTD skipped
	results := eng.Run(context.Background(), specs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Pass {
		t.Error("expected pass=false for failing experiment")
	}
	if results[0].ActualOutcome != "permitted" {
		t.Errorf("expected actual_outcome=permitted, got %q", results[0].ActualOutcome)
	}
}

func TestEngine_RunnerError(t *testing.T) {
	specs := []experiment.ExperimentSpec{
		{Name: "error-exp", Namespace: "test"},
	}

	runner := &fakePodRunner{err: context.DeadlineExceeded}
	eng := New(runner, nil)
	results := eng.Run(context.Background(), specs)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ActualOutcome != "error" {
		t.Errorf("expected actual_outcome=error, got %q", results[0].ActualOutcome)
	}
	if results[0].Pass {
		t.Error("expected pass=false on runner error")
	}
}

func TestEngine_MTTDNilWhenNoAlert(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name:            "mttd-exp",
		ExpectedOutcome: "blocked",
		FalcoRule:       "test_rule",
		Namespace:       "test",
	}

	store := siem.NewAlertStore()
	runner := &fakePodRunner{}
	eng := New(runner, store)
	eng.AlertWaitTimeout = 100 * time.Millisecond // short timeout: no alert will arrive

	results := eng.Run(context.Background(), []experiment.ExperimentSpec{spec})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	// No alert was injected, so MTTD must be nil.
	if results[0].MTTD != nil {
		t.Errorf("expected nil MTTD (no alert received), got %v", *results[0].MTTD)
	}
}

func TestEngine_MTTDComputed(t *testing.T) {
	const ruleName = "test_rule_mttd"
	spec := experiment.ExperimentSpec{
		Name:            "mttd-computed-exp",
		ExpectedOutcome: "blocked",
		FalcoRule:       ruleName,
		Namespace:       "test",
	}

	store := siem.NewAlertStore()

	// Inject a Falco alert shortly after the experiment pod would start.
	go func() {
		time.Sleep(50 * time.Millisecond)
		store.Handler(
			httpRecorder(),
			falcoAlertRequest(t, ruleName),
		)
	}()

	runner := &fakePodRunner{}
	eng := New(runner, store)
	eng.AlertWaitTimeout = 2 * time.Second

	results := eng.Run(context.Background(), []experiment.ExperimentSpec{spec})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].MTTD == nil {
		t.Fatal("expected MTTD to be set when alert is received")
	}
	if *results[0].MTTD < 0 {
		t.Errorf("MTTD should be non-negative, got %.3f", *results[0].MTTD)
	}
}

// httpRecorder returns a minimal http.ResponseWriter for use in tests.
func httpRecorder() http.ResponseWriter {
	return httptest.NewRecorder()
}

// falcoAlertRequest builds an *http.Request containing a JSON-encoded FalcoAlert
// for the given rule, suitable for passing to AlertStore.Handler in tests.
func falcoAlertRequest(t *testing.T, ruleName string) *http.Request {
	t.Helper()
	payload := map[string]string{"rule": ruleName, "priority": "WARNING", "output": "test"}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshalling alert: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, "/falco", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	return req
}

func TestEngine_NilSIEMSkipsMTTD(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name:            "nil-siem-exp",
		ExpectedOutcome: "blocked",
		FalcoRule:       "some_rule",
		Namespace:       "test",
	}
	eng := New(&fakePodRunner{}, nil) // nil SIEM — must not panic
	results := eng.Run(context.Background(), []experiment.ExperimentSpec{spec})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].MTTD != nil {
		t.Error("expected nil MTTD when SIEM store is nil")
	}
}

func TestEngine_ContinuesAfterError(t *testing.T) {
	specs := []experiment.ExperimentSpec{
		{Name: "error-first", Namespace: "test", ExpectedOutcome: "blocked"},
		{Name: "ok-second", Namespace: "test", ExpectedOutcome: "blocked"},
	}
	// First call errors, second call succeeds.
	callCount := 0
	runner := &callCountRunner{
		onCall: func(spec experiment.ExperimentSpec) (experiment.ExperimentResult, error) {
			callCount++
			if callCount == 1 {
				return experiment.ExperimentResult{}, context.DeadlineExceeded
			}
			return experiment.ExperimentResult{
				Spec: spec, Pass: true, ActualOutcome: "blocked",
				StartTime: time.Now(), EndTime: time.Now(),
			}, nil
		},
	}
	eng := New(runner, nil)
	results := eng.Run(context.Background(), specs)
	if len(results) != 2 {
		t.Fatalf("expected 2 results (engine should continue after error), got %d", len(results))
	}
	if results[0].ActualOutcome != "error" {
		t.Errorf("expected first result to be error, got %q", results[0].ActualOutcome)
	}
	if !results[1].Pass {
		t.Error("expected second result to pass")
	}
}

func TestEngine_EmptySpecs(t *testing.T) {
	eng := New(&fakePodRunner{}, nil)
	results := eng.Run(context.Background(), nil)
	if len(results) != 0 {
		t.Errorf("expected 0 results for empty specs, got %d", len(results))
	}
}

// callCountRunner lets tests control Run behaviour per-call.
type callCountRunner struct {
	onCall func(spec experiment.ExperimentSpec) (experiment.ExperimentResult, error)
}

func (r *callCountRunner) Run(_ context.Context, spec experiment.ExperimentSpec) (experiment.ExperimentResult, error) {
	return r.onCall(spec)
}
