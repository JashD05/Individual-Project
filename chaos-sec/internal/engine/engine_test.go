package engine

import (
	"context"
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
