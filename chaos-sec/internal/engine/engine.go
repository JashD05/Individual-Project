package engine

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jashdashandi/chaos-sec/internal/experiment"
	"github.com/jashdashandi/chaos-sec/internal/siem"
)

// PodRunner abstracts the Kubernetes pod lifecycle so the engine can be tested
// without a live cluster by injecting a fake implementation.
type PodRunner interface {
	Run(ctx context.Context, spec experiment.ExperimentSpec) (experiment.ExperimentResult, error)
}

// Engine orchestrates security experiments end-to-end.
type Engine struct {
	Runner    PodRunner
	SIEMStore *siem.AlertStore
	// AlertWaitTimeout is how long to wait for a Falco alert after an experiment completes.
	AlertWaitTimeout time.Duration
}

// New creates an Engine with sensible defaults.
func New(runner PodRunner, store *siem.AlertStore) *Engine {
	return &Engine{
		Runner:           runner,
		SIEMStore:        store,
		AlertWaitTimeout: 30 * time.Second,
	}
}

// Run executes each experiment in specs sequentially and returns a slice of results.
// Experiments continue even if one fails; all results are returned together.
func (e *Engine) Run(ctx context.Context, specs []experiment.ExperimentSpec) []experiment.ExperimentResult {
	results := make([]experiment.ExperimentResult, 0, len(specs))

	for _, spec := range specs {
		slog.Info("starting experiment", "name", spec.Name)

		// Clear any stale alerts for this rule before spawning the pod so that
		// alerts from a previous run don't skew the MTTD calculation.
		if e.SIEMStore != nil && spec.FalcoRule != "" {
			e.SIEMStore.ClearRule(spec.FalcoRule)
		}

		start := time.Now()

		result, err := e.Runner.Run(ctx, spec)
		if err != nil {
			slog.Error("experiment failed with error",
				"name", spec.Name,
				"error", err.Error(),
			)
			results = append(results, experiment.ExperimentResult{
				Spec:          spec,
				StartTime:     start,
				EndTime:       time.Now(),
				ActualOutcome: "error",
				Pass:          false,
			})
			continue
		}

		// Detect MTTD: wait for Falco alert matching the experiment's expected rule.
		if e.SIEMStore != nil && spec.FalcoRule != "" {
			alertCtx, cancel := context.WithTimeout(ctx, e.AlertWaitTimeout)
			alert, alertErr := e.SIEMStore.WaitForAlert(alertCtx, spec.FalcoRule)
			cancel()
			if alertErr == nil {
				mttd := alert.ReceivedAt.Sub(result.StartTime).Seconds()
				result.MTTD = &mttd
				slog.Info("Falco alert received",
					"rule", spec.FalcoRule,
					"mttd_seconds", fmt.Sprintf("%.3f", mttd),
				)
			} else {
				slog.Warn("no Falco alert received within timeout",
					"rule", spec.FalcoRule,
					"timeout", e.AlertWaitTimeout,
				)
			}
		}

		if result.Pass {
			slog.Info("experiment PASSED", "name", spec.Name, "outcome", result.ActualOutcome)
		} else {
			slog.Warn("experiment FAILED",
				"name", spec.Name,
				"expected", spec.ExpectedOutcome,
				"actual", result.ActualOutcome,
			)
		}

		results = append(results, result)
	}

	return results
}
