package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jashdashandi/chaos-sec/internal/experiment"
)

// Summary is the top-level JSON structure written to the report file.
type Summary struct {
	GeneratedAt time.Time                    `json:"generated_at"`
	TotalRuns   int                          `json:"total_runs"`
	Passed      int                          `json:"passed"`
	Failed      int                          `json:"failed"`
	Results     []experiment.ExperimentResult `json:"results"`
}

// Write marshals results into an indented JSON report and writes it to outPath.
// If outPath is "-", the report is written to stdout.
func Write(results []experiment.ExperimentResult, outPath string) error {
	passed, failed := 0, 0
	for _, r := range results {
		if r.Pass {
			passed++
		} else {
			failed++
		}
	}

	summary := Summary{
		GeneratedAt: time.Now().UTC(),
		TotalRuns:   len(results),
		Passed:      passed,
		Failed:      failed,
		Results:     results,
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling report: %w", err)
	}

	if outPath == "-" {
		_, err = os.Stdout.Write(data)
		return err
	}

	if err := os.WriteFile(outPath, data, 0o644); err != nil {
		return fmt.Errorf("writing report to %s: %w", outPath, err)
	}
	return nil
}
