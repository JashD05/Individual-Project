package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jashdashandi/chaos-sec/internal/experiment"
)

func TestWrite_ProducesValidJSON(t *testing.T) {
	results := []experiment.ExperimentResult{
		{
			Spec:          experiment.ExperimentSpec{Name: "exp-a"},
			Pass:          true,
			ActualOutcome: "blocked",
			StartTime:     time.Now(),
			EndTime:       time.Now(),
		},
		{
			Spec:          experiment.ExperimentSpec{Name: "exp-b"},
			Pass:          false,
			ActualOutcome: "permitted",
			StartTime:     time.Now(),
			EndTime:       time.Now(),
		},
	}

	outPath := filepath.Join(t.TempDir(), "report.json")
	if err := Write(results, outPath); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}

	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if s.TotalRuns != 2 {
		t.Errorf("expected TotalRuns=2, got %d", s.TotalRuns)
	}
	if s.Passed != 1 {
		t.Errorf("expected Passed=1, got %d", s.Passed)
	}
	if s.Failed != 1 {
		t.Errorf("expected Failed=1, got %d", s.Failed)
	}
	if len(s.Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(s.Results))
	}
}

func TestWrite_EmptyResults(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "empty.json")
	if err := Write(nil, outPath); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}

	data, _ := os.ReadFile(outPath)
	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if s.TotalRuns != 0 {
		t.Errorf("expected TotalRuns=0, got %d", s.TotalRuns)
	}
}
