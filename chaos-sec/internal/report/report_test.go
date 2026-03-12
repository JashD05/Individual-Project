package report

import (
	"bytes"
	"encoding/json"
	"io"
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

func TestWrite_Stdout(t *testing.T) {
	// Capture stdout by redirecting os.Stdout.
	r, w, _ := os.Pipe()
	orig := os.Stdout
	os.Stdout = w

	err := Write([]experiment.ExperimentResult{
		{Spec: experiment.ExperimentSpec{Name: "stdout-exp"}, Pass: true},
	}, "-")

	w.Close()
	os.Stdout = orig

	if err != nil {
		t.Fatalf("Write to stdout returned error: %v", err)
	}

	var buf bytes.Buffer
	io.Copy(&buf, r)

	var s Summary
	if err := json.Unmarshal(buf.Bytes(), &s); err != nil {
		t.Fatalf("stdout output is not valid JSON: %v", err)
	}
	if s.TotalRuns != 1 {
		t.Errorf("expected TotalRuns=1, got %d", s.TotalRuns)
	}
}

func TestWrite_AllPassedCounting(t *testing.T) {
	results := make([]experiment.ExperimentResult, 5)
	for i := range results {
		results[i] = experiment.ExperimentResult{Pass: true, ActualOutcome: "blocked"}
	}
	outPath := filepath.Join(t.TempDir(), "all-pass.json")
	if err := Write(results, outPath); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	var s Summary
	json.Unmarshal(data, &s)
	if s.Passed != 5 || s.Failed != 0 {
		t.Errorf("expected Passed=5 Failed=0, got Passed=%d Failed=%d", s.Passed, s.Failed)
	}
}

func TestWrite_MTTDPreservedInJSON(t *testing.T) {
	mttd := 4.321
	results := []experiment.ExperimentResult{
		{
			Spec:          experiment.ExperimentSpec{Name: "mttd-exp"},
			Pass:          false,
			ActualOutcome: "permitted",
			MTTD:          &mttd,
		},
	}
	outPath := filepath.Join(t.TempDir(), "mttd.json")
	if err := Write(results, outPath); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	var s Summary
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if s.Results[0].MTTD == nil {
		t.Fatal("expected MTTD to be non-nil in JSON output")
	}
	if *s.Results[0].MTTD != mttd {
		t.Errorf("expected MTTD=%.3f, got %.3f", mttd, *s.Results[0].MTTD)
	}
}

func TestWrite_GeneratedAtIsSet(t *testing.T) {
	outPath := filepath.Join(t.TempDir(), "ts.json")
	if err := Write(nil, outPath); err != nil {
		t.Fatalf("Write returned error: %v", err)
	}
	data, _ := os.ReadFile(outPath)
	var s Summary
	json.Unmarshal(data, &s)
	if s.GeneratedAt.IsZero() {
		t.Error("expected GeneratedAt to be set, got zero time")
	}
}
