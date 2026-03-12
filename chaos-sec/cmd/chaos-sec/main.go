package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jashdashandi/chaos-sec/internal/engine"
	"github.com/jashdashandi/chaos-sec/internal/experiment"
	k8sclient "github.com/jashdashandi/chaos-sec/internal/k8s"
	"github.com/jashdashandi/chaos-sec/internal/report"
	"github.com/jashdashandi/chaos-sec/internal/siem"
	"k8s.io/client-go/kubernetes"
)

func main() {
	experimentsDir := flag.String("experiments", "./experiments", "Directory containing YAML experiment payload files")
	namespace := flag.String("namespace", "chaos-sec-experiments", "Kubernetes namespace to run attacker pods in")
	siemPort := flag.String("siem-port", "8080", "Port for the Mock SIEM webhook server")
	reportOut := flag.String("report-out", "-", "Path for JSON report output ('-' for stdout)")
	timeout := flag.Duration("timeout", 5*time.Minute, "Overall timeout for all experiments")
	flag.Parse()

	// Structured JSON logging to stdout.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	// Load experiment specs from YAML directory.
	specs, err := experiment.LoadAll(*experimentsDir)
	if err != nil {
		slog.Error("failed to load experiments", "error", err.Error())
		os.Exit(1)
	}
	if len(specs) == 0 {
		slog.Warn("no experiment files found", "dir", *experimentsDir)
		os.Exit(0)
	}
	slog.Info("loaded experiments", "count", len(specs), "dir", *experimentsDir)

	// Start Mock SIEM webhook server.
	store := siem.NewAlertStore()
	if err := siem.ListenAndServe(":"+*siemPort, store); err != nil {
		slog.Error("failed to start SIEM server", "error", err.Error())
		os.Exit(1)
	}
	slog.Info("mock SIEM listening", "port", *siemPort, "endpoint", "/falco")

	// Build Kubernetes client.
	cs, err := k8sclient.NewClientset()
	if err != nil {
		slog.Error("failed to build Kubernetes client", "error", err.Error())
		os.Exit(1)
	}

	// Wire up the real pod runner and engine.
	runner := &k8sPodRunner{cs: cs, namespace: *namespace}
	eng := engine.New(runner, store)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	results := eng.Run(ctx, specs)

	// Write JSON report.
	if err := report.Write(results, *reportOut); err != nil {
		slog.Error("failed to write report", "error", err.Error())
		os.Exit(1)
	}

	// Exit non-zero if any experiment failed, so CI can detect regressions.
	for _, r := range results {
		if !r.Pass {
			fmt.Fprintf(os.Stderr, "\n%d/%d experiments FAILED — see report for details\n",
				countFailed(results), len(results))
			os.Exit(1)
		}
	}
	fmt.Fprintf(os.Stdout, "\nAll %d experiments PASSED ✓\n", len(results))
}

// k8sPodRunner implements engine.PodRunner using the real Kubernetes API.
type k8sPodRunner struct {
	cs        *kubernetes.Clientset
	namespace string
}

func (r *k8sPodRunner) Run(ctx context.Context, spec experiment.ExperimentSpec) (experiment.ExperimentResult, error) {
	if spec.Namespace == "" {
		spec.Namespace = r.namespace
	}
	podName := fmt.Sprintf("chaos-sec-%s-%d", spec.Name, time.Now().UnixMilli())

	start := time.Now()
	actualOutcome, pass, exitCode, logs, err := k8sclient.RunPod(ctx, r.cs, spec, podName)
	end := time.Now()

	if err != nil {
		return experiment.ExperimentResult{}, err
	}

	return experiment.ExperimentResult{
		Spec:          spec,
		StartTime:     start,
		EndTime:       end,
		PodExitCode:   exitCode,
		ActualOutcome: actualOutcome,
		Pass:          pass,
		PodLogs:       logs,
	}, nil
}

func countFailed(results []experiment.ExperimentResult) int {
	n := 0
	for _, r := range results {
		if !r.Pass {
			n++
		}
	}
	return n
}
