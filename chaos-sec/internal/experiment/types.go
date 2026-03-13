// Package experiment defines the data types and YAML loader for Chaos-Sec
// security experiments. Each experiment is described by an ExperimentSpec
// loaded from a *.yaml file, and produces an ExperimentResult after execution.
package experiment

import "time"

// ExperimentSpec is loaded from a YAML payload file in the experiments/ directory.
type ExperimentSpec struct {
	Name            string   `yaml:"name"             json:"name"`
	Description     string   `yaml:"description"      json:"description"`
	Image           string   `yaml:"image"            json:"image"`
	Command         []string `yaml:"command"          json:"command"`
	ExpectedOutcome string   `yaml:"expected_outcome" json:"expected_outcome"`
	FalcoRule       string   `yaml:"falco_rule"       json:"falco_rule"`
	Namespace       string   `yaml:"namespace"        json:"namespace"`
	HostPathMount   string   `yaml:"host_path_mount,omitempty" json:"host_path_mount,omitempty"`
}

// ExperimentResult is produced by the engine after running one experiment.
type ExperimentResult struct {
	Spec          ExperimentSpec `json:"spec"`
	StartTime     time.Time      `json:"start_time"`
	EndTime       time.Time      `json:"end_time"`
	PodExitCode   int            `json:"pod_exit_code"`
	ActualOutcome string         `json:"actual_outcome"` // "blocked" or "permitted"
	Pass          bool           `json:"pass"`
	PodLogs       string         `json:"pod_logs"`
	// MTTD is nil when no Falco alert was received within the timeout window.
	MTTD *float64 `json:"mttd_seconds,omitempty"`
}
