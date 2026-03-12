package experiment

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAll_ValidFiles(t *testing.T) {
	dir := t.TempDir()

	writeYAML(t, dir, "test-exp.yaml", `
name: test-exp
description: A test experiment
image: busybox:1.36
command: ["sh", "-c", "echo hello"]
expected_outcome: blocked
falco_rule: some_rule
namespace: test-ns
`)

	specs, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll returned error: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].Name != "test-exp" {
		t.Errorf("expected name %q, got %q", "test-exp", specs[0].Name)
	}
	if specs[0].ExpectedOutcome != "blocked" {
		t.Errorf("expected outcome %q, got %q", "blocked", specs[0].ExpectedOutcome)
	}
}

func TestLoadAll_SkipsNonYAML(t *testing.T) {
	dir := t.TempDir()

	// Write a valid YAML and a non-YAML file that would fail parsing.
	writeYAML(t, dir, "valid.yaml", `
name: valid
image: busybox:1.36
command: ["echo"]
expected_outcome: permitted
namespace: test-ns
`)
	writeYAML(t, dir, "notes.txt", "this is not yaml at all!!!")

	specs, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec (txt skipped), got %d", len(specs))
	}
}

func TestLoadAll_MissingRequiredField(t *testing.T) {
	dir := t.TempDir()

	// Missing 'image'
	writeYAML(t, dir, "bad.yaml", `
name: bad-exp
command: ["echo"]
expected_outcome: blocked
namespace: test-ns
`)

	_, err := LoadAll(dir)
	if err == nil {
		t.Fatal("expected error for missing 'image' field, got nil")
	}
}

func TestLoadAll_InvalidExpectedOutcome(t *testing.T) {
	dir := t.TempDir()

	writeYAML(t, dir, "bad-outcome.yaml", `
name: bad-outcome
image: busybox:1.36
command: ["echo"]
expected_outcome: maybe
namespace: test-ns
`)

	_, err := LoadAll(dir)
	if err == nil {
		t.Fatal("expected validation error for invalid expected_outcome, got nil")
	}
}

func TestLoadAll_EmptyDir(t *testing.T) {
	dir := t.TempDir()

	specs, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("unexpected error on empty dir: %v", err)
	}
	if len(specs) != 0 {
		t.Fatalf("expected 0 specs, got %d", len(specs))
	}
}

func TestLoadAll_HostPathMount(t *testing.T) {
	dir := t.TempDir()

	writeYAML(t, dir, "hostpath.yaml", `
name: hostpath-exp
image: busybox:1.36
command: ["cat", "/host-etc/shadow"]
expected_outcome: blocked
namespace: test-ns
host_path_mount: /etc
`)

	specs, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if specs[0].HostPathMount != "/etc" {
		t.Errorf("expected host_path_mount %q, got %q", "/etc", specs[0].HostPathMount)
	}
}

// writeYAML is a test helper that writes content to filename inside dir.
func writeYAML(t *testing.T, dir, filename, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, filename), []byte(content), 0o644); err != nil {
		t.Fatalf("writing test file: %v", err)
	}
}
