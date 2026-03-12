package k8s

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jashdashandi/chaos-sec/internal/experiment"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestBuildAttackerPod_BasicFields(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name:            "test-exp",
		Image:           "busybox:1.36",
		Command:         []string{"echo", "hello"},
		Namespace:       "test-ns",
		ExpectedOutcome: "blocked",
	}

	pod := BuildAttackerPod(spec, "test-pod")

	if pod.Name != "test-pod" {
		t.Errorf("expected pod name %q, got %q", "test-pod", pod.Name)
	}
	if pod.Namespace != "test-ns" {
		t.Errorf("expected namespace %q, got %q", "test-ns", pod.Namespace)
	}
	if pod.Labels["app"] != "chaos-sec" {
		t.Errorf("expected label app=chaos-sec, got %q", pod.Labels["app"])
	}
	if pod.Labels["experiment"] != "test-exp" {
		t.Errorf("expected label experiment=test-exp, got %q", pod.Labels["experiment"])
	}
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("expected RestartPolicyNever, got %q", pod.Spec.RestartPolicy)
	}
	if len(pod.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(pod.Spec.Containers))
	}
	c := pod.Spec.Containers[0]
	if c.Name != "attacker" {
		t.Errorf("expected container name %q, got %q", "attacker", c.Name)
	}
	if c.Image != "busybox:1.36" {
		t.Errorf("expected image %q, got %q", "busybox:1.36", c.Image)
	}
}

func TestBuildAttackerPod_NoHostPath(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name:      "no-hp",
		Image:     "busybox:1.36",
		Command:   []string{"echo"},
		Namespace: "test-ns",
	}
	pod := BuildAttackerPod(spec, "pod-no-hp")

	if len(pod.Spec.Volumes) != 0 {
		t.Errorf("expected no volumes, got %d", len(pod.Spec.Volumes))
	}
	if len(pod.Spec.Containers[0].VolumeMounts) != 0 {
		t.Errorf("expected no volume mounts, got %d", len(pod.Spec.Containers[0].VolumeMounts))
	}
}

func TestBuildAttackerPod_WithHostPath(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name:          "hp-exp",
		Image:         "busybox:1.36",
		Command:       []string{"cat", "/host-etc/shadow"},
		Namespace:     "test-ns",
		HostPathMount: "/etc",
	}
	pod := BuildAttackerPod(spec, "pod-hp")

	if len(pod.Spec.Volumes) != 1 {
		t.Fatalf("expected 1 volume, got %d", len(pod.Spec.Volumes))
	}
	vol := pod.Spec.Volumes[0]
	if vol.HostPath == nil || vol.HostPath.Path != "/etc" {
		t.Errorf("expected hostPath=/etc, got %+v", vol.HostPath)
	}
	mounts := pod.Spec.Containers[0].VolumeMounts
	if len(mounts) != 1 {
		t.Fatalf("expected 1 volume mount, got %d", len(mounts))
	}
	if mounts[0].MountPath != "/host-etc" {
		t.Errorf("expected mountPath=/host-etc, got %q", mounts[0].MountPath)
	}
}

func TestEvaluateOutcome_BlockedMatchesExpected(t *testing.T) {
	pod := podWithExitCode(1)
	actual, pass := EvaluateOutcome(pod, "blocked")
	if actual != "blocked" {
		t.Errorf("expected actual=blocked, got %q", actual)
	}
	if !pass {
		t.Error("expected pass=true when actual==expected")
	}
}

func TestEvaluateOutcome_PermittedMatchesExpected(t *testing.T) {
	pod := podWithExitCode(0)
	actual, pass := EvaluateOutcome(pod, "permitted")
	if actual != "permitted" {
		t.Errorf("expected actual=permitted, got %q", actual)
	}
	if !pass {
		t.Error("expected pass=true when actual==expected")
	}
}

func TestEvaluateOutcome_Mismatch(t *testing.T) {
	// Pod succeeded (exit 0 = permitted) but we expected it to be blocked.
	pod := podWithExitCode(0)
	actual, pass := EvaluateOutcome(pod, "blocked")
	if actual != "permitted" {
		t.Errorf("expected actual=permitted, got %q", actual)
	}
	if pass {
		t.Error("expected pass=false on mismatch")
	}
}

func TestIsAdmissionError(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		{"pods \"x\" is forbidden: violates PodSecurity", true},
		{"admission webhook denied the request", true},
		{"connection refused", false},
		{"timeout", false},
		{"", false},
	}
	for _, tt := range tests {
		got := isAdmissionError(errors.New(tt.msg))
		if got != tt.want {
			t.Errorf("isAdmissionError(%q) = %v, want %v", tt.msg, got, tt.want)
		}
	}
}

// podWithExitCode constructs a minimal completed Pod with the given exit code.
func podWithExitCode(code int32) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "test-pod"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{
							ExitCode: code,
						},
					},
				},
			},
		},
	}
}

func TestEvaluateOutcome_NoContainerStatuses(t *testing.T) {
	// Pod with no container statuses — should default to exit code 0 (permitted).
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "empty-pod"},
		Status:     corev1.PodStatus{},
	}
	actual, pass := EvaluateOutcome(pod, "permitted")
	if actual != "permitted" {
		t.Errorf("expected actual=permitted, got %q", actual)
	}
	if !pass {
		t.Error("expected pass=true when actual==expected")
	}
}

func TestEvaluateOutcome_NilTerminatedState(t *testing.T) {
	// Container status exists but Terminated is nil — should default to exit 0.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "nil-term-pod"},
		Status: corev1.PodStatus{
			ContainerStatuses: []corev1.ContainerStatus{
				{State: corev1.ContainerState{Terminated: nil}},
			},
		},
	}
	actual, pass := EvaluateOutcome(pod, "permitted")
	if actual != "permitted" {
		t.Errorf("expected actual=permitted, got %q", actual)
	}
	if !pass {
		t.Error("expected pass=true")
	}
}

func TestIsAdmissionError_Nil(t *testing.T) {
	if isAdmissionError(nil) {
		t.Error("expected isAdmissionError(nil) == false")
	}
}

func TestBuildAttackerPod_RestartPolicyNever(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name: "rp-test", Image: "busybox", Command: []string{"echo"}, Namespace: "ns",
	}
	pod := BuildAttackerPod(spec, "rp-pod")
	if pod.Spec.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("expected RestartPolicyNever, got %q", pod.Spec.RestartPolicy)
	}
}

func TestBuildAttackerPod_ContainerName(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name: "cn-test", Image: "busybox", Command: []string{"sh"}, Namespace: "ns",
	}
	pod := BuildAttackerPod(spec, "cn-pod")
	if pod.Spec.Containers[0].Name != "attacker" {
		t.Errorf("expected container name 'attacker', got %q", pod.Spec.Containers[0].Name)
	}
}

func TestBuildAttackerPod_ExperimentLabel(t *testing.T) {
	spec := experiment.ExperimentSpec{
		Name: "label-test", Image: "busybox", Command: []string{"echo"}, Namespace: "ns",
	}
	pod := BuildAttackerPod(spec, "label-pod")
	if pod.Labels["experiment"] != "label-test" {
		t.Errorf("expected experiment label %q, got %q", "label-test", pod.Labels["experiment"])
	}
	if pod.Labels["app"] != "chaos-sec" {
		t.Errorf("expected app label %q, got %q", "chaos-sec", pod.Labels["app"])
	}
}

// TestRunPod_AdmissionBlock verifies that RunPod treats a "is forbidden" API error
// as a PASS when the experiment expects "blocked".
func TestRunPod_AdmissionBlock(t *testing.T) {
	cs := kfake.NewSimpleClientset()

	// Inject a reactor that returns a forbidden error for pod Create.
	cs.PrependReactor("create", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New(`pods "x" is forbidden: violates PodSecurity "restricted:latest"`)
	})

	spec := experiment.ExperimentSpec{
		Name:            "adm-block",
		Image:           "busybox",
		Command:         []string{"sh"},
		Namespace:       "test-ns",
		ExpectedOutcome: "blocked",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	outcome, pass, _, _, err := RunPod(ctx, cs, spec, "pod-adm-block")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != "blocked" {
		t.Errorf("expected outcome=blocked, got %q", outcome)
	}
	if !pass {
		t.Error("expected pass=true when admission blocks a pod that should be blocked")
	}
}

// TestRunPod_AdmissionBlock_WrongExpected verifies that a "is forbidden" error
// returns an error (not a pass) when the experiment does NOT expect "blocked".
func TestRunPod_AdmissionBlock_WrongExpected(t *testing.T) {
	cs := kfake.NewSimpleClientset()
	cs.PrependReactor("create", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New(`pods "x" is forbidden: violates PodSecurity "restricted:latest"`)
	})

	spec := experiment.ExperimentSpec{
		Name:            "adm-mismatch",
		Image:           "busybox",
		Command:         []string{"sh"},
		Namespace:       "test-ns",
		ExpectedOutcome: "permitted",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, _, _, _, err := RunPod(ctx, cs, spec, "pod-adm-mismatch")
	if err == nil {
		t.Error("expected error when admission blocks a pod that should be permitted")
	}
}

// TestWaitForPodCompletion_PodSucceeded verifies that WaitForPodCompletion returns
// a pod immediately when it is already in Succeeded phase.
func TestWaitForPodCompletion_PodSucceeded(t *testing.T) {
	successPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "done-pod", Namespace: "test-ns"},
		Status:     corev1.PodStatus{Phase: corev1.PodSucceeded},
	}
	cs := kfake.NewSimpleClientset(successPod)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pod, err := WaitForPodCompletion(ctx, cs, "test-ns", "done-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pod.Status.Phase != corev1.PodSucceeded {
		t.Errorf("expected PodSucceeded, got %q", pod.Status.Phase)
	}
}

// TestWaitForPodCompletion_PodFailed verifies that WaitForPodCompletion returns a
// pod in Failed phase (e.g., non-zero exit code).
func TestWaitForPodCompletion_PodFailed(t *testing.T) {
	failedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "fail-pod", Namespace: "test-ns"},
		Status:     corev1.PodStatus{Phase: corev1.PodFailed},
	}
	cs := kfake.NewSimpleClientset(failedPod)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pod, err := WaitForPodCompletion(ctx, cs, "test-ns", "fail-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pod.Status.Phase != corev1.PodFailed {
		t.Errorf("expected PodFailed, got %q", pod.Status.Phase)
	}
}

// TestWaitForPodCompletion_Timeout verifies that WaitForPodCompletion returns an
// error when the context expires before the pod completes.
func TestWaitForPodCompletion_Timeout(t *testing.T) {
	pendingPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pending-pod", Namespace: "test-ns"},
		Status:     corev1.PodStatus{Phase: corev1.PodPending},
	}
	cs := kfake.NewSimpleClientset(pendingPod)

	// Very short timeout so the test doesn't slow the suite.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := WaitForPodCompletion(ctx, cs, "test-ns", "pending-pod")
	if err == nil {
		t.Error("expected timeout error, got nil")
	}
}

// TestRunPod_HappyPath verifies that RunPod succeeds when the pod is created,
// completes with exit code 0 (permitted), and evaluates correctly.
// getPodLogs returns an error with the fake client (DoRaw not supported) but the
// error is silently ignored — this tests the main happy-path code path.
func TestRunPod_HappyPath(t *testing.T) {
	// Pre-create a pod in Succeeded state so WaitForPodCompletion returns immediately.
	succeededPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "happy-pod",
			Namespace: "test-ns",
			Labels:    map[string]string{"app": "chaos-sec", "experiment": "happy"},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodSucceeded,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: 0},
					},
				},
			},
		},
	}
	cs := kfake.NewSimpleClientset()

	// Intercept Create to store the pod with Succeeded status immediately.
	cs.PrependReactor("create", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, succeededPod, nil
	})
	// Intercept Get to always return the succeeded pod.
	cs.PrependReactor("get", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, succeededPod, nil
	})
	// Intercept Delete (cleanup) to succeed silently.
	cs.PrependReactor("delete", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})

	spec := experiment.ExperimentSpec{
		Name:            "happy",
		Image:           "busybox",
		Command:         []string{"echo", "ok"},
		Namespace:       "test-ns",
		ExpectedOutcome: "permitted",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	outcome, pass, exitCode, _, err := RunPod(ctx, cs, spec, "happy-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != "permitted" {
		t.Errorf("expected outcome=permitted, got %q", outcome)
	}
	if !pass {
		t.Error("expected pass=true")
	}
	if exitCode != 0 {
		t.Errorf("expected exitCode=0, got %d", exitCode)
	}
}

// TestRunPod_HappyPath_Blocked verifies that RunPod correctly identifies a PASS
// when a pod fails with exit code 1 and the expected outcome is "blocked".
func TestRunPod_HappyPath_Blocked(t *testing.T) {
	blockedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "blocked-run-pod", Namespace: "test-ns"},
		Status: corev1.PodStatus{
			Phase: corev1.PodFailed,
			ContainerStatuses: []corev1.ContainerStatus{
				{
					State: corev1.ContainerState{
						Terminated: &corev1.ContainerStateTerminated{ExitCode: 1},
					},
				},
			},
		},
	}
	cs := kfake.NewSimpleClientset()
	cs.PrependReactor("create", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, blockedPod, nil
	})
	cs.PrependReactor("get", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, blockedPod, nil
	})
	cs.PrependReactor("delete", "pods", func(_ ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, nil
	})

	spec := experiment.ExperimentSpec{
		Name:            "blocked-run",
		Image:           "busybox",
		Command:         []string{"sh", "-c", "exit 1"},
		Namespace:       "test-ns",
		ExpectedOutcome: "blocked",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	outcome, pass, exitCode, _, err := RunPod(ctx, cs, spec, "blocked-run-pod")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if outcome != "blocked" {
		t.Errorf("expected outcome=blocked, got %q", outcome)
	}
	if !pass {
		t.Error("expected pass=true")
	}
	if exitCode != 1 {
		t.Errorf("expected exitCode=1, got %d", exitCode)
	}
}
