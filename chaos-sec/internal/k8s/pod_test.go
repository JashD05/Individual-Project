package k8s

import (
	"errors"
	"testing"

	"github.com/jashdashandi/chaos-sec/internal/experiment"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
