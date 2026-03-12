package k8s

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jashdashandi/chaos-sec/internal/experiment"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
)

// ptr returns a pointer to v. Convenience helper for int64 fields in API objects.
func ptr[T any](v T) *T { return &v }

// BuildAttackerPod constructs a Pod spec for an experiment. The pod runs once
// (RestartPolicy=Never), is labelled for easy cleanup, and optionally has a
// hostPath volume injected when spec.HostPathMount is set.
func BuildAttackerPod(spec experiment.ExperimentSpec, podName string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: spec.Namespace,
			Labels: map[string]string{
				"app":        "chaos-sec",
				"experiment": spec.Name,
			},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "attacker",
					Image:   spec.Image,
					Command: spec.Command,
				},
			},
		},
	}

	if spec.HostPathMount != "" {
		pod.Spec.Volumes = []corev1.Volume{{
			Name: "host-vol",
			VolumeSource: corev1.VolumeSource{
				HostPath: &corev1.HostPathVolumeSource{Path: spec.HostPathMount},
			},
		}}
		pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{
			Name:      "host-vol",
			MountPath: "/host-etc",
		}}
	}

	return pod
}

// RunPod creates the attacker pod, waits for it to complete, collects its logs,
// evaluates the outcome, and always deletes the pod on return.
//
// If the Kubernetes API rejects pod creation with an admission error (e.g., PSA
// blocks a privileged pod), and the experiment expects "blocked", that is treated
// as a PASS — the control is working correctly.
func RunPod(
	ctx context.Context,
	cs *kubernetes.Clientset,
	spec experiment.ExperimentSpec,
	podName string,
) (actualOutcome string, pass bool, exitCode int, logs string, err error) {
	pod := BuildAttackerPod(spec, podName)

	slog.Info("creating attacker pod",
		"pod", podName,
		"namespace", spec.Namespace,
		"experiment", spec.Name,
	)

	_, createErr := cs.CoreV1().Pods(spec.Namespace).Create(ctx, pod, metav1.CreateOptions{})
	if createErr != nil {
		if isAdmissionError(createErr) && spec.ExpectedOutcome == "blocked" {
			slog.Info("pod creation blocked by admission control — PASS",
				"experiment", spec.Name,
				"error", createErr.Error(),
			)
			return "blocked", true, 0, "", nil
		}
		return "", false, 0, "", fmt.Errorf("creating pod: %w", createErr)
	}

	// Always clean up the pod, even if subsequent steps fail.
	defer func() {
		delCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = cs.CoreV1().Pods(spec.Namespace).Delete(delCtx, podName, metav1.DeleteOptions{
			GracePeriodSeconds: ptr(int64(0)),
		})
		slog.Info("deleted attacker pod", "pod", podName)
	}()

	completedPod, waitErr := WaitForPodCompletion(ctx, cs, spec.Namespace, podName)
	if waitErr != nil {
		return "", false, 0, "", fmt.Errorf("waiting for pod completion: %w", waitErr)
	}

	logs, _ = getPodLogs(ctx, cs, spec.Namespace, podName)
	actualOutcome, pass = EvaluateOutcome(completedPod, spec.ExpectedOutcome)

	if len(completedPod.Status.ContainerStatuses) > 0 {
		t := completedPod.Status.ContainerStatuses[0].State.Terminated
		if t != nil {
			exitCode = int(t.ExitCode)
		}
	}

	return actualOutcome, pass, exitCode, logs, nil
}

// WaitForPodCompletion polls the pod status until it reaches Succeeded or Failed,
// or the context deadline is exceeded. It uses a 3-second poll interval to avoid
// hammering the Kubernetes API server.
func WaitForPodCompletion(ctx context.Context, cs *kubernetes.Clientset, namespace, name string) (*corev1.Pod, error) {
	var completedPod *corev1.Pod

	err := wait.PollUntilContextTimeout(ctx, 3*time.Second, 2*time.Minute, true,
		func(ctx context.Context) (bool, error) {
			pod, err := cs.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
			if err != nil {
				// Transient API error — keep retrying.
				return false, nil
			}
			switch pod.Status.Phase {
			case corev1.PodSucceeded, corev1.PodFailed:
				completedPod = pod
				return true, nil
			default:
				return false, nil
			}
		},
	)
	if err != nil {
		return nil, fmt.Errorf("pod %s/%s did not complete: %w", namespace, name, err)
	}
	return completedPod, nil
}

// EvaluateOutcome maps a completed pod's exit code to "blocked" or "permitted"
// and compares it against the expected outcome.
func EvaluateOutcome(pod *corev1.Pod, expected string) (actual string, pass bool) {
	var exitCode int32
	if len(pod.Status.ContainerStatuses) > 0 {
		if t := pod.Status.ContainerStatuses[0].State.Terminated; t != nil {
			exitCode = t.ExitCode
		}
	}

	if exitCode != 0 {
		actual = "blocked"
	} else {
		actual = "permitted"
	}
	return actual, actual == expected
}

// isAdmissionError returns true if err looks like a Kubernetes admission
// webhook / policy rejection (status 403 or a "is forbidden" message).
func isAdmissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{"is forbidden", "violates PodSecurity", "admission webhook"} {
		for i := 0; i+len(marker) <= len(msg); i++ {
			if msg[i:i+len(marker)] == marker {
				return true
			}
		}
	}
	return false
}

// getPodLogs fetches stdout/stderr from the first container of the named pod.
func getPodLogs(ctx context.Context, cs *kubernetes.Clientset, namespace, name string) (string, error) {
	req := cs.CoreV1().Pods(namespace).GetLogs(name, &corev1.PodLogOptions{Container: "attacker"})
	raw, err := req.DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("fetching pod logs: %w", err)
	}
	return string(raw), nil
}
