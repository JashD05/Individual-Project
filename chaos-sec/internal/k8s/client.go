// Package k8s provides helpers for interacting with the Kubernetes API in the
// context of Chaos-Sec experiments: building attacker pod specs, creating and
// monitoring pods, evaluating their exit outcomes, and constructing a clientset
// from in-cluster config or a local kubeconfig file.
package k8s

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// NewClientset builds a Kubernetes clientset. It first tries in-cluster config
// (used when chaos-sec runs as a pod inside the cluster), then falls back to
// the local kubeconfig file for development use.
func NewClientset() (*kubernetes.Clientset, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := kubeConfigPath()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("building kubeconfig: %w", err)
		}
	}
	return kubernetes.NewForConfig(config)
}

// kubeConfigPath returns the path to the local kubeconfig file.
func kubeConfigPath() string {
	if kc := os.Getenv("KUBECONFIG"); kc != "" {
		return kc
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kube", "config")
}
