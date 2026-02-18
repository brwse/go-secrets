// Package k8s provides a secret provider that reads from Kubernetes Secrets.
package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/brwse/go-secrets"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Client abstracts the Kubernetes Secrets API.
// Implement this interface to provide a custom client or for testing.
type Client interface {
	GetSecret(ctx context.Context, namespace, name string) (map[string][]byte, error)
}

// ProviderOption configures the k8s Provider.
type ProviderOption func(*Provider)

// WithClient injects a custom Client implementation.
func WithClient(c Client) ProviderOption {
	return func(p *Provider) {
		p.client = c
	}
}

// WithKubeconfig sets an explicit path to a kubeconfig file.
func WithKubeconfig(path string) ProviderOption {
	return func(p *Provider) {
		p.kubeconfig = path
	}
}

// WithContext selects a specific context from the kubeconfig.
func WithContext(name string) ProviderOption {
	return func(p *Provider) {
		p.context = name
	}
}

// Provider reads secrets from Kubernetes Secrets.
// It implements secrets.Provider.
type Provider struct {
	client     Client
	kubeconfig string
	context    string
}

// New creates a new Kubernetes Secrets Provider.
// If no Client is provided via WithClient, a real Kubernetes client is created
// using the standard kubeconfig chain (in-cluster, KUBECONFIG env, ~/.kube/config).
func New(opts ...ProviderOption) (*Provider, error) {
	p := &Provider{}
	for _, opt := range opts {
		opt(p)
	}
	if p.client == nil {
		config, err := buildConfig(p.kubeconfig, p.context)
		if err != nil {
			return nil, fmt.Errorf("k8s: load kubeconfig: %w", err)
		}
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			return nil, fmt.Errorf("k8s: create client: %w", err)
		}
		p.client = &k8sClient{clientset: clientset}
	}
	return p, nil
}

// Get retrieves a Kubernetes Secret and returns its data as JSON-encoded bytes.
// The key format is "namespace/secret-name".
// Returns secrets.ErrNotFound (wrapped) if the Secret does not exist.
func (p *Provider) Get(ctx context.Context, key string) ([]byte, error) {
	namespace, name, err := parseKey(key)
	if err != nil {
		return nil, fmt.Errorf("k8s: %w", err)
	}
	data, err := p.client.GetSecret(ctx, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("k8s: secret %q: %w", key, err)
	}
	// Convert map[string][]byte to map[string]string for JSON encoding.
	strData := make(map[string]string, len(data))
	for k, v := range data {
		strData[k] = string(v)
	}
	b, err := json.Marshal(strData)
	if err != nil {
		return nil, fmt.Errorf("k8s: secret %q: marshal: %w", key, err)
	}
	return b, nil
}

// parseKey splits "namespace/name" into its components.
func parseKey(key string) (namespace, name string, err error) {
	parts := strings.SplitN(key, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid key %q: expected \"namespace/name\"", key)
	}
	return parts[0], parts[1], nil
}

// buildConfig creates a *rest.Config using the standard loading rules.
func buildConfig(kubeconfig, context string) (*rest.Config, error) {
	// Try in-cluster first if no explicit kubeconfig.
	if kubeconfig == "" && context == "" {
		if config, err := rest.InClusterConfig(); err == nil {
			return config, nil
		}
	}
	// Fall back to kubeconfig.
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfig != "" {
		rules.ExplicitPath = kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if context != "" {
		overrides.CurrentContext = context
	}
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
}

// k8sClient wraps a real Kubernetes clientset.
type k8sClient struct {
	clientset kubernetes.Interface
}

func (c *k8sClient) GetSecret(ctx context.Context, namespace, name string) (map[string][]byte, error) {
	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("%w", secrets.ErrNotFound)
		}
		return nil, err
	}
	return secret.Data, nil
}
