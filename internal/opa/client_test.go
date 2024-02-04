package opa

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestClient_Decision(t *testing.T) {
	opaURL := setupOPA(t)

	client, err := NewClient(opaURL)
	require.NoError(t, err)

	t.Run("Match", func(t *testing.T) {
		deployPolicy(t, opaURL, "./testdata/policy_match.rego")

		var result string
		err := client.Decision(context.TODO(), "/test/decision", "ping", &result)
		require.NoError(t, err)
		require.Equal(t, "pong", result)
	})

	t.Run("Default", func(t *testing.T) {
		deployPolicy(t, opaURL, "./testdata/policy_default.rego")

		var result string
		err := client.Decision(context.TODO(), "/test/decision", "ping", &result)
		require.NoError(t, err)
		require.Equal(t, "pong", result)
	})

	t.Run("Empty", func(t *testing.T) {
		deployPolicy(t, opaURL, "./testdata/policy_empty.rego")

		var result string
		err := client.Decision(context.TODO(), "/test/decision", "ping", &result)
		require.Error(t, err)
		require.Equal(t, ErrNoDecisionResult, err)
	})
}

func setupOPA(t *testing.T) string {
	req := testcontainers.ContainerRequest{
		Image:        "openpolicyagent/opa:0.61.0",
		Cmd:          []string{"run", "--server"},
		ExposedPorts: []string{"8181/tcp"},
		WaitingFor:   wait.ForLog("Initializing server"),
		AutoRemove:   true,
	}

	ctx := context.Background()

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	ip, err := container.Host(ctx)
	require.NoError(t, err)

	mappedPort, err := container.MappedPort(ctx, "8181")
	require.NoError(t, err)

	return fmt.Sprintf("http://%s:%s", ip, mappedPort.Port())
}

func deployPolicy(t *testing.T, opaURL, policyFile string) {
	policyContent, err := os.ReadFile(policyFile)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, fmt.Sprintf("%s/v1/policies/%s", opaURL, t.Name()), bytes.NewReader(policyContent))
	require.NoError(t, err)

	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.StatusCode)

	t.Cleanup(func() {
		req, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/v1/policies/%s", opaURL, t.Name()), nil)
		_, _ = http.DefaultClient.Do(req)
	})
}
