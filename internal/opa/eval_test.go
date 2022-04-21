package opa

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestPolicyEvaluator_Evaluate(t *testing.T) {
	opaURL := setupOPA(t)

	eval, err := NewPolicyEvaluator(opaURL, "/v1/data/test/analysis", zerolog.Nop())
	require.NoError(t, err)

	t.Run("Matched", func(t *testing.T) {
		deployOPAPolicy(t, opaURL, "./testdata/policy_matched.rego")

		var result string
		err := eval.Eval(context.TODO(), "ping", &result)
		require.NoError(t, err)
		require.Equal(t, "pong", result)
	})

	t.Run("Unmatched", func(t *testing.T) {
		deployOPAPolicy(t, opaURL, "./testdata/policy_unmatched.rego")

		var result string
		err := eval.Eval(context.TODO(), "ping", &result)
		require.NoError(t, err)
		require.Equal(t, "pong", result)
	})

	t.Run("Empty", func(t *testing.T) {
		deployOPAPolicy(t, opaURL, "./testdata/policy_empty.rego")

		var result string
		err := eval.Eval(context.TODO(), "ping", &result)
		require.Error(t, err)
		require.Equal(t, errNoResult, err)
	})
}

func setupOPA(t *testing.T) string {
	req := testcontainers.ContainerRequest{
		Image:        "openpolicyagent/opa:0.39.0-rootless",
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

func deployOPAPolicy(t *testing.T, opaURL, policyFile string) {
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
