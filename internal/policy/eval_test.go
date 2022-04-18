package policy

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

func TestEvaluator_Evaluate(t *testing.T) {
	opaURL, opaContainer := setupOPAContainer(t)
	t.Cleanup(func() {
		_ = opaContainer.Terminate(context.Background())
	})

	eval, err := NewEvaluator[string, string](opaURL, "test", zerolog.Nop())
	require.NoError(t, err)

	t.Run("Matched", func(t *testing.T) {
		deployTestPolicy(t, opaURL, "./testdata/policy_matched.rego")

		result, err := eval.Eval(context.TODO(), "ping")
		require.NoError(t, err)
		require.Equal(t, "pong", result)
	})

	t.Run("Unmatched", func(t *testing.T) {
		deployTestPolicy(t, opaURL, "./testdata/policy_unmatched.rego")

		result, err := eval.Eval(context.TODO(), "ping")
		require.NoError(t, err)
		require.Equal(t, "pong", result)
	})

	t.Run("Empty", func(t *testing.T) {
		deployTestPolicy(t, opaURL, "./testdata/policy_empty.rego")

		_, err := eval.Eval(context.TODO(), "ping")
		require.Error(t, err)
		require.Equal(t, errNoResult, err)
	})
}

func setupOPAContainer(t *testing.T) (string, testcontainers.Container) {
	req := testcontainers.ContainerRequest{
		Image:        "openpolicyagent/opa:0.39.0",
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

	ip, err := container.Host(ctx)
	require.NoError(t, err)

	mappedPort, err := container.MappedPort(ctx, "8181")
	require.NoError(t, err)

	return fmt.Sprintf("http://%s:%s", ip, mappedPort.Port()), container
}

func deployTestPolicy(t *testing.T, opaURL, policyFile string) {
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
