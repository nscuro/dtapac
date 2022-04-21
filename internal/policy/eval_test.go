package policy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNopEvaluator_Eval(t *testing.T) {
	require.NoError(t, NewNopEvaluator().Eval(context.TODO(), nil, nil))
}
