package audit

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nscuro/dtapac/internal/model"
)

func TestAuditor_Start(t *testing.T) {
	t.Run("AuditFinding", func(t *testing.T) {
		inputChan := make(chan any, 1)
		inputChan <- model.Finding{}
		close(inputChan)

		auditor := NewAuditor(&opaClientMock{}, inputChan)
		err := auditor.Start(context.TODO())
		require.NoError(t, err)
	})

	t.Run("AuditViolation", func(t *testing.T) {

	})

	t.Run("InvalidInput", func(t *testing.T) {
		inputChan := make(chan any, 1)
		inputChan <- "invalid"
		close(inputChan)

		auditor := NewAuditor(&opaClientMock{}, inputChan)
		err := auditor.Start(context.TODO())
		require.NoError(t, err)
	})
}

type opaClientMock struct {
}

func (ocm opaClientMock) Decision(_ context.Context, _ string, _ any, _ any) error {
	//TODO implement me
	panic("implement me")
}
