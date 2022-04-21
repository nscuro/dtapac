package audit

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/google/uuid"
	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	"github.com/nscuro/dtapac/internal/policy/model"
)

func TestAuditor_AuditFinding(t *testing.T) {
	t.Run("PolicyEvalError", func(t *testing.T) {
		testErr := errors.New("testErr")
		auditor := NewAuditor(&policyEvalerMock{err: testErr}, nil, nil, zerolog.Nop())

		err := auditor.auditFinding(context.TODO(), model.Finding{})
		require.Error(t, err)
		require.Equal(t, err, testErr)
	})

	t.Run("PolicyEvalEmptyResult", func(t *testing.T) {
		auditor := NewAuditor(&policyEvalerMock{result: model.FindingAnalysis{}}, nil, nil, zerolog.Nop())

		err := auditor.auditFinding(context.TODO(), model.Finding{})
		require.NoError(t, err)
	})

	t.Run("FetchAnalysisError", func(t *testing.T) {
		policyEvaler := &policyEvalerMock{result: model.FindingAnalysis{
			State:   dtrack.AnalysisStateNotAffected,
			Comment: t.Name(),
		}}
		analysisSvc := &analysisSvcMock{
			getErr: net.ErrClosed,
		}
		auditor := NewAuditor(policyEvaler, nil, analysisSvc, zerolog.Nop())

		err := auditor.auditFinding(context.TODO(), model.Finding{})
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to fetch existing analysis")
		require.Zero(t, analysisSvc.createInput)
	})

	t.Run("NoExistingAnalysis", func(t *testing.T) {
		suppress := false
		policyEvaler := &policyEvalerMock{result: model.FindingAnalysis{
			State:         dtrack.AnalysisStateNotAffected,
			Justification: dtrack.AnalysisJustificationCodeNotReachable,
			Response:      dtrack.AnalysisResponseWillNotFix,
			Comment:       t.Name(),
			Suppress:      &suppress,
		}}
		analysisSvc := &analysisSvcMock{}
		auditor := NewAuditor(policyEvaler, nil, analysisSvc, zerolog.Nop())
		finding := model.Finding{
			Component: dtrack.Component{
				UUID: uuid.New(),
			},
			Project: dtrack.Project{
				UUID: uuid.New(),
			},
			Vulnerability: dtrack.Vulnerability{
				UUID: uuid.New(),
			},
		}

		err := auditor.auditFinding(context.TODO(), finding)
		require.NoError(t, err)
		require.NotZero(t, analysisSvc.createInput)
		require.Equal(t, finding.Component.UUID, analysisSvc.createInput.Component)
		require.Equal(t, finding.Project.UUID, analysisSvc.createInput.Project)
		require.Equal(t, finding.Vulnerability.UUID, analysisSvc.createInput.Vulnerability)
		require.Equal(t, dtrack.AnalysisStateNotAffected, analysisSvc.createInput.State)
		require.Equal(t, dtrack.AnalysisJustificationCodeNotReachable, analysisSvc.createInput.Justification)
		require.Equal(t, dtrack.AnalysisResponseWillNotFix, analysisSvc.createInput.Response)
		require.Equal(t, t.Name(), analysisSvc.createInput.Comment)
		require.NotNil(t, analysisSvc.createInput.Suppressed)
		require.False(t, *analysisSvc.createInput.Suppressed)
	})

	t.Run("WithExistingAnalysis", func(t *testing.T) {
		suppress := false
		policyEvaler := &policyEvalerMock{result: model.FindingAnalysis{
			State:         dtrack.AnalysisStateNotAffected,
			Justification: dtrack.AnalysisJustificationCodeNotReachable,
			Response:      dtrack.AnalysisResponseWillNotFix,
			Comment:       t.Name(),
			Suppress:      &suppress,
		}}
		analysisSvc := &analysisSvcMock{getResult: &dtrack.Analysis{
			State:         dtrack.AnalysisStateNotSet,
			Justification: dtrack.AnalysisJustificationCodeNotReachable,
			Response:      dtrack.AnalysisResponseWillNotFix,
			Comments: []dtrack.AnalysisComment{
				{
					Comment: t.Name(),
				},
				{
					Comment: "foo",
				},
				{
					Comment: "bar",
				},
			},
			Suppressed: true,
		}}
		auditor := NewAuditor(policyEvaler, nil, analysisSvc, zerolog.Nop())
		finding := model.Finding{
			Component: dtrack.Component{
				UUID: uuid.New(),
			},
			Project: dtrack.Project{
				UUID: uuid.New(),
			},
			Vulnerability: dtrack.Vulnerability{
				UUID: uuid.New(),
			},
		}

		err := auditor.auditFinding(context.TODO(), finding)
		require.NoError(t, err)
		require.NotZero(t, analysisSvc.createInput)
		require.Equal(t, finding.Component.UUID, analysisSvc.createInput.Component)
		require.Equal(t, finding.Project.UUID, analysisSvc.createInput.Project)
		require.Equal(t, finding.Vulnerability.UUID, analysisSvc.createInput.Vulnerability)
		require.Equal(t, dtrack.AnalysisStateNotAffected, analysisSvc.createInput.State)
		require.Equal(t, dtrack.AnalysisJustificationCodeNotReachable, analysisSvc.createInput.Justification) // Applied from existing analyses
		require.Equal(t, dtrack.AnalysisResponseWillNotFix, analysisSvc.createInput.Response)                 // Applied from existing analyses
		require.Empty(t, analysisSvc.createInput.Comment)                                                     // Is in desired state already
		require.NotNil(t, analysisSvc.createInput.Suppressed)
		require.False(t, *analysisSvc.createInput.Suppressed)
	})

	t.Run("WithExistingAnalysisNothingChanged", func(t *testing.T) {
		suppress := false
		policyEvaler := &policyEvalerMock{result: model.FindingAnalysis{
			State:         dtrack.AnalysisStateNotAffected,
			Justification: dtrack.AnalysisJustificationCodeNotReachable,
			Response:      dtrack.AnalysisResponseWillNotFix,
			Comment:       t.Name(),
			Suppress:      &suppress,
		}}
		analysisSvc := &analysisSvcMock{getResult: &dtrack.Analysis{
			State:         dtrack.AnalysisStateNotAffected,
			Justification: dtrack.AnalysisJustificationCodeNotReachable,
			Response:      dtrack.AnalysisResponseWillNotFix,
			Comments: []dtrack.AnalysisComment{
				{
					Comment: t.Name(),
				},
			},
			Suppressed: false,
		}}
		auditor := NewAuditor(policyEvaler, nil, analysisSvc, zerolog.Nop())
		finding := model.Finding{
			Component: dtrack.Component{
				UUID: uuid.New(),
			},
			Project: dtrack.Project{
				UUID: uuid.New(),
			},
			Vulnerability: dtrack.Vulnerability{
				UUID: uuid.New(),
			},
		}

		err := auditor.auditFinding(context.TODO(), finding)
		require.NoError(t, err)
		require.Zero(t, analysisSvc.createInput)
	})
}

type analysisSvcMock struct {
	getResult    *dtrack.Analysis       // Result returned by Get
	getErr       error                  // Error returned by Get
	createInput  dtrack.AnalysisRequest // Input passed to Create
	createResult *dtrack.Analysis       // Result returned by Create
	createErr    error                  // Error returned by Create
}

// Get implements the dtrackAnalysisSvc interface.
func (a analysisSvcMock) Get(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ uuid.UUID) (*dtrack.Analysis, error) {
	return a.getResult, a.getErr
}

// Create implements the dtrackAnalysisSvc interface.
func (a *analysisSvcMock) Create(_ context.Context, input dtrack.AnalysisRequest) (*dtrack.Analysis, error) {
	a.createInput = input
	return a.createResult, a.createErr
}

type policyEvalerMock struct {
	result model.FindingAnalysis // Result returned by Eval
	err    error                 // Error returned by Eval
}

// Eval implements the policy.Evaluator interface.
func (p policyEvalerMock) Eval(_ context.Context, _ any, v any) error {
	if p.err != nil {
		return p.err
	}

	switch result := v.(type) {
	case *model.FindingAnalysis:
		*result = p.result
	default:
		panic("invalid result type")
	}

	return nil
}
