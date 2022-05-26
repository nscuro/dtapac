package audit

import (
	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"
)

// Violation TODO
type Violation struct {
	Component       dtrack.Component       `json:"component"`
	Project         dtrack.Project         `json:"project"`
	PolicyViolation dtrack.PolicyViolation `json:"policyViolation"`
}

// MarshalZerologObject implement the zerolog.LogObjectMarshaler interface.
func (v Violation) MarshalZerologObject(e *zerolog.Event) {
	e.Str("component", v.Component.UUID.String()).
		Str("project", v.Project.UUID.String()).
		Str("violation", v.PolicyViolation.UUID.String())
}

// ViolationAnalysis TODO
type ViolationAnalysis struct {
	State    dtrack.ViolationAnalysisState `json:"state"`
	Comment  string                        `json:"comment"`
	Suppress *bool                         `json:"suppress"`
}

// MarshalZerologObject implement the zerolog.LogObjectMarshaler interface.
func (va ViolationAnalysis) MarshalZerologObject(e *zerolog.Event) {
	e.Str("state", string(va.State)).
		Str("comment", va.Comment).
		Interface("suppress", va.Suppress)
}
