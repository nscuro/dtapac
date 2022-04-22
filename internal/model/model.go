package model

import (
	"github.com/nscuro/dtrack-client"
	"github.com/rs/zerolog"
)

// Finding TODO
type Finding struct {
	Component     dtrack.Component     `json:"component"`
	Project       dtrack.Project       `json:"project"`
	Vulnerability dtrack.Vulnerability `json:"vulnerability"`
}

// MarshalZerologObject implement the zerolog.LogObjectMarshaler interface.
func (f Finding) MarshalZerologObject(e *zerolog.Event) {
	e.Str("component", f.Component.UUID.String()).
		Str("project", f.Project.UUID.String()).
		Str("vulnerability", f.Vulnerability.UUID.String())
}

// FindingAnalysis TODO
type FindingAnalysis struct {
	State         dtrack.AnalysisState         `json:"state"`
	Justification dtrack.AnalysisJustification `json:"justification"`
	Response      dtrack.AnalysisResponse      `json:"response"`
	Comment       string                       `json:"comment"`
	Suppress      *bool                        `json:"suppress"`
}

func (fa FindingAnalysis) MarshalZerologObject(e *zerolog.Event) {
	e.Str("state", string(fa.State)).
		Str("justification", string(fa.Justification)).
		Str("response", string(fa.Response)).
		Str("comment", fa.Comment).
		Interface("suppress", fa.Suppress)
}

// Violation TODO
type Violation struct {
}

func (v Violation) MarshalZerologObject(e *zerolog.Event) {
	//TODO implement me
}

// ViolationAnalysis TODO
type ViolationAnalysis struct {
}

func (va ViolationAnalysis) MarshalZerologObject(e *zerolog.Event) {
	//TODO implement me
}
