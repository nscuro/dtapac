package audit

import "github.com/nscuro/dtapac/internal/model"

type FindingAuditor func(finding model.Finding) (model.FindingAnalysis, error)

type ViolationAuditor func(finding model.Violation) (model.ViolationAnalysis, error)
