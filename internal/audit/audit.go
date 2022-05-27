package audit

// FindingAuditor audits a finding and returns an analysis decision.
type FindingAuditor func(finding Finding) (FindingAnalysis, error)

// ViolationAuditor audits a policy violation and returns an analysis decision.
type ViolationAuditor func(violation Violation) (ViolationAnalysis, error)
