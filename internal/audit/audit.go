package audit

type FindingAuditor func(finding Finding) (FindingAnalysis, error)

type ViolationAuditor func(violation Violation) (ViolationAnalysis, error)
