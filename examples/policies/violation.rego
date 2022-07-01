package dtapac.violation

default analysis = {}

analysis = res {
	# The security team is tracking 3rd party projects in their Dependency-Track instance,
	# but doesn't want to get overwhelmed with violations for software that is out of their
	# control.

	"thirdparty" == input.project.tags[_].name
	input.policyViolation.type == "LICENSE"

	res := {
		"state": "APPROVED",
		"comment": "Third party projects are excluded from internal license policies.",
		"suppress": true,
	}
}
