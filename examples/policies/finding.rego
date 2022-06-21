package dtapac.finding

default analysis = {}

analysis = res {
	# Suppress all vulnerabilities matching a specific pattern.
	# In this case, OSS Index changed its naming scheme for their own
	# vulnerabilities, effectively making the old vulns obsolete.

	regex.match("^[a-f\\d]{8}-[a-f\\d]{4}-[a-f\\d]{4}-[a-f\\d]{4}-[a-f\\d]{12}$", input.vulnerability.vulnId)
	input.vulnerability.source == "OSSINDEX"

	res := {
		"state": "RESOLVED",
		"details": "Legacy OSS Index vulnerability, see https://ossindex.sonatype.org/updates-notice.",
		"suppress": true,
	}
} else = res {
	# Suppress duplicate vulnerabilities.
	# This can happen when different sources report the same vulnerability
	# under different vulnerability identifiers. Utilize a mapping to be able
	# to include which vulnerability is duplicated in the analysis details.

	duplicatedVuln := {
		"GHSA-57j2-w4cx-62h2": "CVE-2020-36518",
		"GHSA-r695-7vr9-jgc2": "CVE-2020-36187",
		"GHSA-vfqx-33qm-g869": "CVE-2020-36189",
	}[input.vulnerability.vulnId]

	res := {
		"state": "RESOLVED",
		"details": sprintf("Duplicate of %s.", [duplicatedVuln]),
		"suppress": true,
	}
} else = res {
	# Suppress false positives for a specific component.

	input.component.group == "org.apache.camel"
	input.component.name == "camel-jetty9"
	input.vulnerability.vulnId == "CVE-2019-0188"

	res := {
		"state": "FALSE_POSITIVE",
		"details": "Affects camel-xmljson, but not camel-jetty9.",
		"suppress": true,
	}
} else = res {
	# Suppress all vulnerabilities in h2 for a selection of specific projects.
	# These projects are using h2 only in unit tests and the devs convinced
	# the security team that ignoring vulns in it is acceptable.

	input.project.name == ["Flux Capacitor", "Mr. Robot"][_]
	input.component.group == "com.h2database"
	input.component.name == "h2"

	res := {
		"state": "NOT_AFFECTED",
		"justification": "CODE_NOT_REACHABLE",
		"details": "h2 is only used in unit tests.",
		"suppress": true,
	}
} else = res {
	# The security team got PTSD from multiple log4shell incidents
	# and they're not willing to take any risks anymore.

	input.component.name == "log4j-core"
	input.vulnerability.vulnId == "CVE-2021-44228"

	res := {
		"state": "EXPLOITABLE",
		"comment": "Update immediately!",
		"suppress": false,
	}
}
