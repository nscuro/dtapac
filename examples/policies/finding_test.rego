package dtapac.finding

# Verify that an empty object is returned when no rule matches the given input.
test_analysis_nomatch {
    res := analysis with input as {}
    count(res) == 0
}

# Verify that legacy OSS Index vulnerabilities will be suppressed.
test_ossindex_legacy {
    res := analysis with input as {
        "vulnerability": {
            "source": "OSSINDEX",
            "vulnId": "8003f1fa-2d6b-4240-8ebb-16ee5a44ead5"
        }
    }

    count(res) == 3
    res.state == "RESOLVED"
    count(res.details) > 0
    res.suppress
}

# Verify that duplicate vulnerabilities will be suppressed.
test_duplicates {
    res := analysis with input as {
        "vulnerability": {
            "vulnId": "GHSA-r695-7vr9-jgc2"
        }
    }

    count(res) == 3
    res.state == "RESOLVED"
    res.details == "Duplicate of CVE-2020-36187."
    res.suppress
}

test_fluxcapacitor_h2 {
    res := analysis with input as {
        "component": {
            "group": "com.h2database",
            "name": "h2",
        },
        "project": {
            "name": "Flux Capacitor"
        }
    }

    count(res) == 4
    res.state == "NOT_AFFECTED"
    res.justification == "CODE_NOT_REACHABLE"
    count(res.details) > 0
    res.suppress
}

# Verify that false positives for the camel-jetty9 component will be suppressed.
test_analysis_cameljetty9 {
    res := analysis with input as {
        "component": {
            "group": "org.apache.camel",
            "name": "camel-jetty9",
            "version": "2.19.0"
        },
        "vulnerability": {
            "vulnId": "CVE-2019-0188"
        }
    }

    count(res) == 3
    res.state == "FALSE_POSITIVE"
    count(res.details) > 0
    res.suppress
}

# Verify that log4shell occurrences are flagged as exploitable.
test_log4shell {
    res := analysis with input as {
        "component": {
            "name": "log4j-core"
        },
        "vulnerability": {
            "vulnId": "CVE-2021-44228"
        }
    }

    count(res) == 3
    res.state == "EXPLOITABLE"
    count(res.comment) > 0
    not res.suppress
}