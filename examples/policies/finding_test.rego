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

    count(res) == 2
    count(res.details) > 0
    res.suppress
}

# Verify that all findings for the acme-test project will be suppressed.
test_analysis_acmetest {
    res := analysis with input as {
        "project": {
            "name": "acme-test"
        }
    }

    count(res) == 2
    res.details == "acme-test is a test project that isn't deployed anywhere."
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

# Verify that the suppression of all findings for acme-test takes
# precedence over the camel-jetty9 specific rule.
test_analysis_acmetest_cameljetty9 {
    res := analysis with input as {
        "component": {
            "group": "org.apache.camel",
            "name": "camel-jetty9",
            "version": "2.19.0"
        },
        "project": {
            "name": "acme-test"
        },
        "vulnerability": {
            "vulnId": "CVE-2019-0188"
        }
    }

    count(res) == 2
    res.details == "acme-test is a test project that isn't deployed anywhere."
    res.suppress
}