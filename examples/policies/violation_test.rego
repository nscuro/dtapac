package dtapac.violation

# Verify that an empty object is returned when no rule matches the given input.
test_analysis_nomatch {
    res := analysis with input as {}
    count(res) == 0
}

# Verify that license policy violations are suppressed for 3rd party projects.
test_thirdparty_license_violations {
    res := analysis with input as {
        "project": {
            "tags": [
                {
                    "name": "thirdparty"
                }
            ]
        },
        "policyViolation": {
            "type": "LICENSE"
        }
    }

    count(res) == 3
    res.state == "APPROVED"
    count(res.comment) > 0
    res.suppress
}