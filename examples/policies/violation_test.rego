package dtapac.violation

# Verify that an empty object is returned when no rule matches the given input.
test_analysis_nomatch {
    res := analysis with input as {}
    count(res) == 0
}
