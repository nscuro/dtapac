package dtapac.finding

test_analysis_nomatch {
    res := analysis with input as {}
    count(res) = 0
}

test_analysis_cameljetty9 {
    res := analysis with input as {
        "component": {
            "group": "org.apache.camel",
            "name": "camel-jetty9",
            "version": "2.19.0"
        },
        "project": {},
        "vulnerability": {
            "vulnId": "CVE-2019-0188"
        }
    }

    count(res) = 3
    res.state = "FALSE_POSITIVE"
    count(res.comment) > 0
    res.suppress
}