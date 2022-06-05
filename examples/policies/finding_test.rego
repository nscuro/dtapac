package dtapac.finding

test_analysis_nomatch {
    res := analysis with input as {}
    count(res) == 0
}

test_analysis_acmetest {
    res := analysis with input as {
        "project": {
            "name": "acme-test"
        }
    }

    count(res) == 2
    res.comment == "acme-test is a test project that isn't deployed anywhere."
    res.suppress
}

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
    res.comment == "acme-test is a test project that isn't deployed anywhere."
    res.suppress
}