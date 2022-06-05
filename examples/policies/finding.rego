package dtapac.finding

default analysis = {}

analysis = res {
    input.project.name == "acme-test"

    res := {
        "comment": sprintf("%s is a test project that isn't deployed anywhere.", [input.project.name]),
        "suppress": true,
    }
} else = res {
    input.component.group == "org.apache.camel" 
    input.component.name == "camel-jetty9"
    input.vulnerability.vulnId = ["CVE-2019-0188"][_]

    res := {
        "state": "FALSE_POSITIVE",
        "details": "Affects camel-xmljson, but not camel-jetty9.",
        "suppress": true
    }
} else = res {
    input.project.name == "acme-app"
    input.component.group == "com.h2database"
    input.component.name == "h2"

    res := {
        "state": "NOT_AFFECTED",
        "justification": "CODE_NOT_REACHABLE",
        "details": "h2 is only used in unit tests.",
        "suppress": true
    }
}