package dtapac.finding

import input.component
import input.project
import input.vulnerability

default analysis = {}

analysis = res {
    component.group == "org.apache.camel"
    component.name == "camel-jetty9"
    vulnerability.vulnId = ["CVE-2019-0188"][_]

    res := {
        "state": "FALSE_POSITIVE",
        "comment": "Affects camel-xmljson, but not camel-jetty9.",
        "suppress": true
    }
}

analysis = res {
    component.name == "h2"

    res := {
        "state": "NOT_AFFECTED",
        "justification": "CODE_NOT_REACHABLE",
        "comment": "h2 is only used in unit tests.",
        "suppress": true
    }
}