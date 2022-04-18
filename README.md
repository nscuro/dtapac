# dtapac

[![Build Status](https://github.com/nscuro/dtapac/actions/workflows/ci.yml/badge.svg)](https://github.com/nscuro/dtapac/actions/workflows/ci.yml)
[![Latest GitHub release](https://img.shields.io/github/v/release/nscuro/dtapac?sort=semver)](https://github.com/nscuro/dtapac/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

*Audit Dependency-Track findings and policy violations (soon™️) via policy as code*

## Introduction

### Use Cases

#### Duplicate Vulnerabilities

```rego
analysis = res {
	duplicatedVuln := {
		"6795ec44-f810-47aa-a22e-5d817e52cbdc": "GHSA-36p3-wjmg-h94x",
	}[vuln.vulnId]

	res := {
		"state": "FALSE_POSITIVE",
		"comment": sprintf("Duplicate of %s.", [duplicatedVuln]),
		"suppress": true,
	}
}
```

#### False Positives

```rego
analysis = res {
    component.name == "acme-lib"
    vulnerability.vulnId == "CVE-20XX-XXXXX"
  
    res := {
      "state": "FALSE_POSITIVE"
      "suppress": true,
    }
}
```

## Usage

```
USAGE
  dtapac [FLAGS...]

Audit Dependency-Track findings via policy as code.

FLAGS
  -audit-workers 2        Number of workers to perform auditing
  -config ...             Path to config file
  -dtrack-apikey ...      Dependency-Track API key
  -dtrack-url ...         Dependency-Track API server URL
  -host 0.0.0.0           Host to listen on
  -log-level info         Log level
  -opa-bundle ...         OPA bundle to listen for status updates for
  -opa-url ...            OPA URL
  -policy-package dtapac  OPA policy package
  -port 8080              Port to listen on

```

## Deployment

### Docker Compose

See [`docker-compose.yml`](./docker-compose.yml).

## Policy Management

It's recommended that you:

* Maintain your policy in a Git repository
* Write [tests](https://www.openpolicyagent.org/docs/latest/policy-testing/) for your policy(!)
* Package your policy as [bundle](https://www.openpolicyagent.org/docs/latest/management-bundles/)
  * Always set a `revision` (using the Git commit makes sense here)
  * e.g. `opa build -o mybundle.tar.gz -r $(git rev-parse HEAD) /path/to/policy`
* Host your bundle on a service [compatible](https://www.openpolicyagent.org/docs/latest/management-bundles/#implementations) with OPA's bundle API
* [Configure](https://www.openpolicyagent.org/docs/latest/management-bundles/#bundle-service-api) OPA to pull bundles from that service

## Shortcomings
