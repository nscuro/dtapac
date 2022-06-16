# dtapac

[![Build Status](https://github.com/nscuro/dtapac/actions/workflows/ci.yml/badge.svg)](https://github.com/nscuro/dtapac/actions/workflows/ci.yml)
[![Latest GitHub release](https://img.shields.io/github/v/release/nscuro/dtapac?sort=semver)](https://github.com/nscuro/dtapac/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)

*Audit Dependency-Track findings and policy violations via policy as code*

> Consider this project to be a proof-of-concept. It is not very sophisticated, but it gets the job done.
> Try it in a test environment first. **Do not skip this step, do not run it in production without prior testing**!

## Introduction

[Dependency-Track](https://dependencytrack.org/) offers a fairly sophisticated auditing workflow for vulnerabilities 
and policy violations.

I often found myself wanting a mechanism that lets me make more generalized audit decisions that would affect
multiple (and sometimes even *all*) projects in my portfolio. While the most common use case for something like this
is definitely suppressing false positives, there are times when other audit actions are desirable as well.
A [suppression file](https://jeremylong.github.io/DependencyCheck/general/suppression.html) as seen in projects like 
[Dependency-Check](https://jeremylong.github.io/DependencyCheck/) simply won't cut it.

I've written a fair share of tools that provide the desired functionality based on some kind of configuration file 
(mostly YAML), but I quickly came to the realization that configuration files are too limiting for my needs. 
Not only are they not a good fit for dynamic decisions, they are also a pain to test.

It turns out that you can have your cake and eat it too using *policy as code*. The most popular implementation of PaC 
probably being [Open Policy Agent](https://www.openpolicyagent.org/) (OPA). 

Think of *dtapac* as a bridge between Dependency-Track and OPA.

> Note that *dtapac* as it stands now is *not* intended for performing all auditing through it. 
> Don't use it for decisions that are project-specific. Use it for decisions that are likely to affects larger
> parts of your portfolio. A few sample [use cases](#use-cases) are listed at the bottom of this document.

## How it works

### Ad-hoc auditing through notifications

The main way that *dtapac* uses to integrate with Dependency-Track is by consuming 
[notifications](https://docs.dependencytrack.org/integrations/notifications/). When receiving a `NEW_VULNERABILITY` or 
`POLICY_VIOLATION` notification, *dtapac* will immediately query OPA for an analysis decision. 

```mermaid
sequenceDiagram
    autonumber
    actor Client
    Client->>Dependency-Track: Upload BOM
    Dependency-Track->>Dependency-Track: Analyze BOM
    alt New Vulnerability identified
        Dependency-Track->>dtapac: NEW_VULNERABILITY notification
    else Policy Violation identified
        Dependency-Track->>dtapac: POLICY_VIOLATION notification
    end
    dtapac->>OPA: Query analysis decision
    OPA->>OPA: Evaluate policy
    OPA->>dtapac: Analysis decision
    dtapac->>Dependency-Track: Query existing analysis
    Dependency-Track->>dtapac: Analysis
    dtapac->>dtapac: Compare analyses
    opt Analysis has changed
        dtapac->>Dependency-Track: Update analysis
    end
```

*dtapac* will only submit the resulting analysis if it differs from what's already recorded in Dependency-Track. 
This ensures that the audit trail won't be cluttered with redundant information, even if *dtapac* receives multiple 
notifications for the same finding or policy violation.

### Portfolio auditing on policy change

If configured, *dtapac* can listen for [status updates](https://www.openpolicyagent.org/docs/latest/management-status/) from OPA. 
*dtapac* will keep track of the revision of the policy bundle, and trigger a portfolio-wide analysis if the revision changed.

```mermaid
sequenceDiagram
    autonumber
    loop Periodically
        OPA->>Nginx: Pull Bundle
        Nginx->>OPA: archive
    end
    loop Periodically
        OPA->>dtapac: Status
        dtapac->>dtapac: Compare reported bundle revision with last-known
        opt Bundle revision changed
            dtapac->>Dependency-Track: Fetch all projects
            Dependency-Track->>dtapac: Projects
            loop For each project
                dtapac->>Dependency-Track: Fetch all findings & policy violations
                Dependency-Track->>dtapac: Findings & policy violations
                loop For each finding & policy violation
                    dtapac->>OPA: Query analysis decision
                    OPA->>OPA: Evaluate policy
                    OPA->>dtapac: Analysis decision
                    dtapac->>Dependency-Track: Query existing analysis
                    Dependency-Track->>dtapac: Analysis
                    dtapac->>dtapac: Compare analyses
                    opt Analysis has changed
                        dtapac->>Dependency-Track: Update analysis
                    end
                end
            end
        end
    end
```

This makes it possible to have new policies applied to the entire portfolio shortly after publishing them, without the
need to restart any service or edit files on any server.

### Shortcomings

Some limitations of *dtapac* that you should be aware of before using it:

* **No retries**. If an analysis decision could not be submitted to Dependency-Track for any reason, it won't be retried.
* **No persistence**. If you stop *dtapac* while it's still processing something, that something is gone.
* **No access control**. *dtapac* trusts that whatever is inside the notifications it receives is valid. Notifications can be forged. Deploy *dtapac* to an internal network or use a service mesh.

## Usage

```
USAGE
  dtapac [FLAGS...]

Audit Dependency-Track findings and policy violations via policy as code.

FLAGS
  -config ...                 Path to config file
  -dry-run=false              Only log analyses but don't apply them
  -dtrack-apikey ...          Dependency-Track API key
  -dtrack-url ...             Dependency-Track API server URL
  -finding-policy-path ...    Policy path for finding analysis
  -host 0.0.0.0               Host to listen on
  -opa-url ...                Open Policy Agent URL
  -port 8080                  Port to listen on
  -violation-policy-path ...  Policy path for violation analysis
  -watch-bundle ...           OPA bundle to watch
```

## Deployment

### Docker Compose

See [`docker-compose.yml`](./docker-compose.yml).

## Writing Policies

### Overview

Please take a moment to read a little about [OPA](https://www.openpolicyagent.org/docs/latest/) and its 
[policy language Rego](https://www.openpolicyagent.org/docs/latest/policy-language/).

Policies for *dtapac* must adhere to the following guidelines:

1. Result MUST be named `analysis`
2. Result MUST be an object
3. There MUST be exactly one result named `analysis`
   * In case of conflicting rules, use [`else`](https://www.openpolicyagent.org/docs/latest/faq/#statement-order)
4. If no rule is matched, an empty object MUST be returned
   * Use `default analysis = {}` for this

Have a look at the example policies at [`./examples/policies`](./examples/policies) if you need inspiration.

### Inputs

#### Finding

```json
{
  "component": {},
  "project": {},
  "vulnerability": {}
}
```

* [`component`](https://pkg.go.dev/github.com/nscuro/dtrack-client#Component)
* [`project`](https://pkg.go.dev/github.com/nscuro/dtrack-client#Project)
* [`vulnerability`](https://pkg.go.dev/github.com/nscuro/dtrack-client#Vulnerability)

##### Example

```json
{
  "component": {
    "uuid": "508f602f-9fd9-40b7-9330-b06e97b1560f",
    "name": "acme-lib",
    "version": "1.0.0"
  },
  "project": {
    "uuid": "0197ba77-1ab9-46a4-8130-20aa96158032",
    "name": "acme-app",
    "version": "LATEST"
  },
  "vulnerability": {
    "uuid": "03e377f5-d78e-4851-89a2-e659e9ac8439",
    "vulnId": "CVE-XXXX-XXXX",
    "source": "NVD"
  }
}
```

#### Violation

```json
{
  "component": {},
  "project": {},
  "policyViolation": {}
}
```

* [`component`](https://pkg.go.dev/github.com/nscuro/dtrack-client#Component)
* [`project`](https://pkg.go.dev/github.com/nscuro/dtrack-client#Project)
* [`policyViolation`](https://pkg.go.dev/github.com/nscuro/dtrack-client#PolicyViolation)

##### Example

```json
{
  "component": {
    "uuid": "508f602f-9fd9-40b7-9330-b06e97b1560f",
    "name": "acme-lib",
    "version": "1.0.0"
  },
  "policyViolation": {
    "uuid": "9e3330f7-40f6-4121-a5f2-13fc67c4e36d",
    "type": "OPERATIONAL",
    "policyCondition": {
      "uuid": "6159e278-26f1-490c-921b-e6d3adf0ee4b",
      "operator": "MATCHES",
      "subject": "COORDINATES",
      "value": "{\"group\":\"*\",\"name\":\"acme-lib\",\"version\":\"*\"}",
      "policy": {
        "uuid": "8fc2b2fd-2535-4e45-8d73-ffc1cce0ff13",
        "name": "ACME Policy",
        "violationState": "FAIL"
      }
    }
  },
  "project": {
    "uuid": "0197ba77-1ab9-46a4-8130-20aa96158032",
    "name": "acme-app",
    "version": "LATEST"
  }
}
```

### Results

#### Finding

TBD

```json
```

##### Example

TBD

#### Violation

TBD

```json
```

##### Example

TBD

```json
```

## Policy Management

This section is for folks who do not have prior experience with PaC. If you do, and you already have well-established
processes around it, you can skip this section.

It is generally a good idea to keep your policies in their own Git repository. Treat it just like any other code
in your SDLC:

* Write tests
* Create pull requests
* Perform code reviews
* Have a CI pipeline

In your policy CI pipeline, you should:

* [Type check](https://www.openpolicyagent.org/docs/latest/schemas/) your policies
  * You can use the input schemas in [`./examples/schemas`](./examples/policies)
  * If you want to write your own schemas, be aware of the [limitations](https://www.openpolicyagent.org/docs/latest/schemas/#limitations)
* [Test](https://www.openpolicyagent.org/docs/latest/policy-testing/) your policies
* Package your policies into a [bundle](https://www.openpolicyagent.org/docs/latest/management-bundles/#bundle-file-format)
  * Always set a `revision` (using the Git commit makes sense here)
* (Optional) Push the bundle to a server [compatible](https://www.openpolicyagent.org/docs/latest/management-bundles/#implementations) with OPA's bundle API

Check out the [*Policy CI*](./.github/workflows/policy-ci.yml) workflow if you need some inspiration. 

## Use Cases

### Duplicate Vulnerabilities

It can happen that multiple vulnerability sources report separate issues for the same vulnerability.
For example, a CVE and a GitHub advisory may be about the same vulnerability, but both are reported separately.
This skews the risk scoring and increases manual auditing efforts, especially if multiple projects are affected by this.

While Dependency-Track [will support](https://github.com/DependencyTrack/dependency-track/issues/1642) deduplication in 
a future release, for the time being it may be desirable to suppress known duplicates throughout the entire portfolio.

```rego
package dtapac.finding

default analysis = {}

analysis = res {
    duplicatedVuln := {
        "6795ec44-f810-47aa-a22e-5d817e52cbdc": "GHSA-36p3-wjmg-h94x",
    }[input.vulnerability.vulnId]
    
    res := {
        "state": "FALSE_POSITIVE",
        "comment": sprintf("Duplicate of %s.", [duplicatedVuln]),
        "suppress": true,
    }
}
```

### False Positives

Similarly to duplicate vulnerabilities, sometimes a reported vulnerability is just plain a false positive.

```rego
package dtapac.finding

default analysis = {}

analysis = res {
    input.component.group == "com.acme"
    input.component.name == "acme-lib"
    input.vulnerability.vulnId == "CVE-20XX-XXXXX"
  
    res := {
      "state": "FALSE_POSITIVE",
      "details": sprintf("%s does not affect %s", [input.vulnerability.vulnId, input.component.name]),
      "suppress": true,
    }
}
```

### Ignoring of vulnerabilities in test-only dependencies

Depending on how you track risk, you may choose to ignore vulnerabilities affecting components that are exclusively
used in testing. A common example would be embedded databases that frequently have vulnerabilities, but are
never used in a production setting.

```rego
package dtapac.finding

default analysis = {}

analysis = res {
    input.project.name == "acme-app"
    input.component.group == "com.h2database"
    input.component.name == "h2"
    
    res := {
        "state": "NOT_AFFECTED",
        "justification": "CODE_NOT_REACHABLE",
        "details": "h2 is exclusively used for unit tests.",
        "suppress": true,
    }
}
```
