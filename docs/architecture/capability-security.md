# Capability and Authority Security

## Core distinction

A capability in the cognitive sense is the ability to solve a class of problems. Authority is permission to affect a protected resource. Variaxiom keeps them separate.

## Lease model

A capability lease is an authenticated object containing:

```text
lease id
subject identity
allowed operation(s)
resource selector
input/output data class
not-before / expiry
call and cost budget
rate limit
secret reference (brokered, not revealed)
parent grant
revocation status
audit obligations
```

Example:

```text
POST only to api.example.com/v1/tickets
maximum 20 calls
expires in 10 minutes
secret may be used by the HTTP broker but not returned to the model
responses classified internal
```

This is preferable to exposing `API_KEY` plus unrestricted `curl`.

## Non-transitivity

A parent worker cannot delegate more than it owns. Child authority is the intersection of:

- parent-delegable scope;
- task contract;
- population policy;
- explicit external grant.

## Taint and data flow

Inputs carry source and trust labels. Untrusted external content cannot become an instruction merely by containing imperative text. High-impact effects require trusted intent and, where policy demands, confirmation or independent review.

The initial implementation will use explicit metadata and broker mediation. Whole-language information-flow control is future research.

## Secrets

- Store secrets outside model-readable files and prompts.
- Use brokered operations or short-lived credentials.
- Scope credentials by audience, method, resource, budget, and time.
- Do not copy parent secrets into child environments.
- Scrub logs and artifacts by default.
- Revoke on worker termination.

## Shell policy

Raw shell is a high-level super-capability. It is acceptable only inside a disposable environment whose filesystem, network, process, secret, device, and resource boundaries are independently enforced. Removing a file-edit tool does not make shell read-only.

## Authority-change protocol

A candidate requesting new authority must include a separately signed grant. Functional success cannot satisfy that requirement. The gate checks exact set difference between baseline and requested capabilities.
