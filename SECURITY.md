# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in the Verifiable Intent specification or
SDK, please email <security@verifiableintent.dev>.

You can also use
[GitHub's private vulnerability reporting](https://github.com/agent-intent/verifiable-intent/security/advisories/new)
to submit a report directly through GitHub.

## What to Include

When reporting a vulnerability, please include:

- A description of the issue and its potential impact
- Steps to reproduce or a proof of concept
- The component affected (spec, SDK, examples)
- Any suggested mitigations

## Response Timeline

The project maintainers will acknowledge your report within **10 working days**.

We use GitHub Security Advisories to privately discuss and fix confirmed issues
before public disclosure. We will coordinate disclosure timing with you.

## Scope

This policy covers:

- **Specification vulnerabilities**: Flaws in the credential format, delegation
  model, or constraint system that could allow unauthorized actions
- **SDK implementation bugs**: Cryptographic errors, verification bypasses, or
  fail-open conditions in the Python SDK
- **Example code**: Security issues in example scripts that could mislead
  implementers

Out of scope: vulnerabilities in third-party dependencies (report those to the
respective maintainers), and transport-layer security (VI does not define a
transport protocol).
