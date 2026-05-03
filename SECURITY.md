# Security Policy

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in NoxTLS,
please report it privately.

Do NOT open a public GitHub issue.

Send reports to:

security@argenox.com

Please include:

- Description of the issue
- Affected versions
- Reproduction steps or proof of concept (if available)
- Impact assessment (if known)

We will acknowledge receipt within 2 business days.

## Disclosure Policy

Argenox follows a coordinated disclosure process:

1. Acknowledge report
2. Validate vulnerability
3. Develop fix
4. Notify affected commercial customers
5. Publish advisory after patch availability

We request that researchers allow reasonable time for remediation
before public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x LTS | Yes |
| 0.x     | No |

## Security Updates

Security fixes are provided:

- To commercial customers immediately
- To GPL community releases after coordinated disclosure

## Encryption and Key Handling

All cryptographic operations are designed for embedded
constrained environments. Configuration must be reviewed
carefully for production deployments.
