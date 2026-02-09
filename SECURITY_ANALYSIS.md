# Security Analysis Report

**Project:** Blockchain Services  
**Date:** 2026-02-09  
**Scope:** Dependency posture + CI security controls

## Executive Summary

This document reflects the current project state in the repository and supersedes previous outdated versions of this report.

- Runtime stack is now based on **Spring Boot 4.0.2** and **Java 21**.
- Dependency versions in this report are aligned with `pom.xml`.
- Security scanning in CI/CD is already implemented via GitHub Actions (`security.yml`), including scheduled scans.

## Current Dependency Baseline (`pom.xml`)

| Component | Version in repository | Source |
|-----------|------------------------|--------|
| Spring Boot Parent | `4.0.2` | `pom.xml` |
| Jackson | `2.18.3` | `pom.xml` (`jackson.version`) |
| Netty | `4.2.10.Final` | `pom.xml` (`netty.version`) |
| Web3j | `5.0.2` | `pom.xml` |
| Flyway | `11.20.2` | `pom.xml` (`flyway.version`) |
| Bouncy Castle | `1.83` | `pom.xml` |

## CI Security Controls (`.github/workflows/security.yml`)

Current automated controls:

1. **CodeQL analysis**
   - Triggered on push and pull_request.
   - Weekly scheduled run (Monday 06:00 UTC).
   - Uses `security-extended` and `security-and-quality` query packs.
2. **Dependency Review**
   - Triggered on pull_request.
   - Fails PR on high-severity dependency risks.

This means the previous action item "implement automated security scanning in CI/CD" is already complete.

## Risk Notes

- Dependency risk remains a moving target and must be re-evaluated continuously as advisories are published.
- Web3/Ethereum client dependencies (Web3j + RPC stack) should continue to be monitored closely due to frequent upstream security and compatibility updates.
- Localhost-only controls for wallet/treasury/admin endpoints reduce exposure, but production hardening still depends on correct reverse proxy/network configuration.

## Recommended Ongoing Actions

### Short Term
- Keep Dependabot and GitHub Security Alerts enabled.
- Treat high-severity Dependency Review failures as release blockers.
- Re-run full regression tests after dependency bumps.

### Medium Term
- Periodically review Spring Boot 4.x and Web3j release notes for security/compatibility updates.
- Track Netty upgrade opportunities driven by Web3j compatibility.

### Long Term
- Add periodic threat-model review for authentication + intent authorization flows.
- Complement static analysis with regular dynamic/integration security testing in pre-production.

## Conclusion

Security automation is in place and active in CI.  
The immediate documentation gap was version drift; this report now matches the current codebase and workflows.
