---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

Hi, I'm Matt Hildom, an IT professional moving into cybersecurity.

## Background

For nearly five years I've been an Application Systems Analyst at a large public university, supporting enterprise systems that thousands of students and staff rely on.

**Emergency rebuild of a HIPAA-regulated application.** When an actively exploited vulnerability started targeting legacy instances of a research platform we ran on RHEL 7, I did the majority of the work to rebuild it on hardened RHEL 9, with a test server in testers' hands within 10 days and production live 5 days after test sign-off:

- Built new RHEL 9 test and production servers, plus a dedicated database server for production data
- Configured the full LAMP stack to meet HIPAA requirements
- Closed security gaps in the legacy setup: replaced a non-standard webroot, moved local files to a separate location, and split the database onto its own server
- Migrated legacy Shibboleth-based OIDC to Microsoft Entra ID, using claims mapping so every existing user kept the same login and data
- Customized TLS configuration and the certificate chain so both the Android and iOS mobile apps could connect
- Rewrote the vendor's SQL migration scripts and troubleshot database connectivity to move data to the new version
- Coordinated across Networking, Database, Systems Operations, Security, and the application's IT team and student staff
- Wrote a ~30-page build runbook that we followed step by step to finish an 8-hour emergency cutover on schedule

Other work includes standing up a Windows Server / Apache environment for an address validation service and building a SOAP API integration between it and PeopleSoft forms.

Before that, I worked on-site in the election technology field, supporting systems at county election centers. That meant passing background checks across roughly two dozen counties and working in environments where security, chain of custody, and getting it right the first time weren't optional.

Outside of work, I help small businesses with infrastructure projects like server migrations to Hyper-V, Remote Desktop Gateway setups, and certificate automation.

## Where I'm headed

**Focus right now:** vulnerability management and security operations, where my background in running and patching real systems carries over directly.

**Building toward:** penetration testing and malware analysis. This blog is where I document the labs I build along the way.

## Certifications

<div data-iframe-width="150" data-iframe-height="270" data-share-badge-id="3ceb46e5-c3bc-4fba-a3a4-dae2ec850cf8" data-share-badge-host="https://www.credly.com"></div><script type="text/javascript" async src="//cdn.credly.com/assets/utilities/embed.js"></script>

- **CompTIA Security+**, October 2026

## What you'll find here

Hands-on lab writeups covering vulnerability scanning and remediation, detection engineering, malware analysis, and offensive security practice. Each one covers what I built, what broke, and what I'd do differently.

## Get in touch

I'm currently open to cybersecurity roles. Feel free to connect on [LinkedIn](https://www.linkedin.com/in/YOUR-PROFILE) or check out my work on [GitHub](https://github.com/mhildom).
