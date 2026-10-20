---
title: "Emergency Rebuild: Moving a HIPAA Research Platform Off RHEL 7 in Under Three Weeks"
date: 2026-10-20 15:00:00 -0400
categories: [Case Studies, Vulnerability Response]
tags: [rhel, hardening, hipaa, entra-id, oidc, tls, incident-response, linux]
---

> Details about the organization, hostnames, network layout, and vendor-specific configuration have been left out or generalized on purpose.
{: .prompt-info }

## TL;DR

A research data platform we ran on a single RHEL 7 server was months out on our migration list. Then the vendor warned us that a threat actor was actively exploiting legacy, internet-exposed instances of it. We locked it down with compensating controls, confirmed with our security team that we hadn't been hit, and then rebuilt the whole thing on hardened RHEL 9 under emergency change management:

- **Test server** live in 1 week, in testers' hands 3 days later
- **Production** live 5 days after test sign-off
- **Cutover** finished inside an 8-hour window, driven by a ~30-page runbook

## Background

The platform is a web-based survey and data-capture system used for research, some of it involving protected health information, so it falls under HIPAA. It ran on a LAMP stack, and everything lived on one RHEL 7 box: web server, uploaded files, and database.

It was stable, it sat behind single sign-on, and we believed it was secure. With RHEL 7 at end of life, the migration was on our roadmap, but other priorities kept pushing it back. I had started the planning before I was pulled onto an unrelated emergency.

## The trigger

The vendor notified customers that a known threat actor was exploiting a vulnerability in legacy versions of the platform, specifically going after instances reachable from the internet. Our version was affected, and RHEL 7 couldn't support the version that fixed it.

## Containment first

Before rebuilding anything, we reduced exposure:

- Moved the server to a new, more restricted subnet
- Required on-campus network access to reach the application at all, on top of the SSO it already used
- Worked with the security team to check our instance for signs of compromise. **None were found.**

That closed the immediate risk but created a new problem. This is a survey platform, and survey participants are mostly outside the network. With public access blocked, the application was close to useless for the people who depended on it. The compensating control bought us time, not a solution, so the migration became an emergency.

## Redesigning instead of copying

Rather than reproduce the old single-server setup, I used the rebuild to fix its architecture:

- **Separate test and production environments** instead of one server doing everything
- **A dedicated database server** for production data
- **Hardened RHEL 9** builds following our standard baseline, with every deviation documented and justified
- **Moved the web root** from a non-standard location to a standard, properly permissioned one
- **Moved user-uploaded files** out of the web server's directory tree

I did most of the build and documentation myself while coordinating Networking, Database, Systems Operations, Security, the application team, and the student staff who support it.

## Problem 1: Mobile apps and the certificate chain

The platform has companion mobile apps for offline data collection. On the new server, they wouldn't connect, and **Android and iOS failed in different ways**.

The certificate chain needed to change, but no single chain configuration satisfied both platforms' trust behavior out of the box. Getting both working meant customizing the server's TLS configuration as well as the chain it presented.

<!-- TODO: add the specific symptoms per platform (error messages, what the logs showed), how you diagnosed it (openssl s_client, SSL Labs, app logs), and what the final change was. This is the most technical part of the post, so a sanitized config snippet or terminal output would make it much stronger. -->

**Lesson:** test TLS changes against every client you support, not just a browser. Mobile platforms handle chain building and trust differently.

## Problem 2: The authentication migration that wasn't what it looked like

The old server used OIDC through a third-party library that bridged to a Shibboleth-style configuration. Because of that bridge, I spent time chasing the Shibboleth config before finding the actual OIDC settings in the system files.

The real issue was the **user identifier**:

- The old setup identified users by **`sAMAccountName`**.
- **Microsoft Entra ID's v2.0 endpoint** doesn't issue that claim by default. It gives you UPN or email.
- So users logging into the new server came in under a different identifier. Their existing accounts were orphaned, and each login created a new, empty profile.

I had never worked in Entra before this. The fix:

1. Exposed **`onPremisesSamAccountName`** as a claim
2. Updated the **app registration manifest** to accept mapped claims
3. Applied a **custom claims mapping policy** so the token carried the identifier the application expected
4. Reconfigured the platform's authentication to read the new claim

After that, every user signed in to the same account and data they had before.

<!-- TODO: add a screenshot (redacted) of the claims mapping or the token claims before and after. -->

**Lesson:** in any identity migration, find out which attribute the application uses as the unique user key *before* switching providers.

## Data migration

The vendor's SQL migration scripts didn't work as-is for our move to a separate database server and newer version. I rewrote the parts that failed and worked through connectivity issues between the application and the new database host.

## Cutover

We went through **emergency change management** with an 8-hour production cutover window. I had rehearsed and narrowed my portion of the work down to specific 15-minute blocks.

The runbook was about **30 pages** with screenshots and terminal output for every step of the build, and we followed it line by line during cutover. My portion went exactly to plan, which gave us the slack we needed when testing ran longer than expected. We finished on time.

## Documentation left behind

- The full build runbook
- Support guides for each integration: Entra ID, Google authentication, SMS, and the certificate process
- A list of every deviation from our hardening standard, with justification
- A network map of each server's identity, role, and responsibilities

## What I'd do differently

- **Treat "stable and behind SSO" as a risk, not a reason to wait.** An end-of-life OS under an internet-facing app holding regulated data should have been higher on the list. The exploit only made that visible.
- **Map identity attributes early.** Most of the auth time went to discovering the `sAMAccountName` dependency. That's a one-hour check up front.
- **Test with every client type from day one**, including the mobile apps, not just the web interface.

## Takeaways

The work that made this succeed wasn't any single fix. It was containing the risk first, using the emergency to correct the architecture instead of copying it, and documenting thoroughly enough that the cutover was routine.
