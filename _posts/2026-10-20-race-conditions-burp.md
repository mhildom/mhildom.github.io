---
title: "Race Conditions: Spending Money You Don't Have with Burp Suite"
date: 2026-10-20 14:30:00 -0400
categories: [Labs, Web Security]
tags: [race-conditions, toctou, burp-suite, web-app, tryhackme]
image:
  path: /assets/img/posts/race-conditions/negative-balance.png
  alt: Account balance driven negative by a race condition
---

> Lab work from a TryHackMe web application security module, done in a deliberately vulnerable training environment. Room answers and flags are left out.
> To see more where I got this from, and to give it a try yourself, you can go to: [TryHackMe | Race Conditions Attacks](https://tryhackme.com/room/raceconditionsattacks "Visit TryHackMe")
{: .prompt-info }

## TL;DR

A mobile-carrier style web app checks your balance before allowing a transfer, but nothing stops several transfers from being checked *at the same time*. By sending a batch of identical transfer requests in parallel with Burp Suite's Repeater, every request passed the balance check before any of them updated it, and the account ended up at **-$13.75**.

## What a race condition is

A race condition happens when the outcome of a program depends on the timing of events that the program doesn't control. On the web, it usually shows up when several requests (handled by separate threads or workers) read and modify the same piece of data without coordinating.

The classic form is **TOCTOU: Time of Check to Time of Use**.

Say an account has **$100**:

1. Request A asks to withdraw $60. The app checks the balance: $100, fine.
2. Before A writes the new balance, Request B asks to withdraw $15. The app checks: still $100, fine.
3. A finishes and writes $40.
4. B finishes and writes $85, based on the $100 it saw.

Both withdrawals went through, and the account shows *more* money than it should. The check was correct when it ran; it just wasn't true anymore by the time the result was used.

## Where the gap lives

Web apps are typically split into three tiers:

- **Presentation tier:** the browser (HTML, CSS, JavaScript)
- **Application tier:** server-side logic (Node.js, PHP, Python, ...)
- **Data tier:** the database

A money transfer *looks* like it has two outcomes, sent or not sent. In reality, the request passes through intermediate states: received, checking balance, checking limits, writing the debit, writing the credit. Each of those states exists for a moment, and if two requests can be in the "checking" state at once, the gap between check and use is exploitable.

## Recon: a good request and a bad request

The target was a phone-account dashboard that lets you transfer credit to another number. I logged in with the test account the lab provided and proxied everything through Burp.

![Account dashboard showing a $7.40 balance](/assets/img/posts/race-conditions/dashboard.png){: width="500" }

First, a transfer I couldn't afford ($10,000), to see what failure looks like:

![Transaction declined for insufficient balance](/assets/img/posts/race-conditions/declined.png){: width="300" }

The request is a simple POST with three body parameters:

![Request parameters for the declined transfer](/assets/img/posts/race-conditions/params-declined.png){: width="320" }

Then a $1 transfer that should succeed, for comparison:

![Request parameters for a $1 transfer](/assets/img/posts/race-conditions/params-success.png){: width="320" }

![Response redirecting to transaction-successful](/assets/img/posts/race-conditions/response-success.png){: width="460" }

Having a known-good and known-bad request side by side makes it easy to tell what a "win" looks like in the response before trying anything clever.

## Exploit: parallel requests in Repeater

I sent the successful transfer request to **Repeater**, duplicated it about 20 times, and put all the tabs in a **group**:

![Twenty-one Repeater tabs in one group](/assets/img/posts/race-conditions/repeater-group.png)

Burp gives you a few ways to send a group:

![Burp Repeater group send options](/assets/img/posts/race-conditions/group-send-options.png){: width="320" }

- **Sequence (single connection):** one after another over one connection. Useful for client-side desync testing.
- **Sequence (separate connections):** one after another, opening and closing a connection for each.
- **Parallel (last-byte sync):** sends every request except its final byte, then releases all the final bytes at once, so they arrive at the server as close to simultaneously as possible.

Parallel is the one that matters here. Every request reached the balance check before any of them wrote the new balance, so they all passed:

![Balance showing -$13.75](/assets/img/posts/race-conditions/negative-balance.png){: width="500" }

The account went **negative**, meaning it transferred money it never had. Repeating the race from the other account pushed a balance past the lab's $100 target:

![Account balance at $112.25](/assets/img/posts/race-conditions/final-balance.png){: width="500" }

## A second target: when rapid requests get dropped

The follow-up challenge was a different banking app with a JSON API. Two things stood out:

- Tampering with the `receiver_amount` field directly was rejected, so the server recalculates amounts instead of trusting the client. Good.
- Firing 20 transfers at once "worked" partially, but some requests were dropped, which suggests rate limiting or request throttling.

Throttling doesn't fix a race condition. It just shrinks the window, so fewer requests land inside it. My next idea was to snowball smaller races between three accounts (A → B → C → A), compounding the balance each round instead of relying on one large burst.

## How to detect it

- **Logs:** look for bursts of identical state-changing requests (same session, endpoint, and body) within milliseconds of each other.
- **Data integrity checks:** balances below zero, coupon codes redeemed more times than allowed, or totals that don't reconcile with the transaction ledger are strong signals.
- **Testing:** race conditions rarely show up in normal functional testing because testers send one request at a time. Burp's parallel group send (or Turbo Intruder) should be part of testing any endpoint that spends, redeems, or limits something.

## How to fix it

- **Database transactions with proper isolation:** do the check and the update in one transaction, so they succeed or fail together.
- **Row-level locking:** `SELECT ... FOR UPDATE` (or equivalent) so a second request waits until the first has finished with that balance.
- **Atomic conditional updates:** fold the check into the write, for example:

  ```sql
  UPDATE accounts
  SET balance = balance - :amount
  WHERE id = :id AND balance >= :amount;
  ```

  If zero rows are affected, the transfer fails. There's no gap between check and use because they're the same statement.
- **Idempotency keys** for operations like payments, so a replayed request is recognized and processed only once.
- **Rate limiting** as defense in depth only. It narrows the window but doesn't close it.

## Takeaways

The app's logic was correct for one request at a time, and that's what makes race conditions easy to miss: every individual check passed. The fix belongs in the data layer, by making the check and the update a single atomic operation, not in more validation in front of it.
