---
title: "SQL Injection: From Union Selects to Blind Time-Based Extraction"
date: 2026-10-20 15:30:00 -0400
categories: [Labs, Web Security]
tags: [sql-injection, sqli, union-based, blind-sqli, web-app, tryhackme]
---

> Lab work from a TryHackMe web application security module, done against a
> deliberately vulnerable training app. Room-specific database names, table
> names, and recovered values are genericized; room answers are left out. 
> To see more where I got this from, and to give it a try yourself, you can go to: [TryHackMe | SQL Injection](https://tryhackme.com/room/sqlinjectionlm "Visit TryHackMe")
{: .prompt-info }

## What SQL injection is

SQL is a common database backend, so SQL injection (SQLi) targets that layer to
do things the application never intended: reading data, altering it, or
destroying it. It happens when user input is placed directly into a query
instead of being safely parameterized.

## Types of SQLi

- **In-band:** the injection and the result appear in the same place — e.g. a
  web page where you inject and read the output right there.
- **Error-based:** the database's error messages are shown in the browser, and
  you lever those messages to pull information back.
- **Union-based:** uses the `UNION` operator with `SELECT` to append attacker-
  controlled results to the legitimate query. Used for bulk extraction.

## In-band / Union-based walkthrough

The first step with a `UNION` injection is working out **how many columns** the
original query returns, because `UNION` requires both halves to have the same
column count. You increase the count until the error goes away:

```sql
1 UNION SELECT 1
1 UNION SELECT 1,2
1 UNION SELECT 1,2,3      -- no error: three columns
```

Once the column count is known, each position becomes a slot you can put a query
into. Walking from the current database outward to the actual data:

```sql
-- current database name
0 UNION SELECT 1,2,database()

-- all tables in that database
0 UNION SELECT 1,2,group_concat(table_name)
  FROM information_schema.tables WHERE table_schema = DATABASE()

-- columns in a table of interest
0 UNION SELECT 1,2,group_concat(column_name)
  FROM information_schema.columns WHERE table_name = '<table>'

-- dump the rows
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>')
  FROM <table>
```

`information_schema`, which you see me using above, is the database's built-in catalog of every schema, table, and column. Three things make it useful here: it's defined in the SQL standard, it's read-only, and it's abstracted from the engine's own internal catalogs.

> Oracle is an exception, it doesn't implement `information_schema` and uses 
> its own data dictionary views, such as (`ALL_TABLES`, etc.) instead. Against Oracle, 
> these specific payloads will not work.
{:.prompt-info}

## Blind SQLi

When the app doesn't show query output or errors, you're working *blind* and
have to infer the answer from the app's behavior.

**Classic authentication bypass.** A login query like:

```sql
SELECT * FROM users WHERE username='%username%' AND password='%password%' LIMIT 1;
```

with a username of `' OR 1=1;--` becomes:

```sql
SELECT * FROM users WHERE username='' AND password='' OR 1=1;
```

The `OR 1=1` makes the WHERE always true and `--` comments out the rest, so the
query returns a row and you're logged in.

**Boolean-based.** The response is effectively true/false (e.g. "username
taken" vs not), and you use that one bit of feedback to confirm whether a
payload condition held. You can probe existence conditions like
`WHERE database() LIKE '%a%'` and narrow down a value through process of
elimination.

**Time-based.** Same idea as boolean, but when there's *no* visible difference
in the response, you make the database pause on a true condition and read the
answer off the response time. You will need to know what the typical response
time is before making a Time-based attack, so pick a value that will stand out
from the normal variation that occurs with web based traffic.

Here is a sql payload that will attempt a very basic Time-based recon, if it
works, you will see a 5 second pause before getting a response:

```sql
admin' UNION SELECT SLEEP(5),2;--
```

A 5-second delay means the condition was true; an instant response means that
either the target is not vulnerable or requires more columns for the UNION, 
because it is expecting more of an input. 
Combined with `LIKE` you can brute force a value one character at a time:

```sql
admin' UNION SELECT SLEEP(5),2 FROM users WHERE username LIKE 'a%';--
```

The above payload will induce that pause we are targeting if any usernames 
from the users table starts with an "a". It might be a good place to start, 
you may be able to find a loose admin account. Keep in mind that this is a 
blind attack, so you wont be able to see the actual username. However you 
can force your way through by changing the value you are comparing against, 
so 'a%' could then be changed to 'ad%'. If you get the pause again, that 
means there is a username that starts with "ad".  

To check you are complete, you can run the payload again without the "%" 
wildcard.

```sql
admin' UNION SELECT SLEEP(5),2 FROM users WHERE username LIKE 'admin';--
```

That will pause if the exact username exists within the users table 
(in this case).

Some of this, when done manually, will be an "art". You generally will try
against common names, default credentials like admin, or OSINT / lists of 
users you may have gathered elsewhere. 

This is often done automatically, as sending multiple, slightly different
payloads is where automation excels. It allows you to run the checks 
while you perform other tasks, and can automate the testing against common 
or custom wordlists. SQLMap exists as a great tool to do this.

## How to detect it

SQL injection leaves different traces depending on where you're looking, so
it helps to think about what each log source can and can't see.

**Web server access logs.** Because GET parameters live in the URL, injection
attempts through them land directly in access logs — telltale keywords like
`OR`, `UNION SELECT`, or `SLEEP` showing up in a query string where they have
no business being, often URL-encoded to slip past a quick glance. The blind
spot is POST requests: standard access logs record the URL but not the request
body, so an injection hidden in form data won't appear here at all. Response
size is still useful, though — a response far larger than normal can indicate
bulk data being exfiltrated.

**Web application firewall (WAF).** This is where POST-based injection gets
caught, since a WAF inspects the request body, not just the URL. A WAF is
also what handles evasion: attackers will attempt to dodge naive keyword 
matching using encoding, case variation (`uNiOn`), and inline comments (`UN/**/ION`), 
so a WAF normalizes and decodes input before matching signatures — something 
a simple log search can't do.

**Database logs.** If query logging is enabled, the injected SQL shows up at the
database itself, where certain signatures almost never appear in legitimate
traffic. In practice, though, full query logging is often turned off in
production due to its performance implications, so you may be leaning on the
access log and WAF more than the database log.

**Application error logs.** A sudden spike in SQL errors or HTTP 500s can be
one of the clearest signs of an error-based injection attempt. The 500 range
is for server-side errors — the server received a valid request but couldn't
complete it — so when malformed injected input breaks a query, the resulting
unhandled database error surfaces as a 500. A burst of them is often the sound
of someone probing.

### Signatures worth watching for

- **String-breakout syntax:** `'`, `"`, `--`, `#`, and their URL-encoded
  equivalents.
- **Database keywords:** `UNION SELECT`, always-true conditions like `1=1`,
  references to `INFORMATION_SCHEMA`, and time-based functions like `SLEEP`
  (MySQL) or `WAITFOR` (SQL Server) when they aren't used legitimately.
- **Oversized responses:** a strong indicator of data exfiltration.
- **Sequential, high-volume probing:** rapid requests from the same IP hitting
  the same parameter with small variations — the signature of an automated or
  blind attack.

## How to fix it

The key remediation for SQLi is implementing **parameterized queries** —
sometimes called **prepared statements**. This is the actual fix.

As we saw above, the injection works by escaping out of a string to execute
our own SQL commands. To prevent that, the user's input can never be allowed
to execute as code — and separating the input from the command itself is
exactly the concept behind parameterized queries.

Conceptually, you send the query structure to the database and compile it
**first**, before it ever receives the user input. The input is then bound in
as **data**, so if someone submits `' OR 1=1;--`, it's treated as a username
literal rather than part of the command. 

This is considered the best fix for SQLi because it ultimately defeats all of
the variants above (UNION, time-based, boolean). It addresses the
root-cause of SQLi, the injection part. If you stop the input from being
executed as code, then no input can "break out" of its intended use.

Beyond that core fix, several layers reduce risk as defense in depth:

- **Input validation.** Always validate input you accept from the user. It
  doesn't prevent SQLi on its own, but it's a useful first layer. Blocklisting
  bad characters helps, but it isn't the fix.
- **Least privilege.** For any database-backed application, the app's database
  user shouldn't be able to read or touch data it never needs. This doesn't
  prevent injection — it reduces the blast radius by limiting what an attacker
  can do with that account.
- **Generic error messages.** Be deliberate about what errors you show users.
  They don't need the details; generalized messages are enough. Dynamic,
  detailed errors hand an attacker the feedback that error-based probing
  depends on.

## Takeaways

The key thing to note is that SQLi depends on the abuse of user input.
Whenever you give the user the ability to interact with a system, you
open yourself to them doing things that they shouldn't. 

As an attacker, we can leverage this to execute code, perform recon
against the database, and otherwise just cause mischief. You may not
always get a direct response, but by using critical thinking can turn
things like timing or error messages into tools that let you map an 
entire database and exfiltrate the data you need.

By adding a separation between the query and user input, you prevent a 
malicious input from the user from executing arbitrary code against the 
database. 
