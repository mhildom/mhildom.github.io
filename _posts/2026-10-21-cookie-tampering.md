---
title: "Cookie Tampering: Plaintext, Hashed, and Base64 Cookies"
date: 2026-10-21 13:00:00 -0400
categories: [Labs, Web Security]
tags: [cookie-tampering, authentication-bypass, privilege-escalation, hash-cracking, base64, web-app, tryhackme]
description: "Flipping an admin flag, cracking a hashed cookie, and forging a base64 one to escalate from user to admin."
---

> Lab work from a TryHackMe web application security module, done against a
> deliberately vulnerable training app. Lab IPs are genericized and room
> answers (including captured flags and the cracked value) are redacted.
> To see where I got this from, and to give it a try yourself, you can go to: [TryHackMe | Authentication Bypass Task 5](https://tryhackme.com/room/authenticationbypass "Visit TryHackMe")
{: .prompt-info }

## TL;DR

Cookies are an everyday part of browsing the web, but what happens when an application is too trusting of the cookies a user provides? By manipulating our client-side cookies, we are able to influence the authentication and authorization process, granting ourselves elevated permissions. In our case, simply changing `admin=false` to `admin=true` grants us full admin access to the site. Sometimes we may need to get creative, as cookies may be encoded or hashed, requiring us to utilize special tooling to raid the cookie jar.

## What cookie tampering is

Cookies can be manipulated as a form of attack. Because they're stored client-side, anything the browser holds is something the user can read and change, so an application that trusts a cookie for an authentication or authorization decision is trusting data the user fully controls. Depending on what the cookie drives, tampering with it can get you unauthenticated access, access to other accounts, or elevated permissions on your own.

How hard that is depends on how the value is stored:

- **Plaintext** cookies make their purpose obvious and are trivial to change.
- **Hashed** values add a layer, but an unsalted hash of a weak value can often be cracked.
- **Encoded** values (commonly Base64) look opaque but aren't protected at all — encoding is not encryption.

Like [SQL injection]({% post_url 2026-10-20-sql-injection %}) and [XSS]({% post_url 2026-10-20-xss %}), cookie tampering is the result of a server being too trusting of a user's input. In this case the cookies passed along with requests are being interpreted with no validation of them.

## Recon: what cookies do we get?

After logging in, the first step is to see what the app sets. The browser dev tools **Storage** tab lists every cookie for the site.

![Dev tools Storage tab showing an admin cookie set to false and a session cookie](/assets/img/posts/thm-cookie-tampering/cookies-storage.png)
_Two cookies: `admin`, set to `false`, and `session`, holding what looks like a hash._

Two things stand out right away: an `admin` cookie sitting at `false` is practically an invitation, and none of the cookies are marked `HttpOnly`, `Secure`, or a restrictive `SameSite`.

- `HttpOnly` would prevent client-side scripts from accessing cookies, but does not stop tampering.
- `Secure` forces the browser to send the cookie over HTTPS, giving confidentiality over the wire, but again does not stop tampering.
- `SameSite` controls whether the cookie is sent on cross-site requests, which helps to mitigate CSRF.

These flags govern how a cookie is transmitted or accessed, but not whether it can actually be trusted. They provide no form of integrity, which is at the root of cookie tampering. While they may not be useful for cookie tampering, they hint at other insecure approaches we could potentially manipulate for other exploits, and are worth flagging here.

## Plaintext cookies: just flip the value

The lab box exposes a `/cookie-test` endpoint. Visiting it before tampering returns `Not Logged In`. The lab points us at a `logged_in` cookie to set to `true` — note that this cookie never appeared in the list above, so the app is trusting a value we can simply invent. We can also flip the `admin` cookie we *did* see.

You can do this in dev tools or with curl. Setting `logged_in=true` with `admin` still `false`:

```bash
curl -H "Cookie: logged_in=true; admin=false" http://MACHINE_IP/cookie-test
```

![curl response reading Logged In As A User](/assets/img/posts/thm-cookie-tampering/curl-user.png)
_The app accepts the invented `logged_in` cookie and treats us as a logged-in user._

Then flipping `admin` to `true`:

```bash
curl -H "Cookie: logged_in=true; admin=true" http://MACHINE_IP/cookie-test
```

![curl response reading Logged In As An Admin, flag redacted](/assets/img/posts/thm-cookie-tampering/curl-admin.png)
_Flipping one word escalates us to admin._

Throughout this I have used a combination of browser-based Dev Tools and the curl command. While they can be used interchangeably in most cases, curl allows for more exact control over the header, and is scriptable to provide automation to these attacks.

## Hashed cookies: cracking the value

Not every value is plaintext. When a cookie holds a hash, you can try to crack it, because hashing is one-way but deterministic: the same input always produces the same output, so you can compare the hash against a precomputed table of known values. [CrackStation](https://crackstation.net) is one such service; local tools work too.

The lab gives an md5 hash to crack:

![CrackStation showing an md5 hash cracked to its plaintext value, result redacted](/assets/img/posts/thm-cookie-tampering/crackstation.png)
_CrackStation matches the md5 hash to its original value (redacted)._

An important distinction to make here in the hash cracking section is the different approaches to hash cracking. 

CrackStation is a lookup table. It is a massive pre-computed dictionary mapping hashes to their plaintext values that you can reference. 

A rainbow table on the other hand is more space-optimized because it doesn't actually store the pre-computed values of each hash, it stores the beginning and end of a chain of Hashing and Reduction functions, making it much more storage friendly, but requires re-computing every time.

Both of those tables however are defeated by using high-entropy values and salting each value, making pre-computation worthless. In our case, the value is small and unsalted, making it essentially free to crack.

## Encoded cookies: base64 decode and forge

Other values are Base64-encoded. This looks opaque but offers no protection — it's encoding, not encryption, and decoding it takes one command:

```bash
echo -n "<ENCODED_VALUE>" | base64 -d
```

Unlike the plain `admin=false` cookie, this part of the room uses a separate cookie whose value is a base64-encoded JSON object. By decoding it, you can see the fields within and change their values. 

![base64 -d decoding a cookie value to reveal its contents, flag redacted](/assets/img/posts/thm-cookie-tampering/base64-decode.png)
_Decoding the value reveals its plaintext (redacted)._

Because we can decode it, we can also build our own and re-encode it. Encoding a forged payload that sets `admin` to `true`:

```bash
echo -n '{"id":1,"admin":true}' | base64
```

![base64 encoding a forged JSON payload setting admin to true](/assets/img/posts/thm-cookie-tampering/base64-encode.png)
_Encoding our own payload to drop back into the cookie._

Because encoding something does not actually ensure its integrity, it does not prevent cookie tampering and lets us carry out the same attack as the plaintext case above.


## How to detect it

Because at its core cookie tampering is an issue with trusting user input, we have to detect it in somewhat similar ways. It relies on the server interpreting cookies without validating them, so we should look to the server and the surrounding network infrastructure for clues.

- **State mismatch**. The cookie the server received from a user claims something different than what the server is expecting. The user cookie claims `admin=true` but the server is expecting them to be a standard user. Confirming cookies against the server's authoritative record and exposing contradictions indicates cookies have been manipulated.
- **Identifying failed integrity**. Monitoring for signature-verification failures will alert us to cookie manipulation. If an alert occurs, we know that the cookies the server issued and signed no longer match the cookies it received back from the user.
- **Privilege anomalies in logs.** Watch the application's audit logs for an account that suddenly performs admin-only actions or whose privilege level changes without a legitimate reason. This won't tell you *how* they got there — only that an account is operating above its normal permissions — but combined with the signals above, a user acting as an admin they were never granted is a strong hint their cookie was tampered with.

## How to fix it

Similar to the other attacks I have mentioned throughout this write-up, cookie tampering is only a possibility when the server is too trusting of user input, so the main fix is to correct that.

- **Keep authorization server-side.** To fix this at its core, the server should never store an authorization decision in a cookie. In this lab, the only reason we got in was that the cookies *were* the authentication — they decided whether we were logged in, and logged in as an admin, with no credentials involved. Instead, the cookie should hold only an opaque session ID, and the server should look up the user's real role from its own session store. With no `admin` value in the cookie, there's nothing to manipulate.

A few other defensive layers can help prevent cookie tampering:

- **Cookie signing**. To ensure integrity, the server can implement cookie signing since unsigned cookies have no way of detecting changes. The server signs outgoing cookies with a secret key only it knows (an HMAC), and then recomputes the signature and verifies it still matches the cookie's value. If it detects that change, it denies the action and logs the bad request. 
- **State validation**. The server should also implement authoritative controls, comparing the cookie sent in the request against its known state in an authoritative record only accessible by the server itself. If there is a mismatch between the request and the known state, it is rejected and logged.


## Takeaways

Most of these attacks require the server or application to be too trusting of input, and they just manipulate that trust in different ways based on context. 
- In SQLi, it's too trusting of input that is directly fed into a database. 
- With XSS, it's too trusting of input in the URL or form fields and actually embeds them somehow into the web code itself. 
- With cookie manipulation, it's the server trusting the cookies sent with each request made by a user.

Each case is the same attack methodology, just different forms of input and slightly different payloads.

That got me thinking over my lunch one day. I learned these in isolation to each other, independent labs meant to teach bare concepts. Is it possible to combine these attacks? 

*What if a cookie contains some value that is directly consumed by a database query?*

While engineers may protect against obvious entry points, such as login fields and comment sections, anywhere intended to be modified by the user, what happens if we use cookie modification as an envelope for our SQLi?

I would have to imagine that this would be a very hard attack to detect without something like a WAF, since cookies reside in the header of a request, though I have never implemented this, and it remains purely speculative at this point. It would slip past traditional access logs since they do not display the contents of the header, in the same way SQLi via POST is harder to detect than GET. 
