# AI Phishing Detector

A Python tool that reads an email (`.eml` file) and scores how likely it is
to be phishing — then explains every signal it found, so the verdict can be
checked instead of just trusted. Built with the Python standard library only:
no installs, no API keys, no data leaves the machine.

> **Lab project, honestly labelled.** This is hands-on lab work, not job
> experience and not a production email filter. All sample emails are
> synthetic and clearly marked as such. The text classifier is trained on a
> small synthetic corpus bundled in the script — it demonstrates the
> technique, it is not trained on real mail.

## What it checks

| Area | Signals |
|------|---------|
| **Headers** | From vs Reply-To / Return-Path mismatch; display-name spoofing (a brand name shown with a different domain); SPF / DKIM / DMARC results; missing Date / Message-ID |
| **Sender & link domains** | Lookalike / typosquat domains (edit-distance check against known brands, e.g. `paypa1-secure.com`, `micros0ft365-alert.com`); brand-name-in-domain tricks; suspicious TLDs (`.xyz`, `.tk`, `.top`…) |
| **Links** | URL shorteners, IP-address hosts, the `@` userinfo trick, punycode (`xn--`), plain-http links, link text showing a different URL from the real destination, deep subdomain chains |
| **Content** | Urgency / threat language, credential-harvest phrases, generic greetings ("Dear Customer"), risky attachments (`.exe`, `.scr`, `.zip`…) and double extensions |
| **Text classifier** | A Naive Bayes model written from scratch (no libraries) and trained on the synthetic corpus in the script. Its phishing probability adds up to 18 points — one input among many, never the whole verdict |

## Verdict bands

| Score | Verdict |
|-------|---------|
| 0–29 | Legitimate |
| 30–59 | Suspicious |
| 60+ | Likely Phishing |

## How to run it

```bash
# analyse one email
python3 phishing_detector.py samples/sample1_phishing_paypal.eml

# analyse every sample
python3 phishing_detector.py samples/

# machine-readable output
python3 phishing_detector.py samples/ --json
```

Requires Python 3.8+ and nothing else.

## Tested results (real output, 2026-11-16)

Ran against the 5 synthetic samples in `samples/`:

| Sample | What it is | Score | Verdict |
|--------|-----------|-------|---------|
| `sample1_phishing_paypal.eml` | Fake "PayPal account limited" — lookalike domain, Reply-To mismatch, urgency, credential request | 109 | **Likely Phishing** |
| `sample2_phishing_invoice.eml` | Fake overdue invoice — `.xyz` sender, URL shortener, `.zip` attachment, final-notice threats | 89 | **Likely Phishing** |
| `sample3_phishing_microsoft.eml` | Fake "password expires today" — display-name spoof, SPF/DKIM/DMARC all fail, lookalike domain | 109 | **Likely Phishing** |
| `sample4_legit_newsletter.eml` | Real-style newsletter — matching domains, SPF/DKIM/DMARC pass, no urgency | 0 | **Legitimate** |
| `sample5_legit_order.eml` | Real-style order confirmation — matching domains, auth passes, no pressure language | 0 | **Legitimate** |

Summary: 5 emails — Likely Phishing: 3, Legitimate: 2. No false positives
and no misses on the sample set.

Example signal list (sample 1, fake PayPal):

```
+12  Reply-To domain (paypal-helpdesk.net) does not match From domain
+15  Display name shows 'Paypal' but the sender domain is paypa1-secure.com
+ 8  No Authentication-Results header — SPF/DKIM/DMARC status unknown
+20  Sender domain is a lookalike: paypa1-secure.com imitates paypal.com
+ 5  Plain-http link (not https)
+18  Urgency / threat language (5 patterns matched)
+ 8  Asks for credentials / login (1 pattern matched)
+ 5  Generic greeting ('Dear Customer') instead of a name
+18  Text classifier: 100% phishing-like (trained on synthetic lab data)
```

## Files

- `phishing_detector.py` — the tool (single file, standard library only)
- `samples/` — 5 synthetic `.eml` files: 3 phishing, 2 legitimate

## Limitations (stated plainly)

- The classifier is trained on 20 short synthetic sentences. It shows the
  method works end to end; it is not accurate enough for real mail.
- The tool does not check links against live threat intelligence, URL
  reputation feeds, or attachment sandboxes — a real SOC tool would.
- A well-made phish with passing SPF/DKIM/DMARC and a clean-looking domain
  can still score low. The verdict is a lab result, not a guarantee.

## What this demonstrates

Email header forensics (SPF/DKIM/DMARC), domain analysis and typosquat
detection, URL analysis, pattern-based content triage, and a from-scratch
Naive Bayes text classifier — the same kinds of checks a SOC analyst runs
when triaging a reported phishing email, with the reasoning shown for each
finding.
