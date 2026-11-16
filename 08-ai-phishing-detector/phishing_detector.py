#!/usr/bin/env python3
"""
AI Phishing Detector — hands-on lab project (Project 8).

Analyses a .eml email file and scores how likely it is to be phishing,
explaining every signal it found. Built with the Python standard library
only — no installs, no API keys, no data leaves the machine.

What it checks
--------------
1. Headers: From vs Reply-To / Return-Path mismatch, display-name
   spoofing (a brand name shown with a different domain), and
   SPF / DKIM / DMARC results in Authentication-Results.
2. Links: URL shorteners, IP-address hosts, lookalike / typosquat
   domains, brand-name-in-domain tricks, suspicious TLDs, plain-http
   links, the "@" userinfo trick, punycode, and href text that shows
   a different URL from the real destination.
3. Content: urgency and threat language, credential-harvest phrases,
   generic greetings, and risky attachments (.exe, .scr, .zip, ...).
4. Text classifier: a small Naive Bayes model, written from scratch
   and trained on a synthetic lab corpus bundled in this file, that
   scores the subject + body. It is demonstration-grade — trained on
   synthetic examples, not on real mail — and its score is only one
   input to the final verdict.

Verdict bands (total score):  0–29 Legitimate | 30–59 Suspicious |
60+ Likely Phishing. The verdict is a lab result, not a guarantee.

Usage:
    python3 phishing_detector.py samples/
    python3 phishing_detector.py samples/sample1.eml
    python3 phishing_detector.py samples/ --json

Author: Yankuba Bah — lab project, synthetic sample data only.
"""

import argparse
import json
import math
import re
import sys
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------- config

KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office 365": "microsoft.com",
    "outlook": "outlook.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st", "adf.ly",
}

SUSPICIOUS_TLDS = {
    ".tk", ".xyz", ".top", ".buzz", ".click", ".link", ".zip",
    ".mov", ".su", ".ru", ".cn",
}

RISKY_ATTACHMENTS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".js", ".jar",
    ".zip", ".rar", ".7z", ".iso", ".msi",
}

URGENCY_PATTERNS = [
    r"act (now|immediately)",
    r"within 24 hours",
    r"account will be (closed|suspended|limited)",
    r"urgent(ly)?",
    r"immediate(ly)? action (is )?required",
    r"verify (your|this) (account|identity) (immediately|now|today)",
    r"payment (is )?overdue",
    r"final (notice|warning)",
    r"expires? (today|in \d+ hours?)",
    r"confirm .* (immediately|now|today|within)",
]

CREDENTIAL_PATTERNS = [
    r"confirm your (login|password|credentials)",
    r"enter your (password|login|credentials)",
    r"verify your (password|login|credentials)",
    r"update your (password|payment|billing) (details|information)",
    r"sign in to (restore|verify|confirm|unlock)",
    r"reset your password",
]

# Small synthetic training corpus for the Naive Bayes text classifier.
# These are invented lab examples, NOT real emails.
PHISHING_TRAINING = [
    "your account has been limited verify your identity immediately",
    "password expires today click here to reset it now",
    "unpaid invoice download the attachment to view your bill",
    "suspicious activity detected confirm your login credentials",
    "your package could not be delivered click the link to reschedule",
    "your account will be closed within 24 hours act now",
    "verify your payment information to avoid suspension",
    "you have won a prize claim it now by entering your details",
    "urgent security alert your mailbox is full upgrade now",
    "your bank account is locked sign in to unlock it today",
]

LEGIT_TRAINING = [
    "your order has shipped tracking number inside",
    "thanks for subscribing to our monthly newsletter",
    "your appointment is confirmed for tuesday morning",
    "here is your receipt for your recent purchase",
    "weekly digest of articles you might enjoy reading",
    "meeting notes from yesterday are attached for review",
    "your flight check in is now open",
    "new seasonal blend now available in our stores",
    "your delivery arrives tomorrow between 9am and 12pm",
    "thank you for your feedback we appreciate your support",
]


# ---------------------------------------------------------------- helpers

def levenshtein(a, b):
    """Edit distance between two short strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1,
                           prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def domain_of(addr):
    """Domain part of an email address, lower-cased."""
    if not addr:
        return ""
    addr = addr.strip().lower()
    if "<" in addr:
        addr = addr.split("<", 1)[1].split(">", 1)[0]
    return addr.rsplit("@", 1)[-1].strip()


def registered_domain(host):
    """Best-effort registrable domain (last two labels)."""
    host = host.lower().strip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_ip_literal(host):
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host or ""))


def looks_like_brand_domain(host, brand, real_domain):
    """
    True when a host imitates a brand without being that brand's domain:
    the brand name (or a 1–2 edit variant of it) appears in the host,
    but the host is not the real domain or one of its subdomains.
    """
    host = (host or "").lower().strip(".")
    if not host or host == real_domain or host.endswith("." + real_domain):
        return False
    brand = brand.lower()
    if brand in host:
        return True
    for label in host.split("."):
        # split hyphenated labels too: paypa1-secure -> paypa1, secure
        for token in label.split("-"):
            cleaned = re.sub(r"\d+", "", token)  # micros0ft365 -> microsft
            if cleaned and levenshtein(cleaned, brand.replace(" ", "")) <= 2:
                return True
    return False


# ------------------------------------------------------- Naive Bayes (from scratch)

class NaiveBayes:
    """Multinomial Naive Bayes on word tokens, Laplace smoothing."""

    def __init__(self):
        self.vocab = set()
        self.word_counts = {"phishing": {}, "legit": {}}
        self.class_totals = {"phishing": 0, "legit": 0}
        self.doc_counts = {"phishing": 0, "legit": 0}

    @staticmethod
    def _tokens(text):
        return re.findall(r"[a-z]{3,}", (text or "").lower())

    def train(self, texts, label):
        for text in texts:
            self.doc_counts[label] += 1
            for tok in self._tokens(text):
                self.vocab.add(tok)
                self.word_counts[label][tok] = \
                    self.word_counts[label].get(tok, 0) + 1
                self.class_totals[label] += 1

    def phishing_probability(self, text):
        toks = self._tokens(text)
        if not toks:
            return 0.5
        total_docs = sum(self.doc_counts.values())
        vocab_size = len(self.vocab) or 1
        scores = {}
        for label in ("phishing", "legit"):
            logp = math.log(self.doc_counts[label] / total_docs)
            for tok in toks:
                count = self.word_counts[label].get(tok, 0)
                logp += math.log((count + 1) /
                                 (self.class_totals[label] + vocab_size))
            scores[label] = logp
        # log-sum-exp to turn log scores into a probability
        m = max(scores.values())
        exp_p = math.exp(scores["phishing"] - m)
        exp_l = math.exp(scores["legit"] - m)
        return exp_p / (exp_p + exp_l)


CLASSIFIER = NaiveBayes()
CLASSIFIER.train(PHISHING_TRAINING, "phishing")
CLASSIFIER.train(LEGIT_TRAINING, "legit")


# ------------------------------------------------------------- email reading

def get_body(msg):
    """Plain-text body plus any HTML part (for link extraction)."""
    text_parts, html_parts = [], []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if payload is None:
                continue
            try:
                decoded = payload.decode("utf-8", errors="replace")
            except Exception:
                decoded = ""
            if ctype == "text/plain":
                text_parts.append(decoded)
            elif ctype == "text/html":
                html_parts.append(decoded)
    else:
        try:
            payload = msg.get_payload(decode=True)
            decoded = payload.decode("utf-8", errors="replace") \
                if payload else str(msg.get_payload() or "")
        except Exception:
            decoded = ""
        if msg.get_content_type() == "text/html":
            html_parts.append(decoded)
        else:
            text_parts.append(decoded)
    return "\n".join(text_parts), "\n".join(html_parts)


def get_attachments(msg):
    found = []
    if msg.is_multipart():
        for part in msg.walk():
            name = part.get_filename()
            if name:
                found.append(name)
    return found


def extract_links(text_body, html_body):
    """Return list of (url, display_text_or_None)."""
    links = []
    for url in re.findall(r"https?://[^\s\"'<>]+", text_body):
        links.append((url.rstrip(".,);"), None))
    for href, anchor in re.findall(
            r'href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>',
            html_body, flags=re.IGNORECASE | re.DOTALL):
        anchor_text = re.sub(r"<[^>]+>", "", anchor).strip()
        links.append((href, anchor_text or None))
    # de-duplicate, keep order
    seen, out = set(), []
    for item in links:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


# ------------------------------------------------------------------ analysis

def analyse_file(path):
    with open(path, "rb") as fh:
        msg = BytesParser(policy=policy.default).parse(fh)

    signals = []  # (points, description)

    def add(points, description):
        signals.append((points, description))

    from_hdr = str(msg.get("From", "") or "")
    reply_to = str(msg.get("Reply-To", "") or "")
    return_path = str(msg.get("Return-Path", "") or "")
    subject = str(msg.get("Subject", "") or "")
    auth = str(msg.get("Authentication-Results", "") or "")
    from_domain = domain_of(from_hdr)
    text_body, html_body = get_body(msg)
    full_text = subject + "\n" + text_body

    # ---- headers -----------------------------------------------------
    if reply_to and domain_of(reply_to) != from_domain:
        add(12, f"Reply-To domain ({domain_of(reply_to)}) does not match "
                 f"From domain ({from_domain})")
    if return_path and domain_of(return_path) != from_domain:
        add(8, f"Return-Path domain ({domain_of(return_path)}) does not "
                f"match From domain ({from_domain})")

    # display-name spoofing: brand name shown, different domain behind it
    display = from_hdr.split("<", 1)[0].strip().strip('"').lower()
    for brand, real in KNOWN_BRANDS.items():
        if brand in display and from_domain not in (real, "localhost"):
            if not from_domain.endswith("." + real):
                add(15, f"Display name shows '{brand.title()}' but the "
                         f"sender domain is {from_domain}, not {real}")
                break

    if not auth:
        add(8, "No Authentication-Results header — SPF/DKIM/DMARC "
                "status unknown")
    else:
        for mech in ("spf", "dkim", "dmarc"):
            m = re.search(rf"{mech}=(\w+)", auth, re.IGNORECASE)
            if m and m.group(1).lower() == "fail":
                add(15, f"{mech.upper()} check failed in "
                         "Authentication-Results")
    if not msg.get("Date"):
        add(4, "Missing Date header")
    if not msg.get("Message-ID"):
        add(4, "Missing Message-ID header")

    # sender domain itself: suspicious TLD or lookalike of a known brand
    flagged_lookalike_regs = set()
    if from_domain:
        tld = "." + from_domain.rsplit(".", 1)[-1] \
            if "." in from_domain else ""
        if tld in SUSPICIOUS_TLDS:
            add(8, f"Sender domain uses a suspicious top-level domain: "
                    f"{from_domain}")
        for brand, real in KNOWN_BRANDS.items():
            if looks_like_brand_domain(from_domain, brand, real):
                add(20, f"Sender domain is a lookalike: {from_domain} "
                         f"imitates {real}")
                flagged_lookalike_regs.add(registered_domain(from_domain))
                break

    # ---- links -------------------------------------------------------
    links = extract_links(text_body, html_body)
    for url, anchor in links:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            continue
        if not host:
            continue
        reg = registered_domain(host)
        if host in URL_SHORTENERS or reg in URL_SHORTENERS:
            add(15, f"URL shortener used: {url}")
        if is_ip_literal(host):
            add(20, f"Link points directly at an IP address: {url}")
        if "@" in url.split("://", 1)[-1].split("/", 1)[0]:
            add(15, f"Link uses the '@' userinfo trick: {url}")
        if "xn--" in host:
            add(15, f"Punycode (xn--) in link host: {host}")
        for brand, real in KNOWN_BRANDS.items():
            if looks_like_brand_domain(host, brand, real):
                # don't count the same domain twice (sender + link)
                if reg not in flagged_lookalike_regs:
                    add(20, f"Lookalike domain: {host} imitates {real}")
                break
        if reg.rsplit(".", 1)[-1] and ("." + reg.rsplit(".", 1)[-1]) \
                in SUSPICIOUS_TLDS:
            add(8, f"Suspicious top-level domain: {reg}")
        if urlparse(url).scheme == "http":
            add(5, f"Plain-http link (not https): {url}")
        if anchor and re.match(r"https?://", anchor.strip()):
            anchor_host = (urlparse(anchor.strip()).hostname or "").lower()
            if anchor_host and anchor_host != host:
                add(15, "Link text shows "
                         f"{anchor.strip()[:60]} but goes to {host}")
        if host.count(".") >= 3 and not is_ip_literal(host):
            add(5, f"Unusually deep subdomain chain: {host}")

    # ---- content -----------------------------------------------------
    lowered = full_text.lower()
    urgency_hits = 0
    for pat in URGENCY_PATTERNS:
        if re.search(pat, lowered):
            urgency_hits += 1
    if urgency_hits:
        add(min(18, urgency_hits * 6),
            f"Urgency / threat language ({urgency_hits} "
            f"{'pattern' if urgency_hits == 1 else 'patterns'} matched)")

    cred_hits = 0
    for pat in CREDENTIAL_PATTERNS:
        if re.search(pat, lowered):
            cred_hits += 1
    if cred_hits:
        add(min(16, cred_hits * 8),
            f"Asks for credentials / login ({cred_hits} "
            f"{'pattern' if cred_hits == 1 else 'patterns'} matched)")

    if re.search(r"dear (customer|user|valued customer|member)",
                 lowered):
        add(5, "Generic greeting ('Dear Customer') instead of a name")

    for name in get_attachments(msg):
        ext = Path(name).suffix.lower()
        if ext in RISKY_ATTACHMENTS:
            add(12, f"Risky attachment: {name}")
        if re.search(r"\.[a-z0-9]+\.[a-z0-9]+$", name.lower()) \
                and ext in RISKY_ATTACHMENTS:
            add(5, f"Double extension in attachment name: {name}")

    # ---- text classifier ---------------------------------------------
    prob = CLASSIFIER.phishing_probability(full_text)
    if prob >= 0.8:
        add(18, f"Text classifier: {prob:.0%} phishing-like "
                 "(trained on synthetic lab data)")
    elif prob >= 0.6:
        add(12, f"Text classifier: {prob:.0%} phishing-like "
                 "(trained on synthetic lab data)")
    elif prob >= 0.4:
        add(6, f"Text classifier: {prob:.0%} phishing-like "
                "(trained on synthetic lab data)")

    score = sum(p for p, _ in signals)
    if score >= 60:
        verdict = "Likely Phishing"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return {
        "file": str(path),
        "from": from_hdr,
        "subject": subject,
        "score": score,
        "verdict": verdict,
        "classifier_phishing_probability": round(prob, 3),
        "signals": [{"points": p, "detail": d} for p, d in signals],
    }


def print_report(result):
    print("=" * 68)
    print(f"File:    {result['file']}")
    print(f"From:    {result['from']}")
    print(f"Subject: {result['subject']}")
    print("-" * 68)
    print(f"Score:   {result['score']}  ->  {result['verdict'].upper()}")
    print(f"Text classifier phishing probability: "
          f"{result['classifier_phishing_probability']:.0%}")
    print("-" * 68)
    if result["signals"]:
        for s in result["signals"]:
            print(f"  +{s['points']:>2}  {s['detail']}")
    else:
        print("  No suspicious signals found.")
    print()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Score .eml files for phishing signals (lab tool).")
    parser.add_argument("target", help=".eml file or folder of .eml files")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if target.is_dir():
        files = sorted(target.glob("*.eml")) + sorted(target.glob("*.EML"))
    elif target.is_file():
        files = [target]
    else:
        print(f"Error: no such file or folder: {target}", file=sys.stderr)
        return 2
    if not files:
        print(f"Error: no .eml files found in {target}", file=sys.stderr)
        return 2

    results = [analyse_file(f) for f in files]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print_report(r)
        counts = {}
        for r in results:
            counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
        print(f"Summary: {len(results)} emails — " +
              ", ".join(f"{v}: {n}" for v, n in counts.items()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
