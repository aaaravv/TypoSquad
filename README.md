# Simple URL Security Checker

This project is a small command-line phishing checker for an introductory security class.

The goal is to show how a URL can be checked using a few simple security ideas:
1. A basic TLS certificate check
2. Domain similarity against a trusted list
3. A certificate-age heuristic

The program is meant to be a warning/demo tool, not a full browser replacement.

## Threat Model

The main threat is phishing through lookalike domains.

An attacker can register a domain that looks very similar to a trusted site, such as:
- `google.com` vs `goog1e.com`
- `paypal.com` vs `paypa1.com`

A user may not notice the small spelling difference and may trust the fake site.  
The attacker may also be able to obtain a valid TLS certificate for the fake domain, so TLS alone is not always enough to detect phishing.

## Security Mechanisms

### 1. TLS Certificate Check
The program tries to open a basic TLS connection to the domain on port 443.

If the site presents a certificate, this check passes.

### 2. Domain Similarity Check
The program compares the input domain against a small trusted list:

- `google.com`
- `paypal.com`
- `amazon.com`

It uses edit distance to find the closest trusted domain.

Our project rule is:
- edit distance `0` = pass
- edit distance `1` or `2` = suspicious and fail
- edit distance greater than `2` = pass, because it is not likely a typo-squatting attempt

### 3. Certificate Age Check
The program reads the certificate `notBefore` field and estimates how old the certificate is.

For this project:
- if the certificate age cannot be determined, it is treated as risky
- if the certificate is less than 7 days old, it is treated as risky
- otherwise, it passes this mechanism

These are simple project-defined heuristics, not universal security rules.

## How to Run

Open PowerShell in the project folder and run:

```powershell
python .\test.py
