import socket
import ssl
import sys
from urllib.parse import urlparse
from datetime import datetime, timezone

# -----------------------------
# TRUSTED DOMAINS
# -----------------------------
TRUSTED_DOMAINS = [
    "google.com",
    "paypal.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "facebook.com",
    "netflix.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "chase.com",
    "linkedin.com",
    "dropbox.com",
    "adobe.com",
    "zoom.us",
    "slack.com",
    "github.com",
    "coinbase.com",
    "twitter.com",
    "walmart.com",
    "instagram.com",
]

# -----------------------------
# DOMAIN EXTRACTION
# -----------------------------
def extract_domain(url):
    """Take a URL and grab the main domain part from it.
    
    For this project, we just use the last two parts of the hostname.
    """
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("Invalid URL")
    
    # Normalizes url into a lowercase structure that splits at each .
    parts = hostname.lower().split(".")
    return ".".join(parts[-2:])

# -----------------------------
# EDIT DISTANCE 
# -----------------------------
def edit_distance(a, b):
    """Find how many character changes it takes to turn one domain into another."""
    dp = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]

    for i in range(len(a) + 1):
        dp[i][0] = i
    for j in range(len(b) + 1):
        dp[0][j] = j

    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,
                dp[i][j - 1] + 1,
                dp[i - 1][j - 1] + cost
            )

    return dp[-1][-1]

# -----------------------------
# TLS CHECK
# -----------------------------
def check_tls(domain):
    """Try a basic TLS connection to see if the domain gives us a certificate.

    This is a simple check for our project and not a full browser-level check.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return True
    except:
        return False

# -----------------------------
# CERTIFICATE AGE
# -----------------------------
def get_cert_age_days(domain):
    """Fetch the certificate and figure out how many days old it is.

    If we cannot get the certificate or read its start date, we return None.
    """
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_before = cert.get("notBefore")
        if not not_before:
            return None

        cert_time = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
        cert_time = cert_time.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)

        return (now - cert_time).days

    except:
        return None

# -----------------------------
# AGE TO RISK SCORE
# -----------------------------
def age_to_risk(days):
    """Turn certificate age into a simple risk score for our demo."""
    
    # These age cutoffs are simple project rules, not official security standards.
    if days is None:
        return 1.0  # unknown cert = extremely risky
    if days < 7:
        return 1.0
    return 0
    


# -----------------------------
# DOMAIN SIMILARITY
# -----------------------------
def check_similarity(domain):
    """Compare the domain to our trusted list and find the closest match."""
    results = []

    for trusted in TRUSTED_DOMAINS:
        dist = edit_distance(domain, trusted)
        results.append((trusted, dist))

    closest = min(results, key=lambda x: x[1])

    return {
        "closest": closest[0],
        "distance": closest[1],
    }

# -----------------------------
# MAIN ANALYSIS
# -----------------------------
def analyze(url, use_similarity=True):
    """Run all of our checks on a URL and print the results."""
    domain = extract_domain(url)

    tls_valid = check_tls(domain)
    sim = check_similarity(domain)

    cert_age_days = get_cert_age_days(domain)
    age_risk = age_to_risk(cert_age_days)

    similarity_pass = sim["distance"] == 0 if use_similarity else True
    age_pass = age_risk == 0.0

    # -----------------------------
    # SCORING
    # -----------------------------
    passed_tests = 0
    passed_tests += 1 if tls_valid else 0
    passed_tests += 1 if similarity_pass else 0
    passed_tests += 1 if age_pass else 0

    total_tests = 3

    # -----------------------------
    # VERDICT LOGIC
    # -----------------------------
    if not tls_valid:
        verdict = "SUSPICIOUS"
    elif not similarity_pass:
        verdict = "SUSPICIOUS"
    elif not age_pass:
        verdict = "USE CAUTION"
    else:
        verdict = "SAFE"

    # -----------------------------
    # OUTPUT
    # -----------------------------
    print("\nSimple Phishing Checker")
    print("------------------------")
    print(f"\nInput: {domain}")
    print(f"Tests: Passes {passed_tests}/{total_tests} tests")

    print("\n------------------------")

    print("\nCertificate Check:")
    if tls_valid:
        print("  PASS: TLS certificate was found.")
    else:
        print("  FAIL: TLS certificate was not valid.")

    print("\nDomain Similarity:")
    print(f"  Closest trusted domain: {sim['closest']}")
    print(f"  Edit Distance: {sim['distance']}")

    if similarity_pass:
        print("  PASS: No typosquatting detected.")
    elif sim["distance"] <= 2:
        print(f"  FAIL: Domain is suspiciously similar to {sim['closest']}.")
    else:
        print("  Pass: Domain is not similar to trusted list.")

    print("\nCertificate Age:")
    if cert_age_days is None:
        print("  Could not determine certificate age.")
    else:
        print(f"  Age: {cert_age_days} days")

    print(f"  Risk Score: {age_risk:.2f}")

    print("\nResult:")
    print(f"  This URL passed {passed_tests} of {total_tests} checks. {verdict}.")

# -----------------------------
# CLI
# -----------------------------
if __name__ == "__main__":
    print("=== SIMPLE URL SECURITY CHECKER ===")
    print("Type 'exit' to quit")
    print("Use '--broken' to disable similarity checking\n")

    # The --broken flag removes the similarity mechanism for our failure-case demo.
    use_similarity = "--broken" not in sys.argv

    while True:
        user_input = input("Enter URL: ").strip()

        if user_input.lower() == "exit":
            break

        try:
            analyze(user_input, use_similarity)
        except Exception as e:
            print("Error:", e)