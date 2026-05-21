# ============================================================
#   PHISHING URL DETECTORr  
#   Author: Balaji PV
#   Description: Checks if a URL might be a phishing link
# ============================================================

import re  # 're' helps us search for patterns inside text

# -------------------------------------------------------
# LIST OF SUSPICIOUS WORDS
# Phishing websites often use these words to trick users
# into thinking the site is official or urgent.
# -------------------------------------------------------
SUSPICIOUS_WORDS = ["login", "verify", "secure", "update", "bank",
                    "account", "confirm", "password", "signin", "urgent"]

# -------------------------------------------------------
# FUNCTION: check_at_symbol
# Phishing URLs sometimes contain '@' to confuse browsers.
# Example: http://google.com@evil.com  --> goes to evil.com
# -------------------------------------------------------
def check_at_symbol(url):
    if "@" in url:
        return True, "Contains '@' symbol (used to trick browsers)"
    return False, ""

# -------------------------------------------------------
# FUNCTION: check_too_many_dots
# Legitimate websites usually have 1-2 dots.
# Phishing sites sometimes use many dots to hide the real domain.
# Example: secure.login.bank.update.com
# -------------------------------------------------------
def check_too_many_dots(url):
    # Remove "http://" or "https://" before counting dots
    clean = re.sub(r"https?://", "", url)
    dot_count = clean.count(".")
    if dot_count > 4:
        return True, f"Too many dots in URL ({dot_count} dots found)"
    return False, ""

# -------------------------------------------------------
# FUNCTION: check_url_length
# Very long URLs are often used to hide the real destination.
# Legitimate sites usually have short, clean URLs.
# -------------------------------------------------------
def check_url_length(url):
    if len(url) > 75:
        return True, f"URL is very long ({len(url)} characters)"
    return False, ""

# -------------------------------------------------------
# FUNCTION: check_suspicious_words
# Phishing sites use words like "login", "verify", "bank"
# to make users feel the site is safe and official.
# -------------------------------------------------------
def check_suspicious_words(url):
    url_lower = url.lower()  # Convert to lowercase for easy matching
    found_words = []
    for word in SUSPICIOUS_WORDS:
        if word in url_lower:
            found_words.append(word)
    if found_words:
        return True, f"Suspicious keyword(s) found: {', '.join(found_words)}"
    return False, ""

# -------------------------------------------------------
# FUNCTION: check_ip_address
# Real websites use domain names (like google.com).
# Phishing sites sometimes use raw IP addresses to avoid detection.
# Example: http://192.168.1.1/login
# -------------------------------------------------------
def check_ip_address(url):
    # This pattern looks for something like 192.168.0.1 inside the URL
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    if ip_pattern.search(url):
        return True, "URL uses an IP address instead of a domain name"
    return False, ""

# -------------------------------------------------------
# FUNCTION: check_too_many_hyphens
# Phishing sites often use hyphens to fake official names.
# Example: secure-login-bank-update.com
# -------------------------------------------------------
def check_too_many_hyphens(url):
    hyphen_count = url.count("-")
    if hyphen_count >= 3:
        return True, f"Too many hyphens in URL ({hyphen_count} hyphens found)"
    return False, ""

# -------------------------------------------------------
# FUNCTION: check_https
# Legitimate websites usually use HTTPS (secure connection).
# If a site uses plain HTTP, it might be unsafe.
# -------------------------------------------------------
def check_https(url):
    if not url.startswith("https://"):
        return True, "URL does not use HTTPS (no secure connection)"
    return False, ""

# -------------------------------------------------------
# FUNCTION: analyze_url
# This is the MAIN function that runs all the checks above.
# It collects all the issues found and calculates a risk score.
# -------------------------------------------------------
def analyze_url(url):
    issues = []  # List to store all detected problems

    # Run each check and collect results
    checks = [
        check_at_symbol(url),
        check_too_many_dots(url),
        check_url_length(url),
        check_suspicious_words(url),
        check_ip_address(url),
        check_too_many_hyphens(url),
        check_https(url),
    ]

    # Loop through each check result
    for is_suspicious, message in checks:
        if is_suspicious:
            issues.append(message)  # Add the issue to our list

    # -------------------------------------------------------
    # CALCULATE RISK SCORE
    # Each issue adds points to the risk score.
    # Maximum score is 10.
    # -------------------------------------------------------
    points_per_issue = {
        0: 0,
        1: 2,
        2: 4,
        3: 6,
        4: 7,
        5: 8,
        6: 9,
        7: 10,
    }
    issue_count = len(issues)
    risk_score = points_per_issue.get(issue_count, 10)

    # -------------------------------------------------------
    # DECIDE RESULT LABEL
    # Based on risk score, we label the URL as:
    # - Safe        (score 0-2)
    # - Suspicious  (score 3-6)
    # - Phishing    (score 7-10)
    # -------------------------------------------------------
    if risk_score <= 2:
        result = "✅ Safe URL"
    elif risk_score <= 6:
        result = "⚠️  Suspicious URL"
    else:
        result = "🚨 Possible Phishing URL"

    return result, issues, risk_score

# -------------------------------------------------------
# FUNCTION: print_report
# Neatly displays the result in the terminal.
# -------------------------------------------------------
def print_report(url, result, issues, risk_score):
    print()
    print("=" * 50)
    print("       PHISHING URL DETECTOR - REPORT")
    print("=" * 50)
    print(f"  URL Entered : {url}")
    print(f"  Result      : {result}")
    print("-" * 50)

    if issues:
        print("  Detected Issues:")
        for i, issue in enumerate(issues, start=1):
            print(f"    {i}. {issue}")
    else:
        print("  No issues detected.")

    print("-" * 50)
    print(f"  Risk Score  : {risk_score}/10")

    # Simple visual bar for risk level
    bar = "█" * risk_score + "░" * (10 - risk_score)
    print(f"  Risk Level  : [{bar}]")
    print("=" * 50)
    print()

# -------------------------------------------------------
# FUNCTION: show_phishing_info
# A small educational section explaining how phishing works.
# -------------------------------------------------------
def show_phishing_info():
    print()
    print("=" * 50)
    print("   HOW PHISHING WEBSITES TRICK USERS")
    print("=" * 50)
    tips = [
        "They copy the look of real websites (like banks).",
        "They use URLs that look almost real (go0gle.com).",
        "They create fake urgency: 'Your account will close!'",
        "They ask you to enter your password or card details.",
        "They use HTTP instead of HTTPS (no padlock icon).",
        "They hide behind long, confusing web addresses.",
    ]
    for tip in tips:
        print(f"  • {tip}")
    print("=" * 50)
    print()

# -------------------------------------------------------
# MAIN PROGRAM STARTS HERE
# This is where everything runs when you execute the file.
# -------------------------------------------------------
def main():
    print()
    print("*" * 50)
    print("*     PHISHING URL DETECTOR v1.0               *")
    print("*     Author: Balaji PV                        *")
    print("*     A Simple Cybersecurity Student Project   *")
    print("*" * 50)
    print()

    # Show educational info at the start
    show_phishing_info()

    # Keep running until user types 'exit'
    while True:
        print("  Type 'exit' to quit the program.")
        url = input("  Enter URL to check: ").strip()

        # Exit condition
        if url.lower() == "exit":
            print("\n  Goodbye! Stay safe online. 👋\n")
            break

        # Check if user entered something
        if not url:
            print("\n  ⚠️  Please enter a valid URL.\n")
            continue

        # Add http:// if user forgot to type it
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
            print(f"  (Added http:// → checking: {url})")

        # Run the analysis
        result, issues, risk_score = analyze_url(url)

        # Show the report
        print_report(url, result, issues, risk_score)

# Run the main function
if __name__ == "__main__":
    main()
