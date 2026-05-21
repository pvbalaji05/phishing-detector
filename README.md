#  Phishing URL Detector

A beginner-friendly Python cybersecurity project that checks whether a URL might be a phishing link.

---

## File
```
phishing_detector.py
```

---

## How to Run

1. Open **VS Code**
2. Open the file `phishing_detector.py`
3. Open the terminal: `View → Terminal`
4. Run:
```
python phishing_detector.py
```

---

##  What It Checks

| Check | Why It Matters |
|---|---|
| `@` symbol in URL | Can redirect browsers to a fake site |
| Too many dots | Hides the real domain name |
| Very long URL | Makes it hard to see the real destination |
| Suspicious keywords | Words like `login`, `bank`, `verify` are bait |
| IP address instead of domain | Real sites use names, not raw IPs |
| Too many hyphens | Used to fake official-looking names |
| No HTTPS | Insecure connection, risky to use |

---

## 📊 Risk Score

| Score | Result |
|---|---|
| 0–2 | Safe URL |
| 3–6 | Suspicious URL |
| 7–10 |  Possible Phishing URL |

---

##  Example URLs to Test

```
http://verify-login-bank.com
https://google.com
http://192.168.1.1/update-account
https://secure-signin-update.paypal.verify.com
```

---

## Modules Used

- `re` — built-in Python regex module (no install needed)
- No external libraries required!

---

## Disclaimer

This is a simple educational project. It uses basic rule-based checks and is **not** a replacement for professional cybersecurity tools.
