# Cert-Checker

This tool is designed to return some TLS certificate information quickly during a web application pentest and looks for potential issues such as expired certificates, weak key sizes and signature algorithms and wildcard common names (CNs). If found, it will flag them as potential issues in the output. Additionally, it returns the certificate extension information.

## Installation

To install, simply clone the repository

```bash
git clone https://github.com/JonnyPake/cert-checker
```

And install the pip dependencies included in the requirements.txt file:

```bash
pip install -r requirements.txt
```
