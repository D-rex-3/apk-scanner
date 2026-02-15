import os
import re

def scan_code(extracted_path):
    findings = []

    secret_patterns = [
        r"api[_-]?key\s*=\s*['\"].+?['\"]",
        r"secret\s*=\s*['\"].+?['\"]",
        r"password\s*=\s*['\"].+?['\"]",
        r"sk_live_[0-9a-zA-Z]+",
        r"AIza[0-9A-Za-z-_]{35}"
    ]

    weak_crypto_patterns = [
        r"MD5",
        r"SHA1",
        r"DES",
        r"AES/ECB"
    ]
    for root,dirs, files in os.walk(extracted_path):
        for file in files:
            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r",errors="ignore") as f:
                    content = f.read()

                    for pattern in secret_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                "title": "Hardcoded Secret Detected",
                                "severity": "Critical",
                                "owasp": "M2",
                                "remediation": "Move secrets to secure backend storage."
                            })
                            break
                    
                    for pattern in weak_crypto_patterns:
                        if re.search(pattern, content):
                            findings.append({
                                "title": "Weak Cryptography Usage Detected",
                                "severity": "High",
                                "owasp": "M5",
                                "remediation": "Use strong cryptographic algorithms like SHA-256 and AES-GCM."

                            })
                            break
            except:
                continue
    return findings