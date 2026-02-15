import os 
import xml.etree.ElementTree as ET
from androguard.core.apk import APK

def analyze_manifest(extracted_path,apk_path):
    findings = []

    dangerous_permissions = [
        "android.permission.READ_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_AUDIO",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.READ_PHONE_STATE"
    ]
    if apk_path.lower().endswith(".apk"):
        try:
            app = APK(apk_path)

            for perm in app.get_permissions():
                if perm in dangerous_permissions:
                    findings.append({
                        "title": f"Dangerous Permission: {perm}",
                        "severity": "Medium",
                        "owasp": "M6",
                        "remediation": "Review necessity of this permission."
                    })
            if app.is_debuggable():
                findings.append({
                    "title": "Application Debug Mode Enabled",
                    "severity": "High",
                    "owasp": "M1",
                    "remediation": "Disable debug mode in production."
                })
        except Exception as e:
            print("APK analysis error:",e)
    else:
        manifest_path = os.path.join(extracted_path,"AndroidManifest.xml")

        if not os.path.exists(manifest_path):
            return findings
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            android_ns = "{http://schemas.android.com/apk/res/android}"

            for perm in root.findall("uses-permission"):
                name = perm.get(android_ns + "name")
                if name in dangerous_permissions:
                    findings.append({
                        "title": f"Dangerous Permission: {name}",
                        "severity": "Medium",
                        "owasp": "M6",
                        "remediation": "Review necessity of this permission."
                    })
        except:
            pass
    return findings
