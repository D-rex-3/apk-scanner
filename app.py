from flask import Flask, render_template, request
import os
import shutil
from analyzer.extractor import extract_apk
from analyzer.code_scanner import scan_code
from analyzer.severity import calculate_risk
from analyzer.manifest_analyzer import analyze_manifest

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
EXTRACT_FOLDER = "extracted"
ALLOWED_EXTENSIONS = {"zip","apk"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS


app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/analyze",methods=["POST"])
def analyze():
    file = request.files.get("apk")

    if not file or file.filename == "":
        return "No file selected"
    if not allowed_file(file.filename):
        return "Only ZIP and APK files are allowed"
    
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(EXTRACT_FOLDER,exist_ok=True)

    apk_path = os.path.join(UPLOAD_FOLDER,file.filename)
    file.save(apk_path)

    extracted_path = extract_apk(apk_path,EXTRACT_FOLDER)

    findings = []
    findings += analyze_manifest(extracted_path,apk_path)
    findings += scan_code(extracted_path)

    risk_score = calculate_risk(findings)
    try:
        if os.path.exists(extracted_path):
            shutil.rmtree(extracted_path)
        if os.path.exists(apk_path):
            os.remove(apk_path)
    except Exception as e:
        print("Cleanup error:", e)
    return render_template("report.html",findings=findings,risk_score=risk_score)
    
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)