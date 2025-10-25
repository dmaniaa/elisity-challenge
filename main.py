from src.analyze_log_file import analyze_log_file
import os
from flask import Flask, render_template, request


app = Flask(__name__)
@app.route("/", methods=["GET"])
def index():
    return render_template("upload.html")
@app.route("/", methods=["POST"])
def upload_file():
    file = request.files["file"]
    if file and file.filename.endswith(".log"):
        file.save("uploaded_log.log")
        return render_template("result.html", entries=analyze_log_file("uploaded_log.log"))
    return "No file uploaded."

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=True)