from flask import Flask, render_template, request, jsonify
from modules.threat_aggregator import aggregate_threat, get_dashboard_data
from modules.cve_tracker import get_recent_cves, search_cves
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    query = data.get("query", "").strip()
    query_type = data.get("type", "auto")

    if not query:
        return jsonify({"error": "Sorgu boş olamaz"}), 400

    print(f"\n🔍 Analiz: {query} ({query_type})")
    result = aggregate_threat(query, query_type)
    return jsonify(result)

@app.route("/api/cves/recent")
def recent_cves():
    days = request.args.get("days", 7, type=int)
    limit = request.args.get("limit", 20, type=int)
    result = get_recent_cves(days=days, limit=limit)
    return jsonify(result)

@app.route("/api/cves/search")
def search_cve():
    keyword = request.args.get("q", "")
    if not keyword:
        return jsonify({"error": "Keyword gerekli"}), 400
    result = search_cves(keyword)
    return jsonify(result)

@app.route("/api/dashboard")
def dashboard():
    data = get_dashboard_data()
    return jsonify(data)

if __name__ == "__main__":
    app.run(debug=True, port=5056)