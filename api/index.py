import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

for path in [BASE_DIR, CURRENT_DIR, os.getcwd()]:
    if path and path not in sys.path:
        sys.path.insert(0, path)

try:
    from app.app import app
except Exception as exc:
    import traceback
    err_msg = str(exc)
    err_trace = traceback.format_exc()
    from flask import Flask, jsonify
    app = Flask(__name__)

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>", methods=["GET", "POST"])
    def catch_all(path):
        return jsonify({
            "status": "error",
            "message": "Vercel Python Serverless Function Startup Error in api/index.py",
            "error": err_msg,
            "traceback": err_trace
        }), 500

# WSGI application callable for Vercel
app = app
