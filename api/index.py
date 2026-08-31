import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

for path in [BASE_DIR, CURRENT_DIR, os.getcwd()]:
    if path and path not in sys.path:
        sys.path.insert(0, path)

try:
    from app.app import app

    class VercelPrefixMiddleware:
        """Strip Vercel serverless prefix (/api/index or /api) from PATH_INFO."""
        def __init__(self, wsgi_app):
            self.wsgi_app = wsgi_app

        def __call__(self, environ, start_response):
            path_info = environ.get("PATH_INFO", "")
            for prefix in ["/api/index", "/api"]:
                if path_info == prefix:
                    environ["PATH_INFO"] = "/"
                    break
                elif path_info.startswith(prefix + "/"):
                    environ["PATH_INFO"] = path_info[len(prefix):]
                    break
            return self.wsgi_app(environ, start_response)

    app.wsgi_app = VercelPrefixMiddleware(app.wsgi_app)

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
