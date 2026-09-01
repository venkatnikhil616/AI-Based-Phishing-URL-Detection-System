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
        """Resolve real client request path from Vercel edge headers."""
        def __init__(self, wsgi_app):
            self.wsgi_app = wsgi_app

        def __call__(self, environ, start_response):
            # Check for actual path requested by client from Vercel edge headers
            raw_path = (
                environ.get("HTTP_X_MATCHED_PATH")
                or environ.get("HTTP_X_FORWARDED_URI")
                or environ.get("REQUEST_URI")
                or environ.get("RAW_URI")
                or ""
            ).split("?")[0]

            if raw_path and raw_path not in ["/api/index", "/api/index.py"]:
                environ["PATH_INFO"] = raw_path
            else:
                path_info = environ.get("PATH_INFO", "")
                if path_info in ["/api/index", "/api/index.py", "/api"]:
                    environ["PATH_INFO"] = "/"

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
