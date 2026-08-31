import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

for path in [BASE_DIR, CURRENT_DIR, os.getcwd()]:
    if path and path not in sys.path:
        sys.path.insert(0, path)

from app.app import app

# Expose WSGI application object for Vercel
app = app
