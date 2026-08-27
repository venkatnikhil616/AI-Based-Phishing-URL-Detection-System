import os
import sys

# Project root
BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

# Make project root available for imports
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

# Import Flask application
from app.app import app
