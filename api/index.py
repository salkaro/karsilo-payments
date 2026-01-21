"""
Vercel Serverless Function Handler for FastAPI
This file wraps the FastAPI app for Vercel's Python runtime
"""

import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel expects a handler named 'handler' or the app itself for ASGI
# For FastAPI/ASGI apps, we export the app directly
handler = app
