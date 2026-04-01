"""
Vercel serverless entry point for NepalThreat Intel API
"""

from main import app
from mangum import Mangum

# Create handler for Vercel serverless environment
# Mangum adapts ASGI applications (like FastAPI) to AWS Lambda / Vercel
handler = Mangum(app)