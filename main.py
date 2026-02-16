from asgiref.wsgi import WsgiToAsgi
from app import app as flask_app

# ASGI adapter for running the Flask app with Uvicorn.
app = WsgiToAsgi(flask_app)
