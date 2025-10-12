from flask import Flask
from app.routes.jwt_routes import jwt_bp
from flask_cors import CORS


def create_app():
    app = Flask(__name__)
    CORS(app) 
    app.register_blueprint(jwt_bp, url_prefix="/api")
    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, port=5000)

