"""
Monitor Legislativo Web Application - Secured Version
Flask-based web service with authentication and proper security
"""

import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS
from datetime import timedelta

from core.config.config import Config
from core.auth.jwt_manager import jwt_manager
from core.models.models import init_db
from web.api.routes_secured import api_router
from web.api.auth_routes import auth_router
from web.api.monitoring_routes import monitoring_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_app(config_name='production'):
    """Create and configure Flask application"""
    
    # Create Flask app
    app = Flask(__name__, 
                static_folder='frontend/static',
                template_folder='frontend/templates')
    
    # Load configuration
    config = Config()
    
    # App configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
    app.config['JWT_ALGORITHM'] = 'HS256'
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', 
        'sqlite:///monitor_legislativo.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Security headers
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
        return response
    
    # Configure CORS properly
    CORS(app, 
         origins=os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(','),
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
         supports_credentials=True,
         max_age=3600)
    
    # Initialize extensions
    jwt_manager.init_app(app)
    
    # Initialize database
    init_db(app.config['SQLALCHEMY_DATABASE_URI'])
    
    # Register blueprints
    app.register_blueprint(auth_router)
    app.register_blueprint(api_router)
    app.register_blueprint(monitoring_router)
    
    # Root endpoint
    @app.route('/')
    def index():
        return jsonify({
            'name': 'Monitor Legislativo API',
            'version': '4.0.0',
            'status': 'secured',
            'documentation': {
                'api_docs': '/api/docs',
                'endpoints': {
                    'auth': '/api/auth',
                    'documents': '/api/v1/documents',
                    'monitoring': '/api/v1/monitoring'
                }
            }
        })
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return jsonify({
            'status': 'healthy',
            'version': '4.0.0',
            'timestamp': datetime.now().isoformat()
        })
    
    # Error handlers
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            'error': 'Bad request',
            'message': 'The request could not be understood by the server'
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required'
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'error': 'Forbidden',
            'message': 'You do not have permission to access this resource'
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': 'Not found',
            'message': 'The requested resource was not found'
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}")
        return jsonify({
            'error': 'Internal server error',
            'message': 'An unexpected error occurred'
        }), 500
    
    # Log startup
    logger.info(f"Monitor Legislativo API initialized in {config_name} mode")
    
    return app

def main():
    """Main entry point for web application"""
    # Get environment
    env = os.environ.get('FLASK_ENV', 'production')
    
    # Create app
    app = create_app(env)
    
    # Run app
    if env == 'development':
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=True
        )
    else:
        # In production, use gunicorn or similar
        app.run(
            host='0.0.0.0',
            port=5000,
            debug=False
        )

if __name__ == "__main__":
    from datetime import datetime
    main()