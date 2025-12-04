from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os
import logging
from werkzeug.security import generate_password_hash


try:
    # optional dependency, harmless if not installed
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)

    basedir = os.path.abspath(os.path.dirname(__file__))

    # SECRET KEY (change in production)
    app.config['SECRET_KEY'] = "anaeza_kuwa_na_kazi"

    # Database URI: allow override via environment for testing/dev
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI') or os.getenv('DATABASE_URL') or 'sqlite:///mitumba.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'static', 'uploads')

    

    # Initialize extensions
    db.init_app(app)
    
    

    # Basic logging setup
    logging.basicConfig(level=os.getenv("FLASK_LOG_LEVEL", "INFO"))
    from flask_login import LoginManager

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = "main.login"

    # Return JSON on AJAX unauthorized requests instead of redirecting to login page
    from flask import request, jsonify, redirect, url_for

    @login_manager.unauthorized_handler
    def unauthorized_callback():
        # If the request expects JSON or is an XHR, return 401 JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.headers.get('Accept', '').find('application/json') != -1 or request.is_json:
            return jsonify({'message': 'Login required'}), 401
        # Otherwise redirect to login page
        return redirect(url_for('main.login', next=request.path))


    @login_manager.user_loader
    def load_user(user_id):
        # Import here to avoid circular imports at module import time
        from .models import User
        return User.query.get(int(user_id))


    # Register routes
    from app.routes import main
    app.register_blueprint(main)
    # Optionally create DB tables on startup for development/testing.
    # This will create tables defined by SQLAlchemy models if they don't exist.
    
    with app.app_context():
        db.create_all()

        # Import User here to avoid circular import at module import time
        from .models import User

        # Ensure admin account exists
        admin = User.query.filter_by(email="admin@admin.com").first()
        if not admin:
            admin = User(
                email="admin@admin.com",
                password=generate_password_hash("admin123"),  
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print(">>> Admin account created: admin@admin.com / admin123")

    
    try:
        enable_create = os.getenv("ENABLE_DB_CREATE", "1")
        flask_env = os.getenv("FLASK_ENV", "production")
        if enable_create == "1" or flask_env == "development":
            with app.app_context():
                db.create_all()
                app.logger.info("Database tables ensured (db.create_all()).")
                # Simple dev migration: ensure `is_admin` column exists on user table
                try:
                    from sqlalchemy import text
                    res = db.session.execute(text("PRAGMA table_info('user')")).fetchall()
                    cols = [row[1] for row in res]
                    if 'is_admin' not in cols:
                        app.logger.info("Adding missing 'is_admin' column to user table")
                        db.session.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
                        db.session.commit()
                except Exception:
                    app.logger.exception("Failed to run simple dev migration for user.is_admin")
                # ensure PendingPayment table exists in dev/test environments
                try:
                    from sqlalchemy import text
                    res = db.session.execute(text("SELECT name FROM sqlite_master WHERE type='table' AND name='pending_payment'"))
                    if not res.fetchall():
                        app.logger.info("PendingPayment table not found; creating all tables to ensure model exists")
                        db.create_all()
                except Exception:
                    app.logger.exception("Failed to ensure PendingPayment table")
    except Exception:
        app.logger.exception("Failed to create DB tables on startup")

    return app




