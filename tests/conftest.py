import pytest
import pytest
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path so `import app` works when pytest sets a different cwd
root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))

from app import create_app, db
@pytest.fixture
def app():
    os.environ['FLASK_ENV'] = 'development'
    os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app = create_app()
    with app.app_context():
        db.create_all()
        yield app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()
