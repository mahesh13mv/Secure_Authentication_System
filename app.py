import os
from flask import Flask, render_template
from dotenv import load_dotenv
from models import db
from auth import bp as auth_bp

load_dotenv()

def create_app():
    app = Flask(__name__, static_folder='static', template_folder='templates')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///auth_flask.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'change-me')

    db.init_app(app)
    app.register_blueprint(auth_bp)

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/register')
    def register_page():
        return render_template('register.html')

    @app.route('/mfa-setup')
    def mfa_page():
        return render_template('mfa_setup.html')

    @app.route('/dashboard')
    def dashboard_page():
        return render_template('dashboard.html')

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
