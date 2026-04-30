from datetime import timedelta
from flask import Flask
from werkzeug.security import generate_password_hash
from models import db, User, Ticket
from auth import register_auth_routes
from tickets import register_ticket_routes
from audit import register_audit_routes
from security import get_current_user

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-change-this"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///deskly_secure.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

db.init_app(app)

@app.context_processor
def inject_globals():
    return {"current_user": get_current_user()}

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response

register_auth_routes(app)
register_ticket_routes(app)
register_audit_routes(app)

@app.errorhandler(403)
def forbidden(_):
    return "403 Forbidden", 403

@app.errorhandler(404)
def not_found(_):
    return "404 Not Found", 404

@app.errorhandler(500)
def server_error(_):
    return "500 Internal Server Error", 500

def seed():
    if User.query.count() == 0:
        analyst = User(email="analyst@deskly.local", password_hash=generate_password_hash("Analyst123"), role="ANALYST")
        manager = User(email="manager@deskly.local", password_hash=generate_password_hash("Manager123"), role="MANAGER")
        db.session.add_all([analyst, manager])
        db.session.commit()

        db.session.add(Ticket(title="VPN down", description="Nu merge VPN-ul", severity="HIGH", status="OPEN", owner_id=analyst.id))
        db.session.add(Ticket(title="Printer issue", description="Imprimanta blocheaza hartia", severity="LOW", status="OPEN", owner_id=manager.id))
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed()
    app.run(debug=False)
