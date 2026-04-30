from flask import Flask
from models import db, User, Ticket
from auth import register_auth_routes
from tickets import register_ticket_routes
from audit import register_audit_routes
from security import get_current_user

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///deskly_vulnerable.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)

@app.context_processor
def inject_globals():
    return {"current_user": get_current_user()}

register_auth_routes(app)
register_ticket_routes(app)
register_audit_routes(app)

def seed():
    if User.query.count() == 0:
        analyst = User(email="analyst@deskly.local", password_hash="Analyst123", role="ANALYST")
        manager = User(email="manager@deskly.local", password_hash="Manager123", role="MANAGER")
        db.session.add_all([analyst, manager])
        db.session.commit()

        t1 = Ticket(title="VPN down", description="Nu merge VPN-ul", severity="HIGH", status="OPEN", owner_id=analyst.id)
        t2 = Ticket(title="Printer issue", description="Imprimanta blocheaza hartia", severity="LOW", status="OPEN", owner_id=manager.id)
        db.session.add_all([t1, t2])
        db.session.commit()

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        seed()
    app.run(debug=True)
