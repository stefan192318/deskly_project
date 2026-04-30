from flask import render_template
from models import AuditLog
from security import manager_required

def register_audit_routes(app):
    @app.route("/audit")
    @manager_required
    def audit():
        logs = AuditLog.query.order_by(AuditLog.id.desc()).all()
        return render_template("audit.html", logs=logs)
