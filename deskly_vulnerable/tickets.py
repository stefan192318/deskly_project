from flask import render_template, request, redirect, url_for, abort
from sqlalchemy import text
from models import db, Ticket, AuditLog
from security import login_required, get_current_user

def register_ticket_routes(app):
    @app.route("/")
    def home():
        return redirect(url_for("list_tickets"))

    @app.route("/tickets")
    @login_required
    def list_tickets():
        current_user = get_current_user()
        search = request.args.get("search", "").strip()

        if search:
            # Vulnerabil: SQL injection prin concatenare
            raw_sql = f"SELECT * FROM ticket WHERE title LIKE '%{search}%' OR description LIKE '%{search}%'"
            tickets = db.session.execute(text(raw_sql)).all()
            return render_template("tickets_vuln.html", tickets=tickets, search=search, current_user=current_user)

        query = Ticket.query
        if current_user.role != "MANAGER":
            query = query.filter_by(owner_id=current_user.id)
        tickets = query.order_by(Ticket.id.desc()).all()
        return render_template("tickets.html", tickets=tickets, search=search, current_user=current_user)

    @app.route("/tickets/new", methods=["GET", "POST"])
    @login_required
    def new_ticket():
        current_user = get_current_user()
        if request.method == "POST":
            ticket = Ticket(
                title=request.form.get("title", "").strip(),
                description=request.form.get("description", "").strip(),
                severity=request.form.get("severity", "LOW"),
                status=request.form.get("status", "OPEN"),
                owner_id=current_user.id
            )
            db.session.add(ticket)
            db.session.add(AuditLog(action="TICKET_CREATE", message=f"Ticket creat de {current_user.email}"))
            db.session.commit()
            return redirect(url_for("list_tickets"))
        return render_template("ticket_form.html", ticket=None)

    @app.route("/tickets/<int:ticket_id>")
    @login_required
    def view_ticket(ticket_id):
        ticket = Ticket.query.get_or_404(ticket_id)
        # Vulnerabil: fara verificare ownership -> IDOR
        return render_template("ticket_view_vuln.html", ticket=ticket)

    @app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_ticket(ticket_id):
        ticket = Ticket.query.get_or_404(ticket_id)
        # Vulnerabil: fara verificare ownership -> IDOR
        if request.method == "POST":
            ticket.title = request.form.get("title", "").strip()
            ticket.description = request.form.get("description", "").strip()
            ticket.severity = request.form.get("severity", "LOW")
            ticket.status = request.form.get("status", "OPEN")
            db.session.add(AuditLog(action="TICKET_EDIT", message=f"Ticket editat: {ticket_id}"))
            db.session.commit()
            return redirect(url_for("view_ticket", ticket_id=ticket.id))
        return render_template("ticket_form.html", ticket=ticket)

    @app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
    @login_required
    def delete_ticket(ticket_id):
        current_user = get_current_user()
        ticket = Ticket.query.get_or_404(ticket_id)

        if current_user.role != "MANAGER":
            abort(403)

        db.session.delete(ticket)
        db.session.add(AuditLog(action="TICKET_DELETE", message=f"Ticket sters: {ticket_id}"))
        db.session.commit()
        return redirect(url_for("list_tickets"))

    @app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
    @login_required
    def change_status(ticket_id):
        ticket = Ticket.query.get_or_404(ticket_id)
        # Vulnerabil: fara CSRF token
        ticket.status = request.form.get("status", "OPEN")
        db.session.add(AuditLog(action="STATUS_CHANGE", message=f"Status schimbat pentru ticket {ticket_id}"))
        db.session.commit()
        return redirect(url_for("view_ticket", ticket_id=ticket.id))
