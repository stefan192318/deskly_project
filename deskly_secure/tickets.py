from flask import render_template, request, redirect, url_for, abort
from sqlalchemy import or_
from models import db, Ticket, AuditLog
from security import login_required, get_current_user, csrf_token, check_csrf

def can_access(user, ticket):
    return user.role == "MANAGER" or ticket.owner_id == user.id

def register_ticket_routes(app):
    @app.route("/")
    def home():
        return redirect(url_for("list_tickets"))

    @app.route("/tickets")
    @login_required
    def list_tickets():
        user = get_current_user()
        search = request.args.get("search", "").strip()
        query = Ticket.query

        if user.role != "MANAGER":
            query = query.filter_by(owner_id=user.id)

        if search:
            query = query.filter(or_(
                Ticket.title.ilike(f"%{search}%"),
                Ticket.description.ilike(f"%{search}%")
            ))

        tickets = query.order_by(Ticket.id.desc()).all()
        return render_template("tickets.html", tickets=tickets, search=search)

    @app.route("/tickets/new", methods=["GET", "POST"])
    @login_required
    def new_ticket():
        user = get_current_user()
        if request.method == "POST":
            check_csrf()
            ticket = Ticket(
                title=request.form.get("title", "").strip(),
                description=request.form.get("description", "").strip(),
                severity=request.form.get("severity", "LOW"),
                status=request.form.get("status", "OPEN"),
                owner_id=user.id
            )
            db.session.add(ticket)
            db.session.add(AuditLog(action="TICKET_CREATE", message=f"Ticket creat de {user.email}"))
            db.session.commit()
            return redirect(url_for("list_tickets"))
        return render_template("ticket_form.html", ticket=None, csrf_token=csrf_token())

    @app.route("/tickets/<int:ticket_id>")
    @login_required
    def view_ticket(ticket_id):
        user = get_current_user()
        ticket = Ticket.query.get_or_404(ticket_id)

        if not can_access(user, ticket):
            db.session.add(AuditLog(action="UNAUTHORIZED_ACCESS", message=f"View interzis pe ticket {ticket_id}"))
            db.session.commit()
            abort(403)

        return render_template("ticket_view.html", ticket=ticket, csrf_token=csrf_token())

    @app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_ticket(ticket_id):
        user = get_current_user()
        ticket = Ticket.query.get_or_404(ticket_id)

        if not can_access(user, ticket):
            abort(403)

        if request.method == "POST":
            check_csrf()
            ticket.title = request.form.get("title", "").strip()
            ticket.description = request.form.get("description", "").strip()
            ticket.severity = request.form.get("severity", "LOW")
            ticket.status = request.form.get("status", "OPEN")
            db.session.add(AuditLog(action="TICKET_EDIT", message=f"Ticket editat: {ticket_id}"))
            db.session.commit()
            return redirect(url_for("view_ticket", ticket_id=ticket.id))

        return render_template("ticket_form.html", ticket=ticket, csrf_token=csrf_token())

    @app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
    @login_required
    def change_status(ticket_id):
        check_csrf()
        user = get_current_user()
        ticket = Ticket.query.get_or_404(ticket_id)

        if not can_access(user, ticket):
            abort(403)

        ticket.status = request.form.get("status", "OPEN")
        db.session.add(AuditLog(action="STATUS_CHANGE", message=f"Status schimbat pentru ticket {ticket_id}"))
        db.session.commit()
        return redirect(url_for("view_ticket", ticket_id=ticket.id))

    @app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
    @login_required
    def delete_ticket(ticket_id):
        check_csrf()
        user = get_current_user()
        ticket = Ticket.query.get_or_404(ticket_id)

        if user.role != "MANAGER":
            abort(403)

        db.session.delete(ticket)
        db.session.add(AuditLog(action="TICKET_DELETE", message=f"Ticket sters: {ticket_id}"))
        db.session.commit()
        return redirect(url_for("list_tickets"))
