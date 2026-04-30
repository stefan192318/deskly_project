from flask import render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, AuditLog
from security import strong_password

MAX_FAILED_LOGINS = 5

def register_auth_routes(app):
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "ANALYST")

            if not strong_password(password):
                flash("Parola: minim 8 caractere, o litera mare si o cifra.")
            elif User.query.filter_by(email=email).first():
                flash("Email deja existent.")
            else:
                user = User(
                    email=email,
                    password_hash=generate_password_hash(password),
                    role=role if role in ["ANALYST", "MANAGER"] else "ANALYST"
                )
                db.session.add(user)
                db.session.add(AuditLog(action="REGISTER", message=f"User creat: {email}"))
                db.session.commit()
                return redirect(url_for("login"))
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            user = User.query.filter_by(email=email).first()

            if user and user.is_locked:
                flash("Cont blocat.")
                return render_template("login.html")

            if not user or not check_password_hash(user.password_hash, password):
                if user:
                    user.failed_logins += 1
                    if user.failed_logins >= MAX_FAILED_LOGINS:
                        user.is_locked = True
                    db.session.add(AuditLog(action="LOGIN_FAILED", message=f"Login esuat: {email}"))
                    db.session.commit()
                flash("Date invalide.")
            else:
                session.clear()
                session["user_id"] = user.id
                user.failed_logins = 0
                db.session.add(AuditLog(action="LOGIN_SUCCESS", message=f"Login: {email}"))
                db.session.commit()
                return redirect(url_for("list_tickets"))
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))
