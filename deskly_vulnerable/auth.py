from flask import render_template, request, redirect, url_for, session, flash
from models import db, User, AuditLog

def register_auth_routes(app):
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            role = request.form.get("role", "ANALYST")

            if not email or not password:
                flash("Email si parola sunt obligatorii.")
            elif User.query.filter_by(email=email).first():
                flash("Email deja existent.")
            else:
                # Vulnerabil: parola in clar
                user = User(
                    email=email,
                    password_hash=password,
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

            # Vulnerabil: compara parola in clar
            if not user or user.password_hash != password:
                flash("Date invalide.")
            else:
                session.clear()
                session["user_id"] = user.id
                db.session.add(AuditLog(action="LOGIN_SUCCESS", message=f"Login: {email}"))
                db.session.commit()
                return redirect(url_for("list_tickets"))
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))
