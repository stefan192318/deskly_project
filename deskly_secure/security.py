from functools import wraps
import secrets
from flask import session, redirect, url_for, flash, abort, request
from models import User

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            flash("Trebuie sa fii logat.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def manager_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        if user.role != "MANAGER":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return session["csrf_token"]

def check_csrf():
    if request.form.get("csrf_token") != session.get("csrf_token"):
        abort(403)

def strong_password(password):
    return len(password) >= 8 and any(c.isupper() for c in password) and any(c.isdigit() for c in password)
