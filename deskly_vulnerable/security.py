from functools import wraps
from flask import session, redirect, url_for, flash, abort
from models import User

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return User.query.get(user_id)

def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not get_current_user():
            flash("Trebuie sa fii logat.")
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapper

def manager_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        if user.role != "MANAGER":
            abort(403)
        return view_func(*args, **kwargs)
    return wrapper
