# Deskly secure minimal

## Run
```bash
pip install -r requirements.txt
python app.py
```

## Conturi
- analyst@deskly.local / Analyst123
- manager@deskly.local / Manager123

## Fixuri incluse
1. IDOR: ownership check.
2. Injection: ORM SQLAlchemy.
3. XSS: Jinja escaping.
4. CSRF: hidden csrf_token + check_csrf().
5. Session: HttpOnly, SameSite, lifetime, debug off.
6. Error disclosure: debug=False si error handlers generici.
7. Password storage: hash + policy + lockout simplu.
