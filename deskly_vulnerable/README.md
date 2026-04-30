# Deskly simple project

Acest pachet are 2 versiuni foarte simple:

- `deskly_clean` = MVP curat
- `deskly_vulnerable` = varianta cu vulnerabilitati introduse intentionat

## Cum rulezi

```bash
pip install -r requirements.txt
python app.py
```

## Date initiale

- analyst@deskly.local / Analyst123
- manager@deskly.local / Manager123

## Vulnerabilitati in varianta vulnerable

1. IDOR la `/tickets/<id>` si `/tickets/<id>/edit`
2. SQL Injection la `GET /tickets?search=...`
3. XSS la `description`
4. CSRF la `POST /tickets/<id>/status`
5. Session management slab
6. Error disclosure prin `debug=True` si lipsa handlerelor custom
7. Password storage & policy slab
