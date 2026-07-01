# Fixes aplicados

## SQL Injection

**Antes (Vulnerable):**

```python
query = (
    "SELECT title, year, genre FROM movies "
    "WHERE title LIKE '%" + q + "%'"
)
db = get_db()
try:
    results = db.execute(query).fetchall()
```

**Después (Seguro):**

```python
db = get_db()
try:
    results = db.execute(
        "SELECT title, year, genre FROM movies WHERE title LIKE ?",
        ("%" + q + "%",),
    ).fetchall()
```

Se cambio de concatenación de string a uso de parámetros

## Stored XSS

### Fix HTML Escaping

Se elimino el filtro `| safe` de Jinja2 que desactiva el auto-escaping de HTML

- Al eliminar el filtro convierte: `<script>alert(1)</script>` → `&lt;script&gt;alert(1)&lt;/script&gt;`
- Evita que se ejecuten scripts maliciosos del lado del cliente

### Fix HttpOnly Flag

Se setea `httponly=True` en la cookie admin_flag evitando a Javascript que se pueda acceder desde `document.cookie`.

## Licencia en base64 (no cifrada)

- **Before:** La licencia se codificaba en Base64, haciendo posible al atacante decodificarla, modificarla y volver a codificar para acceder a utilidades premium.
- **After:** Los tokens se firman con HMAC-SHA256. Solo el server (con SECRET_KEY) puede crear firmas válidas. Si se modifica el token el servidor lo rechazará.
