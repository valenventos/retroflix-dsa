"""
RetroFlix - Aplicacion web vulnerable (Trabajo Integrador DSA 2026)
====================================================================

ADVERTENCIA: Esta aplicacion es INTENCIONALMENTE VULNERABLE con fines
educativos (CTF de la catedra). NO desplegar en produccion.

Vulnerabilidades (una por vista, OWASP Top 10):
  - /buscar   -> A03:2021 Injection        -> SQL Injection
  - /reviews  -> A03:2021 Injection (XSS)  -> Stored Cross-Site Scripting
  - /premium  -> A02:2021 Crypto Failures  -> Licencia "cifrada" que es solo base64

La aplicacion NO contiene RCE ni vulnerabilidades que comprometan el servidor.
"""

import os
import sqlite3
import base64
import json
import tempfile
from flask import (
    Flask, request, redirect, url_for, make_response, render_template, g
)

# ---------------------------------------------------------------------------
# Configuracion / Flags (se pueden setear por variable de entorno)
# ---------------------------------------------------------------------------
FLAG_SQLI   = os.environ.get("FLAG_SQLI",   "FLAG{sql1_un10n_r3tr0fl1x_l34k}")
FLAG_XSS    = os.environ.get("FLAG_XSS",    "FLAG{st0r3d_xss_c00k13_st34l3r}")
FLAG_CRYPTO = os.environ.get("FLAG_CRYPTO", "FLAG{b4s364_n0_3s_3ncr1pt4r}")

DB_PATH = os.environ.get("DB_PATH", os.path.join(tempfile.gettempdir(), "retroflix.db"))

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        """
        DROP TABLE IF EXISTS movies;
        DROP TABLE IF EXISTS reviews;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS secrets;

        CREATE TABLE movies (
            id    INTEGER PRIMARY KEY,
            title TEXT,
            year  TEXT,
            genre TEXT
        );

        CREATE TABLE reviews (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            movie   TEXT,
            author  TEXT,
            body    TEXT
        );

        CREATE TABLE users (
            id       INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        );

        CREATE TABLE secrets (
            id    INTEGER PRIMARY KEY,
            name  TEXT,
            flag  TEXT
        );
        """
    )

    movies = [
        (1, "Matrix",                "1999", "Ciencia ficcion"),
        (2, "Volver al Futuro",      "1985", "Aventura"),
        (3, "El Padrino",            "1972", "Drama"),
        (4, "Pulp Fiction",          "1994", "Crimen"),
        (5, "Blade Runner",          "1982", "Ciencia ficcion"),
        (6, "Terminator 2",          "1991", "Accion"),
        (7, "Jurassic Park",         "1993", "Aventura"),
        (8, "El Resplandor",         "1980", "Terror"),
    ]
    cur.executemany("INSERT INTO movies VALUES (?,?,?,?)", movies)

    # Credenciales (la tabla users es 'oculta' y se puede dumpear via SQLi)
    cur.executemany(
        "INSERT INTO users VALUES (?,?,?)",
        [
            (1, "admin", "S3rv3rR00m_K3y_2026!"),
            (2, "guest", "guest"),
        ],
    )

    # Tabla secreta con la flag de SQLi
    cur.execute(
        "INSERT INTO secrets VALUES (?,?,?)",
        (1, "sqli_flag", FLAG_SQLI),
    )

    # Reviews iniciales (texto plano normal)
    cur.executemany(
        "INSERT INTO reviews (movie, author, body) VALUES (?,?,?)",
        [
            ("Matrix",      "neo_fan",   "Un clasico absoluto, la mejor de los 90."),
            ("Blade Runner","replicant", "Visualmente increible, ritmo lento pero vale la pena."),
        ],
    )

    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    movies = db.execute("SELECT title, year, genre FROM movies").fetchall()
    return render_template("index.html", movies=movies)


# ---------------------------------------------------------------------------
# VULN 1 - SQL Injection (A03:2021)
# La query se arma por concatenacion de strings sin sanitizar.
# ---------------------------------------------------------------------------
@app.route("/buscar")
def buscar():
    q = request.args.get("q", "")
    results = None
    error = None
    query = None
    if q:
        # !!! VULNERABLE: concatenacion directa del input del usuario !!!
        query = (
            "SELECT title, year, genre FROM movies "
            "WHERE title LIKE '%" + q + "%'"
        )
        db = get_db()
        try:
            results = db.execute(query).fetchall()
        except Exception as e:
            error = str(e)
    return render_template(
        "buscar.html", q=q, results=results, error=error, query=query
    )


# ---------------------------------------------------------------------------
# VULN 2 - Stored XSS (A03:2021)
# El cuerpo de la review se renderiza SIN escapar (filtro |safe).
# ---------------------------------------------------------------------------
@app.route("/reviews", methods=["GET", "POST"])
def reviews():
    db = get_db()
    if request.method == "POST":
        movie = request.form.get("movie", "")
        author = request.form.get("author", "anonimo")
        body = request.form.get("body", "")
        # !!! VULNERABLE: se guarda el HTML/JS tal cual y luego se renderiza crudo !!!
        db.execute(
            "INSERT INTO reviews (movie, author, body) VALUES (?,?,?)",
            (movie, author, body),
        )
        db.commit()
        return redirect(url_for("reviews"))

    all_reviews = db.execute(
        "SELECT movie, author, body FROM reviews ORDER BY id DESC"
    ).fetchall()
    return render_template("reviews.html", reviews=all_reviews)


# Simula el navegador del ADMIN (la victima). Al abrir esta pagina se setea
# la cookie del admin (que contiene la flag de XSS y NO es httpOnly) y se
# renderizan las reviews crudas -> el XSS almacenado se ejecuta en su contexto.
@app.route("/admin")
def admin():
    db = get_db()
    all_reviews = db.execute(
        "SELECT movie, author, body FROM reviews ORDER BY id DESC"
    ).fetchall()
    resp = make_response(render_template("admin.html", reviews=all_reviews))
    # !!! VULNERABLE: cookie sensible accesible desde JavaScript (httponly=False) !!!
    resp.set_cookie("admin_flag", FLAG_XSS, httponly=False, samesite="Lax")
    return resp


# Endpoint donde el atacante recibe (exfiltra) las cookies robadas via XSS.
_stolen = []

@app.route("/collect")
def collect():
    c = request.args.get("c", "")
    if c:
        _stolen.append(c)
    captured = "\n".join(_stolen) if _stolen else "(todavia no se capturo nada)"
    success = any(FLAG_XSS in s for s in _stolen)
    return render_template("collect.html", captured=captured, success=success,
                           flag=FLAG_XSS if success else None)


# ---------------------------------------------------------------------------
# VULN 3 - Cryptographic Failure (A02:2021)
# La licencia premium NO esta cifrada: es solo base64 de un JSON.
# "Encoding no es encryption" -> se decodifica, se cambia premium a true
# y se vuelve a codificar.
# ---------------------------------------------------------------------------
def make_license(premium=False):
    payload = {"user": "guest", "premium": premium, "role": "user"}
    return base64.b64encode(json.dumps(payload).encode()).decode()


def b64_decode_loose(token: str) -> bytes:
    # Acepta base64 estandar o urlsafe y corrige el padding (para que sirva
    # con cualquier herramienta online o `base64` de consola).
    t = token.strip().replace("-", "+").replace("_", "/")
    t += "=" * ((4 - len(t) % 4) % 4)
    return base64.b64decode(t)


@app.route("/premium")
def premium():
    token = request.cookies.get("license")

    # Si no hay token, se entrega uno de usuario gratuito (guest).
    if not token:
        token = make_license(premium=False)
        resp = make_response(redirect(url_for("premium")))
        resp.set_cookie("license", token, samesite="Lax")
        return resp

    status = None
    is_premium = False
    try:
        decoded = b64_decode_loose(token).decode("utf-8", "replace")
        status = decoded
        data = json.loads(decoded)
        val = data.get("premium")
        is_premium = (val is True) or (str(val).strip().lower() == "true")
    except Exception as e:
        status = "Token con formato invalido: " + str(e)

    flag = FLAG_CRYPTO if is_premium else None
    return render_template(
        "premium.html",
        token=token,
        is_premium=is_premium,
        status=status,
        flag=flag,
        sample=make_license(premium=False),
    )


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
