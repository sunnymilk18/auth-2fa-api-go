# Deploy y operación — auth-2fa-api-go

Este documento es para quien administra el entorno donde corre la API: desplegarla, administrar tenants y cuentas, observabilidad, rotación de claves y el checklist antes de ponerla en producción real. Para desarrollar o integrar contra la API (cómo correrla local, el flujo de autenticación, cómo verificar un access token), ver [`README.md`](README.md).

## Gestionar clientes existentes (API keys)

Por HTTP, con el header `X-Admin-Token` (ver `ADMIN_API_TOKEN` en `.env.example` — deshabilitado si no está seteada):

```bash
curl -X POST https://tu-api/admin/clients/ \
  -H "X-Admin-Token: $ADMIN_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"nombre-de-tu-sistema"}'
```

O por línea de comandos, `cmd/createclient` tiene los mismos subcomandos:

```bash
go run ./cmd/createclient list                     # lista todos los clientes (id, activo, creado, nombre)
go run ./cmd/createclient deactivate -id <id>       # su key deja de funcionar de inmediato
go run ./cmd/createclient activate -id <id>         # reactiva un cliente desactivado
go run ./cmd/createclient rotate -id <id>           # emite una key nueva, invalida la anterior — misma identidad (id, nombre, usuarios)
```

`rotate` es la forma de recuperarse de una key filtrada sin tener que recrear el cliente ni migrar sus usuarios a otro.

## Moderación (lista negra por IP y bloqueo de cuentas)

También por HTTP, con el mismo header `X-Admin-Token`:

```bash
# Bloquear/desbloquear una cuenta puntual.
curl -X POST https://tu-api/admin/users/<id>/ban              -H "X-Admin-Token: $ADMIN_API_TOKEN"
curl -X POST https://tu-api/admin/users/<id>/unban            -H "X-Admin-Token: $ADMIN_API_TOKEN"
curl -X POST https://tu-api/admin/users/<id>/disable-totp     -H "X-Admin-Token: $ADMIN_API_TOKEN"
curl -X POST https://tu-api/admin/users/<id>/revoke-sessions  -H "X-Admin-Token: $ADMIN_API_TOKEN"
curl -X POST https://tu-api/admin/users/<id>/reset-pin        -H "X-Admin-Token: $ADMIN_API_TOKEN"

# Exigir el paso de PIN al final del login para esta cuenta (ver "PIN
# obligatorio al final del login" en el README).
curl -X PUT https://tu-api/admin/users/<id>/login-pin-required -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"required":true}'

# Corregir el correo de una cuenta (para quien se equivocó al escribirlo al
# registrarse y, como consecuencia, nunca pudo verificarlo ni recuperar su
# contraseña). No cambia nada todavía: le manda un código al correo NUEVO —
# ver "Corrección de correo" más abajo para cómo se confirma.
curl -X POST https://tu-api/admin/users/<id>/change-email -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"new_email":"correo.correcto@example.com"}'

# Listar cuentas de TODOS los sistemas a la vez (page/page_size/q — ver el
# listado de "Administración por sistema" más abajo para el detalle de estos
# parámetros). A diferencia de las cuatro rutas de arriba, esta no requiere
# conocer el id de antemano — es la forma de encontrar una cuenta sin saber a
# qué sistema pertenece. Deliberadamente NO está documentada en /docs ni en
# openapi.yaml (esas rutas se sirven sin autenticación) — su existencia solo
# debe conocerla quien ya tiene este X-Admin-Token.
curl "https://tu-api/admin/users?page=1&page_size=50&q=texto"  -H "X-Admin-Token: $ADMIN_API_TOKEN"

# Levantar antes de tiempo un baneo automático por IP.
curl -X DELETE https://tu-api/admin/blacklist/203.0.113.7 -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

Una IP que dispara cualquiera de los rate limits de la API 3 veces separadas en 24h queda baneada del todo (no solo throttleada) — 24h la primera vez, 72h la segunda, 7 días de ahí en más. El nivel de escalada se olvida solo tras 30 días sin nuevas infracciones, para no castigar para siempre una IP compartida (biblioteca pública, wifi comunitario) mucho después de que el que abusó ya se fue.

Mientras dura el baneo, cualquier petición de esa IP recibe `403` con JSON — `{"error":"...", "code":"ip_banned", "retry_after_seconds":N, "reference":"..."}` (`reference` solo si hay `BAN_REFERENCE_SECRET` configurado) — y el header `Retry-After`. Un sistema consumidor puede ver y levantar sus propios baneos sin necesitar el `X-Admin-Token` del operador — ver "Baneos automáticos por IP" en [Administración por sistema](#administración-por-sistema-credencial-scoped) más abajo.

### Lista blanca de IPs (nunca banear)

Para una IP que sabes que es tráfico legítimo pero compartido (una oficina detrás de un mismo NAT, por ejemplo), donde un pico normal de logins podría cruzar el límite por error, sin que nadie esté atacando nada. **Deliberadamente solo del operador** (`X-Admin-Token`), no expuesta a `/system-admin/*`: la exención que otorga es global — protege la IP de los límites de *todos* los sistemas, no solo del que la pida — así que dejar que cualquier sistema la controle le daría la capacidad de debilitar la protección de otros, a diferencia de todo lo demás que puede hacer con su propio `X-System-Admin-Token` (que solo afecta sus propios datos).

```bash
# Nunca banear esta IP — y si ya estaba baneada, la desbanea de inmediato.
curl -X POST https://tu-api/admin/blacklist/allowlist -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -H "Content-Type: application/json" -d '{"ip":"203.0.113.50"}'

# Ver las IPs en la lista.
curl https://tu-api/admin/blacklist/allowlist -H "X-Admin-Token: $ADMIN_API_TOKEN"
# -> {"ips":["203.0.113.50"]}

# Sacarla de la lista (vuelve a poder banearse normalmente).
curl -X DELETE https://tu-api/admin/blacklist/allowlist/203.0.113.50 -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

Si `<ip>` no tiene un formato válido, `400`. Si no estaba en la lista, `404`.

`POST /admin/users/{id}/ban` desactiva una cuenta puntual, revoca todos sus refresh tokens y dispositivos de confianza, y marca sus access tokens ya emitidos como inválidos desde ese instante (revierte con `/unban`) — a diferencia de la lista negra por IP, esto nunca se dispara solo por intentos fallidos de login, precisamente para que nadie pueda bloquear la cuenta de otra persona a propósito solo sabiendo su email/usuario/rut.

## Estadísticas

Números de solo lectura para el panel. Mismo acceso que `GET /admin/users` — cualquier administrador, no solo superadmin — y, al ser de solo lectura, no exige el PIN de operador. Deliberadamente tampoco está en `/docs` ni en `openapi.yaml`, mismo criterio que el resto de `/admin/*`.

```bash
curl "https://tu-api/admin/stats?range=7d&tz=America/Santiago" -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

- `range` es obligatorio: `7d` o `30d` (cualquier otro valor, `400`). Son días calendario, hoy incluido.
- `tz` es opcional (`America/Santiago`, `UTC`, cualquier nombre IANA real) y define en qué zona horaria se cortan los días de los bloques por día — sin especificarla, UTC. Un valor inválido, incluido `Local` (Go lo acepta como "la hora del servidor", pero acá se rechaza a propósito para que el resultado no dependa de dónde corre el contenedor), responde `400`.
- Todos los bloques por día siempre traen un elemento por cada día del rango, con `0` donde no hubo datos — nunca hay huecos para el gráfico.

**Usuarios** (sin tablas nuevas: se calcula al vuelo sobre `users`):

- `users_per_day` y `users_per_tenant` como antes — `users_per_tenant` es un top 50 por cantidad total de usuarios (no el listado completo de sistemas — para eso está `GET /admin/clients`), de mayor a menor; empates se ordenan por nombre y después por id.

**Actividad de operadores** (sobre `admin_audit_log`) — `operator_actions_per_day` y `operator_actions_by_type` solo aparecen en la respuesta si quien llama es superadmin — mismo nivel que `GET /admin/audit`. Para un administrador regular, esos dos campos no vienen (ni siquiera vacíos).

**Actividad de usuarios finales** ("tanda 2", sobre `auth_events` — ver "Eventos de autenticación de usuarios finales" más abajo) — visibles para administrador y superadmin por igual, nunca detrás de la condición anterior:

- `logins_by_day`: `[{day, success, failed}]` — intentos de login (`auth_events.kind = login`), contados por resultado.
- `failures_by_tenant`: `[{api_client_id, name, success, failed}]`, top 50 por fallos, de mayor a menor.
- `top_failing_ips`: `[{ip, failed, last_at}]`, top 10 por intentos fallidos, de mayor a menor.
- `bans_by_day`: `[{day, bans}]` — baneos de IP creados ese día (`auth_events.kind = ip_ban`), de cualquier origen.

## Eventos de autenticación de usuarios finales (`auth_events`)

Tabla append-only (migración `0020_auth_events.sql`) que registra cada intento de login, solicitud/confirmación de recuperación de contraseña y registro de usuarios finales, además del historial de baneos/desbaneos de IP — la base de la sección Estadísticas de arriba y, más adelante, de un Centro de Seguridad. No tiene endpoint de lectura propio todavía (llegará en una entrega futura, `GET /admin/security/events`) — hoy solo se consume agregada vía `GET /admin/stats`.

- Nunca guarda contraseñas, códigos, PIN ni tokens, ni el correo en claro — cuando el identificador de un intento no resuelve a una cuenta real, se guarda `email_hash` (HMAC-SHA256, ver `AUTH_EVENTS_EMAIL_HASH_SECRET` abajo) en vez de `user_id`.
- Escribir un evento nunca bloquea ni hace fallar la acción real (login, registro, etc.) — un error de escritura solo se registra en el log del servidor y en una métrica (`auth.events.write_failures`), igual que `admin_audit_log`.
- Retención configurable con `AUTH_EVENTS_RETENTION_DAYS` (90 días por defecto) — limpieza periódica cada 24h, igual que `AUDIT_RETENTION_DAYS`.
- `AUTH_EVENTS_EMAIL_HASH_SECRET` es opcional: sin configurar, el servidor arranca igual (con una advertencia en el log) y `email_hash` queda `NULL` para esos intentos — nunca se usa un hash sin clave (SHA-256 simple) como respaldo, porque eso permitiría adivinar correos por diccionario.

## Administración por sistema (credencial scoped)

Para que el equipo detrás de un sistema consumidor pueda moderar **sus propios** usuarios sin necesitar tu `X-Admin-Token` (que puede tocar todos los sistemas, no solo el suyo). Se provisiona una vez por cliente, con tu `X-Admin-Token`:

```bash
# Provisiona (o rota, si ya existía una) la credencial scoped del cliente <id>.
# El plaintext se muestra una sola vez, igual que la API key normal.
curl -X POST https://tu-api/admin/clients/<id>/system-admin-key/rotate -H "X-Admin-Token: $ADMIN_API_TOKEN"

# Revoca la credencial scoped por completo — vuelve al estado "nunca provisionada".
curl -X DELETE https://tu-api/admin/clients/<id>/system-admin-key -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

El equipo del sistema consumidor usa esa credencial contra `/system-admin/users/*` (mismas acciones que `/admin/users/*`, pero con el header `X-System-Admin-Token` en vez de `X-Admin-Token`):

```bash
curl -X POST https://tu-api/system-admin/users/<id>/ban             -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/unban           -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/disable-totp    -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/revoke-sessions -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/reset-pin       -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/change-email    -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY" \
  -d '{"new_email":"correo.correcto@example.com"}'
```

Si `<id>` pertenece a otro sistema, la respuesta es `404` (no `403`) — indistinguible de un id que directamente no existe.

### Bloqueos por intentos fallidos (login y PIN)

Cada cuenta tiene dos contadores independientes de intentos fallidos — el de `/auth/login` (`LoginAttemptLimiter`) y el del PIN de cuenta (ver "PIN de cuenta" en el README) — que se bloquean temporalmente tras varios fallos seguidos. Para verlos y, si hace falta, limpiarlos sin esperar a que expiren solos:

```bash
# Estado actual de ambos bloqueos.
curl https://tu-api/system-admin/users/<id>/lockouts -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
# -> {"login":{"locked":false,"retry_after_seconds":0},"pin":{"locked":true,"retry_after_seconds":612}}

# Limpiar uno de los dos, o ambos.
curl -X POST https://tu-api/system-admin/users/<id>/clear-lockouts -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY" \
  -d '{"which":"pin"}'   # "login" | "pin" | "all"
```

`clear-lockouts` solo pone el contador en cero — **no** revoca sesiones, no borra el PIN ni toca dispositivos de confianza (eso es lo que hacen `revoke-sessions`/`reset-pin` más arriba, por separado). Mismo criterio de aislamiento por tenant que el resto de `/system-admin/users/*`.

### Baneos automáticos por IP

La lista negra automática por IP (ver "Lista negra automática por IP" en `DEPLOY.md` más abajo) es, por diseño, global — una IP baneada queda bloqueada para cualquier sistema, no solo el que la disparó. Pero **cada baneo tiene un único sistema dueño**: el que hizo la petición que terminó de cruzar el umbral y creó ese baneo en particular. `/system-admin/blacklist` solo muestra y permite levantar los baneos de los que tu sistema es dueño — nunca los de otro, y nunca los creados antes de que esto existiera (esos solo los levanta el operador, con `X-Admin-Token`, vía `/admin/blacklist`).

```bash
# Baneos vigentes que tu sistema generó (hasta 200, sin paginación por ahora).
curl https://tu-api/system-admin/blacklist -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
# -> {"bans":[{"ip":"203.0.113.7","reference":"a1b2c3d4","banned_at":1234,"banned_until":5678,"level":1,"strikes":3}]}

# Levantarlo antes de tiempo (motivo opcional, queda en los logs).
curl -X DELETE https://tu-api/system-admin/blacklist/203.0.113.7 -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY" \
  -d '{"reason":"confirmado con la persona, era un error de tipeo en la contraseña"}'
```

`reference` solo aparece si configuraste `BAN_REFERENCE_SECRET` (ver variables opcionales en el README) — un código corto y estable derivado de la IP, pensado para que tu panel se lo muestre a la persona bloqueada sin revelarle su propia IP. Una IP que pertenece a `TRUSTED_PROXY_CIDRS` (tu propio proxy/backend) nunca puede terminar baneada — esa es la salvaguarda que evita que un bug tuyo (por ejemplo, una llamada que olvidó mandar `X-Forwarded-For`) tire abajo toda tu integración de un saque.

Si `<ip>` no tiene un formato válido, `400`. Si no está baneada, pertenece a otro sistema, o es un baneo anterior a esta función (sin dueño registrado), `404` — mismo criterio que el resto de `/system-admin/*`, nunca `403`.

Para una IP que nunca debería banearse (una oficina propia detrás de un mismo NAT, por ejemplo, donde un pico normal de logins podría cruzar el límite sin que nadie esté atacando nada) existe una lista blanca — pero es **solo del operador**, no de cada sistema: ver "Lista blanca de IPs (nunca banear)" más arriba. La razón: la exención que otorga es global (protege la IP de los límites de *todos* los sistemas, no solo del que la agregó), así que dejar que cualquier `X-System-Admin-Token` la controle le daría a un sistema la capacidad de debilitar la protección de otros — a diferencia de todo lo demás en `/system-admin/*`, que solo puede afectar sus propios datos.

La misma credencial también sirve para listar las cuentas del tenant — la única ruta de este grupo sin `{id}`:

```bash
curl "https://tu-api/system-admin/users?page=1&page_size=50&q=texto" -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
```

Devuelve una página (`page`/`page_size`, paginado con `COUNT(*) OVER()` para el `total`) de las cuentas registradas, incluidas las que nunca terminaron de registrarse (correo sin verificar, sin segundo factor elegido) — sin campos sensibles (hash de contraseña, secreto TOTP). `q` es opcional: busca coincidencia parcial, sin distinguir mayúsculas/minúsculas, sobre `email`, `username` y `rut`. Es el mismo handler que atiende `GET /admin/users` de arriba — cuál de los dos tokens autenticó la petición es lo único que decide si el resultado queda acotado a un tenant o abarca todos.

## Corrección de correo

Para una cuenta que se equivocó al escribir su correo al registrarse: nunca recibió el código de verificación, así que no puede loguear ni usar la recuperación de contraseña (ambos requieren un correo que funcione). `POST /system-admin/users/{id}/change-email` (o su versión sin acotar, `/admin/users/{id}/change-email`) inicia la corrección — **no cambia nada todavía**, solo valida el correo nuevo (formato y que no esté en uso en ese sistema) y le envía un código.

El administrador **nunca ve ese código**. Quien lo confirma es la propia cuenta, con una ruta pública (solo `X-API-Key`, sin token de administrador ni sesión — la persona puede estar completamente bloqueada de la cuenta en este punto):

```bash
curl -X POST https://tu-api/auth/change-email/confirm -H "X-API-Key: $API_KEY" \
  -d '{"email":"correo.correcto@example.com","code":"123456"}'
```

Al confirmarse: se aplica el cambio, se marca la cuenta como verificada (el problema que esto resuelve de raíz), y se revocan todas sus sesiones, refresh tokens y dispositivos de confianza — mismo criterio que un reset de contraseña. Solo puede haber un cambio pendiente por cuenta a la vez; pedir otro reemplaza al anterior, sin importar si apunta a un correo distinto.

El correo que recibe el correo **nuevo** puede incluir, además del código, un enlace a la pantalla de confirmación del panel (`/confirmar-correo?email=<correo nuevo, con URL-encoding>`) — nunca lleva el código. El enlace solo aparece si hay un panel configurado: por tenant (`PUT /admin/clients/{id}/panel-base-url`, con `{"panel_base_url":"https://panel.tu-tenant.com"}`) o, como respaldo general, con la variable de entorno `PANEL_BASE_URL`. Sin ninguno configurado, el correo sale igual que antes, sin enlace. El aviso al correo **anterior** nunca lleva este enlace.

```bash
curl -X PUT https://tu-api/admin/clients/<id>/panel-base-url -H "X-Admin-Token: $ADMIN_API_TOKEN" \
  -d '{"panel_base_url":"https://panel.tu-tenant.com"}'
```

## Deploy en producción

Corre en un VPS propio, gestionado con [Dokploy](https://dokploy.com) (PaaS autoalojado — build desde `Dockerfile`, deploy desde `docker-compose.yml`, proxy/dominios vía Traefik). No depende de ningún proveedor de PaaS externo — el mismo `Dockerfile`/`docker-compose.yml` de este repo sirve para desplegar en cualquier Docker Compose, gestionado por Dokploy o no.

1. **Conecta el repo a Dokploy** como proyecto tipo *Compose* (o pega el contenido de `docker-compose.yml` directo si prefieres no linkear un repo).
2. **Variables de entorno**: las mismas que en `.env` local (`JWT_REFRESH_SECRET`, `RESEND_API_KEY`, `ADMIN_API_TOKEN` si la vas a usar, etc.) — se cargan en el panel de Environment Variables del proyecto, no en un `.env` en disco.
3. **Claves RS256**: `keys/private.pem`/`public.pem` se montan como volumen (ver `docker-compose.yml`) — no van en el repo (`.gitignore`), hay que dejarlas en el filesystem del servidor antes del primer deploy.
4. **Deploy**. `migrate` corre una vez, aplica el schema, y `api` recién arranca después de que termine bien — no hace falta correr nada a mano.
5. **Dominio + HTTPS**: agrégale un dominio al servicio `api` desde el panel de Domains — Dokploy/Traefik gestiona el certificado. **Importante antes de darle esta URL a un tercero real**: sin dominio+HTTPS, las credenciales viajan sin cifrar.
6. **Firewall, dos capas**: si tu VPS tiene firewall a nivel de nube además del propio del SO (ej. Security Lists/NSG en OCI + `iptables`/`ufw` en la instancia), **las dos** necesitan permitir el tráfico — abrir una sola capa no alcanza, y cerrar una sola también basta para bloquear. Solo deberían estar expuestos a `0.0.0.0/0` los puertos que de verdad necesitan acceso público directo (típicamente 80/443 vía Traefik); cualquier otro servicio (Prometheus, Grafana, la propia API en su puerto interno) que un proxy ya alcance por la red interna del proyecto no necesita (ni debería) estar publicado también hacia afuera.

**Nota sobre Resend en modo sandbox**: con `RESEND_FROM=onboarding@resend.dev` (el default, sin verificar dominio propio) solo se puede enviar correo a la dirección de tu propia cuenta de Resend — cualquier otro destinatario falla. Para que usuarios reales puedan registrarse, hay que verificar un dominio propio en el dashboard de Resend y usar una dirección de ese dominio como `RESEND_FROM`.

## Observabilidad

Métricas y logs, vía [OpenTelemetry](https://opentelemetry.io) — ver `internal/telemetry` (`SetupMetrics`/`SetupLogging`) y `internal/middleware` (`Metrics`, `RequestLogger`). Opcional: sin `OTEL_EXPORTER_OTLP_ENDPOINT`, la API funciona idéntico, solo sin exportar nada (los logs siguen viéndose por stdout igual).

**Arquitectura**: `api` → OTel Collector (OTLP) → Prometheus (métricas) / Loki (logs) → Grafana.

- **Métricas**: `http_server_request_count_total` (contador) y `http_server_request_duration_seconds` (histograma), con labels `http_method`, `http_route` (el patrón de chi, no el path crudo — evita una serie nueva por cada id de recurso) y `http_status_code`.
- **Logs**: JSON estructurado (`log/slog`) — siempre a stdout, y además por OTLP si está configurado. Incluye tanto los logs de arranque de `cmd/api` como uno por cada request (`internal/middleware/logging.go`).

**`OTEL_EXPORTER_OTLP_ENDPOINT`** tiene que ser una URL completa **con esquema** (`http://otel-collector:4318`, no `otel-collector:4318` a secas) — el SDK de OTel la lee dos veces (una vez por su cuenta, otra por las opciones explícitas del código) y sin el esquema arma una URL final corrupta.

### Local (Docker Compose)

Automático — `docker-compose.yml` ya incluye `otel-collector`, `prometheus`, `loki` y `grafana`, con Prometheus/Loki pre-conectados como datasources y un dashboard (`grafana/provisioning/dashboards/auth-2fa-api.json`) pre-cargado.

- API: `http://localhost:8080`
- Prometheus: `http://localhost:9090`
- Loki: `http://localhost:3100` (sin UI propia, se consulta desde Grafana)
- Grafana: `http://localhost:3000` (`admin`/`admin`, acceso anónimo de solo lectura también habilitado)

### Producción (Dokploy)

Todo corre en un mismo proyecto Compose en Dokploy — `api`, `postgres`, `redis`, `otel-collector`, `prometheus`, `loki` y `grafana` comparten la misma red interna y se resuelven por nombre de servicio, igual que en local.

- `docker-compose.otel-collector.yml` y `docker-compose.loki.yml`: versiones standalone alternativas, con la config embebida (`configs:` con `content:` inline), por si en algún momento se despliega alguna de esas dos piezas como proyecto Compose separado (pegando el contenido directo en Dokploy, sin depender de un repo) — en ese caso sí hay que conectarlas por dominio/URL pública en vez de por nombre de servicio, porque proyectos distintos de Dokploy no comparten red entre sí.
- El dashboard de Grafana (`grafana/provisioning/dashboards/auth-2fa-api.json`) se importa manualmente ahí (Dashboards → New → Import) — Dokploy no provisiona archivos de dashboard automáticamente como sí hace con los datasources.
- Los datasources de Grafana necesitan un `uid` fijo (`prometheus-ds`, `loki-ds`) para que el dashboard los encuentre sin preguntar nada al importar — ver los comentarios en `grafana/provisioning/datasources/*.yaml`.
- **Solo deben quedar expuestos a internet los puertos que Traefik necesita (80/443)** — ni la API, ni Prometheus, ni Grafana deberían tener su puerto publicado directo hacia `0.0.0.0/0`: Traefik ya les habla por la red interna del proyecto, y un servicio propio que necesite consumir la API (ej. un backend que reenvía login/registro) también debería hablarle por esa misma red interna en vez de por su dominio público — ver `TRUSTED_PROXY_CIDRS` en el README.

## Rotación de claves JWT

El access token se firma con una sola clave RSA a la vez, pero `/.well-known/jwks.json` puede publicar más de una — el JWT lleva su `kid` (key id) en el header, y `ParseAccessToken` busca la clave pública que corresponda a ese `kid` en vez de asumir que hay una sola. Esto permite rotar la clave de firma sin invalidar de golpe los tokens que ya estaban circulando: durante una ventana de solapamiento, la clave vieja sigue publicada (solo para verificar, ya no para firmar) hasta que ningún token firmado con ella pueda seguir siendo válido.

**Cuándo rotar**: como higiene de rutina, cada 6-12 meses alcanza para un proyecto de este tamaño — no hay ganancia real en rotar más seguido si nadie más tiene acceso a la clave. Rota de inmediato, sin esperar al cronograma, si sospechas que la clave privada pudo haberse expuesto (un backup filtrado, acceso no autorizado al servidor, etc.).

**Procedimiento** (dos deploys, con una espera en el medio):

1. Genera el par de claves nuevo (mismo comando que en [Claves RS256, en el README](README.md#claves-rs256-para-el-access-token), a otro archivo para no pisar el actual) y elige un `kid` nuevo (ej. `auth-2fa-api-2` si el actual es `auth-2fa-api-1`).
2. En las variables de entorno del deploy, configura:
   - `JWT_PREVIOUS_KEY_ID` = el `kid` **actual** (el que está por dejar de firmar).
   - `JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64` = la clave **pública** actual, en base64 (`base64 -w0 keys/public.pem`, o el equivalente de tu SO) — la privada vieja ya no hace falta para nada.
   - `JWT_PRIVATE_KEY_PATH` (o `JWT_PRIVATE_KEY_PEM_BASE64`) + `JWT_KEY_ID` = la clave nueva.
3. Deploy. Desde acá: los tokens nuevos se firman con la clave nueva; el JWKS publica las dos; los tokens ya emitidos (hasta `ACCESS_TOKEN_TTL` de antigüedad) siguen verificando con la vieja.
4. Esperá al menos `ACCESS_TOKEN_TTL` (15m por default) más un margen — una hora es de sobra.
5. Saca `JWT_PREVIOUS_KEY_ID` y `JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64` de las variables de entorno. Deploy de nuevo. El JWKS vuelve a tener una sola clave — rotación terminada.

## Checklist para el equipo de TI antes de producción

Esta API en sí misma no depende de nada de esto para funcionar en desarrollo/pruebas — pero antes de que la use gente real, hay una capa de infraestructura y operación que le corresponde a quien administre el entorno final, no al desarrollo de la API. Se las dejamos listadas acá para que no se pierdan en el traspaso.

- **HTTPS obligatorio, no opcional**: el dominio final necesita certificado válido y debería rechazar tráfico por HTTP plano (redirigir o cerrar el puerto), no solo "tenerlo disponible". Sin esto, credenciales y tokens viajan sin cifrar. Ver [Deploy en producción](#deploy-en-producción) — Dokploy/Traefik lo gestiona, pero hay que confirmar que quede forzado.
- **Backups de PostgreSQL, con restore probado**: hoy no hay ninguna política de backup configurada. Un backup que nunca se probó restaurar no es un backup real — hace falta definir frecuencia, retención, y probar el restore al menos una vez antes de ir a producción.
- **Gestión de secretos**: `JWT_REFRESH_SECRET`, `JWT_PRIVATE_KEY_PATH`/`JWT_PRIVATE_KEY_PEM_BASE64`, `ADMIN_API_TOKEN`, `TOTP_ENCRYPTION_KEY` (si se usa), `RESEND_API_KEY`, `FIREBASE_CREDENTIALS_PATH`/`FIREBASE_CREDENTIALS_JSON_BASE64` (si se usa push — preferí la variante base64 salvo que hayas confirmado que el volumen del archivo realmente llega al contenedor), la contraseña de Postgres — hoy viven como variables de entorno (o archivos en `keys/`) en el panel de Dokploy. Funciona, pero para un ente público conviene evaluar algo más auditable (quién puede verlas, cuándo se rotaron, registro de acceso), según la política interna que ya tengan. `TOTP_ENCRYPTION_KEY` en particular no tiene hoy un procedimiento de rotación (a diferencia de las claves JWT — ver arriba): rotarla sin migrar primero los secretos ya cifrados dejaría ilegibles los de todas las cuentas que ya activaron la app autenticadora.
- **Alertas activas, no solo dashboards**: el stack de [Observabilidad](#observabilidad) ya expone todo lo necesario (métricas de error rate, latencia, salud del servicio) pero nadie recibe una notificación si algo se rompe fuera de horario — hoy hay que entrar a Grafana a mirar. Conviene conectar alertas (Grafana Alerting, o lo que ya usen) sobre esas mismas métricas.
- **Redundancia / alta disponibilidad**: todo corre en un único VPS (ver [Producción (Dokploy)](#producción-dokploy)) — si esa máquina se cae, el sistema completo se cae con ella. Si el municipio requiere continuidad de servicio, esto necesita evaluarse aparte (más de una instancia, balanceo de carga, etc.).
- **Protección a nivel de borde (WAF / anti-DDoS)**: el rate limiting de esta API (`internal/middleware.RateLimiter`/`Blacklist`, por IP y por cuenta, con escalada a baneo automático — ver [Arquitectura, en el README](README.md#arquitectura)) protege contra fuerza bruta sobre credenciales y OTP, pero no contra un ataque volumétrico de verdad contra la infraestructura — eso se resuelve en la capa de red/proxy, no en la aplicación.
- **Pruebas de carga**: nunca se verificó cuánto tráfico real aguanta esta configuración. Antes de anunciar el servicio a todo el municipio, vale la pena simular la carga esperada.
- **Cumplimiento legal y normativo**: fuera del alcance de este documento — el municipio ya cuenta con su propio proceso para esto.
