# auth-2fa-api-go

API independiente en Go para autenticación con doble factor por correo (email + contraseña, luego código OTP enviado por email; el correo debe verificarse antes de poder loguear). Pensada para que cualquier otro sistema la consuma vía HTTP.

## Arquitectura

- **PostgreSQL**: datos persistentes de usuarios (`users`) y tokens de refresco (`refresh_tokens`).
- **Redis**: códigos de corta duración (OTP de login, verificación de correo, reset de contraseña — todos expiran solos vía TTL, no se guardan en Postgres) y contadores de rate limiting.
- **JWT**:
  - Access token firmado con **RS256** (clave privada/pública) — cualquier sistema que reciba el token puede verificarlo por su cuenta usando la clave pública publicada en `/.well-known/jwks.json`, sin llamar de vuelta a esta API.
  - Refresh token firmado con **HS256** (secreto compartido) — de uso exclusivo interno (`/auth/refresh`, `/auth/logout`), rotado en cada uso y revocable desde Postgres.
- **Rate limiting**: por IP, con contador en Redis, sobre `/auth/register`, `/auth/login`, `/auth/verify-otp`, `/auth/devices/login`, `/auth/password-reset/*` y `/auth/verify-email/*` — mitiga fuerza bruta sobre contraseñas, códigos OTP y PINs. Además, `/auth/login` tiene un segundo límite **por cuenta** (`LOGIN_MAX_FAILED_ATTEMPTS`/`LOGIN_LOCKOUT_WINDOW`) — el límite por IP no detecta a alguien probando contraseñas contra una cuenta puntual desde muchas IPs distintas; es un throttle temporal, no un bloqueo permanente (eso sería, en sí mismo, una forma de bloquear a otra persona a propósito).
- **Dispositivos de confianza + PIN**: capa adicional opcional — tras un login completo, un dispositivo puede quedar marcado como confiable (tabla `trusted_devices`, mismo Postgres) y reautenticarse después solo con `device_id` + `device_token` + PIN de 6 dígitos, sin repetir password ni OTP por correo.
- **Multi-tenant (API keys)**: cada sistema consumidor (app móvil, web, etc.) se identifica con una API key propia en el header `X-API-Key`. Los usuarios quedan aislados por sistema — el mismo email, username o rut puede existir como cuentas distintas bajo dos API keys diferentes.
- **Identidad del usuario**: además de email + password, cada cuenta tiene `username` (8-32 caracteres, no único entre personas, sin forma de rut aunque tenga puntos/guiones, sin "@") y `rut` (documento chileno, único por sistema, validado con dígito verificador). El login acepta cualquiera de los tres — email, username o rut — en un único campo `identifier`, detectado automáticamente por su forma.
- **CORS**: habilitado para cualquier origen (`*`), sin credenciales — la API se autentica por headers (`X-API-Key`, `Authorization`), no por cookies de sesión, así que no hay nada que filtrar abriendo el origen a todos. Cada sistema consumidor puede llamar desde su propio frontend sin que haga falta mantener una lista de dominios permitidos.
- **Documentación**: especificación OpenAPI servida en `/openapi.yaml`, con UI interactiva (Swagger UI) en `/docs`.
- **Observabilidad**: métricas (Prometheus) y logs estructurados (Loki) vía OpenTelemetry — ver [Observabilidad](#observabilidad) más abajo.
- **Envío de correo**: interfaz `mailer.Mailer` — implementación actual usa la API HTTP de [Resend](https://resend.com), no SMTP a propósito: varios proveedores cloud (PaaS) bloquean o filtran puertos SMTP salientes, algo que este proyecto sufrió literalmente en un despliegue real. Cambiar de proveedor implica solo escribir una nueva implementación de esa interfaz.

## Flujo de autenticación

Todas las rutas `/auth/*` requieren el header `X-API-Key` (ver [Multi-tenant](#multi-tenant-api-keys) más abajo).

1. `POST /auth/register` — crea el usuario (email + password hasheado con bcrypt + username + rut), dentro del sistema identificado por la API key, y envía un código de verificación por correo (ver [Verificación de correo](#verificación-de-correo) más abajo). La cuenta existe desde ya, pero no puede loguear hasta confirmarlo.
   - `email`: formato validado (un solo "@", dominio con punto, sin espacios) — no alcanza con que no esté vacío.
   - `username`: 8-32 caracteres, no puede tener forma de rut (ni siquiera con puntos/guiones — `"1234.5678"` también se rechaza) ni contener "@" (ver por qué en el paso 2), y no tiene que ser único entre personas — si ya está tomado, el registro falla con `409` sugiriendo una alternativa libre (ej. `"el usuario 'juan.perez' ya está en uso, probá con 'juan.perez2'"`).
   - `rut`: documento de identidad chileno, único por sistema, validado con el dígito verificador (módulo 11) — acepta cualquier formato de entrada (`12.345.678-5`, `12345678-5`, `123456785`).
2. `POST /auth/login` — valida `identifier` + `password`. `identifier` acepta el email, el username **o** el rut de la cuenta — el backend prueba las tres columnas en una sola consulta (`email = ? OR username = ? OR rut = ?`), sin adivinar antes cuál es cuál (nada que el cliente tenga que indicar aparte: un solo campo, sin selector de "con qué querés loguear"). Es justamente por esto que `username` no puede tener forma de rut ni contener "@": si se permitiera, el username de una persona podría coincidir con el rut o el email real de otra, y esa consulta ya no sería segura. Si son correctos pero el correo todavía no fue verificado, devuelve un error (403) en vez de continuar — ver más abajo por qué. Si todo está en orden, genera un código OTP, lo guarda (hasheado) en Redis con expiración, lo envía por correo y devuelve un `login_token` (no el código).
3. `POST /auth/verify-otp` — recibe `login_token` + `code`. Si coincide, emite `access_token` + `refresh_token`.
4. `POST /auth/refresh` — recibe `refresh_token` válido, emite un nuevo par de tokens (rotación).
5. `POST /auth/logout` — revoca un `refresh_token`.
6. `GET /me` — ejemplo de endpoint protegido (requiere `Authorization: Bearer <access_token>`); devuelve `id`, `email`, `username` y `rut`.

### Dispositivo de confianza + PIN (opcional, atajo alrededor de 1-3)

7. `POST /auth/devices/register` (protegido, justo después de un login completo) — marca el dispositivo actual como confiable con un PIN de 6 dígitos; devuelve un `device_token` que el cliente debe guardar en almacenamiento seguro local (se muestra una sola vez).
8. `POST /auth/devices/login` — con `device_id` + `device_token` + `pin`, emite un nuevo par `access_token`/`refresh_token` sin pasar por password ni OTP. Un dispositivo desconocido siempre falla aquí y debe usar el flujo 1-3. El `device_token` se rota en cada uso — la respuesta trae uno nuevo que reemplaza al anterior.
9. `GET /auth/devices` (protegido) — lista los dispositivos de confianza del usuario.
10. `DELETE /auth/devices/{id}` (protegido) — revoca un dispositivo (útil si se perdió el teléfono).

La confianza dura 30 días desde el último uso (ventana deslizante, `DEVICE_TRUST_TTL`), y el dispositivo se revoca automáticamente tras 5 PIN incorrectos seguidos (`DEVICE_PIN_MAX_TRIES`).

### Recuperación de contraseña

11. `POST /auth/password-reset/request` — recibe `email`. Si existe una cuenta con ese correo en el sistema (API key) que llama, genera un código numérico corto (como el OTP de login, `PASSWORD_RESET_CODE_LENGTH` dígitos), lo guarda hasheado en Redis (TTL configurable, `PASSWORD_RESET_TTL`) y lo envía por correo. **La respuesta es idéntica exista o no la cuenta** — no filtra qué correos están registrados, igual que `/auth/login`.
12. `POST /auth/password-reset/confirm` — recibe `email` + `code` + `new_password`. El código es de un solo uso y tiene un límite de intentos (`PASSWORD_RESET_MAX_TRIES`, igual que el OTP de login) — a diferencia del OTP, este código no está protegido por una contraseña correcta de antemano (cualquiera que sepa el email puede intentarlo), por eso necesita ese mismo límite de intentos. Al confirmarse con éxito se **revocan todas las sesiones activas (refresh tokens) y todos los dispositivos de confianza (PIN)** del usuario — un reset de contraseña fuerza a volver a autenticarse en todos lados, ya que el dispositivo de confianza es un atajo que bypasea password+OTP por completo y no debería sobrevivir a un reset motivado por una posible cuenta comprometida.

### Verificación de correo

`POST /auth/register` no deja la cuenta lista para usar de inmediato: manda un código numérico (mismo mecanismo que el OTP de login — hasheado, con límite de intentos, `EMAIL_VERIFICATION_CODE_LENGTH`/`EMAIL_VERIFICATION_MAX_TRIES`) y `/auth/login` **rechaza el login con 403** hasta que se confirme, incluso con la contraseña correcta. Esto no es solo una formalidad: sin esto, cualquiera podría registrar una cuenta usando el correo real de otra persona (sin su consentimiento) y usarla de inmediato — cada intento de login futuro le mandaría a esa persona un código OTP que nunca pidió recibir. Bloquear el login hasta confirmar el correo hace que quien registró la cuenta necesite, de entrada, poder leer ese correo.

13. `POST /auth/verify-email/confirm` — recibe `email` + `code`. Consume el código (un solo uso, con límite de intentos) y marca la cuenta como verificada, desbloqueando `/auth/login`.
14. `POST /auth/verify-email/resend` — recibe `email`. Reenvía un código nuevo (invalida cualquiera pendiente) para una cuenta que todavía no se verificó — por si el primer correo se perdió o el código expiró (`EMAIL_VERIFICATION_TTL`, por default 24h, bastante más laxo que el OTP de login ya que confirmar una cuenta nueva es menos urgente que un login en curso).

A diferencia de `/auth/password-reset/*`, estos dos endpoints no necesitan ocultar si la cuenta existe — `/auth/register` ya revela eso mismo con su propio error de "correo ya registrado".

**Registrarse de nuevo con un correo que todavía no se verificó reclama esa cuenta en vez de rechazarla** (contraseña nueva, estado sin verificar de nuevo) — una cuenta nunca confirmada no probó que su dueño realmente controla ese correo, así que no hay nada legítimo que proteger rechazando el intento nuevo. Sin esto, un solo error de tipeo al registrarse dejaría ese correo ocupado para siempre por una cuenta zombi que nadie puede confirmar, bloqueando a su dueño real de registrarse alguna vez (el email es único por sistema, y nada más libera una cuenta sin verificar abandonada). Solo una cuenta ya **verificada** sigue bloqueando el registro duplicado con `409`.

## Requisitos previos

- Go 1.26+
- Una cuenta en [Resend](https://resend.com) (gratis) con una API key generada — se usa para enviar los códigos OTP, de verificación de correo y de reset de contraseña
- PostgreSQL y Redis — dos formas, elegí una:
  - **Con Docker** (más simple si ya lo tenés instalado): `docker-compose.yml` levanta Postgres y Redis por vos — ver [Ejecutar con Docker Compose](#ejecutar-con-docker-compose) más abajo. No hace falta nada de lo que sigue en esta sección.
  - **Sin Docker**, con capas gratuitas en la nube (no requiere instalar nada localmente):

### PostgreSQL con Neon (gratis)

1. Crea una cuenta en https://neon.tech
2. Crea un proyecto → te da una **connection string** tipo `postgres://usuario:password@ep-xxxx.neon.tech/neondb?sslmode=require`
3. Copia esa cadena a `POSTGRES_DSN` en tu `.env`

### Redis con Upstash (gratis)

1. Crea una cuenta en https://upstash.com
2. Crea una base Redis → en el dashboard copia la URL que empieza con `rediss://` (con TLS)
3. Copia esa URL a `REDIS_URL` en tu `.env`

## Configuración

```bash
cp .env.example .env
# Edita .env: POSTGRES_DSN (Neon), REDIS_URL (Upstash), JWT_REFRESH_SECRET y RESEND_API_KEY
```

Genera un secreto fuerte para el refresh token:

```bash
openssl rand -base64 48
```

### Claves RS256 para el access token

El access token se firma con RSA (RS256), no con un secreto compartido. Genera el par de claves una sola vez:

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

`JWT_PRIVATE_KEY_PATH` en `.env` ya apunta a `keys/private.pem` por defecto. **La carpeta `keys/` está en `.gitignore` — nunca se sube al repo.** Cada entorno (dev, staging, prod) debería generar su propio par de claves; la clave pública se distribuye vía el endpoint `/.well-known/jwks.json`, no hace falta compartirla manualmente.

### Variables opcionales

- **`ADMIN_API_TOKEN`**: habilita `/admin/clients/*` (gestionar API keys por HTTP en vez de solo por CLI — ver [Gestionar clientes existentes](#gestionar-clientes-existentes)). Sin setear, esas rutas ni siquiera existen (404, no "abiertas sin auth"). Generá un secreto fuerte igual que el del refresh token (`openssl rand -base64 48`) si la vas a usar.
- **`OTEL_EXPORTER_OTLP_ENDPOINT`**: habilita el envío de métricas y logs a un collector de OpenTelemetry — ver [Observabilidad](#observabilidad) más abajo. Sin setear, la API funciona igual, solo sin exportar telemetría (los logs siempre se ven por stdout de todas formas).

## Base de datos

Con `POSTGRES_DSN` configurado en `.env`, aplica todas las migraciones (`migrations/*.sql`, en orden) con la herramienta incluida en el proyecto — no necesitas tener `psql` instalado:

```bash
go run ./cmd/migrate
```

(Alternativa manual: pegar el contenido de cada archivo en el **SQL Editor** del dashboard de Neon.)

Redis (Upstash) no necesita migración — las claves OTP y de rate limiting se crean solas con TTL.

**Nota sobre la migración `0004`**: agrega el aislamiento por sistema (multi-tenant) a la tabla `users`. En una base nueva se activa sola en este mismo paso, sin nada más que hacer. El único caso especial es una base que ya tenía usuarios *antes* de que existiera el aislamiento por tenant: ahí hay que crear primero un `api_client` (ver la sección siguiente) al que asignarles esos usuarios existentes, y volver a correr `go run ./cmd/migrate` para que los reasigne.

## Multi-tenant (API keys)

Cada sistema que va a consumir esta API (una app móvil, un sitio web, etc.) necesita su propia API key. Los usuarios quedan aislados por sistema — el mismo email, username o rut puede existir como cuentas distintas en dos sistemas diferentes.

### Crear el primer cliente

```bash
go run ./cmd/createclient -name nombre-de-tu-sistema
```

`-name` es solo descriptivo — usá el que identifique al sistema que va a consumir la API (una app, un sitio, etc.), no hay un valor especial requerido. Esto imprime la API key **una sola vez** — cópiala de inmediato, no se puede recuperar después (solo se guarda su hash).

### Usarla

El sistema consumidor debe enviar la key en cada request a `/auth/*`:

```
X-API-Key: sk_live_...
```

Sin ese header (o con una key inválida/inactiva), la API responde `401`.

**Importante para quien vaya a consumir la API — dónde NO poner esta key:** `X-API-Key` identifica a tu sistema, no a un usuario individual — es un secreto de servidor, no algo que deba viajar dentro de código que corre en el dispositivo del usuario final (JavaScript de navegador, una app móvil). Cualquiera puede extraerla abriendo las devtools del sitio o descompilando el APK. El patrón correcto es que **tu propio backend** sea el que llame a esta API con la key — tu frontend/app le habla a tu backend, nunca directo a `auth-2fa-api` con la key embebida. Si tu key se filtra igual (pasa), `rotate` (ver abajo) la reemplaza sin tener que recrear el cliente.

### Gestionar clientes existentes

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

## Ejecutar

```bash
go mod tidy
go run ./cmd/api
```

El servidor arranca en `http://localhost:8080`.

## Ejecutar con Docker Compose

Alternativa a lo de arriba: `docker-compose.yml` levanta todo junto — Postgres, Redis, migraciones aplicadas automáticamente, la API, y el stack completo de observabilidad (ver [Observabilidad](#observabilidad)).

**Antes de arrancar:**
1. Par de claves RS256 generado (`keys/private.pem` + `keys/public.pem` — ver [Claves RS256](#claves-rs256-para-el-access-token) más arriba), legible por el usuario no-root del contenedor (`chmod 644 keys/*.pem` si hace falta).
2. Un `.env` en la raíz con al menos `JWT_REFRESH_SECRET` y `RESEND_API_KEY` — Compose lo lee solo para las sustituciones `${VAR}` del archivo.

```bash
docker compose up --build
```

- API: `http://localhost:8080`
- Prometheus: `http://localhost:9090`
- Loki: `http://localhost:3100` (sin UI propia, se consulta desde Grafana)
- Grafana: `http://localhost:3000` (`admin`/`admin`, acceso anónimo de solo lectura también habilitado) — con Prometheus, Loki y un dashboard de la API ya provisionados, nada que configurar a mano.

Para crear un cliente (API key) sin salir del compose:
```bash
docker compose run --rm api ./createclient create -name "mi-app"
```

No incluye un servidor de correo local a propósito: Resend es una API HTTP hacia la nube de Resend, no algo autoalojable — simplemente usá tu `RESEND_API_KEY` real (la de sandbox alcanza), es una llamada saliente igual desde un contenedor que desde tu máquina.

## Tests

```bash
go test ./...
```

Corre toda la suite. Los tests que necesitan Postgres (la mayoría) se **saltan** (no fallan) si no encuentran una base disponible — para que corran de verdad, apuntá `TEST_POSTGRES_DSN` a una base local descartable:

```bash
# Linux/macOS/Git Bash:
TEST_POSTGRES_DSN="postgres://postgres:postgres@localhost:5432/auth2fa_test?sslmode=disable" go test ./...
```
```powershell
# PowerShell:
$env:TEST_POSTGRES_DSN = "postgres://postgres:postgres@localhost:5432/auth2fa_test?sslmode=disable"
go test ./...
```

Aplica las migraciones a esa base automáticamente — no hace falta correr `cmd/migrate` a mano primero. Los tests que dependen de Redis no necesitan nada externo: usan un Redis en memoria (`miniredis`) que arranca solo.

Flags útiles: `-v` (detalle de cada test, no solo el resumen), `-count=1` (ignora el caché de resultados), `-run <patrón>` (solo los tests cuyo nombre matchea), y limitar a un paquete con `go test ./internal/auth/...`.

El CI (`.github/workflows/ci.yml`) corre exactamente esto en cada push, contra un Postgres efímero — no hace falta correrlo a mano antes de subir cambios, pero es lo primero a probar localmente si el CI falla.

## Deploy en producción

Corre en un VPS propio, gestionado con [Dokploy](https://dokploy.com) (PaaS autoalojado — build desde `Dockerfile`, deploy desde `docker-compose.yml`, proxy/dominios vía Traefik). No depende de ningún proveedor de PaaS externo — el mismo `Dockerfile`/`docker-compose.yml` de este repo sirve para desplegar en cualquier Docker Compose, gestionado por Dokploy o no.

1. **Conectá el repo a Dokploy** como proyecto tipo *Compose* (o pegá el contenido de `docker-compose.yml` directo si preferís no linkear un repo).
2. **Variables de entorno**: las mismas que en `.env` local (`JWT_REFRESH_SECRET`, `RESEND_API_KEY`, `ADMIN_API_TOKEN` si la vas a usar, etc.) — se cargan en el panel de Environment Variables del proyecto, no en un `.env` en disco.
3. **Claves RS256**: `keys/private.pem`/`public.pem` se montan como volumen (ver `docker-compose.yml`) — no van en el repo (`.gitignore`), hay que dejarlas en el filesystem del servidor antes del primer deploy.
4. **Deploy**. `migrate` corre una vez, aplica el schema, y `api` recién arranca después de que termine bien — no hace falta correr nada a mano.
5. **Dominio + HTTPS**: agregale un dominio al servicio `api` desde el panel de Domains — Dokploy/Traefik gestiona el certificado. **Importante antes de darle esta URL a un tercero real**: sin dominio+HTTPS, las credenciales viajan sin cifrar.
6. **Firewall, dos capas**: si tu VPS tiene firewall a nivel de nube además del propio del SO (ej. Security Groups/NSG en AWS/OCI + `iptables`/`ufw` en la instancia), **las dos** necesitan permitir el tráfico — abrir una sola capa no alcanza. Típicamente: puerto 80/443 si accedés por dominio (Traefik), o el puerto específico si publicás uno directo.

**Nota sobre Resend en modo sandbox**: con `RESEND_FROM=onboarding@resend.dev` (el default, sin verificar dominio propio) solo se puede enviar correo a la dirección de tu propia cuenta de Resend — cualquier otro destinatario falla. Para que usuarios reales puedan registrarse, hay que verificar un dominio propio en el dashboard de Resend y usar una dirección de ese dominio como `RESEND_FROM`.

## Probar el flujo

```bash
API_KEY="<tu api key de cmd/createclient>"

# 1. Registro (envía un código de verificación por correo). username no
# puede tener forma de rut ni de email, y rut necesita dígito verificador válido.
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123","username":"juan.perez","rut":"12.345.678-5"}'

# 2. Verificar el correo con el código recibido — sin esto, el login del
# siguiente paso falla con 403 aunque la contraseña sea correcta.
curl -X POST http://localhost:8080/auth/verify-email/confirm \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","code":"<el del correo>"}'

# 3. Login (dispara el envío del código OTP por email) — "identifier" acepta
# el email, el username o el rut indistintamente, no hace falta indicar cuál es.
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"identifier":"tucorreo@example.com","password":"unaClaveSegura123"}'
# -> devuelve { "login_token": "...", "message": "..." }

# 4. Verificar el código recibido por correo
curl -X POST http://localhost:8080/auth/verify-otp \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 3>","code":"<el del correo>"}'
# -> devuelve { "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }

# 5. Consumir un endpoint protegido (no necesita X-API-Key, solo el JWT)
curl http://localhost:8080/me -H "Authorization: Bearer <access_token>"

# 6. Marcar este dispositivo como de confianza (usando el access_token del paso 4)
curl -X POST http://localhost:8080/auth/devices/register \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -H "Authorization: Bearer <access_token>" \
  -d '{"device_id":"un-uuid-generado-por-tu-app","device_name":"Mi teléfono","pin":"123456"}'
# -> devuelve { "device_token": "..." } (guardar en almacenamiento seguro, se muestra una sola vez)

# 7. Próximas veces: login solo con PIN, sin password ni OTP
curl -X POST http://localhost:8080/auth/devices/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"device_id":"un-uuid-generado-por-tu-app","device_token":"<el del paso 6>","pin":"123456"}'
# -> devuelve access_token + refresh_token + un device_token rotado (reemplaza al anterior)
```

## Documentación de la API

Con el servidor corriendo:

- **Especificación OpenAPI**: `http://localhost:8080/openapi.yaml`
- **UI interactiva (Swagger UI)**: `http://localhost:8080/docs` — permite explorar y probar cada endpoint desde el navegador.

Cualquier equipo que vaya a consumir esta API puede usar `/openapi.yaml` para generar un cliente automáticamente (con `openapi-generator`, `swagger-codegen`, etc.) en el lenguaje que necesite.

## Cómo otros sistemas verifican el access token

El access token es un JWT RS256. Cualquier sistema (aunque no tenga acceso a esta base de datos ni a estos secretos) puede:

1. Obtener la clave pública desde `GET /.well-known/jwks.json` (cachearla; solo cambia si se rota la clave).
2. Verificar la firma del JWT con esa clave pública, usando cualquier librería estándar de JWT en su lenguaje (no requiere llamar de vuelta a esta API en cada request).
3. Confiar en los claims `sub` (id de usuario), `email` y `exp` (expiración) una vez la firma es válida.

El refresh token, en cambio, es de uso exclusivo de esta API (HS256) — nunca debe ser verificado ni aceptado por otro sistema.

## Observabilidad

Métricas y logs, vía [OpenTelemetry](https://opentelemetry.io) — ver `internal/telemetry` (`SetupMetrics`/`SetupLogging`) y `internal/middleware` (`Metrics`, `RequestLogger`). Opcional: sin `OTEL_EXPORTER_OTLP_ENDPOINT`, la API funciona idéntico, solo sin exportar nada (los logs siguen viéndose por stdout igual).

**Arquitectura**: `api` → OTel Collector (OTLP) → Prometheus (métricas) / Loki (logs) → Grafana.

- **Métricas**: `http_server_request_count_total` (contador) y `http_server_request_duration_seconds` (histograma), con labels `http_method`, `http_route` (el patrón de chi, no el path crudo — evita una serie nueva por cada id de recurso) y `http_status_code`.
- **Logs**: JSON estructurado (`log/slog`) — siempre a stdout, y además por OTLP si está configurado. Incluye tanto los logs de arranque de `cmd/api` como uno por cada request (`internal/middleware/logging.go`).

**`OTEL_EXPORTER_OTLP_ENDPOINT`** tiene que ser una URL completa **con esquema** (`http://otel-collector:4318`, no `otel-collector:4318` a secas) — el SDK de OTel la lee dos veces (una vez por su cuenta, otra por las opciones explícitas del código) y sin el esquema arma una URL final corrupta.

### Local (Docker Compose)

Automático — `docker-compose.yml` ya incluye `otel-collector`, `prometheus`, `loki` y `grafana`, con Prometheus/Loki pre-conectados como datasources y un dashboard (`grafana/provisioning/dashboards/auth-2fa-api.json`) pre-cargado. Ver [Ejecutar con Docker Compose](#ejecutar-con-docker-compose).

### Producción (Dokploy)

Todo corre en un mismo proyecto Compose en Dokploy — `api`, `postgres`, `redis`, `otel-collector`, `prometheus`, `loki` y `grafana` comparten la misma red interna y se resuelven por nombre de servicio, igual que en local (ver [Ejecutar con Docker Compose](#ejecutar-con-docker-compose)).

- `docker-compose.otel-collector.yml` y `docker-compose.loki.yml`: versiones standalone alternativas, con la config embebida (`configs:` con `content:` inline), por si en algún momento se despliega alguna de esas dos piezas como proyecto Compose separado (pegando el contenido directo en Dokploy, sin depender de un repo) — en ese caso sí hay que conectarlas por dominio/URL pública en vez de por nombre de servicio, porque proyectos distintos de Dokploy no comparten red entre sí.
- El dashboard de Grafana (`grafana/provisioning/dashboards/auth-2fa-api.json`) se importa manualmente ahí (Dashboards → New → Import) — Dokploy no provisiona archivos de dashboard automáticamente como sí hace con los datasources.
- Los datasources de Grafana necesitan un `uid` fijo (`prometheus-ds`, `loki-ds`) para que el dashboard los encuentre sin preguntar nada al importar — ver los comentarios en `grafana/provisioning/datasources/*.yaml`.

## Notas para producción (pendiente, no implementado aún)

- **Verificar un dominio propio en Resend**: mientras `RESEND_FROM` siga siendo `onboarding@resend.dev` (el sandbox), solo se puede mandar correo a la dirección de la cuenta de Resend — hace falta verificar un dominio propio antes de que usuarios reales puedan registrarse. Sin esto, nadie fuera de esa única cuenta puede recibir el código de verificación ni el OTP de login — es lo primero a resolver antes de cualquier usuario real.
- **Rotación de claves JWT**: hoy se usa una sola clave RSA (`JWT_KEY_ID` fijo). En producción conviene poder rotar claves sin invalidar tokens en curso (publicar varias claves en el JWKS durante la transición).

## Checklist para el equipo de TI antes de producción

Esta API en sí misma no depende de nada de esto para funcionar en desarrollo/pruebas — pero antes de que la use gente real, hay una capa de infraestructura y operación que le corresponde a quien administre el entorno final, no al desarrollo de la API. Se las dejamos listadas acá para que no se pierdan en el traspaso.

- **HTTPS obligatorio, no opcional**: el dominio final necesita certificado válido y debería rechazar tráfico por HTTP plano (redirigir o cerrar el puerto), no solo "tenerlo disponible". Sin esto, credenciales y tokens viajan sin cifrar. Ver [Deploy en producción](#deploy-en-producción) — Dokploy/Traefik lo gestiona, pero hay que confirmar que quede forzado.
- **Backups de PostgreSQL, con restore probado**: hoy no hay ninguna política de backup configurada. Un backup que nunca se probó restaurar no es un backup real — hace falta definir frecuencia, retención, y probar el restore al menos una vez antes de ir a producción.
- **Gestión de secretos**: `JWT_REFRESH_SECRET`, `JWT_PRIVATE_KEY_PATH`/`JWT_PRIVATE_KEY_PEM_BASE64`, `ADMIN_API_TOKEN`, `RESEND_API_KEY`, la contraseña de Postgres — hoy viven como variables de entorno en el panel de Dokploy. Funciona, pero para un ente público conviene evaluar algo más auditable (quién puede verlas, cuándo se rotaron, registro de acceso), según la política interna que ya tengan.
- **Alertas activas, no solo dashboards**: el stack de [Observabilidad](#observabilidad) ya expone todo lo necesario (métricas de error rate, latencia, salud del servicio) pero nadie recibe una notificación si algo se rompe fuera de horario — hoy hay que entrar a Grafana a mirar. Conviene conectar alertas (Grafana Alerting, o lo que ya usen) sobre esas mismas métricas.
- **Redundancia / alta disponibilidad**: todo corre en un único VPS (ver [Producción (Dokploy)](#producción-dokploy)) — si esa máquina se cae, el sistema completo se cae con ella. Si el municipio requiere continuidad de servicio, esto necesita evaluarse aparte (más de una instancia, balanceo de carga, etc.).
- **Protección a nivel de borde (WAF / anti-DDoS)**: el rate limiting de esta API (`internal/middleware.RateLimiter`, por IP y por cuenta) protege contra fuerza bruta sobre credenciales y OTP, pero no contra un ataque volumétrico de verdad contra la infraestructura — eso se resuelve en la capa de red/proxy, no en la aplicación.
- **Pruebas de carga**: nunca se verificó cuánto tráfico real aguanta esta configuración. Antes de anunciar el servicio a todo el municipio, vale la pena simular la carga esperada.
- **Cumplimiento legal y normativo**: fuera del alcance de este README — el municipio ya cuenta con su propio proceso para esto.
