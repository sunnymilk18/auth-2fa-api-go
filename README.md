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
- **Multi-tenant (API keys)**: cada sistema consumidor (app móvil, web, etc.) se identifica con una API key propia en el header `X-API-Key`. Los usuarios quedan aislados por sistema — el mismo email puede existir como cuentas distintas bajo dos API keys diferentes.
- **Documentación**: especificación OpenAPI servida en `/openapi.yaml`, con UI interactiva (Swagger UI) en `/docs`.
- **Envío de correo**: interfaz `mailer.Mailer` — implementación actual usa la API HTTP de [Resend](https://resend.com) (no SMTP, a propósito: varios proveedores cloud bloquean o filtran puertos SMTP salientes, algo que este proyecto sufrió literalmente al desplegar en Render). Cambiar de proveedor implica solo escribir una nueva implementación de esa interfaz.

## Flujo de autenticación

Todas las rutas `/auth/*` requieren el header `X-API-Key` (ver [Multi-tenant](#multi-tenant-api-keys) más abajo).

1. `POST /auth/register` — crea el usuario (email + password, hasheado con bcrypt), dentro del sistema identificado por la API key, y envía un código de verificación por correo (ver [Verificación de correo](#verificación-de-correo) más abajo). La cuenta existe desde ya, pero no puede loguear hasta confirmarlo.
2. `POST /auth/login` — valida email/password. Si son correctos pero el correo todavía no fue verificado, devuelve un error (403) en vez de continuar — ver más abajo por qué. Si todo está en orden, genera un código OTP, lo guarda (hasheado) en Redis con expiración, lo envía por correo y devuelve un `login_token` (no el código).
3. `POST /auth/verify-otp` — recibe `login_token` + `code`. Si coincide, emite `access_token` + `refresh_token`.
4. `POST /auth/refresh` — recibe `refresh_token` válido, emite un nuevo par de tokens (rotación).
5. `POST /auth/logout` — revoca un `refresh_token`.
6. `GET /me` — ejemplo de endpoint protegido (requiere `Authorization: Bearer <access_token>`).

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
- Una cuenta en [Resend](https://resend.com) (gratis) con una API key generada — se usa para enviar los códigos OTP y de reset por correo
- PostgreSQL y Redis — sin Docker instalado, la forma más rápida es usar capas gratuitas en la nube (no requiere instalar nada localmente):

### PostgreSQL con Neon (gratis)

1. Crea una cuenta en https://neon.tech
2. Crea un proyecto → te da una **connection string** tipo `postgres://usuario:password@ep-xxxx.neon.tech/neondb?sslmode=require`
3. Copia esa cadena a `POSTGRES_DSN` en tu `.env`

### Redis con Upstash (gratis)

1. Crea una cuenta en https://upstash.com
2. Crea una base Redis → en el dashboard copia la URL que empieza con `rediss://` (con TLS)
3. Copia esa URL a `REDIS_URL` en tu `.env`

(Si en algún momento instalas Postgres/Redis localmente o con Docker, `POSTGRES_DSN` y `REDIS_URL` aceptan igual las cadenas locales — ver los comentarios en `.env.example`.)

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

## Base de datos

Con `POSTGRES_DSN` configurado en `.env`, aplica todas las migraciones (`migrations/*.sql`, en orden) con la herramienta incluida en el proyecto — no necesitas tener `psql` instalado:

```bash
go run ./cmd/migrate
```

(Alternativa manual: pegar el contenido de cada archivo en el **SQL Editor** del dashboard de Neon.)

Redis (Upstash) no necesita migración — las claves OTP y de rate limiting se crean solas con TTL.

**Nota sobre la migración `0004`**: agrega el aislamiento por sistema (multi-tenant) a la tabla `users`. En una base nueva se activa sola en este mismo paso, sin nada más que hacer. El único caso especial es una base que ya tenía usuarios *antes* de que existiera el aislamiento por tenant: ahí hay que crear primero un `api_client` (ver la sección siguiente) al que asignarles esos usuarios existentes, y volver a correr `go run ./cmd/migrate` para que los reasigne.

## Multi-tenant (API keys)

Cada sistema que va a consumir esta API (una app móvil, un sitio web, etc.) necesita su propia API key. Los usuarios quedan aislados por sistema — el mismo email puede existir como cuentas distintas en dos sistemas diferentes.

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

### Gestionar clientes existentes

`cmd/createclient` tiene subcomandos además de crear:

```bash
go run ./cmd/createclient list                     # lista todos los clientes (id, activo, creado, nombre)
go run ./cmd/createclient deactivate -id <id>       # su key deja de funcionar de inmediato
go run ./cmd/createclient activate -id <id>         # reactiva un cliente desactivado
go run ./cmd/createclient rotate -id <id>           # emite una key nueva, invalida la anterior — misma identidad (id, nombre, usuarios)
```

`rotate` es la forma de recuperarse de una key filtrada sin tener que recrear el cliente ni migrar sus usuarios a otro. Todo esto sigue siendo por línea de comandos — no hay (todavía) un endpoint HTTP de administración; ver "Notas para producción" más abajo.

## Ejecutar

```bash
go mod tidy
go run ./cmd/api
```

El servidor arranca en `http://localhost:8080`.

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

## Deploy a Render

El repo incluye [`render.yaml`](render.yaml) (Blueprint) — Render lo detecta solo al conectar el repo. Como Postgres (Neon) y Redis (Upstash) ya son de nube, no hace falta provisionar nada nuevo ahí: se reusan las mismas connection strings del `.env` local.

1. En el dashboard de Render: **New +** → **Blueprint** → conectar este repo de GitHub.
2. Render va a pedir el valor de cada variable marcada `sync: false` en `render.yaml`. Completar:
   - `POSTGRES_DSN`, `REDIS_URL`, `JWT_REFRESH_SECRET`, `RESEND_API_KEY`: los mismos valores de tu `.env` local. **Ojo**: si tu `.env` tiene el valor entre comillas (`REDIS_URL="rediss://..."`), pegá solo lo de adentro, sin las comillas — Render las toma como parte literal del valor.
   - `JWT_PRIVATE_KEY_PEM_BASE64`: el contenido de `keys/private.pem` en base64 (ver comando abajo) — Render no tiene filesystem persistente, así que la clave se pasa como variable de entorno en vez de archivo (`JWT_PRIVATE_KEY_PATH` no se usa ahí).
     ```bash
     # Linux/macOS/Git Bash:
     base64 -w0 keys/private.pem
     # PowerShell:
     [Convert]::ToBase64String([IO.File]::ReadAllBytes("keys/private.pem"))
     ```
3. **Deploy**. Render construye (`go build -o app ./cmd/api`) y arranca (`./app`), y usa `/health` para saber si la instancia está sana — con el chequeo real de Postgres/Redis que ya tiene este endpoint.
4. Al terminar, Render da una URL propia con HTTPS (`https://auth-2fa-api-xxxx.onrender.com`). No hace falta correr `cmd/migrate` ni `cmd/createclient` de nuevo — la base ya tiene el schema y al menos un cliente con su API key, porque es la misma que ya usás en local.

**Nota**: el plan free de Render duerme el servicio tras ~15 min sin tráfico; el primer request después de eso tarda unos 30-50s en responder mientras despierta. Normal, no es un error.

**Nota sobre Resend en modo sandbox**: con `RESEND_FROM=onboarding@resend.dev` (el default, sin verificar dominio propio) solo se puede enviar correo a la dirección de tu propia cuenta de Resend — cualquier otro destinatario falla. Para que usuarios reales puedan registrarse, hay que verificar un dominio propio en el dashboard de Resend y usar una dirección de ese dominio como `RESEND_FROM`.

## Probar el flujo

```bash
API_KEY="<tu api key de cmd/createclient>"

# 1. Registro (envía un código de verificación por correo)
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123"}'

# 2. Verificar el correo con el código recibido — sin esto, el login del
# siguiente paso falla con 403 aunque la contraseña sea correcta.
curl -X POST http://localhost:8080/auth/verify-email/confirm \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","code":"<el del correo>"}'

# 3. Login (dispara el envío del código OTP por email)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123"}'
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

## Notas para producción (pendiente, no implementado aún)

- **Verificar un dominio propio en Resend**: mientras `RESEND_FROM` siga siendo `onboarding@resend.dev` (el sandbox), solo se puede mandar correo a la dirección de la cuenta de Resend — hace falta verificar un dominio propio antes de que usuarios reales puedan registrarse.
- **Rotación de claves JWT**: hoy se usa una sola clave RSA (`JWT_KEY_ID` fijo). En producción conviene poder rotar claves sin invalidar tokens en curso (publicar varias claves en el JWKS durante la transición).
- **Gestión de API keys por HTTP**: `cmd/createclient` ya cubre crear/listar/activar/desactivar/rotar (ver [Gestionar clientes existentes](#gestionar-clientes-existentes)), pero sigue siendo un CLI de línea de comandos — sin un endpoint de administración remoto, cada operación requiere acceso a la máquina/entorno donde corre este comando.
