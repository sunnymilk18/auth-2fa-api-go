# auth-2fa-api-go

API independiente en Go para autenticación con doble factor por correo (email + contraseña, luego código OTP enviado por email; el correo debe verificarse antes de poder loguear). Pensada para que cualquier otro sistema la consuma vía HTTP.

Este documento es para quien va a **desarrollar o integrar** contra la API. Para desplegar, administrar tenants/cuentas, observabilidad y el checklist previo a producción, ver [`DEPLOY.md`](DEPLOY.md).

## Arquitectura

- **PostgreSQL**: datos persistentes (`users`, `refresh_tokens`). La limpieza de tokens vencidos/revocados corre sola en segundo plano, sin intervención manual.
- **Redis**: códigos de corta duración (OTP de login, verificación de correo, reset de contraseña) y contadores de rate limiting — todo con TTL, nada persiste más de lo necesario.
- **JWT**: access token **RS256** (cualquier sistema lo verifica por su cuenta vía `/.well-known/jwks.json`, sin llamar de vuelta a esta API — ver [Cómo otros sistemas verifican el access token](#cómo-otros-sistemas-verifican-el-access-token)); refresh token **HS256** (uso exclusivo interno, rotado en cada uso, con detección de reuso que revoca todo ante una señal de robo).
- **Rate limiting + lista negra automática por IP**: fuerza bruta sobre contraseñas, OTP y PIN se frena por IP y por cuenta; una IP reincidente escala a baneo automático.
- **Bloqueo manual de cuentas** y **revocación instantánea de access tokens** para casos de abuso identificados puntualmente (ver [`DEPLOY.md`](DEPLOY.md) para los comandos).
- **Dispositivos de confianza + PIN de cuenta**: atajo opcional alrededor de password+segundo factor, y confirmación de acciones sensibles desde cualquier cliente.
- **Segundos factores alternativos**, cada uno opcional y activado por variable de entorno: app autenticadora (TOTP) y aprobación por notificación push (Android, FCM).
- **Multi-tenant (API keys)**: cada sistema consumidor tiene su propia API key (`X-API-Key`); los usuarios quedan aislados por sistema.
- **CORS abierto** (`*`, sin credenciales) — la API se autentica por headers, no por cookies, así que no hay nada que filtrar abriendo el origen a todos.
- **Documentación interactiva**: OpenAPI servido en `/openapi.yaml`, con Swagger UI en `/docs`.
- **Observabilidad**: métricas y logs vía OpenTelemetry — ver [`DEPLOY.md`](DEPLOY.md).
- **Envío de correo**: vía la API HTTP de [Resend](https://resend.com), no SMTP a propósito (varios proveedores PaaS bloquean puertos SMTP salientes).

## Flujo de autenticación

Todas las rutas `/auth/*` requieren el header `X-API-Key` (ver [Multi-tenant](#multi-tenant-api-keys) más abajo). Esto es el panorama general — para el detalle exacto de cada request/response, usar `/docs` (Swagger UI, interactivo) con el servidor corriendo.

**Flujo base:**

1. `POST /auth/register` — email + password + username + rut. Envía un código de verificación por correo; la cuenta no puede loguear hasta confirmarlo.
2. `POST /auth/verify-email/confirm` — confirma el correo con el código recibido.
3. `POST /auth/login` — `identifier` (email, username **o** rut, indistintamente) + `password`. Devuelve `login_token` y, salvo el primer login de la cuenta, ya manda el código del segundo factor.
4. `POST /auth/verify-otp` — `login_token` + `code` → `access_token` + `refresh_token`.
5. `POST /auth/refresh` / `POST /auth/logout` — rotar o cerrar la sesión.
6. `GET /me` — ejemplo de endpoint protegido (`Authorization: Bearer <access_token>`).

**Segundos factores alternativos** (la cuenta elige uno en su primer login; cada uno requiere su propia variable de entorno o ni siquiera existe):

- **App autenticadora (TOTP)** — requiere `TOTP_ENCRYPTION_KEY`. `/auth/totp/enroll` + `/auth/totp/confirm`.
- **Notificación push** (solo Android, vía Firebase) — requiere `FIREBASE_CREDENTIALS_PATH`. Corre en paralelo al correo/TOTP, nunca los reemplaza — `/auth/login/push-status`, `/auth/login/push-answer`.

**Atajos y capas extra:**

- **Dispositivo de confianza + PIN de cuenta** — tras un login completo, `POST /auth/devices/register` marca el dispositivo actual como confiable; `POST /auth/devices/login` reautentica después solo con `device_id` + `device_token` + el PIN de 6 dígitos de la cuenta, sin repetir password ni segundo factor. El mismo PIN sirve para confirmar acciones sensibles desde cualquier cliente (`POST /auth/pin/verify`).
- **PIN obligatorio al final del login** — interruptor por cuenta (`PUT /system-admin/users/{id}/login-pin-required`, ver [`DEPLOY.md`](DEPLOY.md)), pensado para que ciertas cuentas (ej. superadmins de un panel) confirmen el PIN además del segundo factor normal antes de recibir tokens. Ninguna vía de login lo saltea — ver `/docs` para la respuesta exacta de cada endpoint cuando está activo.
- **Recuperación de contraseña** (`/auth/password-reset/request` + `/confirm`) y **reenvío de código de verificación** (`/auth/verify-email/resend`) — flujos estándar, código numérico de un solo uso con límite de intentos.

## Requisitos previos

- Go 1.26+
- Una cuenta en [Resend](https://resend.com) (gratis) con una API key generada — se usa para enviar los códigos OTP, de verificación de correo y de reset de contraseña.
- PostgreSQL y Redis — la forma más simple es `docker-compose.yml`, que los levanta automáticamente (ver [Ejecutar con Docker Compose](#ejecutar-con-docker-compose) más abajo). Si prefieres instancias propias o en la nube, cualquier proveedor sirve: solo hacen falta las connection strings en `POSTGRES_DSN`/`REDIS_URL` (ver `.env.example` para el formato esperado de cada una).

## Configuración

```bash
cp .env.example .env
# Edita .env: POSTGRES_DSN, REDIS_URL, JWT_REFRESH_SECRET y RESEND_API_KEY
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

Cada una de estas, sin configurar, deja las rutas que habilita sin existir (404) — no "abiertas sin auth". Ver `.env.example` para el detalle completo de cada una (formato exacto, alternativas, defaults).

- **`ADMIN_API_TOKEN`**: habilita `/admin/clients/*` (gestión de API keys y administración por HTTP — ver [`DEPLOY.md`](DEPLOY.md)).
- **`TOTP_ENCRYPTION_KEY`**: habilita `/auth/totp/*` (app autenticadora). Base64 de exactamente 32 bytes (`openssl rand -base64 32`).
- **`TOTP_ISSUER`**: nombre mostrado en la app autenticadora (default `auth-2fa-api`), puramente cosmético.
- **`FIREBASE_CREDENTIALS_PATH`** / **`FIREBASE_CREDENTIALS_JSON_BASE64`**: habilitan la aprobación de login por notificación push. La variante base64 tiene prioridad y es preferible en plataformas sin filesystem persistente/escribible.
- **`PUSH_LOGIN_TTL`** / **`PUSH_MAX_REQUESTS`** / **`PUSH_REQUEST_WINDOW`**: ventana de espera y límite de solicitudes push por cuenta (defaults `60s`, `5` cada `15m`).
- **`OTEL_EXPORTER_OTLP_ENDPOINT`**: exporta métricas/logs a un collector de OpenTelemetry — ver [`DEPLOY.md`](DEPLOY.md).
- **`TRUSTED_PROXY_CIDRS`**: redes autorizadas a indicar la IP real del cliente vía `X-Forwarded-For` (CIDR, separadas por coma) — necesario cuando un backend propio hace de intermediario entre los usuarios reales y esta API. Tiene que incluir **todas** las redes de proxies propios que están delante de la API (cada salto, no solo el primero) — si falta alguno, ese tramo se trata como no confiable y la IP real se pierde ahí. La IP del header solo se usa cuando la conexión TCP misma viene de una de estas redes; los headers de cualquier otro origen se ignoran siempre, sin importar qué digan. Sin configurar, el header nunca se consulta — se usa la IP de la conexión tal cual, igual que si esta variable no existiera.

## Base de datos

Con `POSTGRES_DSN` configurado en `.env`, aplica todas las migraciones (`migrations/*.sql`, en orden) con la herramienta incluida en el proyecto:

```bash
go run ./cmd/migrate
```

Redis no necesita migración — las claves OTP y de rate limiting se crean solas con TTL.

**Nota sobre la migración `0004`**: agrega el aislamiento por sistema (multi-tenant) a la tabla `users`. En una base nueva se activa sola en este mismo paso. El único caso especial es una base que ya tenía usuarios *antes* de que existiera el aislamiento por tenant: ahí hay que crear primero un `api_client` (ver [Multi-tenant](#multi-tenant-api-keys) abajo) al que asignarles esos usuarios existentes, y volver a correr `go run ./cmd/migrate` para que los reasigne.

## Multi-tenant (API keys)

Cada sistema que va a consumir esta API (una app móvil, un sitio web, etc.) necesita su propia API key. Los usuarios quedan aislados por sistema — el mismo email, username o rut puede existir como cuentas distintas en dos sistemas diferentes.

### Crear el primer cliente

```bash
go run ./cmd/createclient -name nombre-de-tu-sistema
```

`-name` es solo descriptivo. Esto imprime la API key **una sola vez** — cópiala de inmediato, no se puede recuperar después (solo se guarda su hash). Gestionar clientes existentes (listar, desactivar, rotar) está en [`DEPLOY.md`](DEPLOY.md).

### Usarla

El sistema consumidor debe enviar la key en cada request a `/auth/*`:

```
X-API-Key: sk_live_...
```

Sin ese header (o con una key inválida/inactiva), la API responde `401`.

**Importante para quien vaya a consumir la API — dónde NO poner esta key:** `X-API-Key` identifica a tu sistema, no a un usuario individual — es un secreto de servidor, no algo que deba viajar dentro de código que corre en el dispositivo del usuario final (JavaScript de navegador, una app móvil). Cualquiera puede extraerla abriendo las devtools del sitio o descompilando el APK. El patrón correcto es que **tu propio backend** sea el que llame a esta API con la key — tu frontend/app le habla a tu backend, nunca directo a `auth-2fa-api` con la key embebida. Si tu key se filtra igual (pasa), rotarla (ver [`DEPLOY.md`](DEPLOY.md)) la reemplaza sin tener que recrear el cliente.

## Ejecutar

```bash
go mod tidy
go run ./cmd/api
```

El servidor arranca en `http://localhost:8080`.

## Ejecutar con Docker Compose

Alternativa a lo de arriba: `docker-compose.yml` levanta todo junto — Postgres, Redis, migraciones aplicadas automáticamente, la API, y el stack completo de observabilidad (ver [`DEPLOY.md`](DEPLOY.md)).

**Antes de arrancar:**
1. Par de claves RS256 generado (`keys/private.pem` + `keys/public.pem` — ver [Claves RS256](#claves-rs256-para-el-access-token) más arriba), legible por el usuario no-root del contenedor (`chmod 644 keys/*.pem` si hace falta).
2. Un `.env` en la raíz con al menos `JWT_REFRESH_SECRET` y `RESEND_API_KEY` — Compose lo lee solo para las sustituciones `${VAR}` del archivo.

```bash
docker compose up --build
```

API en `http://localhost:8080`. El resto del stack (Prometheus, Loki, Grafana) y sus URLs están en [`DEPLOY.md`](DEPLOY.md).

Para crear un cliente (API key) sin salir del compose:
```bash
docker compose run --rm api ./createclient create -name "mi-app"
```

No incluye un servidor de correo local a propósito: Resend es una API HTTP hacia la nube de Resend, no algo autoalojable — simplemente usa tu `RESEND_API_KEY` real (la de sandbox alcanza), es una llamada saliente igual desde un contenedor que desde tu máquina.

## Tests

```bash
go test ./...
```

Corre toda la suite. Los tests que necesitan Postgres (la mayoría) se **saltan** (no fallan) si no encuentran una base disponible — para que corran de verdad, apunta `TEST_POSTGRES_DSN` a una base local descartable:

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

## Probar el flujo

Quickstart mínimo de punta a punta. Para TOTP, push, dispositivos de confianza y el resto de las variantes, explóralas interactivamente en `/docs` (Swagger UI) una vez con el servidor corriendo — ahí se puede armar y mandar cada request desde el navegador, con la forma exacta de cada respuesta.

```bash
API_KEY="<tu api key de cmd/createclient>"

# 1. Registro (envía un código de verificación por correo).
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123","username":"juan.perez","rut":"12.345.678-5"}'

# 2. Verificar el correo con el código recibido — sin esto, el login falla
# con 403 aunque la contraseña sea correcta.
curl -X POST http://localhost:8080/auth/verify-email/confirm \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","code":"<el del correo>"}'

# 3. Login — "identifier" acepta el email, el username o el rut indistintamente.
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"identifier":"tucorreo@example.com","password":"unaClaveSegura123"}'
# -> { "login_token": "...", "needs_2fa_setup": false, "method": "email", ... }

# 4. Verificar el código OTP recibido por correo
curl -X POST http://localhost:8080/auth/verify-otp \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 3>","code":"<el del correo>"}'
# -> { "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }

# 5. Consumir un endpoint protegido (no necesita X-API-Key, solo el JWT)
curl http://localhost:8080/me -H "Authorization: Bearer <access_token>"
```

## Documentación de la API

Con el servidor corriendo:

- **Especificación OpenAPI**: `http://localhost:8080/openapi.yaml`
- **UI interactiva (Swagger UI)**: `http://localhost:8080/docs` — permite explorar y probar cada endpoint desde el navegador. Esta es la referencia completa de cada flujo (TOTP, push, PIN, dispositivos de confianza, etc.) — este README solo da el panorama general.

Cualquier equipo que vaya a consumir esta API puede usar `/openapi.yaml` para generar un cliente automáticamente (con `openapi-generator`, `swagger-codegen`, etc.) en el lenguaje que necesite.

## Cómo otros sistemas verifican el access token

El access token es un JWT RS256. Cualquier sistema (aunque no tenga acceso a esta base de datos ni a estos secretos) puede:

1. Obtener el conjunto de claves públicas desde `GET /.well-known/jwks.json` (cachearlo). **Normalmente trae una sola clave, pero durante una rotación (ver [`DEPLOY.md`](DEPLOY.md)) puede traer dos a la vez** — no asumas que siempre hay una sola ni tomes "la primera" del array.
2. Mirar el campo `kid` del header del JWT, y usar la clave del JWKS cuyo `kid` coincida. Con esa clave, verificar la firma usando cualquier librería estándar de JWT en su lenguaje (no requiere llamar de vuelta a esta API en cada request).
3. Confiar en los claims `sub` (id de usuario), `email` y `exp` (expiración) una vez la firma es válida.

Cachear el JWKS está bien, pero no para siempre: si tu caché no vuelve a pedirlo nunca, no te vas a enterar cuando aparezca una clave nueva durante una rotación — refréscalo cada tanto (por hora, por ejemplo), no solo una vez al arrancar.

El refresh token, en cambio, es de uso exclusivo de esta API (HS256) — nunca debe ser verificado ni aceptado por otro sistema.
