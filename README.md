# auth-2fa-api-go

API independiente en Go para autenticación con doble factor por correo (email + contraseña, luego código OTP enviado por email). Pensada para que cualquier otro sistema la consuma vía HTTP.

## Arquitectura

- **PostgreSQL**: datos persistentes de usuarios (`users`) y tokens de refresco (`refresh_tokens`).
- **Redis**: códigos OTP de corta duración (expiran solos vía TTL, no se guardan en Postgres) y contadores de rate limiting.
- **JWT**:
  - Access token firmado con **RS256** (clave privada/pública) — cualquier sistema que reciba el token puede verificarlo por su cuenta usando la clave pública publicada en `/.well-known/jwks.json`, sin llamar de vuelta a esta API.
  - Refresh token firmado con **HS256** (secreto compartido) — de uso exclusivo interno (`/auth/refresh`, `/auth/logout`), rotado en cada uso y revocable desde Postgres.
- **Rate limiting**: por IP, con contador en Redis, sobre `/auth/register`, `/auth/login`, `/auth/verify-otp`, `/auth/devices/login` y `/auth/password-reset/*` — mitiga fuerza bruta sobre contraseñas, códigos OTP y PINs.
- **Dispositivos de confianza + PIN**: capa adicional opcional — tras un login completo, un dispositivo puede quedar marcado como confiable (tabla `trusted_devices`, mismo Postgres) y reautenticarse después solo con `device_id` + `device_token` + PIN de 6 dígitos, sin repetir password ni OTP por correo.
- **Multi-tenant (API keys)**: cada sistema consumidor (app móvil, web, etc.) se identifica con una API key propia en el header `X-API-Key`. Los usuarios quedan aislados por sistema — el mismo email puede existir como cuentas distintas bajo dos API keys diferentes.
- **Documentación**: especificación OpenAPI servida en `/openapi.yaml`, con UI interactiva (Swagger UI) en `/docs`.
- **Envío de correo**: interfaz `mailer.Mailer` — implementación actual usa Gmail SMTP + App Password (solo desarrollo/pruebas). Cambiar de proveedor implica solo escribir una nueva implementación de esa interfaz.

## Flujo de autenticación

Todas las rutas `/auth/*` requieren el header `X-API-Key` (ver [Multi-tenant](#multi-tenant-api-keys) más abajo).

1. `POST /auth/register` — crea el usuario (email + password, hasheado con bcrypt), dentro del sistema identificado por la API key.
2. `POST /auth/login` — valida email/password. Si son correctos, genera un código OTP, lo guarda (hasheado) en Redis con expiración, lo envía por correo y devuelve un `login_token` (no el código).
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

11. `POST /auth/password-reset/request` — recibe `email`. Si existe una cuenta con ese correo en el sistema (API key) que llama, genera un token aleatorio de 256 bits, lo guarda en Redis (TTL configurable, `PASSWORD_RESET_TTL`) y lo envía por correo. **La respuesta es idéntica exista o no la cuenta** — no filtra qué correos están registrados, igual que `/auth/login`.
12. `POST /auth/password-reset/confirm` — recibe `reset_token` + `new_password`. El token es de un solo uso (se borra al consumirse, exista o no la contraseña nueva se aplique correctamente). Al confirmarse con éxito se **revocan todas las sesiones activas (refresh tokens) y todos los dispositivos de confianza (PIN)** del usuario — un reset de contraseña fuerza a volver a autenticarse en todos lados, ya que el dispositivo de confianza es un atajo que bypasea password+OTP por completo y no debería sobrevivir a un reset motivado por una posible cuenta comprometida.

A diferencia del código OTP (6 dígitos), el token de reset no tiene límite de intentos — no hace falta, ya que sus 256 bits de entropía hacen inviable adivinarlo por fuerza bruta.

## Requisitos previos

- Go 1.25+
- Una cuenta Gmail con verificación en 2 pasos activada y un **App Password** generado (Configuración de Google → Seguridad → Verificación en dos pasos → Contraseñas de aplicaciones)
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
# Edita .env: POSTGRES_DSN (Neon), REDIS_URL (Upstash), JWT_REFRESH_SECRET y SMTP_PASSWORD (App Password de Gmail)
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

**Nota sobre la migración `0004`**: agrega el aislamiento por sistema (multi-tenant) a la tabla `users`. Se auto-protege: si todavía no existe ningún `api_client`, no hace nada (deja aviso en el log de Postgres) — hay que crearlo primero (ver la sección siguiente) y volver a correr `go run ./cmd/migrate` para que la aplique de verdad.

## Multi-tenant (API keys)

Cada sistema que va a consumir esta API (una app móvil, un sitio web, etc.) necesita su propia API key. Los usuarios quedan aislados por sistema — el mismo email puede existir como cuentas distintas en dos sistemas diferentes.

### Crear el primer cliente

```bash
go run ./cmd/createclient -name auth-2fa-app-flutter
```

Esto imprime la API key **una sola vez** — cópiala de inmediato, no se puede recuperar después (solo se guarda su hash). Con al menos un cliente creado, vuelve a correr `go run ./cmd/migrate` para que la migración `0004` complete el aislamiento por tenant sobre los usuarios ya existentes.

### Usarla

El sistema consumidor debe enviar la key en cada request a `/auth/*`:

```
X-API-Key: sk_live_...
```

Sin ese header (o con una key inválida/inactiva), la API responde `401`.

## Ejecutar

```bash
go mod tidy
go run ./cmd/api
```

El servidor arranca en `http://localhost:8080`.

## Probar el flujo

```bash
API_KEY="<tu api key de cmd/createclient>"

# 1. Registro
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123"}'

# 2. Login (dispara el envío del código por email)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123"}'
# -> devuelve { "login_token": "...", "message": "..." }

# 3. Verificar el código recibido por correo
curl -X POST http://localhost:8080/auth/verify-otp \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 2>","code":"<el del correo>"}'
# -> devuelve { "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }

# 4. Consumir un endpoint protegido (no necesita X-API-Key, solo el JWT)
curl http://localhost:8080/me -H "Authorization: Bearer <access_token>"

# 5. Marcar este dispositivo como de confianza (usando el access_token del paso 3)
curl -X POST http://localhost:8080/auth/devices/register \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -H "Authorization: Bearer <access_token>" \
  -d '{"device_id":"un-uuid-generado-por-tu-app","device_name":"Mi teléfono","pin":"123456"}'
# -> devuelve { "device_token": "..." } (guardar en almacenamiento seguro, se muestra una sola vez)

# 6. Próximas veces: login solo con PIN, sin password ni OTP
curl -X POST http://localhost:8080/auth/devices/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"device_id":"un-uuid-generado-por-tu-app","device_token":"<el del paso 5>","pin":"123456"}'
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

- **Gmail SMTP es solo para desarrollo.** Tiene límites de envío bajos y riesgo de bloqueo de cuenta. Migrar a un proveedor transaccional (SendGrid, SES, Mailgun, Resend) implementando `mailer.Mailer`.
- **Rotación de claves JWT**: hoy se usa una sola clave RSA (`JWT_KEY_ID` fijo). En producción conviene poder rotar claves sin invalidar tokens en curso (publicar varias claves en el JWKS durante la transición).
- **Rate limiting por email además de por IP**: hoy el límite es solo por IP; se puede añadir un límite adicional por email para frenar ataques dirigidos a una cuenta específica desde múltiples IPs.
- **Rotación/revocación de API keys**: hoy `cmd/createclient` solo crea; falta un comando o endpoint para rotar o desactivar una key existente sin recrear el cliente.
