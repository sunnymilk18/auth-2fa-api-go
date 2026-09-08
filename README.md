# auth-2fa-api-go

API independiente en Go para autenticación con doble factor por correo (email + contraseña, luego código OTP enviado por email). Pensada para que cualquier otro sistema la consuma vía HTTP.

## Arquitectura

- **PostgreSQL**: datos persistentes de usuarios (`users`) y tokens de refresco (`refresh_tokens`).
- **Redis**: códigos OTP de corta duración (expiran solos vía TTL, no se guardan en Postgres) y contadores de rate limiting.
- **JWT**:
  - Access token firmado con **RS256** (clave privada/pública) — cualquier sistema que reciba el token puede verificarlo por su cuenta usando la clave pública publicada en `/.well-known/jwks.json`, sin llamar de vuelta a esta API.
  - Refresh token firmado con **HS256** (secreto compartido) — de uso exclusivo interno (`/auth/refresh`, `/auth/logout`), rotado en cada uso y revocable desde Postgres.
- **Rate limiting**: por IP, con contador en Redis, sobre `/auth/register`, `/auth/login`, `/auth/verify-otp` y `/auth/devices/login` — mitiga fuerza bruta sobre contraseñas, códigos OTP y PINs.
- **Dispositivos de confianza + PIN**: capa adicional opcional — tras un login completo, un dispositivo puede quedar marcado como confiable (tabla `trusted_devices`, mismo Postgres) y reautenticarse después solo con `device_id` + `device_token` + PIN de 6 dígitos, sin repetir password ni OTP por correo.
- **Documentación**: especificación OpenAPI servida en `/openapi.yaml`, con UI interactiva (Swagger UI) en `/docs`.
- **Envío de correo**: interfaz `mailer.Mailer` — implementación actual usa Gmail SMTP + App Password (solo desarrollo/pruebas). Cambiar de proveedor implica solo escribir una nueva implementación de esa interfaz.

## Flujo de autenticación

1. `POST /auth/register` — crea el usuario (email + password, hasheado con bcrypt).
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

## Ejecutar

```bash
go mod tidy
go run ./cmd/api
```

El servidor arranca en `http://localhost:8080`.

## Probar el flujo

```bash
# 1. Registro
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123"}'

# 2. Login (dispara el envío del código por email)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"tucorreo@example.com","password":"unaClaveSegura123"}'
# -> devuelve { "login_token": "...", "message": "..." }

# 3. Verificar el código recibido por correo
curl -X POST http://localhost:8080/auth/verify-otp \
  -H "Content-Type: application/json" \
  -d '{"login_token":"<el del paso 2>","code":"<el del correo>"}'
# -> devuelve { "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }

# 4. Consumir un endpoint protegido
curl http://localhost:8080/me -H "Authorization: Bearer <access_token>"

# 5. Marcar este dispositivo como de confianza (usando el access_token del paso 3)
curl -X POST http://localhost:8080/auth/devices/register \
  -H "Content-Type: application/json" -H "Authorization: Bearer <access_token>" \
  -d '{"device_id":"un-uuid-generado-por-tu-app","device_name":"Mi teléfono","pin":"123456"}'
# -> devuelve { "device_token": "..." } (guardar en almacenamiento seguro, se muestra una sola vez)

# 6. Próximas veces: login solo con PIN, sin password ni OTP
curl -X POST http://localhost:8080/auth/devices/login \
  -H "Content-Type: application/json" \
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
- **Multi-tenant / API keys**: hoy la API es de un solo consumidor. Para que varios sistemas la consuman de forma aislada, se puede añadir una capa de API keys o client_id/secret por sistema.
- **Rotación de claves JWT**: hoy se usa una sola clave RSA (`JWT_KEY_ID` fijo). En producción conviene poder rotar claves sin invalidar tokens en curso (publicar varias claves en el JWKS durante la transición).
- **Rate limiting por email además de por IP**: hoy el límite es solo por IP; se puede añadir un límite adicional por email para frenar ataques dirigidos a una cuenta específica desde múltiples IPs.
