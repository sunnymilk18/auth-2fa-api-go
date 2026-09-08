# auth-2fa-api

API independiente en Go para autenticación con doble factor por correo (email + contraseña, luego código OTP enviado por email). Pensada para que cualquier otro sistema la consuma vía HTTP.

## Arquitectura

- **PostgreSQL**: datos persistentes de usuarios (`users`) y tokens de refresco (`refresh_tokens`).
- **Redis**: códigos OTP de corta duración (expiran solos vía TTL, no se guardan en Postgres).
- **JWT (HS256)**: access token (corta duración) + refresh token (larga duración, rotado y revocable).
- **Envío de correo**: interfaz `mailer.Mailer` — implementación actual usa Gmail SMTP + App Password (solo desarrollo/pruebas). Cambiar de proveedor implica solo escribir una nueva implementación de esa interfaz.

## Flujo de autenticación

1. `POST /auth/register` — crea el usuario (email + password, hasheado con bcrypt).
2. `POST /auth/login` — valida email/password. Si son correctos, genera un código OTP, lo guarda (hasheado) en Redis con expiración, lo envía por correo y devuelve un `login_token` (no el código).
3. `POST /auth/verify-otp` — recibe `login_token` + `code`. Si coincide, emite `access_token` + `refresh_token`.
4. `POST /auth/refresh` — recibe `refresh_token` válido, emite un nuevo par de tokens (rotación).
5. `POST /auth/logout` — revoca un `refresh_token`.
6. `GET /me` — ejemplo de endpoint protegido (requiere `Authorization: Bearer <access_token>`).

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
# Edita .env: POSTGRES_DSN (Neon), REDIS_URL (Upstash), JWT_ACCESS_SECRET, JWT_REFRESH_SECRET y SMTP_PASSWORD (App Password de Gmail)
```

Genera secretos fuertes para JWT, por ejemplo:

```bash
openssl rand -base64 48
```

## Base de datos

Aplica la migración contra tu base de Neon (o local). Necesitas `psql` instalado, o puedes pegar el contenido de `migrations/0001_init.sql` directamente en el **SQL Editor** que trae el dashboard de Neon (más simple si no quieres instalar `psql`):

```bash
psql "<tu POSTGRES_DSN>" -f migrations/0001_init.sql
```

Redis (Upstash) no necesita migración — las claves OTP se crean solas con TTL.

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
```

## Notas para producción (pendiente, no implementado aún)

- **Gmail SMTP es solo para desarrollo.** Tiene límites de envío bajos y riesgo de bloqueo de cuenta. Migrar a un proveedor transaccional (SendGrid, SES, Mailgun, Resend) implementando `mailer.Mailer`.
- **Multi-tenant / API keys**: hoy la API es de un solo consumidor. Para que varios sistemas la consuman de forma aislada, se puede añadir una capa de API keys o client_id/secret por sistema.
- **Rate limiting**: agregar límite de intentos de login y de reenvío de OTP por IP/email para mitigar fuerza bruta.
- **JWT con RS256**: si otros sistemas necesitan validar el token sin llamar de vuelta a esta API, conviene pasar de HS256 (secreto compartido) a RS256 (clave pública/privada) y exponer la clave pública (o un endpoint JWKS).
