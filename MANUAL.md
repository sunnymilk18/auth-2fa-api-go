# Manual de la API de autenticación (auth-2fa-api-go)

Este manual tiene dos partes:

1. **Cómo usar la API**: para quien va a conectar un sistema (un sitio web, una aplicación móvil, un backend) a la API.
2. **Cómo implementarla en otro lugar**: para quien va a instalarla en un servidor o en otra organización.

Es un resumen ordenado. Los detalles finos están en otros documentos del repositorio:

| Documento | Para qué sirve |
|---|---|
| [`README.md`](README.md) | Desarrollo, configuración local y flujo de autenticación |
| [`DEPLOY.md`](DEPLOY.md) | Operación: administración, moderación, observabilidad, rotación de claves, lista de verificación previa a producción |
| `/docs` (con la API corriendo) | Referencia interactiva de cada endpoint, con la forma exacta de cada solicitud y respuesta |
| [`.env.example`](.env.example) | Todas las variables de entorno, con su explicación |

---

# Parte 1. Cómo usar la API

## 1.1 Qué hace

Es una API independiente que se encarga de **iniciar sesión con doble factor**. Cualquier sistema puede usarla por HTTP, sin reescribir su propia autenticación.

- El usuario se registra con correo, contraseña, nombre de usuario y RUT.
- Debe confirmar su correo antes de poder iniciar sesión.
- Para entrar, además de la contraseña, necesita un segundo factor: un código enviado por correo, una aplicación autenticadora (TOTP) o la aprobación en su teléfono (notificación push, solo Android).
- Al terminar, recibe un `access_token` (válido 15 minutos por defecto) y un `refresh_token` (válido 7 días por defecto).

## 1.2 Conceptos básicos

**Sistema consumidor (tenant).** Cada sistema que usa la API tiene su propia **API key**. Los usuarios quedan aislados por sistema: el mismo correo puede existir como dos cuentas distintas en dos sistemas.

**Dos tipos de token.**

| Token | Para qué sirve | Quién lo verifica |
|---|---|---|
| `access_token` (JWT, RS256) | Demostrar quién es el usuario en cada solicitud | Cualquier sistema, con la clave pública |
| `refresh_token` | Obtener un `access_token` nuevo cuando vence | Solo esta API. Ningún otro sistema debe aceptarlo |

**Credenciales de administración.** Hay tres, y no son intercambiables:

| Credencial | Header | Quién la tiene | Alcance |
|---|---|---|---|
| API key del sistema | `X-API-Key` | El backend de cada sistema consumidor | Rutas `/auth/*` de ese sistema |
| Credencial de administración por sistema | `X-System-Admin-Token` | El equipo de cada sistema | Moderar a los usuarios de **su propio** sistema (`/system-admin/*`) |
| Token de administración global | `X-Admin-Token` | Solo el operador de la API | Todos los sistemas (`/admin/*`) |

## 1.3 Regla de seguridad más importante

> **La API key (`X-API-Key`) es un secreto de servidor.** Nunca debe ir dentro de una aplicación móvil ni de código JavaScript de un navegador: cualquiera podría extraerla.

El patrón correcto es que **tu propio backend** llame a esta API con la key. Tu sitio o tu aplicación le hablan a tu backend, nunca directamente a la API con la key incluida.

```
Usuario ──► Tu app / sitio ──► Tu backend ──(X-API-Key)──► auth-2fa-api
```

Si la key se filtra, se puede rotar sin recrear el cliente (ver sección 2.8).

## 1.4 Flujo de inicio de sesión

Todas las rutas `/auth/*` necesitan el header `X-API-Key`. Sin él, o con una key inválida o desactivada, la API responde `401`.

```
 1. POST /auth/register              Crea la cuenta y envía un código por correo
 2. POST /auth/verify-email/confirm  Confirma el correo con ese código
 3. POST /auth/login                 Contraseña correcta → devuelve login_token
 4. POST /auth/verify-otp            login_token + código del segundo factor → tokens
 5. GET  /me                         Ejemplo de ruta protegida (Authorization: Bearer ...)
 6. POST /auth/refresh               Renueva los tokens cuando el access_token vence
 7. POST /auth/logout                Cierra la sesión
```

Notas del flujo:

- En el campo `identifier` de `/auth/login` se puede usar el correo, el nombre de usuario o el RUT, indistintamente.
- Sin confirmar el correo, el login responde `403` aunque la contraseña sea correcta.
- El `refresh_token` se rota en cada uso. Si se reutiliza uno ya usado, la API lo interpreta como robo y revoca la sesión completa.
- Si el usuario no recibe el código: `POST /auth/login/resend-code` (login) y `POST /auth/verify-email/resend` (verificación de correo).

### Ejemplo completo con curl

```bash
API=https://tu-api.ejemplo.cl
API_KEY="<la key de tu sistema>"

# 1. Registro
curl -X POST $API/auth/register \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"usuario@ejemplo.cl","password":"UnaClaveSegura123","username":"juan.perez","rut":"12.345.678-5"}'

# 2. Confirmar el correo con el código recibido
curl -X POST $API/auth/verify-email/confirm \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"email":"usuario@ejemplo.cl","code":"<código del correo>"}'

# 3. Iniciar sesión
curl -X POST $API/auth/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"identifier":"usuario@ejemplo.cl","password":"UnaClaveSegura123"}'
# → { "login_token": "...", "method": "email", ... }

# 4. Enviar el código del segundo factor
curl -X POST $API/auth/verify-otp \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<del paso 3>","code":"<código del correo>"}'
# → { "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }

# 5. Usar el access_token (esta ruta no necesita X-API-Key)
curl $API/me -H "Authorization: Bearer <access_token>"
```

## 1.5 Segundos factores y capas adicionales

Cada uno se activa por una variable de entorno. Si no está configurada, las rutas correspondientes **no existen** (responden `404`, no "abiertas sin autenticación").

| Función | Variable que la habilita | Rutas principales |
|---|---|---|
| Aplicación autenticadora (TOTP) | `TOTP_ENCRYPTION_KEY` | `/auth/totp/enroll`, `/auth/totp/confirm`, `/auth/totp/disable` |
| Aprobación por notificación push (Android) | `FIREBASE_CREDENTIALS_PATH` o `FIREBASE_CREDENTIALS_JSON_BASE64` | `/auth/devices/{id}/push`, `/auth/login/push-status`, `/auth/login/push-answer` |
| Dispositivo de confianza + PIN de 6 dígitos | Siempre disponible | `/auth/devices/register`, `/auth/devices/login`, `/auth/pin/verify`, `PUT /auth/pin` |
| PIN obligatorio al final del login | Interruptor por cuenta (lo maneja el administrador) | `POST /auth/login/pin` |
| Recuperación de contraseña | Siempre disponible | `/auth/password-reset/request`, `/auth/password-reset/confirm` |

Con el PIN obligatorio activado en una cuenta, ningún método de login entrega tokens hasta completar `POST /auth/login/pin`.

## 1.6 Cómo verificar el `access_token` en otro sistema

El `access_token` es un JWT firmado con RS256. Cualquier sistema puede verificarlo **sin llamar de vuelta a la API**:

1. Descargar las claves públicas de `GET /.well-known/jwks.json` y guardarlas en caché.
2. Leer el `kid` del encabezado del JWT y usar la clave del JWKS con ese mismo `kid`. Durante una rotación de claves, el JWKS puede traer dos claves a la vez: no tomes siempre la primera.
3. Verificar la firma con cualquier librería estándar de JWT.
4. Confiar en los campos `sub` (id del usuario), `email` y `exp` (expiración).

Refresca el caché del JWKS cada cierto tiempo (por ejemplo, cada hora). Si nunca lo vuelves a pedir, no te enterarás cuando aparezca una clave nueva.

## 1.7 Protecciones automáticas que verá el integrador

- **Límite de solicitudes por IP y por cuenta** en login, código, PIN, registro y recuperación de contraseña. Al superarlo, la API responde con un error de demasiadas solicitudes (`429`).
- **Bloqueo temporal de cuenta** tras varios intentos fallidos seguidos.
- **Baneo automático de una IP** reincidente.
- **Detrás de un proxy propio**: si tu backend reenvía las solicitudes a esta API, la IP que verá la API es la de tu backend, no la del visitante. Para que los límites y el baneo funcionen con la IP real, el operador debe configurar `TRUSTED_PROXY_CIDRS` con la red de tu backend y tu backend debe enviar `X-Forwarded-For`.

## 1.8 Documentación interactiva y generación de clientes

Con la API corriendo:

- `GET /docs`: interfaz interactiva (Swagger) para ver y probar cada endpoint.
- `GET /openapi.yaml`: especificación OpenAPI. Sirve para generar un cliente automáticamente en el lenguaje que uses (con `openapi-generator`, por ejemplo).
- `GET /health`: comprobación de salud, responde `200`.

---

# Parte 2. Cómo implementarla en otro lugar

## 2.1 Qué necesita para funcionar

| Componente | Para qué se usa | Obligatorio |
|---|---|---|
| **PostgreSQL** (16 recomendado) | Datos persistentes: usuarios, sesiones, registros de actividad | Sí |
| **Redis** | Códigos de corta duración y contadores de límite de solicitudes | Sí |
| **Cuenta de Resend** | Envío de correos (códigos de verificación, de login, de recuperación) | Sí, para que lleguen correos |
| **Par de claves RSA** | Firma de los `access_token` | Sí |
| **Proyecto de Firebase** | Notificaciones push | No |
| **Stack de observabilidad** (OpenTelemetry, Prometheus, Loki, Grafana) | Métricas y logs | No |
| **Dominio con HTTPS** | Acceso público seguro | Sí, para usuarios reales |

Para compilar desde el código fuente hace falta **Go 1.26.10 o superior de la rama 1.26** (la versión que usa hoy el proyecto). Con Docker no hace falta instalar Go.

> **Correo y Resend.** Con el remitente de prueba (`onboarding@resend.dev`) solo se puede enviar a la dirección de tu propia cuenta de Resend. Para que usuarios reales puedan registrarse hay que **verificar un dominio propio** en Resend y usar una dirección de ese dominio en `RESEND_FROM`.

## 2.2 Variables de entorno

### Mínimas para que funcione de verdad

| Variable | Qué es |
|---|---|
| `POSTGRES_DSN` | Cadena de conexión a PostgreSQL |
| `REDIS_URL` | URL de Redis (`redis://` o `rediss://`) |
| `JWT_REFRESH_SECRET` | Secreto del refresh token. **Sin él, la API no arranca.** Se genera con `openssl rand -base64 48` |
| `JWT_PRIVATE_KEY_PATH` o `JWT_PRIVATE_KEY_PEM_BASE64` | Clave privada RSA. La variante base64 sirve donde no hay disco persistente |
| `JWT_KEY_ID` | Identificador de la clave (por ejemplo, `auth-2fa-api-1`) |
| `RESEND_API_KEY` | API key de Resend |
| `RESEND_FROM` | Dirección remitente (de un dominio verificado) |

### Opcionales frecuentes

| Variable | Qué habilita |
|---|---|
| `ADMIN_API_TOKEN` | Rutas `/admin/*` con token global (gestión de sistemas y moderación). Sin ella, esas rutas no existen |
| `TOTP_ENCRYPTION_KEY` | Aplicación autenticadora. Base64 de 32 bytes: `openssl rand -base64 32` |
| `FIREBASE_CREDENTIALS_JSON_BASE64` | Aprobación por push. Es preferible a la variante con ruta de archivo |
| `ADMIN_PANEL_ORIGIN` | Inicio de sesión individual del panel de operadores. Exige también `TOTP_ENCRYPTION_KEY` |
| `TRUSTED_PROXY_CIDRS` | Redes de proxies propios que pueden indicar la IP real del cliente |
| `BAN_REFERENCE_SECRET` | Código de referencia de los baneos, sin exponer la IP |
| `AUTH_EVENTS_EMAIL_HASH_SECRET` | Evita guardar correos en claro en los eventos de autenticación |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Exportar métricas y logs. Debe incluir el esquema (`http://...`) |
| `PANEL_BASE_URL` | Enlace de respaldo para el correo de cambio de correo |

Los tiempos de vida, los intentos máximos y los plazos de retención tienen valores por defecto razonables. Están todos comentados en [`.env.example`](.env.example).

## 2.3 Generar las claves RSA (una sola vez por entorno)

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

- La carpeta `keys/` está en `.gitignore`: **nunca la subas al repositorio**.
- Cada entorno (desarrollo, pruebas, producción) debe tener **su propio par**.
- No hace falta distribuir la clave pública a mano: se publica en `/.well-known/jwks.json`.
- Para una plataforma sin disco persistente, codifica la privada en base64 y úsala en `JWT_PRIVATE_KEY_PEM_BASE64`:
  `base64 -w0 keys/private.pem`

## 2.4 Opción A: Docker Compose (la más simple)

Es lo mismo que se usa en desarrollo y sirve en cualquier servidor con Docker.

1. Copia el repositorio al servidor.
2. Genera las claves RSA (sección 2.3). Deben ser legibles por el usuario sin privilegios del contenedor (`chmod 644 keys/*.pem`).
3. Crea un archivo `.env` junto a `docker-compose.yml`, con al menos `JWT_REFRESH_SECRET` y `RESEND_API_KEY`.
4. Levanta todo:

```bash
docker compose up --build -d
```

Esto inicia PostgreSQL, Redis, las migraciones (se aplican solas), la API y el stack de observabilidad. La API queda en el puerto `8080`.

5. Crea el primer sistema consumidor (la API key se muestra **una sola vez**: guárdala de inmediato):

```bash
docker compose run --rm api ./createclient create -name "nombre-del-sistema"
```

6. Comprueba que responde:

```bash
curl http://localhost:8080/health
```

> `docker-compose.yml` trae datos de acceso de ejemplo para PostgreSQL (`postgres` / `postgres`). Sirven para pruebas locales. **Cámbialos antes de exponer el servidor a internet.**

## 2.5 Opción B: VPS con Dokploy (como está hoy en producción)

El proyecto corre en un VPS propio gestionado con [Dokploy](https://dokploy.com), que construye desde el `Dockerfile` y despliega con `docker-compose.yml`. Traefik gestiona el dominio y el certificado.

1. **Conecta el repositorio** a Dokploy como proyecto de tipo *Compose*. Si activas el despliegue automático, cada `push` a la rama configurada reconstruye y despliega.
2. **Variables de entorno**: cárgalas en el panel de variables del proyecto, no en un archivo en disco.
3. **Claves RSA**: déjalas en el servidor antes del primer despliegue y móntalas como volumen, o usa `JWT_PRIVATE_KEY_PEM_BASE64`.
4. **Despliega.** El servicio de migraciones se ejecuta una vez y la API arranca solo si terminó bien. No hay que correr nada a mano.
5. **Dominio y HTTPS**: agrega un dominio al servicio `api` desde el panel de dominios.
6. **Firewall en dos capas**: si el proveedor tiene un firewall de nube además del del sistema operativo, ambos deben permitir el tráfico. Solo deben estar expuestos a internet los puertos 80 y 443. La API, Prometheus y Grafana no deberían tener su puerto publicado hacia afuera.
7. **Si otro servicio tuyo consume la API**, que le hable por la **red interna** del proyecto, no por el dominio público, y configura `TRUSTED_PROXY_CIDRS` con esa red.

## 2.6 Opción C: binario directo con servicios gestionados

Sirve si ya tienes PostgreSQL y Redis (por ejemplo, servicios en la nube) y no quieres Docker.

```bash
# 1. Configurar
cp .env.example .env        # edita los valores

# 2. Aplicar las migraciones
go run ./cmd/migrate

# 3. Crear el primer sistema consumidor
go run ./cmd/createclient create -name "nombre-del-sistema"

# 4. Arrancar
go run ./cmd/api
```

Para producción, compila los binarios (`go build -o api ./cmd/api`) y ejecútalos con un administrador de procesos (`systemd`, por ejemplo). Pon un proxy con HTTPS delante (Nginx, Caddy o Traefik).

## 2.7 Primeros pasos después de instalar

1. **Verifica la salud**: `GET /health` debe responder `200`.
2. **Crea el primer sistema consumidor** y guarda su API key.
3. **Prueba el flujo completo** con el ejemplo de la sección 1.4: registro, confirmación del correo, login y `GET /me`.
4. **Si usarás el panel de operadores**, crea la primera cuenta de administrador. Debe ser superadmin y exige que `TOTP_ENCRYPTION_KEY` esté configurada:

```bash
docker compose run --rm api ./createadmin create -email admin@ejemplo.cl -password "<mínimo 8 caracteres>"
```

   Muestra una sola vez, en la terminal, un código QR para escanear con la aplicación autenticadora y, debajo, la misma clave en texto y en grupos de 4 caracteres, por si la terminal no dibuja bien el QR (se puede ingresar a mano; los espacios son opcionales).

## 2.8 Administración del día a día

Todo esto está detallado en [`DEPLOY.md`](DEPLOY.md). Lo esencial:

| Tarea | Cómo |
|---|---|
| Listar, desactivar, reactivar o rotar la key de un sistema | `createclient list / deactivate / activate / rotate`, o `/admin/clients` con `X-Admin-Token` |
| Banear o desbanear una cuenta, revocar sesiones, restablecer un PIN | `/admin/users/*` o `/system-admin/users/*` |
| Corregir el correo de una cuenta | `POST /system-admin/users/{id}/change-email` (envía un código al correo nuevo) |
| Levantar el baneo de una IP | `/admin/blacklist` |
| Ver estadísticas y eventos de seguridad | `GET /admin/stats` y `GET /admin/security/events` |
| Ver la actividad de los operadores | `GET /admin/audit` |
| Rotar la clave de firma del JWT | Procedimiento de dos despliegues en `DEPLOY.md`, sección "Rotación de claves JWT" |

Si una API key se filtra, `rotate` emite una nueva e invalida la anterior sin perder a los usuarios del sistema.

## 2.9 Lista de verificación antes de abrirla a usuarios reales

- [ ] HTTPS con certificado válido, y el tráfico por HTTP plano redirigido o cerrado.
- [ ] Dominio propio verificado en Resend y `RESEND_FROM` configurado con él.
- [ ] Contraseñas de PostgreSQL y Redis cambiadas. Ningún valor de ejemplo en producción.
- [ ] Claves RSA propias del entorno, fuera del repositorio.
- [ ] Todos los secretos (`JWT_REFRESH_SECRET`, `ADMIN_API_TOKEN`, `TOTP_ENCRYPTION_KEY`, etc.) generados con alta entropía y guardados en un lugar controlado.
- [ ] Solo los puertos 80 y 443 expuestos a internet, en todas las capas de firewall.
- [ ] **Copias de seguridad de PostgreSQL con restauración probada.** Una copia que nunca se restauró no es una copia confiable.
- [ ] Alertas activas sobre las métricas (tasa de errores, latencia), para enterarse de una caída fuera de horario.
- [ ] `TRUSTED_PROXY_CIDRS` configurada si hay un backend propio delante de la API.
- [ ] Pruebas de carga con el tráfico esperado.
- [ ] Plan de continuidad si el servicio no puede depender de un único servidor.

## 2.10 Actualizaciones y mantenimiento

- **Actualizar la API**: obtén el código nuevo y vuelve a desplegar. Las migraciones se aplican solas.
- **Seguridad del lenguaje**: revisa de vez en cuando las vulnerabilidades conocidas con
  `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`
  y mantén `go.mod` y el `Dockerfile` en la misma versión de Go (hoy, 1.26.10).
- **Pruebas**: `go test ./...`. Las pruebas que necesitan PostgreSQL se omiten si no encuentran una base. Para que corran, apunta `TEST_POSTGRES_DSN` a una base descartable.

## 2.11 Problemas frecuentes

| Síntoma | Causa probable |
|---|---|
| La API no arranca y dice `JWT_REFRESH_SECRET must be set` | Falta esa variable |
| `401` en todas las rutas `/auth/*` | Falta el header `X-API-Key`, o la key es inválida o está desactivada |
| El login responde `403` con la contraseña correcta | El correo no se ha confirmado |
| No llegan correos | `RESEND_API_KEY` vacía o incorrecta, o remitente de prueba enviando a una dirección que no es la de tu cuenta |
| Una ruta (`/admin/*`, `/auth/totp/*`, rutas de push) responde `404` | La variable que la habilita no está configurada. Es lo esperado |
| Todos los usuarios aparecen con la misma IP | Falta `TRUSTED_PROXY_CIDRS`, o no incluye todas las redes de proxies delante de la API |
| El despliegue falla al construir la imagen | Revisa que la versión de Go del `Dockerfile` exista en Docker Hub |
