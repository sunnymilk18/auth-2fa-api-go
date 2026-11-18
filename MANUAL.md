# Manual de la API de autenticación (auth-2fa-api-go)

Este manual tiene tres partes:

1. **Cómo usar la API**: para quien va a conectar un sistema (un sitio web, una aplicación móvil, un backend) a la API.
2. **Cómo implementarla en otro lugar**: para quien va a instalarla en un servidor o en otra organización.
3. **Detector de accesos anómalos y experimento**: las alertas, las cuentas señuelo y cómo reproducir el experimento con datos simulados.

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
| `DETECTOR_ENABLED` | Detector de accesos anómalos (apagado por defecto). Todas sus variables están en la Parte 3 |
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
| Revisar y cerrar las alertas de accesos anómalos | `GET /admin/alerts`, `POST /admin/alerts/{id}/dismiss` y `/resolve` (ver la Parte 3) |
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

---

# Parte 3. Detector de accesos anómalos y experimento

Esta parte describe el módulo que revisa la actividad de autenticación en busca de accesos anómalos y deja alertas que un operador puede leer y cerrar, y cómo reproducir el experimento con datos simulados que lo evalúa.

## 3.1 Qué hace

El detector mira los eventos de inicio de sesión (`auth_events`) en **ventanas de 10 minutos** alineadas al reloj (UTC), una por **tenant** y otra por **IP**. De cada ventana calcula seis características:

| Característica | Qué cuenta |
|---|---|
| `fallos` | Intentos con credenciales o códigos malos. Es la misma definición que usa Estadísticas: no cuenta `pin_step_required`, `session_expired` ni `email_not_verified` |
| `correctos` | Inicios de sesión completados |
| `ips_distintas_con_fallos` | IPs distintas entre los intentos fallidos |
| `cuentas_distintas_atacadas` | Cuentas distintas entre los intentos fallidos (una cuenta que no existe cuenta por el hash de su correo) |
| `intentos_cuenta_inexistente` | Fallos cuyo identificador no corresponde a ninguna cuenta |
| `intentos_contra_senuelos` | Intentos, de inicio de sesión o de recuperación de contraseña, contra una cuenta señuelo |

Con eso hay tres fuentes de alerta (el campo `source`):

- **`regla`**: umbrales fijos y configurables. Una ventana alerta si alcanza o supera cualquiera de ellos (tabla de la sección 3.2).
- **`senuelo`**: cualquier intento contra una cuenta señuelo, sin umbral.
- **`isolation_forest`**: un bosque de aislamiento propio, escrito con la biblioteca estándar de Go (sin dependencias nuevas). Se entrena **fuera de línea** con tráfico normal (`cmd/train`) y la API solo carga el archivo del modelo al arrancar. El puntaje es `s = 2^(-E(h)/c(ψ))`: cerca de 1 significa más aislado, es decir, más raro. Hay un bosque para tenants y otro para IPs, porque lo normal en una ventana que junta a muchas personas no lo es en una de una sola IP.

**Sin modelo, la API funciona solo con las reglas y los señuelos.** Si el archivo no existe o no se puede leer, lo registra en el log y sigue.

Cada alerta explica por qué saltó (`motives`, en español). Las del bosque listan las características que más se alejan de lo normal en el entrenamiento, usando la mediana y la desviación absoluta mediana (MAD), por ejemplo: `"42 fallos en 10 min (lo normal es 3)"`. Ojo: "lo normal" es la mediana de **todas** las ventanas de entrenamiento, también las de madrugada, así que a las horas de más actividad puede quedar por debajo de lo que de verdad es normal a esa hora.

## 3.2 Activarlo

Está **apagado por defecto**. Para encenderlo:

```text
DETECTOR_ENABLED=true
```

| Variable | Por defecto | Qué es |
|---|---|---|
| `DETECTOR_ENABLED` | `false` | Arranca la tarea en segundo plano |
| `DETECTOR_INTERVAL` | `5m` | Cada cuánto corre |
| `DETECTOR_LOOKBACK` | `1h` | Cuánto hacia atrás revisa en cada pasada (mínimo, dos ventanas). Volver a mirar ventanas ya revisadas no duplica alertas |
| `DETECTOR_MODEL_PATH` | `models/iforest.json` | Archivo del modelo |
| `DETECTOR_RULE_FALLOS` | `20` | Umbral de `fallos` |
| `DETECTOR_RULE_CUENTAS` | `10` | Umbral de `cuentas_distintas_atacadas` |
| `DETECTOR_RULE_IPS` | `10` | Umbral de `ips_distintas_con_fallos` |
| `DETECTOR_RULE_INEXISTENTES` | `10` | Umbral de `intentos_cuenta_inexistente` |
| `DETECTOR_IF_TREES` | `100` | Árboles (t). Solo lo usa `cmd/train` |
| `DETECTOR_IF_SUBSAMPLE` | `256` | Submuestra por árbol (ψ). Solo `cmd/train` |
| `DETECTOR_IF_SEED` | `42` | Semilla del bosque. Solo `cmd/train` |
| `DETECTOR_IF_QUANTILE` | `0.995` | Cuantil de los puntajes de entrenamiento con que `cmd/train` calibra el umbral guardado en el modelo |
| `DETECTOR_IF_THRESHOLD` | sin definir | Umbral de puntaje (entre 0 y 1). Sin definir, cada bosque usa el umbral calibrado de su modelo; definido, vale para los dos |

Un umbral de regla en `0` desactiva esa regla. Los umbrales por defecto son razonables, pero **no están calibrados** contra datos reales: ajústalos a la actividad normal de tus sistemas.

**Por qué el umbral del bosque se calibra y no es un valor fijo.** Con conteos tan repetidos (la mayoría de las ventanas son "un inicio de sesión correcto y nada más") el puntaje de lo normal no se queda en 0,5: en el entrenamiento de la simulación, el 10 % de las ventanas por IP ya puntúa sobre 0,58. Por eso `cmd/train` guarda, para cada bosque, el primer valor por encima del cuantil 0,995 de sus propios puntajes: se espera alertar a lo más un 0,5 % del tráfico normal. Una limitación conocida del método: un valor fuera del rango visto en el entrenamiento puntúa más o menos como el más extremo que sí se vio, no mucho más. El AUC y la tabla de sensibilidad de `cmd/evaluate` ayudan a verlo.

## 3.3 Rutas de alertas

Mismo acceso que `GET /admin/security/events`: administrador o superadmin con sesión del panel (o el `X-Admin-Token`). Ninguna lleva PIN: cerrar una alerta no le quita acceso a nadie. Como el resto de `/admin/*`, no están en `openapi.yaml`.

| Ruta | Qué hace |
|---|---|
| `GET /admin/alerts` | Lista paginada, la más reciente primero |
| `GET /admin/alerts/{id}` | Una alerta |
| `POST /admin/alerts/{id}/dismiss` | La marca como `descartada` (falsa alarma) |
| `POST /admin/alerts/{id}/resolve` | La marca como `resuelta` (era real y ya se atendió) |

**Filtros de `GET /admin/alerts`**: `state` (`abierta`, `descartada` o `resuelta`), `tenant` (UUID), `from` y `to` (`AAAA-MM-DD`, en UTC; el día de `to` entra completo), `page` y `page_size` (por defecto 50, máximo 100). Sin fechas se muestran los últimos 7 días; el rango no puede pasar de 90 días. Un filtro mal formado responde `400`. Las fechas se comparan con el **inicio de la ventana** de la alerta, no con el momento en que el detector la generó.

La respuesta es `{ "items": [...], "total": n, "page": n, "page_size": n }`. Cada alerta tiene esta forma:

```json
{
  "id": "256dc433-bd76-4f9d-98d3-731dfca9fb5f",
  "tenant": { "id": "21b1ee80-9c67-4062-bd93-67cb831e3b15", "name": "sim-hospital" },
  "ip": null,
  "window_start": "2026-10-13T23:40:00Z",
  "window_end": "2026-10-13T23:50:00Z",
  "source": "isolation_forest",
  "score": 0.802606636526959,
  "features": {
    "fallos": 73, "correctos": 1, "ips_distintas_con_fallos": 52,
    "cuentas_distintas_atacadas": 4, "intentos_cuenta_inexistente": 0, "intentos_contra_senuelos": 0
  },
  "motives": [
    "52 IPs distintas con fallos en 10 min (lo normal es 0)",
    "73 fallos en 10 min (lo normal es 0)",
    "4 cuentas distintas atacadas en 10 min (lo normal es 0)"
  ],
  "state": "abierta",
  "created_at": "2026-11-18T14:00:29Z",
  "resolved_at": null,
  "resolved_by": null,
  "note": null
}
```

- `tenant` llega como `{}` si la alerta no tiene tenant (por ejemplo, una IP que tocó a varios sistemas en la misma ventana).
- `ip` es `null` en las alertas por tenant. `score` es `null` salvo en las del bosque.
- `resolved_by` es el **correo de la cuenta de operador** que cerró la alerta, o `null` si sigue abierta o la cerró la credencial compartida `X-Admin-Token` (que no tiene cuenta individual).

`dismiss` y `resolve` aceptan un cuerpo opcional `{ "note": "..." }` (hasta 1000 caracteres) y responden con la alerta ya cerrada. Si la alerta ya no está abierta responden `409`; si no existe, `404`. Quedan en el registro de actividad (`GET /admin/audit`) con los códigos `alert_dismissed` y `alert_resolved`.

## 3.4 Cuentas señuelo

Una cuenta señuelo (`users.is_decoy = TRUE`) es una trampa: ninguna persona real tiene motivo para usarla, así que cualquier intento contra ella delata a quien anda probando cuentas.

- **Nunca inicia sesión con éxito**, ni con la contraseña correcta. Responde exactamente igual que unas credenciales incorrectas, sin pistas de que existe. El intento queda en `auth_events` con `is_decoy = TRUE`.
- Una solicitud de recuperación de contraseña sobre un señuelo responde lo mismo que para cualquier cuenta, pero no manda ningún correo y también queda marcada.
- **No cuentan como usuarios reales**: quedan fuera de `users_per_tenant` y de los demás números de usuarios de Estadísticas, y fuera de `GET /admin/users` salvo que se pida con `include_decoys=true`. Cada elemento de ese listado trae ahora el campo `is_decoy`.

Todavía no hay un comando para crear señuelos (los de la simulación los crea `cmd/simulate` directamente). Mientras tanto, se registra una cuenta con un correo que controles, se confirma, y se marca en la base: `UPDATE users SET is_decoy = TRUE WHERE id = '...'`. Conviene que el nombre se parezca a una cuenta valiosa (`respaldo.sistemas`, `admin.soporte`).

## 3.5 El experimento: simular, entrenar y evaluar

Tres comandos, **solo contra la base de datos local**:

| Comando | Qué hace |
|---|---|
| `cmd/simulate` | Genera datos **simulados** con semilla fija: tráfico normal (con su ruido: contraseñas olvidadas, oficinas enteras tras una misma IP) y cinco escenarios de ataque: relleno de credenciales, pulverizado de contraseñas, fuerza bruta a una cuenta, ataque distribuido y toque a señuelos. Escribe las etiquetas reales en `ground_truth.json` y los rangos de fechas en `meta.json` |
| `cmd/train` | Entrena el Isolation Forest con el tráfico normal del primer período y escribe el modelo en JSON (árboles y estadísticas de normalidad por característica) |
| `cmd/evaluate` | Corre reglas y bosque sobre el segundo período y los compara con las etiquetas: matriz de confusión, precisión, exhaustividad y F1 por método, detección por escenario y detección de señuelos. Escribe CSV y tablas en Markdown |

El detector **nunca lee** `ground_truth.json`: solo `cmd/evaluate` lo usa, para calificar. Los tres comandos se niegan a correr si el servidor de la base no es local (`localhost`, `127.0.0.1`, `::1` o un socket Unix), y `cmd/simulate` además exige la variable de confirmación `SIMULATE_CONFIRM_LOCAL=yes`. Ninguno carga el `.env` de la API, porque ese archivo podría apuntar a producción: la base sale de `EXPERIMENT_POSTGRES_DSN`, `TEST_POSTGRES_DSN` o `POSTGRES_DSN` del entorno del proceso, y si no hay ninguna, de la base local por defecto (`postgres://postgres:postgres@localhost:5432/auth2fa`).

Los datos simulados viven en tenants cuyo nombre empieza con `sim-`. Cada corrida de `cmd/simulate` borra antes la simulación anterior (solo esos tenants) y la reemplaza; `cmd/simulate -limpiar` solo borra. Las migraciones tienen que estar aplicadas (`go run ./cmd/migrate`).

### Con un solo comando

Desde la raíz del proyecto, con PostgreSQL local encendido:

```powershell
pwsh scripts/experimento.ps1
```

o, en Linux y macOS, `sh scripts/experimento.sh`. Los dos aceptan una semilla, una carpeta de salida y una intensidad de los ataques (`-Semilla 7 -Salida experimento-7 -Intensidad lento` en PowerShell; `sh scripts/experimento.sh 7 experimento-7 lento` en shell; ver la sección 3.7). Esto equivale a:

```powershell
$env:SIMULATE_CONFIRM_LOCAL = "yes"
go run ./cmd/simulate -semilla 42 -salida experimento
go run ./cmd/train -meta experimento/meta.json -prefijo-tenant sim- -salida experimento/modelo.json
go run ./cmd/evaluate -meta experimento/meta.json -etiquetas experimento/ground_truth.json -modelo experimento/modelo.json -prefijo-tenant sim- -salida experimento
```

Escribe en `experimento/` (que está en `.gitignore`): `ground_truth.json`, `meta.json`, `modelo.json`, `resultados.md` (las tablas, listas para pegar en el informe) y cinco CSV (`resultados_metricas.csv`, `resultados_escenarios.csv`, `resultados_senuelos.csv`, `resultados_umbral.csv` y `resultados_tiempos.csv`).

**Es reproducible**: con la misma semilla, la simulación, el modelo y los resultados salen idénticos byte a byte (no se escribe ninguna fecha de ejecución). Los identificadores también salen de la semilla, y las fechas de la simulación son fijas (del 5 al 16 de octubre de 2026: siete días de entrenamiento sin ataques y cuatro de evaluación con ataques).

### Cómo leer los resultados

- **La unidad evaluada** es una ventana de 10 minutos para una clave (un tenant o una IP). Es positiva si alguna etiqueta apunta a ella. En un ataque distribuido solo es positiva la unidad del tenant: cada IP suelta se ve como tráfico normal, así que las unidades por IP de esos participantes **se excluyen de la matriz** (el informe dice cuántas).
- **Los umbrales de las reglas no se ajustaron a la simulación**: son los valores por defecto. El umbral del bosque sale del cuantil 0,995 de los puntajes del propio entrenamiento, sin mirar la evaluación. La tabla de sensibilidad muestra el bosque con otros umbrales solo para ver qué tan sensible es, no para escoger uno.
- **Los resultados dependen de cómo se simularon los ataques** (intensidad, duración, cantidad de cuentas). Esos parámetros son supuestos y están en `internal/simulate/simulate.go`; conviene decirlo en el informe. La simulación tampoco modela el limitador de tasa por IP de la API, que en producción recortaría varios de estos ataques.

Cifras de referencia con la semilla 42 (matriz sobre 7620 unidades, 140 positivas), para comprobar que tu corrida coincide:

| Método | VP | FP | FN | VN |
|---|---:|---:|---:|---:|
| Reglas (umbrales) | 115 | 2 | 25 | 7478 |
| Señuelos (regla) | 20 | 0 | 120 | 7480 |
| Reglas + señuelos (línea base) | 135 | 2 | 5 | 7478 |
| Isolation Forest | 96 | 59 | 44 | 7421 |
| Combinado | 140 | 59 | 0 | 7421 |

Si cambias el código de la simulación o del detector, estas cifras cambian; actualízalas.

## 3.6 Entrenar con datos propios

`cmd/train` no necesita la simulación: acepta `-desde` y `-hasta` (`AAAA-MM-DD`) para entrenar con un rango de la base local y `-salida` para elegir el archivo (por defecto `DETECTOR_MODEL_PATH`). El rango debe ser tráfico normal: si hay ataques mezclados, el bosque los aprende como normales (el comando avisa cuántas ventanas del entrenamiento ya disparan las reglas). Como solo lee de la base local, para entrenar con datos de producción hay que traer antes una copia a una base local. Copia el archivo resultante al servidor y apunta `DETECTOR_MODEL_PATH` a él; la API lo carga al arrancar.

## 3.7 Varias semillas e intensidad de los ataques

Para comprobar que los resultados no dependen de una sola semilla ni de un único nivel de dificultad, el experimento se puede correr con otras semillas y con una segunda intensidad.

**Intensidad `actual`** (la de siempre): es la simulación original y no cambia. Una prueba automática guarda la huella de la simulación de la semilla 42, para que sus resultados sigan siendo comparables con los del informe.

**Intensidad `lento`**: vuelve más sigilosos el relleno de credenciales y el pulverizado de contraseñas. En vez de 25 a 70 intentos (relleno) o de 8 a 28 cuentas (pulverizado) en una a cuatro ventanas, hacen 5 a 9 intentos (relleno) o 6 a 9 cuentas (pulverizado) por ventana, durante 6 a 12 ventanas seguidas desde la misma IP. Cada ventana, vista sola, queda bajo **todos** los umbrales de las reglas por defecto (menos de 20 fallos, de 10 cuentas y de 10 intentos contra cuentas inexistentes); lo anómalo es la combinación. Los otros tres escenarios y todo el tráfico normal quedan idénticos para una misma semilla, así que el modelo entrenado también es el mismo. Los umbrales de las reglas y el cuantil del bosque no se tocan: el umbral sigue saliendo solo del entrenamiento.

```powershell
pwsh scripts/experimento.ps1 -Semilla 42 -Intensidad lento -Salida experimento_lento_s42
```

o `go run ./cmd/simulate -semilla 42 -intensidad lento ...` si corres los tres comandos por separado. Cuando la intensidad no es `actual`, queda anotada en `meta.json`, en `ground_truth.json` y en la cabecera de `resultados.md`; con `actual` esos archivos no cambian.

Para varias semillas, corre el script una vez por semilla con una carpeta de salida distinta. `cmd/simulate` reemplaza la simulación anterior en cada corrida (solo los tenants `sim-`); si quieres partir de cero, corre antes `go run ./cmd/simulate -limpiar` con `SIMULATE_CONFIRM_LOCAL=yes`.

### Cifras de referencia (semillas 42, 7, 123 y 2026)

Promedio y rango del F1 entre las cuatro semillas, matriz sobre todas las unidades (ver la sección 3.5 para qué es una unidad):

| Método | Intensidad `actual` | Intensidad `lento` |
|---|---|---|
| Reglas (umbrales) | 0,900 [0,878–0,917] | 0,260 [0,204–0,306] |
| Señuelos (regla) | 0,241 [0,212–0,269] | 0,106 [0,098–0,111] |
| Reglas + señuelos (línea base) | 0,977 [0,968–0,983] | 0,340 [0,283–0,384] |
| Isolation Forest | 0,629 [0,578–0,674] | 0,698 [0,533–0,824] |
| Combinado | 0,854 [0,826–0,879] | 0,804 [0,704–0,911] |

AUC-ROC del bosque (tenant / IP): 0,971 / 0,993 con `actual` y 0,984 / 0,997 con `lento`.

Detección de incidentes por escenario, promedio entre semillas (el rango completo está en las carpetas de resultados):

| Escenario | Intensidad | Línea base | Isolation Forest | Combinado |
|---|---|---:|---:|---:|
| Relleno de credenciales | actual | 100 % | 100 % | 100 % |
| Relleno de credenciales | lento | 25 % | 100 % | 100 % |
| Pulverizado | actual | 100 % | 100 % | 100 % |
| Pulverizado | lento | 22 % | 100 % | 100 % |
| Fuerza bruta | ambas | 100 % | 50 % (0–100 %) | 100 % |
| Distribuido | ambas | 100 % | 25–31 % (0–100 %) | 100 % |
| Señuelos | ambas | 100 % | 2,5 % | 100 % |

Cómo leer estas cifras:

- **Con `lento`, las reglas dejan de servir y el bosque no:** detectan solo el 3 al 4 % de las ventanas de relleno y de pulverizado, mientras el bosque detecta todas. El combinado supera ampliamente a la línea base.
- **El bosque falla donde las reglas aciertan:** en fuerza bruta y en ataque distribuido su detección cambia mucho de una semilla a otra (de 0 a 100 %), porque el puntaje de un valor fuera del rango visto casi no sube más que el de los valores más extremos del entrenamiento (sección 3.2). Los resultados de la semilla 42 de esos dos escenarios son de los más favorables al bosque, no representativos.
- **Los F1 de `actual` y `lento` no se comparan entre sí sin cuidado:** con `lento` hay entre 2 y 3 veces más unidades positivas (muchas ventanas por incidente), y precisión y F1 dependen de la proporción de positivos.
- **`lento` está diseñado para quedar bajo los umbrales de las reglas por defecto:** es una prueba de sigilo, no una estimación de qué tan frecuente es un ataque así.

### Tiempo de detección

`cmd/evaluate` también mide qué tan rápido detecta cada método. Para cada incidente detectado calcula el **retraso en ventanas**: la distancia entre la primera ventana atacada del incidente y la primera en que ese método alertó (0 = detectado en la primera ventana). Lo reporta por método y por escenario: promedio, mediana y máximo, y cuántos incidentes quedaron **sin detectar** (esos no entran en el promedio y se muestran aparte).

Para pasarlo a tiempo real con el detector actual, calcula el **peor caso en minutos**: el fin de la ventana detectada, más el intervalo de la tarea (`DETECTOR_INTERVAL`, 5 min por defecto), menos el inicio de la primera ventana atacada. Un incidente detectado en su primera ventana tiene entonces un peor caso de 15 minutos: el detector solo mira ventanas ya completas (10 min) y la pasada que la recoge puede tardar hasta un intervalo más.

Está en la última sección de `resultados.md` y en `resultados_tiempos.csv`. Para agregarlo por semilla e intensidad, junto con el resto de las métricas, corre las carpetas por semilla e intensidad (`experimento`, `experimento_s<semilla>`, `experimento_lento_s<semilla>`) y después:

```powershell
python scripts/resumen_experimento.py
```

El resumen queda en `experimento_resumen/resumen.md` (ignorado por git).

Con las cuatro semillas y el intervalo por defecto:

- **Intensidad `actual`:** todo lo que se detecta se detecta en la primera ventana (peor caso de 15 minutos). La única excepción son algunos incidentes de pulverizado que las reglas detectan en la segunda ventana (peor caso de 25 minutos). El combinado detecta todos los incidentes, siempre en la primera ventana.
- **Intensidad `lento`:** las reglas detectan 8 de 32 incidentes de relleno y 7 de 32 de pulverizado, y los que detectan los ven con retraso: 1,3 ventanas en promedio en el relleno y 3,75 en el pulverizado (peor caso promedio de 28 y 52,5 minutos; máximo de 105). El bosque los detecta todos en la primera ventana. El combinado sigue detectando todos los incidentes en la primera ventana.

Cómo leer estas cifras:

- **El retraso solo cuenta los incidentes detectados.** El bosque aparece siempre con retraso 0, pero no detecta la mitad de las fuerzas brutas ni entre el 69 y el 75 % de los ataques distribuidos: un promedio sin mirar los "sin detectar" engaña.
- **La simulación no tiene escalada:** cada ataque arranca a plena intensidad en el comienzo de una ventana, así que un retraso 0 es en buena parte consecuencia de cómo se simuló. Los retrasos mayores que 0 (las reglas con ataques lentos) son lo más informativo de esta métrica.
- **El inicio del ataque se toma como el comienzo de su primera ventana**, por lo que el peor caso es conservador: un ataque real que empieza a mitad de ventana se detecta en menos tiempo.

## 3.8 Alertas de prueba para el panel

Para probar la pantalla del panel con alertas reales (y no inventadas a mano), con la simulación ya cargada (`cmd/simulate`) y el modelo entrenado (`cmd/train`; el script `scripts/experimento.ps1` hace las dos cosas):

```powershell
$env:SIMULATE_CONFIRM_LOCAL = "yes"
go run ./cmd/seedalerts -meta experimento/meta.json -modelo experimento/modelo.json
```

`cmd/seedalerts` hace que el detector recorra el período de evaluación (12 al 16 de octubre de 2026 en la simulación original) con `detector.Run`, o sea, por el mismo camino que la tarea en segundo plano de la API: nunca inserta alertas a mano. Después cierra algunas por las rutas de la API (`POST /admin/alerts/{id}/dismiss` y `/resolve`, con una nota): unas como `descartada` y otras como `resuelta`, y deja el resto `abierta`. Con la semilla 42 en intensidad `actual` quedan 292 alertas: 117 de la fuente `regla`, 20 de `senuelo` y 155 de `isolation_forest`; de cada fuente, 2 descartadas, 2 resueltas y el resto abiertas (`-por-fuente N` cambia cuántas).

- **Es repetible:** correrlo otra vez no duplica alertas (índice único de `alerts`) ni cierra más: los cierres se calculan contra las que ya están cerradas.
- **Solo base local:** mismas protecciones que `cmd/simulate` (se niega si la base no es local y exige `SIMULATE_CONFIRM_LOCAL=yes`) y no carga el `.env`. Solo toca alertas de tenants `sim-*`.
- **Cómo pasa por las rutas sin levantar la API:** sirve el router real de la API en proceso, con un Redis en memoria y una credencial `X-Admin-Token` aleatoria que no sale del proceso. Por eso los cierres quedan atribuidos a esa credencial compartida (`resolved_by` vacío) y en el registro de actividad aparecen con actor `token`, no con la cuenta de un operador.
- **Se borra con `cmd/simulate -limpiar`:** junto con los tenants `sim-*` se borran sus alertas y las entradas del registro de actividad de esos cierres.

Si no hay `modelo.json`, `cmd/seedalerts` se niega: corre antes `cmd/train` (o el script de un solo comando).
