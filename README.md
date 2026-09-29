# auth-2fa-api-go

API independiente en Go para autenticación con doble factor por correo (email + contraseña, luego código OTP enviado por email; el correo debe verificarse antes de poder loguear). Pensada para que cualquier otro sistema la consuma vía HTTP.

## Arquitectura

- **PostgreSQL**: datos persistentes de usuarios (`users`) y tokens de refresco (`refresh_tokens`). Un job en segundo plano dentro del propio proceso de la API (`cleanupExpiredRefreshTokens` en `cmd/api/main.go`) corre una vez al iniciar y luego cada 24h, y borra las filas que ya no sirven para nada: las expiradas (`expires_at` pasado) y las revocadas hace más de 48h (`revokedRetentionWindow`, ver `RefreshRepository.DeleteExpired`) — sin esto la tabla crecería sin límite, ya que `ConsumeIfValid` solo rechaza un token inválido, no lo borra. La ventana de 48h (en vez de borrar al revocar, o esperar los 7 días completos del `REFRESH_TOKEN_TTL`) es a propósito: un token revocado sigue existiendo un rato para poder reconocer si alguien intenta reusar una copia robada, sin arrastrar filas muertas más tiempo del que ese margen realmente aporta. Seguro de correr desde más de una instancia a la vez si en algún momento se despliega con réplicas (cada corrida es solo un `DELETE ... WHERE`, sin coordinación necesaria).
- **Redis**: códigos de corta duración (OTP de login, verificación de correo, reset de contraseña — todos expiran solos vía TTL, no se guardan en Postgres) y contadores de rate limiting.
- **JWT**:
  - Access token firmado con **RS256** (clave privada/pública) — cualquier sistema que reciba el token puede verificarlo por su cuenta usando la clave pública publicada en `/.well-known/jwks.json`, sin llamar de vuelta a esta API.
  - Refresh token firmado con **HS256** (secreto compartido) — de uso exclusivo interno (`/auth/refresh`, `/auth/logout`), rotado en cada uso (verificación y revocación en un solo paso atómico, `RefreshRepository.ConsumeIfValid` — evita que dos solicitudes casi simultáneas con el mismo token, ej. varias pestañas del navegador abiertas, logren "colarse" las dos antes de que cualquiera quede marcado como usado) y revocable desde Postgres.
- **Rate limiting**: por IP, con contador en Redis, sobre `/auth/register`, `/auth/login`, `/auth/verify-otp`, `/auth/refresh`, `/auth/devices/login`, `/auth/password-reset/*` y `/auth/verify-email/*` — mitiga fuerza bruta sobre contraseñas, códigos OTP y PINs, y evita que alguien con un solo refresh token válido pueda inflar `refresh_tokens` a propósito golpeando `/auth/refresh` sin freno. Además, `/auth/login` tiene un segundo límite **por cuenta** (`LOGIN_MAX_FAILED_ATTEMPTS`/`LOGIN_LOCKOUT_WINDOW`) — el límite por IP no detecta a alguien probando contraseñas contra una cuenta puntual desde muchas IPs distintas; es un throttle temporal, no un bloqueo permanente (eso sería, en sí mismo, una forma de bloquear a otra persona a propósito).
- **Lista negra automática por IP** (`internal/middleware.Blacklist`): una IP que dispara cualquiera de los rate limits de arriba 3 veces separadas en 24h queda baneada del todo (no solo throttleada) — 24h la primera vez, 72h la segunda, 7 días de ahí en más. El nivel de escalada se olvida solo tras 30 días sin nuevas infracciones, para no castigar para siempre una IP compartida (biblioteca pública, wifi comunitario) mucho después de que el que abusó ya se fue. Un admin puede levantar un baneo a mano con `DELETE /admin/blacklist/{ip}` (mismo header `X-Admin-Token`).
- **Bloqueo manual de cuentas**: `POST /admin/users/{id}/ban` desactiva una cuenta puntual, revoca todos sus refresh tokens y dispositivos de confianza, y marca sus access tokens ya emitidos como inválidos desde ese instante (revierte con `/unban`) — a diferencia de la lista negra por IP, esto nunca se dispara solo por intentos fallidos de login, precisamente para que nadie pueda bloquear la cuenta de otra persona a propósito solo sabiendo su email/usuario/rut. Es una herramienta operativa, para cuando un caso de abuso se identifica puntualmente. `/auth/refresh` además verifica por su cuenta que la cuenta siga activa antes de renovar un token — una segunda capa de defensa, no un sustituto de la revocación de arriba, por si esta llegara a fallar a medias. `/admin/users/{id}/disable-totp` y `/admin/users/{id}/revoke-sessions` cubren dos casos más puntuales: apagar la app autenticadora de alguien que perdió el celular (sin necesidad de que pueda loguear), y cerrar todas las sesiones de una cuenta sin llegar a bloquearla (esta última también marca los access tokens vigentes como inválidos, igual que el ban).
- **Revocación instantánea de access tokens** (`internal/auth.AccessRevocationStore`): un access token es un JWT sin estado — por diseño, cualquier ruta protegida lo valida solo con la firma y la fecha de expiración, sin consultar la base en cada request. Eso significa que revocar el refresh token de una cuenta (ban, `revoke-sessions`, reset de contraseña) no alcanza para cortar un access token que ya estaba en uso: seguiría funcionando hasta que expire solo (`ACCESS_TOKEN_TTL`, 15 minutos por defecto). Para esos tres casos, además se guarda en Redis una marca por usuario ("nada emitido antes de este instante vale") con esa misma expiración, y cada request autenticado la consulta — un costo extra mínimo (una lectura a Redis, normalmente un `MISS` rapidísimo ya que la mayoría de las cuentas nunca la disparan) a cambio de que un bloqueo sea efectivo de inmediato, no en hasta 15 minutos.
- **Dispositivos de confianza + PIN**: capa adicional opcional — tras un login completo, un dispositivo puede quedar marcado como confiable (tabla `trusted_devices`, mismo Postgres) y reautenticarse después solo con `device_id` + `device_token` + PIN de 6 dígitos, sin repetir password ni OTP por correo.
- **Verificación por app autenticadora (TOTP)**: alternativa opcional al código por correo — cada cuenta la activa por su cuenta (ver [Verificación por app autenticadora](#verificación-por-app-autenticadora-totp-opcional)). Requiere `TOTP_ENCRYPTION_KEY`; sin ella, `/auth/totp/*` no existe (mismo criterio que `ADMIN_API_TOKEN`).
- **Aprobación por notificación push**: tercer método opcional, además de correo y TOTP — un login en un dispositivo (típicamente PC) se confirma con un tap en un celular ya emparejado, en vez de tipear un código. Vía Firebase Cloud Messaging (Android). Requiere `FIREBASE_CREDENTIALS_PATH`; sin ella, `/auth/devices/{id}/push`, `/auth/login/push-status`, `/auth/login/push-answer` y `/auth/login/request-email-code` no existen (mismo criterio que `TOTP_ENCRYPTION_KEY`).
- **Multi-tenant (API keys)**: cada sistema consumidor (app móvil, web, etc.) se identifica con una API key propia en el header `X-API-Key`. Los usuarios quedan aislados por sistema — el mismo email, username o rut puede existir como cuentas distintas bajo dos API keys diferentes.
- **Administración por sistema (credencial scoped)**: además del `X-Admin-Token` global (el operador de toda la infraestructura), cada sistema consumidor puede tener su propia credencial de administración — `X-System-Admin-Token` — que solo puede moderar **sus propios** usuarios: ban/unban, desactivar TOTP y cerrar sesiones. Contra un usuario de otro sistema responde `404`, nunca `403` — así nunca confirma ni niega que ese id exista en algún otro sistema. Se provisiona con el `X-Admin-Token` (ver [Administración por sistema](#administración-por-sistema-credencial-scoped) más abajo); la mayoría de los clientes nunca necesitan una.
- **Identidad del usuario**: además de email + password, cada cuenta tiene `username` (8-32 caracteres, no único entre personas, al menos una letra, sin forma de rut aunque tenga puntos/guiones, sin "@") y `rut` (documento chileno, único por sistema, validado con dígito verificador). El login acepta cualquiera de los tres — email, username o rut — en un único campo `identifier`: no hay detección de forma, se prueban los tres normalizados en una sola consulta (`email = ? OR username = ? OR rut = ?`), y las reglas de arriba garantizan que solo una columna puede coincidir.
- **CORS**: habilitado para cualquier origen (`*`), sin credenciales — la API se autentica por headers (`X-API-Key`, `Authorization`), no por cookies de sesión, así que no hay nada que filtrar abriendo el origen a todos. Cada sistema consumidor puede llamar desde su propio frontend sin que haga falta mantener una lista de dominios permitidos.
- **Documentación**: especificación OpenAPI servida en `/openapi.yaml`, con UI interactiva (Swagger UI) en `/docs`.
- **Observabilidad**: métricas (Prometheus) y logs estructurados (Loki) vía OpenTelemetry — ver [Observabilidad](#observabilidad) más abajo.
- **Envío de correo**: interfaz `mailer.Mailer` — implementación actual usa la API HTTP de [Resend](https://resend.com), no SMTP a propósito: varios proveedores cloud (PaaS) bloquean o filtran puertos SMTP salientes, algo que este proyecto sufrió literalmente en un despliegue real. Cambiar de proveedor implica solo escribir una nueva implementación de esa interfaz.

## Flujo de autenticación

Todas las rutas `/auth/*` requieren el header `X-API-Key` (ver [Multi-tenant](#multi-tenant-api-keys) más abajo).

1. `POST /auth/register` — crea el usuario (email + password hasheado con bcrypt + username + rut), dentro del sistema identificado por la API key, y envía un código de verificación por correo (ver [Verificación de correo](#verificación-de-correo) más abajo). La cuenta existe desde ya, pero no puede loguear hasta confirmarlo.
   - `email`: formato validado (un solo "@", dominio con punto, sin espacios) — no alcanza con que no esté vacío.
   - `username`: 8-32 caracteres, al menos una letra (un username puramente numérico se rechaza — se lee como un número de cuenta, no como un nombre elegido; no exige también un número, `"juanperez"` es válido), no puede tener forma de rut (ni siquiera con puntos/guiones — `"1234.5678"` también se rechaza) ni contener "@" (ver por qué en el paso 2), y no tiene que ser único entre personas — si ya está tomado, el registro falla con `409` sugiriendo una alternativa libre (ej. `"el usuario 'juan.perez' ya está en uso, probá con 'juan.perez2'"`).
   - `rut`: documento de identidad chileno, único por sistema, validado con el dígito verificador (módulo 11) — acepta cualquier formato de entrada (`12.345.678-5`, `12345678-5`, `123456785`).
2. `POST /auth/login` — valida `identifier` + `password`. `identifier` acepta el email, el username **o** el rut de la cuenta — el backend prueba las tres columnas en una sola consulta (`email = ? OR username = ? OR rut = ?`), sin adivinar antes cuál es cuál (nada que el cliente tenga que indicar aparte: un solo campo, sin selector de "con qué querés loguear"). Es justamente por esto que `username` no puede tener forma de rut ni contener "@": si se permitiera, el username de una persona podría coincidir con el rut o el email real de otra, y esa consulta ya no sería segura. Si son correctos pero el correo todavía no fue verificado, devuelve un error (403) en vez de continuar — ver más abajo por qué.
   - **Primer login de la cuenta** (y solo si el servidor tiene `TOTP_ENCRYPTION_KEY` configurada — ver [Verificación por app autenticadora](#verificación-por-app-autenticadora-totp-opcional)): no manda ningún código todavía. La respuesta trae `needs_2fa_setup: true` + un `login_token` — el cliente le muestra al usuario la elección ("¿correo o app autenticadora?") y sigue por uno de los dos caminos descritos ahí. Esto pasa una sola vez por cuenta.
   - **Cualquier otro caso** (ya eligió método antes, o el servidor no tiene TOTP configurada): genera un código OTP, lo guarda (hasheado) en Redis con expiración, lo envía por correo y devuelve `login_token` (`needs_2fa_setup: false`) — el comportamiento de siempre.
   - **Además**, si la cuenta tiene un dispositivo con aprobación por notificación push habilitada (ver [Aprobación por notificación push](#aprobación-por-notificación-push-opcional) más abajo), la respuesta también trae `push_approval_offered: true` — el cliente puede hacer polling de `GET /auth/login/push-status` con ese mismo `login_token` y dejar que el usuario apruebe desde el celular. **A diferencia de TOTP, en este caso el código NO se manda por correo todavía** — mismo criterio que sistemas como Microsoft Authenticator o Duo: push es el desafío por defecto, el correo queda como respaldo bajo demanda (`POST /auth/login/request-email-code`), no algo que se dispara en cada login tenga o no sentido. Nunca junto con `needs_2fa_setup: true` — recién en el primer login no hay ningún dispositivo emparejado todavía.
3. `POST /auth/verify-otp` — recibe `login_token` + `code`. Si coincide, emite `access_token` + `refresh_token`. El mismo endpoint sirve tanto si la cuenta usa el código por correo como si activó una app autenticadora (ver [Verificación por app autenticadora](#verificación-por-app-autenticadora-totp-opcional) más abajo) — el cliente no necesita saber cuál de los dos aplica, el paso 2 ya decide eso por dentro.
   - **"No recibí el código"**: `POST /auth/login/resend-code` con el mismo `login_token` reenvía un código nuevo por correo (invalida el anterior) para el caso normal del paso 2 (sin push). Siempre disponible, a diferencia de `/auth/login/request-email-code` (que necesita una sesión de push) — no depende de ninguna variable opcional. Para una cuenta con TOTP no hay nada que reenviar (el código sale de la app del usuario, no del servidor): devuelve `409`.
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

### Verificación por app autenticadora (TOTP, opcional)

Alternativa al código por correo — cada cuenta la elige (o no) por su cuenta, no es algo que el sistema consumidor decida de antemano. Requiere `TOTP_ENCRYPTION_KEY` configurada (ver [Variables opcionales](#variables-opcionales)); si no está seteada, estas rutas ni siquiera existen (404, mismo criterio que `ADMIN_API_TOKEN`) y `/auth/login` nunca ofrece la elección — se comporta exactamente como si esta sección no existiera.

`/auth/totp/enroll` y `/auth/totp/confirm` aceptan **dos formas distintas** de identificar la cuenta, según el momento:

- **`Authorization: Bearer <access_token>`** — cambiar de método más adelante, desde una pantalla de "Seguridad de mi cuenta" ya logueado. `/confirm` responde `204`, sin tokens (la sesión ya existe).
- **`{"login_token": "..."}` en el body** — eligiendo el método en el primer login de la cuenta (ver abajo), antes de que exista ningún `access_token` todavía. `/confirm` responde `200` con `access_token` + `refresh_token` directo — confirmar el código activa TOTP **y** completa el login en un solo paso, sin pasar por `/auth/verify-otp`.

**Primer login de una cuenta, paso a paso** (solo la primera vez — ver el paso 2 de arriba):

15. `POST /auth/login` devuelve `needs_2fa_setup: true` + `login_token`, sin mandar ningún correo. El cliente le muestra al usuario la elección.
16. Si elige **correo**: `POST /auth/login/send-email-code` con ese mismo `login_token` — recién ahí se manda el código, y de ahí en más el flujo sigue normal con `/auth/verify-otp` (mismo `login_token`, sin necesidad de uno nuevo).
17. Si elige **app autenticadora**: `POST /auth/totp/enroll` con `{"login_token": "..."}` (en vez de `Authorization: Bearer`) → devuelve `otpauth_url` para el QR → `POST /auth/totp/confirm` con `{"login_token": "...", "code": "..."}` → si coincide, activa TOTP y entrega `access_token` + `refresh_token` ahí mismo.
18. Cualquiera de los dos caminos marca la elección como hecha — todos los logins siguientes de esa cuenta van directo al método elegido, sin volver a mostrar la pantalla de elección.

**Cambiar de método más adelante** (ya logueado, en cualquier momento):

19. `POST /auth/totp/enroll` (protegido, con `Authorization: Bearer`) — genera un secreto nuevo y devuelve `otpauth_url`. Todavía no queda activo — ver el paso siguiente.
20. `POST /auth/totp/confirm` (protegido) — recibe `code`. Si coincide, activa la app autenticadora: de ahí en más, el login de esa cuenta salta el correo por completo y `/auth/verify-otp` valida contra la app en su lugar.
21. `POST /auth/totp/disable` (protegido) — desactiva la app autenticadora; el login vuelve a usar el código por correo. No pide el código de la app para desactivarla, mismo criterio que revocar un dispositivo de confianza — alcanza con una sesión ya autenticada.

El secreto de cada cuenta se guarda cifrado (`AES-256-GCM`) en la base, nunca en texto plano — a diferencia de la contraseña (que se guarda hasheada, de un solo sentido), acá el servidor necesita poder recuperar el secreto real para calcular si un código es válido en este momento, así que un hash no alcanza.

**Cuentas que ya existían antes de activar esta función**: la migración que agrega la elección de método marca automáticamente como "ya elegida" (correo) a toda cuenta que ya existiera en ese momento — nadie que ya usaba la API antes ve la pantalla de elección de golpe en su próximo login. Solo las cuentas registradas después empiezan a verla.

### Aprobación por notificación push (opcional)

Tercer método, además de correo y TOTP — un login en un dispositivo (típicamente una PC) se confirma con un tap en un celular ya emparejado, en vez de tipear ningún código. Requiere `FIREBASE_CREDENTIALS_PATH` configurada (ver [Variables opcionales](#variables-opcionales)); si no está seteada, `/auth/devices/{id}/push`, `/auth/login/push-status`, `/auth/login/push-answer` y `/auth/login/request-email-code` ni siquiera existen (404, mismo criterio que `TOTP_ENCRYPTION_KEY`). Solo Android por ahora — vía [Firebase Cloud Messaging](https://firebase.google.com/docs/cloud-messaging).

A diferencia de TOTP, esto **nunca se ofrece en el primer login** de una cuenta — necesita, además del servidor configurado, un dispositivo ya emparejado con push habilitado, y en el primer login todavía no existe ninguno. Push tampoco reemplaza al correo/TOTP: siempre corre en paralelo a la sesión OTP/TOTP normal que `POST /auth/login` ya inició — cualquiera de los dos caminos (código tipeado, o aprobado desde el celular) completa el mismo `login_token`.

**Emparejar un dispositivo** (protegido, ya logueado — normalmente desde una pantalla de "Seguridad de mi cuenta"):

22. `POST /auth/devices/{id}/push` — recibe `{"push_token": "..."}` (el token FCM que el celular obtiene del SDK de Firebase) y lo asocia al dispositivo `{id}` (el id de `trusted_devices`, no el `device_id` del cliente — ver `GET /auth/devices`, que también trae `push_enabled` por dispositivo). Por eso push **piggybackea sobre el mismo dispositivo de confianza + PIN** en vez de ser un emparejamiento separado: el dispositivo tiene que estar ya registrado como confiable (paso 7 más arriba) antes de poder habilitar push en él.
23. `DELETE /auth/devices/{id}/push` — apaga push en ese dispositivo (borra el token FCM guardado) sin tocar el resto — el PIN y la confianza del dispositivo quedan intactos. La contraparte de "apagar" del paso anterior; no confundir con `DELETE /auth/devices/{id}` (paso 10), que revoca el dispositivo entero.

**Login con push disponible** (siguiendo del paso 2 de arriba, cuando la respuesta trae `push_approval_offered: true`):

24. `GET /auth/login/push-status?login_token=...` — la PC hace polling acá cada ~2s (mismo patrón que el *Device Authorization Grant* de OAuth 2.0, RFC 8628, para "esperar a que un humano actúe en otro dispositivo") mientras el celular no respondió. La respuesta trae `status` (`"pending"`, `"approved"` o `"rejected"`) y `number` — el número de 2 dígitos que la PC tiene que mostrar en pantalla, el mismo que el celular recibió como una de sus tres opciones (sin esto no hay nada contra qué comparar). En `"approved"` la respuesta también trae `access_token` + `refresh_token` directo y la solicitud queda consumida — un poll después de eso devuelve `401` (mismo criterio que reusar un OTP ya verificado). Pasado `PUSH_LOGIN_TTL` (60s por default) sin respuesta, también devuelve `401` — el cliente debe dejar de hacer polling.
25. `POST /auth/login/push-answer` (protegido — con el `Authorization: Bearer` del celular, **no** del `login_token` de la PC) — recibe `{"login_token": "...", "chosen_number": NN}`. El celular recibe, junto a la notificación push, tres números de 2 dígitos (uno correcto, dos señuelos, ya mezclados por el servidor); debe tocar el que coincide con el que la PC muestra en pantalla. Devuelve `{"status": "approved"}` o `{"status": "rejected"}` — un número equivocado **rechaza la sesión de forma permanente y sin reintentos** (misma mitigación anti-"MFA fatigue" que Microsoft Authenticator agregó tras ataques reales de bombardeo de notificaciones) — no hay forma de volver a intentar con el número correcto después de fallar una vez.
26. `POST /auth/login/request-email-code` — recibe `{"login_token": "..."}`. El "usar otro método": a diferencia de un login sin push disponible, acá el código **no se manda por correo automáticamente** (mismo criterio que Microsoft Authenticator/Duo — push es el desafío por defecto, no algo que se dispara igual sin importar si termina usándose). Este endpoint lo pide recién cuando la persona no puede o no quiere usar push; de ahí en más el flujo sigue normal con `/auth/verify-otp`, mismo `login_token`.

**Límite de solicitudes por cuenta** (`PUSH_MAX_REQUESTS`/`PUSH_REQUEST_WINDOW`, default 5 cada 15 minutos): la defensa real contra ese mismo bombardeo — alguien que ya sabe la contraseña de una cuenta puede loguear exitosamente todas las veces que quiera, y cada login exitoso dispararía una notificación nueva si no fuera por este límite, independiente de `LOGIN_MAX_FAILED_ATTEMPTS` (que solo cuenta contraseñas *fallidas*).

**Notificaciones fallidas por dispositivo no interrumpen el login**: enviar el push es best-effort — si `startPushLogin` falla por cualquier motivo (Redis, límite de solicitudes alcanzado, un token FCM que quedó obsoleto), simplemente no se ofrece la opción push y el login sigue normal por correo/TOTP; nunca se propaga un error al cliente por esto. Esos fallos sí quedan registrados en los logs estructurados del servidor (ver [Observabilidad](#observabilidad)) para poder diagnosticarlos.

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
- **`TOTP_ENCRYPTION_KEY`**: habilita `/auth/totp/*` (verificación por app autenticadora — ver [Verificación por app autenticadora](#verificación-por-app-autenticadora-totp-opcional)). Sin setear, esas rutas ni siquiera existen (mismo criterio que `ADMIN_API_TOKEN`). Base64 de exactamente 32 bytes (`openssl rand -base64 32`) — a diferencia de otros secretos del proyecto, este tiene que ser de ese tamaño exacto porque se usa como clave AES-256, no como secreto HMAC de largo libre.
- **`TOTP_ISSUER`**: nombre mostrado junto a la cuenta en la app autenticadora (default `auth-2fa-api`) — puramente cosmético, cambialo al nombre de tu propio sistema.
- **`FIREBASE_CREDENTIALS_PATH`**: habilita `/auth/devices/{id}/push`, `/auth/login/push-status`, `/auth/login/push-answer` y `/auth/login/request-email-code` (aprobación de login por notificación push). Sin setear (ni `FIREBASE_CREDENTIALS_JSON_BASE64`, ver abajo), esas rutas ni siquiera existen (mismo criterio que `TOTP_ENCRYPTION_KEY`). Ruta a un archivo JSON de cuenta de servicio de Firebase (consola de Firebase → Configuración del proyecto → Cuentas de servicio → Generar nueva clave privada) — igual que las claves JWT, este archivo va en `keys/` y nunca se sube al repo.
- **`FIREBASE_CREDENTIALS_JSON_BASE64`**: alternativa a `FIREBASE_CREDENTIALS_PATH` para una plataforma sin filesystem persistente/escribible — o donde un volumen aparentemente montado en realidad no es lo que ve el contenedor corriendo (nos pasó exactamente eso en producción: el archivo estaba bien puesto en el servidor, pero el contenedor real no tenía ningún volumen montado). Tiene prioridad sobre `FIREBASE_CREDENTIALS_PATH` si están las dos. Base64 del contenido completo del archivo de cuenta de servicio — mismo criterio que `JWT_PRIVATE_KEY_PEM_BASE64`:
  ```bash
  base64 -w0 keys/firebase-service-account.json
  ```
- **`PUSH_LOGIN_TTL`**: cuánto dura pendiente una solicitud de aprobación push antes de expirar sin respuesta (default `60s`). La PC hace polling durante esta ventana.
- **`PUSH_MAX_REQUESTS`** / **`PUSH_REQUEST_WINDOW`**: tope de solicitudes push por cuenta dentro de una ventana (default `5` cada `15m`) — la defensa real contra "MFA fatigue" (alguien que ya sabe la contraseña bombardeando notificaciones esperando un tap por error). Independiente de `LOGIN_MAX_FAILED_ATTEMPTS`, que solo cuenta contraseñas fallidas.
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

### Moderación (lista negra por IP y bloqueo de cuentas)

También por HTTP, con el mismo header `X-Admin-Token`:

```bash
# Bloquear/desbloquear una cuenta puntual (ver "Bloqueo manual de cuentas" en Arquitectura).
curl -X POST https://tu-api/admin/users/<id>/ban              -H "X-Admin-Token: $ADMIN_API_TOKEN"
curl -X POST https://tu-api/admin/users/<id>/unban            -H "X-Admin-Token: $ADMIN_API_TOKEN"
curl -X POST https://tu-api/admin/users/<id>/disable-totp     -H "X-Admin-Token: $ADMIN_API_TOKEN"
curl -X POST https://tu-api/admin/users/<id>/revoke-sessions  -H "X-Admin-Token: $ADMIN_API_TOKEN"

# Levantar antes de tiempo un baneo automático por IP (ver "Lista negra automática por IP").
curl -X DELETE https://tu-api/admin/blacklist/203.0.113.7 -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

### Administración por sistema (credencial scoped)

Para que el equipo detrás de un sistema consumidor pueda moderar **sus propios** usuarios sin necesitar tu `X-Admin-Token` (que puede tocar todos los sistemas, no solo el suyo). Se provisiona una vez por cliente, con tu `X-Admin-Token`:

```bash
# Provisiona (o rota, si ya existía una) la credencial scoped del cliente <id>.
# El plaintext se muestra una sola vez, igual que la API key normal.
curl -X POST https://tu-api/admin/clients/<id>/system-admin-key/rotate -H "X-Admin-Token: $ADMIN_API_TOKEN"

# Revoca la credencial scoped por completo — vuelve al estado "nunca provisionada".
curl -X DELETE https://tu-api/admin/clients/<id>/system-admin-key -H "X-Admin-Token: $ADMIN_API_TOKEN"
```

El equipo del sistema consumidor usa esa credencial contra `/system-admin/users/*` (mismas cuatro acciones que `/admin/users/*`, pero con el header `X-System-Admin-Token` en vez de `X-Admin-Token`):

```bash
curl -X POST https://tu-api/system-admin/users/<id>/ban             -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/unban           -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/disable-totp    -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
curl -X POST https://tu-api/system-admin/users/<id>/revoke-sessions -H "X-System-Admin-Token: $SYSTEM_ADMIN_KEY"
```

Si `<id>` pertenece a otro sistema, la respuesta es `404` (no `403`) — indistinguible de un id que directamente no existe.

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

# 3. Login — "identifier" acepta el email, el username o el rut
# indistintamente, no hace falta indicar cuál es.
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"identifier":"tucorreo@example.com","password":"unaClaveSegura123"}'
# -> Sin TOTP_ENCRYPTION_KEY configurada (el caso de abajo), manda el OTP
# por correo directo: { "login_token": "...", "needs_2fa_setup": false, ... }
#
# -> CON TOTP_ENCRYPTION_KEY configurada, y solo en el primer login de esta
# cuenta, en cambio devuelve { "login_token": "...", "needs_2fa_setup": true }
# sin mandar ningún correo todavía — ver "Elegir método (primer login)" más
# abajo antes de seguir con el paso 4.

# 4. Verificar el código recibido por correo
curl -X POST http://localhost:8080/auth/verify-otp \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 3>","code":"<el del correo>"}'
# -> devuelve { "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }

# --- Elegir método (solo el primer login de la cuenta, y solo si el
# servidor tiene TOTP_ENCRYPTION_KEY configurada — ver paso 3) ---

# 4a. Elige correo: pide el código con el login_token del paso 3, y de ahí
# el flujo sigue normal con el paso 4 de arriba (mismo login_token).
curl -X POST http://localhost:8080/auth/login/send-email-code \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 3>"}'

# 4b. O elige app autenticadora: enroll + confirm usando el login_token del
# paso 3 en vez de un Authorization: Bearer (todavía no existe uno).
curl -X POST http://localhost:8080/auth/totp/enroll \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 3>"}'
# -> devuelve { "otpauth_url": "otpauth://totp/...?secret=...&issuer=..." }
# Renderizar esa URL como código QR (o pasar el "secret" a mano) y
# escanearla con Google Authenticator/Authy antes de confirmar.

curl -X POST http://localhost:8080/auth/totp/confirm \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 3>","code":"<el que muestra la app>"}'
# -> 200 con { "access_token": "...", "refresh_token": "...", "token_type": "Bearer" }
# directo — activa TOTP y completa el login en un solo paso, no hace falta
# pasar por /auth/verify-otp acá.

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

# 8. Cambiar de método MÁS ADELANTE, ya logueado (a diferencia del paso 4b,
# acá se usa Authorization: Bearer en vez de login_token, y confirmar no
# devuelve tokens nuevos — la sesión ya existe).
curl -X POST http://localhost:8080/auth/totp/enroll \
  -H "X-API-Key: $API_KEY" -H "Authorization: Bearer <access_token>"
# -> devuelve { "otpauth_url": "otpauth://totp/...?secret=...&issuer=..." }

curl -X POST http://localhost:8080/auth/totp/confirm \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -H "Authorization: Bearer <access_token>" \
  -d '{"code":"<el que muestra la app>"}'
# -> 204. De ahí en más, /auth/login para esta cuenta ya no manda OTP por
# correo — /auth/verify-otp espera el código de la app en su lugar.

# --- Aprobación por notificación push (opcional, requiere
# FIREBASE_CREDENTIALS_PATH configurada) — ver "Aprobación por notificación
# push" más arriba. El push_token real solo lo obtiene el SDK de Firebase
# desde una app de verdad (no hay forma de simular esto con curl solo),
# así que estos dos últimos pasos son ilustrativos de la forma de la
# petición/respuesta, no un flujo que se pueda correr de punta a punta acá. ---

# 9. Habilitar push en un dispositivo ya de confianza (el {id} es el de
# "trusted_devices" — ver GET /auth/devices, no el device_id del paso 6).
curl -X POST http://localhost:8080/auth/devices/<id>/push \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -H "Authorization: Bearer <access_token>" \
  -d '{"push_token":"<token FCM que entrega el SDK de Firebase en el celular>"}'

# 10. Con push habilitado, /auth/login (paso 3) también devuelve
# "push_approval_offered": true — y esta vez NO manda el código por correo
# (a diferencia del paso 3 normal). La PC hace polling:
curl http://localhost:8080/auth/login/push-status?login_token=<el del paso 3> \
  -H "X-API-Key: $API_KEY"
# -> { "status": "pending", "number": 42 }  <- este es el número a mostrar en pantalla
# (o "approved" con access_token/refresh_token, o "rejected")

# ...mientras el celular, al tocar uno de los tres números que le llegó en
# la notificación, responde:
curl -X POST http://localhost:8080/auth/login/push-answer \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" -H "Authorization: Bearer <access_token del celular>" \
  -d '{"login_token":"<el del paso 3>","chosen_number":42}'
# -> { "status": "approved" }  o  { "status": "rejected" } (sin reintentos)

# 11. "Usar otro método" — si la persona no puede usar push, pide el
# código por correo recién en este momento, con el mismo login_token:
curl -X POST http://localhost:8080/auth/login/request-email-code \
  -H "Content-Type: application/json" -H "X-API-Key: $API_KEY" \
  -d '{"login_token":"<el del paso 3>"}'
# -> de ahí en más sigue normal con /auth/verify-otp (paso 4)
```

## Documentación de la API

Con el servidor corriendo:

- **Especificación OpenAPI**: `http://localhost:8080/openapi.yaml`
- **UI interactiva (Swagger UI)**: `http://localhost:8080/docs` — permite explorar y probar cada endpoint desde el navegador.

Cualquier equipo que vaya a consumir esta API puede usar `/openapi.yaml` para generar un cliente automáticamente (con `openapi-generator`, `swagger-codegen`, etc.) en el lenguaje que necesite.

## Cómo otros sistemas verifican el access token

El access token es un JWT RS256. Cualquier sistema (aunque no tenga acceso a esta base de datos ni a estos secretos) puede:

1. Obtener el conjunto de claves públicas desde `GET /.well-known/jwks.json` (cachearlo). **Normalmente trae una sola clave, pero durante una rotación (ver [Rotación de claves JWT](#rotación-de-claves-jwt)) puede traer dos a la vez** — no asumas que siempre hay una sola ni tomes "la primera" del array.
2. Mirar el campo `kid` del header del JWT, y usar la clave del JWKS cuyo `kid` coincida (así es como esta misma API verifica sus propios tokens — ver `internal/auth/jwt.go`). Con esa clave, verificar la firma usando cualquier librería estándar de JWT en su lenguaje (no requiere llamar de vuelta a esta API en cada request).
3. Confiar en los claims `sub` (id de usuario), `email` y `exp` (expiración) una vez la firma es válida.

Cachear el JWKS está bien, pero no para siempre: si tu caché no vuelve a pedirlo nunca, no te vas a enterar cuando aparezca una clave nueva durante una rotación — refrescalo cada tanto (por hora, por ejemplo), no solo una vez al arrancar.

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

## Rotación de claves JWT

El access token se firma con una sola clave RSA a la vez, pero `/.well-known/jwks.json` puede publicar más de una — el JWT lleva su `kid` (key id) en el header, y `ParseAccessToken` busca la clave pública que corresponda a ese `kid` en vez de asumir que hay una sola. Esto permite rotar la clave de firma sin invalidar de golpe los tokens que ya estaban circulando: durante una ventana de solapamiento, la clave vieja sigue publicada (solo para verificar, ya no para firmar) hasta que ningún token firmado con ella pueda seguir siendo válido.

**Cuándo rotar**: como higiene de rutina, cada 6-12 meses alcanza para un proyecto de este tamaño — no hay ganancia real en rotar más seguido si nadie más tiene acceso a la clave. Rotá de inmediato, sin esperar al cronograma, si sospechás que la clave privada pudo haberse expuesto (un backup filtrado, acceso no autorizado al servidor, etc.).

**Procedimiento** (dos deploys, con una espera en el medio):

1. Generá el par de claves nuevo (mismo comando que en [Claves RS256](#claves-rs256-para-el-access-token), a otro archivo para no pisar el actual) y elegí un `kid` nuevo (ej. `auth-2fa-api-2` si el actual es `auth-2fa-api-1`).
2. En las variables de entorno del deploy, seteá:
   - `JWT_PREVIOUS_KEY_ID` = el `kid` **actual** (el que está por dejar de firmar).
   - `JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64` = la clave **pública** actual, en base64 (`base64 -w0 keys/public.pem`, o el equivalente de tu SO) — la privada vieja ya no hace falta para nada.
   - `JWT_PRIVATE_KEY_PATH` (o `JWT_PRIVATE_KEY_PEM_BASE64`) + `JWT_KEY_ID` = la clave nueva.
3. Deploy. Desde acá: los tokens nuevos se firman con la clave nueva; el JWKS publica las dos; los tokens ya emitidos (hasta `ACCESS_TOKEN_TTL` de antigüedad) siguen verificando con la vieja.
4. Esperá al menos `ACCESS_TOKEN_TTL` (15m por default) más un margen — una hora es de sobra.
5. Sacá `JWT_PREVIOUS_KEY_ID` y `JWT_PREVIOUS_PUBLIC_KEY_PEM_BASE64` de las variables de entorno. Deploy de nuevo. El JWKS vuelve a tener una sola clave — rotación terminada.

## Checklist para el equipo de TI antes de producción

Esta API en sí misma no depende de nada de esto para funcionar en desarrollo/pruebas — pero antes de que la use gente real, hay una capa de infraestructura y operación que le corresponde a quien administre el entorno final, no al desarrollo de la API. Se las dejamos listadas acá para que no se pierdan en el traspaso.

- **HTTPS obligatorio, no opcional**: el dominio final necesita certificado válido y debería rechazar tráfico por HTTP plano (redirigir o cerrar el puerto), no solo "tenerlo disponible". Sin esto, credenciales y tokens viajan sin cifrar. Ver [Deploy en producción](#deploy-en-producción) — Dokploy/Traefik lo gestiona, pero hay que confirmar que quede forzado.
- **Backups de PostgreSQL, con restore probado**: hoy no hay ninguna política de backup configurada. Un backup que nunca se probó restaurar no es un backup real — hace falta definir frecuencia, retención, y probar el restore al menos una vez antes de ir a producción.
- **Gestión de secretos**: `JWT_REFRESH_SECRET`, `JWT_PRIVATE_KEY_PATH`/`JWT_PRIVATE_KEY_PEM_BASE64`, `ADMIN_API_TOKEN`, `TOTP_ENCRYPTION_KEY` (si se usa), `RESEND_API_KEY`, `FIREBASE_CREDENTIALS_PATH`/`FIREBASE_CREDENTIALS_JSON_BASE64` (si se usa push — preferí la variante base64 salvo que hayas confirmado que el volumen del archivo realmente llega al contenedor), la contraseña de Postgres — hoy viven como variables de entorno (o archivos en `keys/`) en el panel de Dokploy. Funciona, pero para un ente público conviene evaluar algo más auditable (quién puede verlas, cuándo se rotaron, registro de acceso), según la política interna que ya tengan. `TOTP_ENCRYPTION_KEY` en particular no tiene hoy un procedimiento de rotación (a diferencia de las claves JWT — ver [Rotación de claves JWT](#rotación-de-claves-jwt)): rotarla sin migrar primero los secretos ya cifrados dejaría ilegibles los de todas las cuentas que ya activaron la app autenticadora.
- **Alertas activas, no solo dashboards**: el stack de [Observabilidad](#observabilidad) ya expone todo lo necesario (métricas de error rate, latencia, salud del servicio) pero nadie recibe una notificación si algo se rompe fuera de horario — hoy hay que entrar a Grafana a mirar. Conviene conectar alertas (Grafana Alerting, o lo que ya usen) sobre esas mismas métricas.
- **Redundancia / alta disponibilidad**: todo corre en un único VPS (ver [Producción (Dokploy)](#producción-dokploy)) — si esa máquina se cae, el sistema completo se cae con ella. Si el municipio requiere continuidad de servicio, esto necesita evaluarse aparte (más de una instancia, balanceo de carga, etc.).
- **Protección a nivel de borde (WAF / anti-DDoS)**: el rate limiting de esta API (`internal/middleware.RateLimiter`/`Blacklist`, por IP y por cuenta, con escalada a baneo automático — ver [Arquitectura](#arquitectura)) protege contra fuerza bruta sobre credenciales y OTP, pero no contra un ataque volumétrico de verdad contra la infraestructura — eso se resuelve en la capa de red/proxy, no en la aplicación.
- **Pruebas de carga**: nunca se verificó cuánto tráfico real aguanta esta configuración. Antes de anunciar el servicio a todo el municipio, vale la pena simular la carga esperada.
- **Cumplimiento legal y normativo**: fuera del alcance de este README — el municipio ya cuenta con su propio proceso para esto.
