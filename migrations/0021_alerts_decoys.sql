-- Detector de accesos anómalos: cuentas señuelo (honeytokens) y alertas
-- explicables. Todo idempotente, igual que el resto de las migraciones
-- (testutil.PostgresPool vuelve a aplicar cada archivo antes de cada prueba).
--
-- La reversa vive en migrations/down/0021_alerts_decoys.down.sql — fuera de
-- este directorio a propósito, para que ni cmd/migrate ni las pruebas (que
-- solo leen migrations/*.sql) la apliquen por accidente.

-- users.is_decoy: una cuenta señuelo nunca inicia sesión con éxito (ver
-- user.Service.VerifyPassword) y no cuenta como usuario real en las
-- estadísticas ni en los listados normales. Existe solo para que cualquier
-- intento contra ella delate a quien anda probando cuentas.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_decoy BOOLEAN NOT NULL DEFAULT FALSE;

-- auth_events.is_decoy ya existe desde 0020 (siempre FALSE hasta ahora): desde
-- esta migración el código lo deja en TRUE cuando el intento apunta a una
-- cuenta señuelo. No hay nada que alterar aquí.

-- alerts: una fila por (ventana de 10 min, clave, fuente). La clave es el
-- tenant (ip NULL), o la IP (tenant NULL, o el tenant si todo el tráfico de
-- esa IP en la ventana fue contra uno solo).
--
-- tenant_id es ON DELETE SET NULL por la misma razón que auth_events: borrar
-- un tenant jamás debe quedar bloqueado por su historial de alertas.
-- resolved_by apunta a la cuenta de operador que cerró la alerta; NULL si
-- sigue abierta o si la cerró la credencial compartida X-Admin-Token (que no
-- tiene cuenta individual a quien atribuirla).
CREATE TABLE IF NOT EXISTS alerts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    UUID REFERENCES api_clients(id) ON DELETE SET NULL,
    ip           INET,
    window_start TIMESTAMPTZ NOT NULL,
    window_end   TIMESTAMPTZ NOT NULL,
    -- regla | isolation_forest | senuelo
    source       TEXT NOT NULL CHECK (source IN ('regla', 'isolation_forest', 'senuelo')),
    -- Solo para isolation_forest: s = 2^(-E(h)/c(psi)), entre 0 y 1.
    score        DOUBLE PRECISION,
    -- Valores de las seis características de la ventana.
    features     JSONB NOT NULL,
    -- Lista de motivos legibles (texto en español), del más al menos relevante.
    motives      JSONB NOT NULL,
    state        TEXT NOT NULL DEFAULT 'abierta' CHECK (state IN ('abierta', 'descartada', 'resuelta')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_by  UUID REFERENCES admin_accounts(id) ON DELETE SET NULL,
    resolved_at  TIMESTAMPTZ,
    note         TEXT
);

-- Evita duplicar la alerta de una misma ventana, misma clave (tenant + IP) y
-- misma fuente cuando el detector vuelve a recorrer una ventana ya revisada
-- (cada pasada mira una hora hacia atrás, ver detector.Detector). Un índice
-- sobre expresiones porque tenant_id/ip son NULL en uno de los dos tipos de
-- clave, y en un índice único normal los NULL nunca chocan entre sí.
CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_unique_window_key_source
    ON alerts (window_start, COALESCE(tenant_id::text, ''), COALESCE(host(ip), ''), source);

-- Respalda el listado (GET /admin/alerts: rango de fechas, orden descendente).
CREATE INDEX IF NOT EXISTS idx_alerts_window_start ON alerts (window_start DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_window_start ON alerts (tenant_id, window_start DESC);
