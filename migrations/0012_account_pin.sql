-- PIN moves from being per-device (trusted_devices.pin_hash) to a single
-- per-account secret: it still unlocks a trusted device, and now also
-- confirms sensitive actions (e.g. an admin ban) from any client.
--
-- Idempotent like every migration here (IF NOT EXISTS / IF EXISTS) — the
-- test harness re-applies every *.sql file on every test run (see
-- testutil.applyMigrations), not just once. That's also why the one-time
-- wipe of existing trusted_devices this needs in a real deployment (see
-- README) is a separate manual step, not a DELETE in here: a DELETE would
-- re-run on every test too, destroying devices other tests just created.
--
-- Cada cambio va protegido con una comprobación previa del catálogo
-- (information_schema) dentro de un bloque DO, igual que 0009 y 0016. No es
-- un adorno: ALTER TABLE ... IF [NOT] EXISTS de Postgres pide un bloqueo total
-- de la tabla aunque no haya nada que cambiar, y esta migración toca DOS tablas
-- (trusted_devices y luego users) dentro de un mismo archivo, que Postgres
-- ejecuta como una sola transacción. Como las pruebas la reaplican en cada
-- ejecución, ese orden se cruzaba con el DELETE FROM users en cascada de las
-- limpiezas de otros paquetes (users y luego trusted_devices) y Postgres
-- abortaba una de las dos con un deadlock (SQLSTATE 40P01). Con la
-- comprobación previa, una base que ya la tiene aplicada no pide ningún
-- bloqueo; el esquema que deja es idéntico al de antes.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'trusted_devices' AND column_name = 'pin_hash'
    ) THEN
        ALTER TABLE trusted_devices DROP COLUMN pin_hash;
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'trusted_devices' AND column_name = 'failed_pin_attempts'
    ) THEN
        ALTER TABLE trusted_devices DROP COLUMN failed_pin_attempts;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'pin_hash'
    ) THEN
        ALTER TABLE users ADD COLUMN pin_hash TEXT; -- bcrypt of a 6-digit PIN; NULL = never set
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'pin_failed_attempts'
    ) THEN
        ALTER TABLE users ADD COLUMN pin_failed_attempts INT NOT NULL DEFAULT 0;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'pin_locked_until'
    ) THEN
        ALTER TABLE users ADD COLUMN pin_locked_until TIMESTAMPTZ; -- NULL = not locked
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'pin_set_at'
    ) THEN
        ALTER TABLE users ADD COLUMN pin_set_at TIMESTAMPTZ;
    END IF;
END $$;
