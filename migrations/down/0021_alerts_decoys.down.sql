-- Reversa de 0021_alerts_decoys.sql. Se aplica a mano (no la toma cmd/migrate
-- ni testutil: ambos leen solo migrations/*.sql):
--
--   psql "$POSTGRES_DSN" -f migrations/down/0021_alerts_decoys.down.sql
--
-- Antes de quitar users.is_decoy se borran las cuentas señuelo: sin la
-- columna pasarían a ser usuarios normales y podrían iniciar sesión. El DO
-- hace que correr la reversa dos veces no falle.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'is_decoy'
    ) THEN
        DELETE FROM users WHERE is_decoy;
    END IF;
END $$;

DROP TABLE IF EXISTS alerts;
ALTER TABLE users DROP COLUMN IF EXISTS is_decoy;
