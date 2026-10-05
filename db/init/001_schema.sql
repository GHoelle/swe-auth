-- Initial schema. Runs once, when the Postgres data volume is first created.
-- To re-run it in development: docker compose down -v   (this deletes all data)

-- citext = case-insensitive text. "Alice@Example.com" and "alice@example.com"
-- are treated as the same email, so the UNIQUE constraint can't be bypassed with capital letters.
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    -- Random UUIDs instead of 1, 2, 3...: IDs can't be guessed or counted,
    -- and they don't reveal how many users the service has.
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    email         citext      NOT NULL UNIQUE,
    password_hash text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_email_length CHECK (char_length(email) BETWEEN 3 AND 254),

    -- Defense in depth: even if a future bug tries to store a plaintext password,
    -- the database rejects anything that isn't an Argon2id hash string.
    CONSTRAINT users_password_hash_is_argon2id CHECK (password_hash LIKE '$argon2id$%')
);

-- Sessions are stored in Redis, not in this table (see app/security/sessions.py, Step 2).
