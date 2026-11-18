CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY,
    cn TEXT NOT NULL,
    sans TEXT NOT NULL DEFAULT '',
    csr_pem TEXT NOT NULL,
    key_pem TEXT,
    state TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certs (
    serial TEXT PRIMARY KEY,
    request_id INTEGER REFERENCES requests(id),
    cn TEXT NOT NULL,
    issuer TEXT NOT NULL,
    not_before TEXT NOT NULL,
    not_after TEXT NOT NULL,
    pem TEXT NOT NULL,
    revoked_at TEXT,
    revoke_reason TEXT
);
