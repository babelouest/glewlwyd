DROP TABLE IF EXISTS g_client_property;
DROP TABLE IF EXISTS g_client_scope_client;
DROP TABLE IF EXISTS g_client_scope;
DROP TABLE IF EXISTS g_client;

CREATE TABLE g_client (
  gc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_client_id TEXT NOT NULL UNIQUE,
  gc_name TEXT DEFAULT '',
  gc_description TEXT DEFAULT '',
  gc_confidential INTEGER DEFAULT 0,
  gc_password TEXT,
  gc_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_client_scope (
  gcs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gcs_name TEXT NOT NULL UNIQUE
);

CREATE TABLE g_client_scope_client (
  gcsu_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_id INTEGER,
  gcs_id INTEGER,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE,
  FOREIGN KEY(gcs_id) REFERENCES g_client_scope(gcs_id) ON DELETE CASCADE
);

CREATE TABLE g_client_property (
  gcp_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_id INTEGER,
  gcp_name TEXT NOT NULL,
  gcp_value TEXT DEFAULT NULL,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_property_name ON g_client_property(gcp_name);
