DROP TABLE IF EXISTS g_user_property;
DROP TABLE IF EXISTS g_user_scope_user;
DROP TABLE IF EXISTS g_user_scope;
DROP TABLE IF EXISTS g_user;

CREATE TABLE g_user (
  gc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_username TEXT NOT NULL UNIQUE,
  gc_name TEXT DEFAULT '',
  gu_email TEXT,
  gc_password TEXT,
  gc_enabled INTEGER DEFAULT 1
);

CREATE TABLE g_user_scope (
  gcs_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gcs_name TEXT NOT NULL UNIQUE
);

CREATE TABLE g_user_scope_user (
  gcsu_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_id INTEGER,
  gcs_id INTEGER,
  FOREIGN KEY(gc_id) REFERENCES g_user(gc_id) ON DELETE CASCADE,
  FOREIGN KEY(gcs_id) REFERENCES g_user_scope(gcs_id) ON DELETE CASCADE
);

CREATE TABLE g_user_property (
  gcp_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gc_id INTEGER,
  gcp_name TEXT NOT NULL,
  gcp_value TEXT DEFAULT NULL,
  FOREIGN KEY(gc_id) REFERENCES g_user(gc_id) ON DELETE CASCADE
);
CREATE INDEX i_g_user_property_name ON g_user_property(gcp_name);
