DROP TABLE IF EXISTS g_client_property;
DROP TABLE IF EXISTS g_client_scope_client;
DROP TABLE IF EXISTS g_client_scope;
DROP TABLE IF EXISTS g_client;

CREATE TABLE g_client (
  gc_id SERIAL PRIMARY KEY,
  gc_client_id VARCHAR(128) NOT NULL UNIQUE,
  gc_name VARCHAR(256) DEFAULT '',
  gc_description VARCHAR(512) DEFAULT '',
  gc_confidential SMALLINT DEFAULT 0,
  gc_password VARCHAR(256),
  gc_enabled SMALLINT DEFAULT 1
);

CREATE TABLE g_client_scope (
  gcs_id SERIAL PRIMARY KEY,
  gcs_name VARCHAR(128) NOT NULL UNIQUE
);

CREATE TABLE g_client_scope_client (
  gcsu_id SERIAL PRIMARY KEY,
  gc_id SERIAL,
  gcs_id SERIAL,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE,
  FOREIGN KEY(gcs_id) REFERENCES g_client_scope(gcs_id) ON DELETE CASCADE
);

CREATE TABLE g_client_property (
  gcp_id SERIAL PRIMARY KEY,
  gc_id SERIAL,
  gcp_name VARCHAR(128) NOT NULL,
  gcp_value TEXT DEFAULT NULL,
  FOREIGN KEY(gc_id) REFERENCES g_client(gc_id) ON DELETE CASCADE
);
CREATE INDEX i_g_client_property_name ON g_client_property(gcp_name);
