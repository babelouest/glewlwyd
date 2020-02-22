DROP TABLE IF EXISTS gs_oauth2_session;
DROP TABLE IF EXISTS gs_oauth2_registration;

CREATE TABLE gs_oauth2_registration (
  gsor_id SERIAL PRIMARY KEY,
  gsor_mod_name VARCHAR(128) NOT NULL,
  gsor_provider VARCHAR(128) NOT NULL,
  gsor_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gsor_username VARCHAR(128) NOT NULL,
  gsor_userinfo_sub VARCHAR(128)
);
CREATE INDEX i_gsor_username ON gs_oauth2_registration(gsor_username);

CREATE TABLE gs_oauth2_session (
  gsos_id SERIAL PRIMARY KEY,
  gsor_id INTEGER,
  gsos_created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gsos_expires_at TIMESTAMPTZ,
  gsos_state TEXT NOT NULL,
  gsos_session_export TEXT,
  gsos_status SMALLINT DEFAULT 0, -- 0: registration, 1: authentication, 2: verified, 3: cancelled
  FOREIGN KEY(gsor_id) REFERENCES gs_oauth2_registration(gsor_id) ON DELETE CASCADE
);
