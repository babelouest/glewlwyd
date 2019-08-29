DROP TABLE IF EXISTS gs_user_certificate;

CREATE TABLE gs_user_certificate (
  gsuc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gsuc_mod_name TEXT NOT NULL,
  gsuc_username TEXT NOT NULL,
  gsuc_enabled INTEGER DEFAULT 1,
  gsuc_x509_certificate_content TEXT DEFAULT NULL,
  gsuc_x509_certificate_id TEXT NOT NULL,
  gsuc_activation TIMESTAMP NOT NULL DEFAULT NOW(),
  gsuc_expiration TIMESTAMP DEFAULT NOW(),
  gsuc_last_used TIMESTAMP DEFAULT NOW(),
  gsuc_last_user_agent TEXT DEFAULT NULL
);
CREATE INDEX i_gsuc_username ON gs_user_certificate(gsuc_username);
CREATE INDEX i_gsuc_x509_certificate_id ON gs_user_certificate(gsuc_x509_certificate_id);
