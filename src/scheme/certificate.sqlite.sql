DROP TABLE IF EXISTS gs_user_certificate;
DROP TABLE IF EXISTS gs_user_pkcs12;

CREATE TABLE gs_user_certificate (
  gsuc_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gsuc_mod_name TEXT NOT NULL,
  gsuc_username TEXT NOT NULL,
  gsuc_enabled INTEGER DEFAULT 1,
  gsuc_x509_certificate_content TEXT DEFAULT NULL,
  gsuc_x509_certificate_id TEXT NOT NULL,
  gsuc_x509_certificate_dn TEXT NOT NULL,
  gsuc_x509_certificate_issuer_dn TEXT NOT NULL,
  gsuc_activation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsuc_expiration TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gsuc_last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gsuc_last_user_agent TEXT DEFAULT NULL
);
CREATE INDEX i_gsuc_username ON gs_user_certificate(gsuc_username);
CREATE INDEX i_gsuc_x509_certificate_id ON gs_user_certificate(gsuc_x509_certificate_id);

CREATE TABLE gs_user_pkcs12 (
  gsup_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gsup_mod_name TEXT NOT NULL,
  gsup_username TEXT NOT NULL,
  gsup_pkcs12_content TEXT DEFAULT NULL,
  gsup_pkcs12_password TEXT DEFAULT NULL,
  gsup_activation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsup_expiration TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gsup_host TEXT DEFAULT NULL,
  gsup_user_agent TEXT DEFAULT NULL
);
CREATE INDEX i_gsup_username ON gs_user_pkcs12(gsup_username);
