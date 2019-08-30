DROP TABLE IF EXISTS gs_user_certificate;

CREATE TABLE gs_user_certificate (
  gsuc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsuc_mod_name VARCHAR(128) NOT NULL,
  gsuc_username VARCHAR(128) NOT NULL,
  gsuc_enabled TINYINT(1) DEFAULT 1,
  gsuc_x509_certificate_content BLOB DEFAULT NULL,
  gsuc_x509_certificate_id VARCHAR(128) NOT NULL,
  gsuc_x509_certificate_dn VARCHAR(512) NOT NULL,
  gsuc_activation TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsuc_expiration TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gsuc_last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  gsuc_last_user_agent VARCHAR(512) DEFAULT NULL
);
CREATE INDEX i_gsuc_username ON gs_user_certificate(gsuc_username);
CREATE INDEX i_gsuc_x509_certificate_id ON gs_user_certificate(gsuc_x509_certificate_id);
