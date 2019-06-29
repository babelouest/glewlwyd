DROP TABLE IF EXISTS gs_code;

CREATE TABLE gs_code (
  gsc_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gsc_mod_name VARCHAR(128) NOT NULL,
  gsc_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gsc_username VARCHAR(128) NOT NULL,
  gsc_enabled TINYINT(1) DEFAULT 1,
  gsc_code_hash VARCHAR(128),
  gsc_result TINYINT(1) DEFAULT 0
);
CREATE INDEX i_gssc_username ON gs_code(gsc_username);
