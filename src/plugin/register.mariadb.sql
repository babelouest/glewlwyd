DROP TABLE IF EXISTS gpr_session;

CREATE TABLE gpr_session (
  gprs_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gprs_username VARCHAR(256) NOT NULL,
  gprs_name VARCHAR(512),
  gprs_email VARCHAR(512),
  gprs_code_hash VARCHAR(512),
  gprs_code_verified TINYINT(1) DEFAULT 0,
  gprs_password_set TINYINT(1) DEFAULT 0,
  gprs_session_hash VARCHAR(512) NOT NULL,
  gprs_expires_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gprs_issued_for VARCHAR(256), -- IP address or hostname
  gprs_user_agent VARCHAR(256),
  gprs_enabled TINYINT(1) DEFAULT 1
);
CREATE INDEX i_gprs_session_hash ON gpr_session(gprs_session_hash);
