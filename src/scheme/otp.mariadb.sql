DROP TABLE IF EXISTS gs_otp;

CREATE TABLE gs_otp (
  gso_id INT(11) PRIMARY KEY AUTO_INCREMENT,
  gso_mod_name VARCHAR(128) NOT NULL,
  gso_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gso_last_used TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gso_username VARCHAR(128) NOT NULL,
  gso_otp_type TINYINT(1) DEFAULT 0, -- 0 HOTP, 1 TOTP
  gso_secret VARCHAR(128) NOT NULL,
  gso_hotp_moving_factor INT(11),
  gso_totp_time_step_size INT(11)
);
CREATE INDEX i_gsso_username ON gs_otp(gso_username);
