DROP TABLE IF EXISTS gs_otp;

CREATE TABLE gs_otp (
  gso_id INTEGER PRIMARY KEY AUTOINCREMENT,
  gso_mod_name TEXT NOT NULL,
  gso_issued_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gso_last_used TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  gso_username TEXT NOT NULL,
  gso_otp_type INTEGER DEFAULT 0, -- 0 HOTP, 1 TOTP
  gso_secret TEXT NOT NULL,
  gso_hotp_moving_factor INTEGER,
  gso_totp_time_step_size INTEGER
);
CREATE INDEX i_gsso_username ON gs_otp(gso_username);
