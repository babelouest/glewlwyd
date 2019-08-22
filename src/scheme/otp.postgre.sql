DROP TABLE IF EXISTS gs_otp;

CREATE TABLE gs_otp (
  gso_id SERIAL PRIMARY KEY,
  gso_mod_name VARCHAR(128) NOT NULL,
  gso_issued_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gso_last_used TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  gso_username VARCHAR(128) NOT NULL,
  gso_otp_type SMALLINT DEFAULT 0, -- 0 HOTP, 1 TOTP
  gso_secret VARCHAR(128) NOT NULL,
  gso_hotp_moving_factor INTEGER,
  gso_totp_time_step_size INTEGER
);
CREATE INDEX i_gsso_username ON gs_otp(gso_username);
