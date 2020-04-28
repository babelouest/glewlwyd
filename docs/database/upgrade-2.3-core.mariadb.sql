-- Upgrade Glewlwyd 2.2.x 2.3.0

ALTER TABLE gpg_access_token
ADD gpoa_jti VARCHAR(128);
CREATE INDEX i_gpoa_jti ON gpo_access_token(gpoa_jti);
