-- Upgrade Glewlwyd 2.0.x or 2.1.x to 2.2.0

ALTER TABLE g_user_module_instance
ADD gumi_enabled INTEGER DEFAULT 1;

ALTER TABLE g_user_auth_scheme_module_instance
ADD guasmi_enabled INTEGER DEFAULT 1;

ALTER TABLE g_client_module_instance
ADD gcmi_enabled INTEGER DEFAULT 1;

ALTER TABLE g_plugin_module_instance
ADD gpmi_enabled INTEGER DEFAULT 1;
