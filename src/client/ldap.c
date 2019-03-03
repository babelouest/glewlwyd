/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * LDAP client module
 * 
 * Copyright 2016-2019 Nicolas Mora <mail@babelouest.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation;
 * version 3 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <string.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include "../glewlwyd-common.h"

int client_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("ldap");
    *display_name = o_strdup("LDAP backend client");
    *description = o_strdup("Module to store clients in a LDAP server");
    *parameters = o_strdup("{}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int client_module_unload(struct config_module * config) {
  return G_OK;
}

int client_module_init(struct config_module * config, const char * parameters, void ** cls) {
  return G_OK;
}

int client_module_close(struct config_module * config, void * cls) {
  return G_OK;
}

size_t client_module_count_total(struct config_module * config, void * cls) {
  return 0;
}

char * client_module_get_list(const char * pattern, size_t limit, size_t offset, int * result, void * cls) {
  *result = G_ERROR;
  return NULL;
}

char * client_module_get(const char * client_id, int * result, void * cls) {
  *result = G_ERROR;
  return NULL;
}

char * client_is_valid(const char * client_id, const char * str_client, int mode, int * result, void * cls) {
  return NULL;
}

int client_module_add(const char * str_new_client, void * cls) {
  return G_ERROR;
}

int client_module_update(const char * client_id, const char * str_client, void * cls) {
  return G_ERROR;
}

int client_module_delete(const char * client_id, void * cls) {
  return G_ERROR;
}

int client_module_check_password(const char * client_id, const char * password, void * cls) {
  return G_ERROR;
}

int client_module_update_password(const char * client_id, const char * new_password, void * cls) {
  return G_ERROR;
}
