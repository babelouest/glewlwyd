/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * LDAP user module
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
#include <hoel.h>
#include "../glewlwyd-common.h"

int user_module_load(struct config_elements * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("ldap");
    *display_name = o_strdup("LDAP backend user");
    *description = o_strdup("Module to store users in a LDAP server");
    *parameters = o_strdup("{}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int user_module_unload(struct config_elements * config) {
  return G_OK;
}

int user_module_init(struct config_elements * config, const char * parameters, void ** cls) {
  return G_OK;
}

int user_module_close(struct config_elements * config, void * cls) {
  return G_OK;
}

char ** user_module_get_list(const char * pattern, uint limit, uint offset, uint * total, int * result, void * cls) {
  return NULL;
}

char * user_module_get(const char * username, int * result, void * cls) {
  return NULL;
}

int user_module_add(const char * str_new_user, void * cls) {
  return G_OK;
}

int user_module_update(const char * username, const char * str_user, void * cls) {
  return G_OK;
}

int user_module_update_profile(const char * username, const char * str_user, void * cls) {
  return G_OK;
}

int user_module_delete(const char * username, void * cls) {
  return G_OK;
}

int user_module_check_password(const char * username, const char * password, void * cls) {
  return G_OK;
}

int user_module_update_password(const char * username, const char * new_password, void * cls) {
  return G_ERROR_PARAM;
}
