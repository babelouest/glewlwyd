/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Database user module
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

struct parameters {
  int use_glewlwyd_connection;
  struct _h_connection * conn;
}

int user_module_load(struct config_module * config, char ** name, char ** display_name, char ** description, char ** parameters) {
  int ret = G_OK;
  if (name != NULL && parameters != NULL && display_name != NULL && description != NULL) {
    *name = o_strdup("database");
    *display_name = o_strdup("Database backend user");
    *description = o_strdup("Module to store users in the database");
    *parameters = o_strdup("{\"use-glewlwyd-connection\":{\"type\":\"boolean\",\"default\":true},"
                           "\"type\":{\"type\":\"list\",\"values\":[\"sqlite\",\"mariadb\",\"postgre\"],\"mandatory\":false},"
                           "\"sqlite-path\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"mariadb-host\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"mariadb-user\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"mariadb-password\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"mariadb-dbname\":{\"type\":\"string\",\"mandatory\":false},"
                           "\"mariadb-port\":{\"type\":\"number\",\"mandatory\":false},"
                           "\"postgre-conninfo\":{\"type\":\"string\",\"mandatory\":false},"
                           "}");
  } else {
    ret = G_ERROR;
  }
  return ret;
}

int user_module_unload(struct config_module * config) {
  return G_OK;
}

int user_module_init(struct config_module * config, const char * parameters, void ** cls) {
  json_t * j_params = json_loads(parameters, JSON_ENCODE_ANY);
  int ret;
  
  if (j_params != NULL) {
    if (json_object_get(j_params, "use-glewlwyd-connection") != NULL && !json_is_boolean(json_object_get(j_params, "use-glewlwyd-connection"))) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parameter use-glewlwyd-connection invalid");
      ret = G_ERROR_PARAM;
    } else {
      if (json_object_get(j_params, "use-glewlwyd-connection") != json_false()) {
        *cls = o_malloc(sizeof(struct parameters));
        if (*cls != NULL) {
          ((struct parameters *)*cls)->use_glewlwyd_connection = 0;
          ((struct parameters *)*cls)->conn = config->conn;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error allocating resources for cls");
          ret = G_ERROR_MEMORY;
        }
      } else {
        // TODO
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_module_init database - Error parsing parameters");
    ret = G_ERROR_PARAM;
  }
  json_decref(j_params);
  return ret;
}

int user_module_close(struct config_module * config, void * cls) {
  if (((struct parameters *)cls)->use_glewlwyd_connection) {
    if (h_close_db(((struct parameters *)cls)->conn) != H_OK) {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_module_close database - Error h_close_db");
      return G_ERROR_DB;
    } else {
      return G_OK;
    }
  } else {
    return G_OK;
  }
}

size_t user_module_count_total(const char * pattern, void * cls) {
  return 0;
}

char * user_module_get_list(const char * pattern, size_t offset, size_t limit, int * result, void * cls) {
  return NULL;
}

char * user_module_get(const char * username, int * result, void * cls) {
  return NULL;
}

char * user_module_get_profile(const char * username, int * result, void * cls) {
  return NULL;
}

char * user_is_valid(const char * username, const char * str_user, int mode, int * result, void * cls) {
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
