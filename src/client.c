/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * client management functions definition
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
#include "glewlwyd.h"

json_t * auth_check_client_credentials(struct config_elements * config, const char * client_id, const char * password) {
  int res;
  json_t * j_return = NULL, * j_module_list = get_client_module_list(config), * j_module;
  struct _client_module_instance * client_module;
  size_t index;
  
  if (check_result_value(j_module_list, G_OK)) {
    json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
      client_module = get_client_module_instance(config, json_string_value(json_object_get(j_module, "name")));
      if (client_module != NULL) {
        if (client_module->enabled) {
          res = client_module->module->client_module_check_password(config->config_m, client_id, password, client_module->cls);
          if (res == G_OK) {
            j_return = json_pack("{si}", "result", G_OK);
          } else if (res == G_ERROR_UNAUTHORIZED) {
            j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
          } else if (res != G_ERROR_NOT_FOUND) {
            y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_credentials - Error, client_module_check_password for module '%s', skip", client_module->name);
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_credentials - Error, client_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
      }
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "auth_check_client_credentials - Error get_client_module_list");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_module_list);
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_UNAUTHORIZED);
  }
  return j_return;
}

json_t * get_client(struct config_elements * config, const char * client_id, const char * source) {
  int found = 0;
  json_t * j_return = NULL, * j_client, * j_module_list, * j_module;
  struct _client_module_instance * client_module;
  size_t index;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL) {
      j_client = client_module->module->client_module_get(config->config_m, client_id, client_module->cls);
      if (check_result_value(j_client, G_OK)) {
        json_object_set_new(json_object_get(j_client, "client"), "source", json_string(source));
        j_return = json_incref(j_client);
      } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
        j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error, client_module_get for module %s", client_module->name);
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_client);
    } else {
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    j_module_list = get_client_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          client_module = get_client_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (client_module != NULL) {
            if (client_module->enabled) {
              j_client = client_module->module->client_module_get(config->config_m, client_id, client_module->cls);
              if (check_result_value(j_client, G_OK)) {
                json_object_set_new(json_object_get(j_client, "client"), "source", json_string(client_module->name));
                j_return = json_incref(j_client);
              } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
                j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error, client_module_get for module %s", client_module->name);
                j_return = json_pack("{si}", "result", G_ERROR);
              }
              json_decref(j_client);
            }
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error, client_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error get_client_module_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_module_list);
  }
  if (j_return == NULL) {
    j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
  }
  return j_return;
}

json_t * get_client_list(struct config_elements * config, const char * pattern, size_t offset, size_t limit, const char * source) {
  json_t * j_return, * j_module_list, * j_module, * j_list_parsed, * j_element;
  struct _client_module_instance * client_module;
  int result;
  size_t cur_offset, cur_limit, count_total, index, index_c;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled) {
      result = G_ERROR;
      j_list_parsed = client_module->module->client_module_get_list(config->config_m, pattern, offset, limit, client_module->cls);
      if (check_result_value(j_list_parsed, G_OK)) {
        json_array_foreach(json_object_get(j_list_parsed, "list"), index, j_element) {
          json_object_set_new(j_element, "source", json_string(client_module->name));
        }
        j_return = json_pack("{sisO}", "result", G_OK, "client", json_object_get(j_list_parsed, "list"));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error client_module_get_list");
        j_return = json_pack("{si}", "result", result);
      }
      json_decref(j_list_parsed);
    } else if (client_module != NULL && !client_module->enabled) {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error get_client_module_instance");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
  } else {
    j_module_list = get_client_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      cur_offset = offset;
      cur_limit = limit;
      j_return = json_pack("{sis[]}", "result", G_OK, "client");
      if (j_return != NULL) {
        json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
          client_module = get_client_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (client_module != NULL && client_module->enabled) {
            result = G_ERROR;
            if ((count_total = client_module->module->client_module_count_total(config->config_m, pattern, client_module->cls)) > cur_offset && cur_limit) {
              j_list_parsed = client_module->module->client_module_get_list(config->config_m, pattern, cur_offset, cur_limit, client_module->cls);
              if (check_result_value(j_list_parsed, G_OK)) {
                json_array_foreach(json_object_get(j_list_parsed, "list"), index_c, j_element) {
                  json_object_set_new(j_element, "source", json_string(client_module->name));
                }
                cur_offset = 0;
                if (cur_limit > json_array_size(json_object_get(j_list_parsed, "list"))) {
                  cur_limit -= json_array_size(json_object_get(j_list_parsed, "list"));
                } else {
                  cur_limit = 0;
                }
                json_array_extend(json_object_get(j_return, "client"), json_object_get(j_list_parsed, "list"));
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error client_module_get_list for module %s", json_string_value(json_object_get(j_module, "name")));
              }
              json_decref(j_list_parsed);
            } else {
              cur_offset -= count_total;
            }
          } else if (client_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error, client_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error allocating resources for j_return");
        j_return = json_pack("{si}", "result", G_ERROR);
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error get_client_module_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_module_list);
  }
  return j_return;
}

json_t * is_client_valid(struct config_elements * config, const char * client_id, json_t * j_client, int add, const char * source) {
  int found = 0;
  json_t * j_return = NULL, * j_error_list, * j_module_list, * j_module;
  struct _client_module_instance * client_module;
  size_t index;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      j_error_list = client_module->module->client_module_is_valid(config->config_m, client_id, j_client, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, client_module->cls);
      if (check_result_value(j_error_list, G_ERROR_PARAM) || check_result_value(j_error_list, G_OK)) {
        j_return = json_incref(j_error_list);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error, client_module_is_valid for module %s", client_module->name);
        j_return = json_pack("{si}", "result", G_ERROR);
      }
      json_decref(j_error_list);
    } else if (client_module != NULL && (client_module->readonly || !client_module->enabled)) {
      j_return = json_pack("{sis[s]}", "result", G_ERROR_PARAM, "error", "module is unavailable");
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error get_client_module_instance");
      j_return = json_pack("{si}", "result", G_ERROR_NOT_FOUND);
    }
  } else {
    j_module_list = get_client_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          client_module = get_client_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (client_module != NULL && client_module->enabled && !client_module->readonly) {
            found = 1;
            j_error_list = client_module->module->client_module_is_valid(config->config_m, client_id, j_client, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, client_module->cls);
            if (check_result_value(j_error_list, G_ERROR_PARAM) || check_result_value(j_error_list, G_OK)) {
              j_return = json_incref(j_error_list);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error, client_module_is_valid for module %s", client_module->name);
              j_return = json_pack("{si}", "result", G_ERROR);
            }
            json_decref(j_error_list);
          } else if (client_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error, client_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error get_client_module_list");
      j_return = json_pack("{si}", "result", G_ERROR);
    }
    json_decref(j_module_list);
    if (j_return == NULL) {
      j_return = json_pack("{si}", "result", G_ERROR_PARAM);
    }
  }
  return j_return;
}

int add_client(struct config_elements * config, json_t * j_client, const char * source) {
  int found = 0, result, ret;
  json_t * j_module_list, * j_module;
  struct _client_module_instance * client_module;
  size_t index;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      result = client_module->module->client_module_add(config->config_m, j_client, client_module->cls);
      if (result == G_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error client_module_add");
        ret = result;
      }
    } else if (client_module != NULL && (client_module->readonly || !client_module->enabled)) {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error module %s", source);
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error get_client_module_instance");
      ret = G_ERROR;
    }
  } else {
    j_module_list = get_client_module_list(config);
    if (check_result_value(j_module_list, G_OK)) {
      json_array_foreach(json_object_get(j_module_list, "module"), index, j_module) {
        if (!found) {
          client_module = get_client_module_instance(config, json_string_value(json_object_get(j_module, "name")));
          if (client_module != NULL && client_module->enabled && !client_module->readonly) {
            found = 1;
            result = client_module->module->client_module_add(config->config_m, j_client, client_module->cls);
            if (result == G_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error client_module_add");
              ret = result;
            }
          } else if (client_module == NULL) {
            y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error, client_module_instance %s is NULL", json_string_value(json_object_get(j_module, "name")));
          }
        }
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error get_client_module_list");
      ret = G_ERROR;
    }
    json_decref(j_module_list);
    if (!found) {
      y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error no module in write mode available");
      ret = G_ERROR;
    }
  }
  return ret;
}

int set_client(struct config_elements * config, const char * client_id, json_t * j_client, const char * source) {
  int ret, result;
  struct _client_module_instance * client_module;
  json_t * j_cur_client;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      j_cur_client = client_module->module->client_module_get(config->config_m, client_id, client_module->cls);
      if (check_result_value(j_cur_client, G_OK)) {
        result = client_module->module->client_module_update(config->config_m, client_id, j_client, client_module->cls);
        if (result == G_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error client_module_update");
          ret = result;
        }
      } else if (check_result_value(j_cur_client, G_ERROR_NOT_FOUND)) {
        ret = G_ERROR_NOT_FOUND;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error client_module_get");
        ret = G_ERROR;
      }
      json_decref(j_cur_client);
    } else if (client_module != NULL && (client_module->readonly || !client_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error get_client_module_instance");
      ret = G_ERROR;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}

int delete_client(struct config_elements * config, const char * client_id, const char * source) {
  int ret, result;
  struct _client_module_instance * client_module;
  json_t * j_client;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      j_client = client_module->module->client_module_get(config->config_m, client_id, client_module->cls);
      if (check_result_value(j_client, G_OK)) {
        result = client_module->module->client_module_delete(config->config_m, client_id, client_module->cls);
        if (result == G_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "delete_client - Error client_module_delete");
          ret = result;
        }
      } else if (check_result_value(j_client, G_ERROR_NOT_FOUND)) {
        ret = G_ERROR_NOT_FOUND;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_client - Error client_module_get");
        ret = G_ERROR;
      }
      json_decref(j_client);
    } else if (client_module != NULL && (client_module->readonly || !client_module->enabled)) {
      ret = G_ERROR_PARAM;
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "delete_client - Error get_client_module_instance");
      ret = G_ERROR;
    }
  } else {
    ret = G_ERROR_PARAM;
  }
  return ret;
}
