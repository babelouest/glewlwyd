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
          res = client_module->module->client_module_check_password(client_id, password, client_module->cls);
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
  int found = 0, result;
  char * str_client;
  json_t * j_return = NULL, * j_client, * j_module_list, * j_module;
  struct _client_module_instance * client_module;
  size_t index;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL) {
      result = G_ERROR;
      str_client = client_module->module->client_module_get(client_id, &result, client_module->cls);
      if (result == G_OK && str_client != NULL) {
        j_client = json_loads(str_client, JSON_DECODE_ANY, NULL);
        if (j_client != NULL) {
          j_return = json_pack("{sisOss}", "result", G_OK, "client", j_client, "source", source);
          json_decref(j_client);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error json_loads");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else if (result != G_OK && result != G_ERROR_NOT_FOUND) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error, client_module_get for module %s", client_module->name);
        j_return = json_pack("{si}", "result", G_ERROR);
      } else {
        j_return = json_pack("{si}", "result", result);
      }
      o_free(str_client);
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
              result = G_ERROR;
              str_client = client_module->module->client_module_get(client_id, &result, client_module->cls);
              if (result == G_OK && str_client != NULL) {
                j_client = json_loads(str_client, JSON_DECODE_ANY, NULL);
                if (j_client != NULL) {
                  found = 1;
                  j_return = json_pack("{sisOss}", "result", G_OK, "client", j_client, "source", client_module->name);
                  json_decref(j_client);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error json_loads");
                }
                found = 1;
              } else if (result != G_OK && result != G_ERROR_NOT_FOUND) {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_client - Error, client_module_get for module %s", client_module->name);
              }
              o_free(str_client);
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
  json_t * j_return, * j_module_list, * j_module, * j_list_parsed;
  struct _client_module_instance * client_module;
  char * list_result = NULL;
  int result;
  size_t cur_offset, cur_limit, count_total, index;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled) {
      result = G_ERROR;
      list_result = client_module->module->client_module_get_list(pattern, offset, limit, &result, client_module->cls);
      if (result == G_OK) {
        j_list_parsed = json_loads(list_result, JSON_DECODE_ANY, NULL);
        if (j_list_parsed && json_is_array(j_list_parsed)) {
          j_return = json_pack("{sisO}", "result", G_OK, "client", j_list_parsed);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error parsing client_module_get_list result into a JSON array");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
        json_decref(j_list_parsed);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error client_module_get_list");
        j_return = json_pack("{si}", "result", result);
      }
      o_free(list_result);
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
            if ((count_total = client_module->module->client_module_count_total(pattern, client_module->cls)) > cur_offset && cur_limit) {
              list_result = client_module->module->client_module_get_list(pattern, cur_offset, cur_limit, &result, client_module->cls);
              if (result == G_OK) {
                j_list_parsed = json_loads(list_result, JSON_DECODE_ANY, NULL);
                if (j_list_parsed && json_is_array(j_list_parsed)) {
                  cur_offset = 0;
                  if (cur_limit > json_array_size(j_list_parsed)) {
                    cur_limit -= json_array_size(j_list_parsed);
                  } else {
                    cur_limit = 0;
                  }
                  json_array_extend(json_object_get(j_return, "client"), j_list_parsed);
                } else {
                  y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error parsing client_module_get_list result into a JSON array for module %s", json_string_value(json_object_get(j_module, "name")));
                  j_return = json_pack("{si}", "result", G_ERROR);
                }
                json_decref(j_list_parsed);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "get_client_list - Error client_module_get_list for module %s", json_string_value(json_object_get(j_module, "name")));
              }
              o_free(list_result);
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
  int found = 0, result;
  char * str_error, * str_client;
  json_t * j_return = NULL, * j_error_list, * j_module_list, * j_module;
  struct _client_module_instance * client_module;
  size_t index;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      str_client = json_dumps(j_client, JSON_COMPACT);
      result = G_ERROR;
      str_error = client_module->module->client_is_valid(client_id, str_client, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, &result, client_module->cls);
      if (result == G_ERROR_PARAM && str_error != NULL) {
        j_error_list = json_loads(str_error, JSON_DECODE_ANY, NULL);
        if (j_error_list != NULL) {
          j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_error_list);
          json_decref(j_error_list);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error json_loads");
          j_return = json_pack("{si}", "result", G_ERROR);
        }
      } else if (result == G_OK) {
        j_return = json_pack("{si}", "result", G_OK);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error client_is_valid");
        j_return = json_pack("{si}", "result", result);
      }
      o_free(str_error);
      o_free(str_client);
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
            str_client = json_dumps(j_client, JSON_COMPACT);
            result = G_ERROR;
            str_error = client_module->module->client_is_valid(client_id, str_client, add?GLEWLWYD_IS_VALID_MODE_ADD:GLEWLWYD_IS_VALID_MODE_UPDATE, &result, client_module->cls);
            if (result == G_ERROR_PARAM && str_error != NULL) {
              j_error_list = json_loads(str_error, JSON_DECODE_ANY, NULL);
              if (j_error_list != NULL) {
                j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "client", j_error_list);
                json_decref(j_error_list);
              } else {
                y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error json_loads");
              }
            } else if (result == G_OK) {
              j_return = json_pack("{si}", "result", G_OK);
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "is_client_valid - Error, client_is_valid for module %s", client_module->name);
              j_return = json_pack("{si}", "result", result);
            }
            o_free(str_error);
            o_free(str_client);
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
  char * str_client;
  json_t * j_module_list, * j_module;
  struct _client_module_instance * client_module;
  size_t index;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      str_client = json_dumps(j_client, JSON_COMPACT);
      result = client_module->module->client_module_add(str_client, client_module->cls);
      if (result == G_OK) {
        ret = G_OK;
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error client_module_add");
        ret = result;
      }
      o_free(str_client);
    } else if (client_module != NULL && (client_module->readonly || !client_module->enabled)) {
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
            str_client = json_dumps(j_client, JSON_COMPACT);
            result = client_module->module->client_module_add(str_client, client_module->cls);
            if (result == G_OK) {
              ret = G_OK;
            } else {
              y_log_message(Y_LOG_LEVEL_ERROR, "add_client - Error client_module_add");
              ret = result;
            }
            o_free(str_client);
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
  }
  if (!found) {
    ret = G_ERROR_NOT_FOUND;
  }
  return ret;
}

int set_client(struct config_elements * config, const char * client_id, json_t * j_client, const char * source) {
  int result, ret;
  char * str_client;
  struct _client_module_instance * client_module;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      o_free(client_module->module->client_module_get(client_id, &result, client_module->cls));
      if (result == G_OK) {
        str_client = json_dumps(j_client, JSON_COMPACT);
        result = client_module->module->client_module_update(client_id, str_client, client_module->cls);
        if (result == G_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error client_module_update");
          ret = result;
        }
        o_free(str_client);
      } else if (result != G_ERROR_NOT_FOUND) {
        y_log_message(Y_LOG_LEVEL_ERROR, "set_client - Error client_module_get");
        ret = result;
      } else {
        ret = G_ERROR_NOT_FOUND;
      }
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
  int result, ret;
  struct _client_module_instance * client_module;
  
  if (source != NULL) {
    client_module = get_client_module_instance(config, source);
    if (client_module != NULL && client_module->enabled && !client_module->readonly) {
      o_free(client_module->module->client_module_get(client_id, &result, client_module->cls));
      if (result == G_OK) {
        result = client_module->module->client_module_delete(client_id, client_module->cls);
        if (result == G_OK) {
          ret = G_OK;
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "delete_client - Error client_module_delete");
          ret = result;
        }
      } else if (result != G_ERROR_NOT_FOUND) {
        y_log_message(Y_LOG_LEVEL_ERROR, "delete_client - Error client_module_get");
        ret = result;
      } else {
        ret = G_ERROR_NOT_FOUND;
      }
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
