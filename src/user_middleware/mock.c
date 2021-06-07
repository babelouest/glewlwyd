/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Mock user middleware module
 * 
 * Copyright 2021 Nicolas Mora <mail@babelouest.org>
 *
 * The MIT License (MIT)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <string.h>
#include <jansson.h>
#include <yder.h>
#include <orcania.h>
#include "glewlwyd-common.h"

json_t * user_middleware_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssssf}",
                   "result", G_OK,
                   "name", "mock",
                   "display_name", "Mock user middleware module",
                   "description", "Mock user middleware module for glewlwyd tests",
                   "api_version", 2.6);
}

int user_middleware_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

json_t * user_middleware_module_init(struct config_module * config, json_t * j_parameters, void ** cls) {
  UNUSED(config);
  if (json_object_get(j_parameters, "middleware") != NULL && !json_is_string(json_object_get(j_parameters, "middleware"))) {
    return json_pack("{si}", "result", G_ERROR_PARAM);
  } else {
    *cls = json_incref(j_parameters);
    return json_pack("{si}", "result", G_OK);
  }
}

int user_middleware_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref((json_t *)cls);
  return G_OK;
}

int user_middleware_module_get_list(struct config_module * config, json_t * j_user_list, void * cls) {
  UNUSED(config);
  json_t * j_element = NULL;
  size_t index = 0;
  
  json_array_foreach(j_user_list, index, j_element) {
    json_object_set_new(j_element, "middleware", json_deep_copy(json_object_get((json_t *)cls, "middleware")));
  }
  return G_OK;
}

int user_middleware_module_get(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  json_object_set_new(j_user, "middleware", json_deep_copy(json_object_get((json_t *)cls, "middleware")));
  return G_OK;
}

int user_middleware_module_get_profile(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  json_object_set_new(j_user, "middleware", json_deep_copy(json_object_get((json_t *)cls, "middleware")));
  return G_OK;
}

int user_middleware_module_update(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  json_object_del(j_user, "middleware");
  return G_OK;
}

int user_middleware_module_delete(struct config_module * config, const char * username, json_t * j_user, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(cls);
  json_object_del(j_user, "middleware");
  return G_OK;
}
