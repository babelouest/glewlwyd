/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * TLS client certificate authentication scheme module
 * 
 * Copyright 2019 Nicolas Mora <mail@babelouest.org>
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

/**
 *
 * Note on the user auth scheme module
 *
 * It's possible for the scheme module to get or store any value in the user object returned by the functions
 * struct config_module.glewlwyd_module_callback_get_user()
 * struct config_module.glewlwyd_module_callback_set_user()
 *
 * Although, the module can't know if any value, other than "name", "password", "email" or "enabled" can be added or updated by the scheme module
 * The scheme module can store its specific data for each user by itself or store the data in the user object, or both, this will depend on the implementation
 *
 * The format of the structure config_module is:
 *
 * struct config_module {
 *   const char              * external_url;    // Absolute url of the glewlwyd service
 *   const char              * login_url;       // Relative url of the login page
 *   const char              * admin_scope;     // Value of the g_admin scope
 *   const char              * profile_scope;   // Value of the g_profile scope
 *   struct _h_connection    * conn;            // Hoel structure to access to the database
 *   digest_algorithm          hash_algorithm;  // Hash algorithm used in Glewlwyd
 *   struct config_elements  * glewlwyd_config; // Pointer to the global config structure
 *                          // Function used to return a user object
 *   json_t               * (* glewlwyd_module_callback_get_user)(struct config_module * config, const char * username);
 *                          // Function used to update a user
 *   int                    (* glewlwyd_module_callback_set_user)(struct config_module * config, const char * username, json_t * j_user);
 *                          // Function used to check the validity of a user's password
 *   int                    (* glewlwyd_module_callback_check_user_password)(struct config_module * config, const char * username, const char * password);
 * };
 *
 */

struct certificate_config {
  json_t           * j_parameters;
  char             * mod_name;
};

static json_t * is_certificate_parameters_valid(json_t * j_parameters) {
  json_t * j_array = json_array(), * j_return;
  
  if (j_array != NULL) {
    if (json_is_object(j_parameters)) {
      if (json_object_get(j_parameters, "check-from-certificate-property") != NULL && !json_is_boolean(json_object_get(j_parameters, "check-from-certificate-property"))) {
        json_array_append_new(j_array, json_string("check-from-certificate-property is optional and must be a boolean"));
      }
      if (json_object_get(j_parameters, "user-certificate-property") != NULL && !json_string_length(json_object_get(j_parameters, "user-certificate-property"))) {
        json_array_append_new(j_array, json_string("user-certificate-property is optional and must be a non empty string"));
      }
      if (json_object_get(j_parameters, "allow-user-add-cert") != NULL && !json_is_boolean(json_object_get(j_parameters, "allow-user-add-cert"))) {
        json_array_append_new(j_array, json_string("allow-user-add-cert is optional and must be a boolean"));
      }
      if (json_object_get(j_parameters, "allow-admin-add-cert") != NULL && !json_is_boolean(json_object_get(j_parameters, "allow-admin-add-cert"))) {
        json_array_append_new(j_array, json_string("allow-admin-add-cert is optional and must be a boolean"));
      }
      if (json_object_get(j_parameters, "store-certificate-user-backend") != NULL && !json_is_boolean(json_object_get(j_parameters, "store-certificate-user-backend"))) {
        json_array_append_new(j_array, json_string("store-certificate-user-backend is optional and must be a boolean"));
      }
      if (json_object_get(j_parameters, "check-from-ca") != NULL && !json_is_boolean(json_object_get(j_parameters, "check-from-ca"))) {
        json_array_append_new(j_array, json_string("check-from-ca is optional and must be a boolean"));
      }
      if (json_object_get(j_parameters, "user-dn-property") != NULL && !json_string_length(json_object_get(j_parameters, "user-dn-property"))) {
        json_array_append_new(j_array, json_string("user-dn-property is optional and must be a non empty string"));
      }
      if (json_object_get(j_parameters, "check-from-certificate-property") != json_true() && json_object_get(j_parameters, "check-from-ca") != json_true()) {
        json_array_append_new(j_array, json_string("At least one setting 'check-from-ca' or 'check-from-certificate-property' must be allowed"));
      }
      if (json_object_get(j_parameters, "check-from-certificate-property") == json_true() && json_object_get(j_parameters, "user-certificate-property") == NULL) {
        json_array_append_new(j_array, json_string("parameter user-certificate-property is mandatory when check-from-certificate-property is set to true"));
      }
      if (json_object_get(j_parameters, "check-from-ca") == json_true() && json_object_get(j_parameters, "user-dn-property") == NULL) {
        json_array_append_new(j_array, json_string("parameter user-dn-property is mandatory when check-from-ca is set to true"));
      }
    } else {
      json_array_append_new(j_array, json_string("certificate parameters must be a JSON object"));
    }
    if (!json_array_size(j_array)) {
      j_return = json_pack("{si}", "result", G_OK);
    } else {
      j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", j_array);
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "is_certificate_parameters_valid - Error allocating resources for j_array");
    j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
  }
  json_decref(j_array);
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_load
 * 
 * Executed once when Glewlwyd service is started
 * Used to identify the module and to show its parameters on init
 * You can also use it to load resources that are required once for all
 * instance modules for example
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  name: string, mandatory, name of the module, must be unique among other scheme modules
 *                  display_name: string, optional, long name of the module
 *                  description: string, optional, description for the module
 *                  parameters: object, optional, parameters description for the module
 *                }
 * 
 *                Example:
 *                {
 *                  result: G_OK,
 *                  name: "mock",
 *                  display_name: "Mock scheme module",
 *                  description: "Mock scheme module for glewlwyd tests",
 *                  parameters: {
 *                    mock-value: {
 *                      type: "string",
 *                      mandatory: true
 *                    }
 *                  }
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
json_t * user_auth_scheme_module_load(struct config_module * config) {
  UNUSED(config);
  return json_pack("{sisssssss{s{ssso}}}",
                   "result",
                   G_OK,
                   "name",
                   "certificate",
                   "display_name",
                   "Client certificate",
                   "description",
                   "Client certificate scheme module",
                   "parameters",
                     "cert-chain",
                       "type",
                       "list",
                       "mandatory",
                       json_true());
}

/**
 * 
 * user_auth_scheme_module_unload
 * 
 * Executed once when Glewlwyd service is stopped
 * You can also use it to release resources that are required once for all
 * instance modules for example
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * 
 */
int user_auth_scheme_module_unload(struct config_module * config) {
  UNUSED(config);
  return G_OK;
}

/**
 * 
 * user_auth_scheme_module_init
 * 
 * Initialize an instance of this module declared in Glewlwyd service.
 * If required, you must dynamically allocate a pointer to the configuration
 * for this instance and pass it to *cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter j_parameters: used to initialize an instance in JSON format
 *                          The module must validate itself its parameters
 * @parameter mod_name: module name in glewlwyd service
 * @parameter cls: will contain an allocated void * pointer that will be sent back
 *                 as void * in all module functions
 * 
 */
json_t * user_auth_scheme_module_init(struct config_module * config, json_t * j_parameters, const char * mod_name, void ** cls) {
  UNUSED(config);
  UNUSED(mod_name);
  json_t * j_result = is_certificate_parameters_valid(j_parameters), * j_return;
  
  if (check_result_value(j_result, G_OK)) {
    *cls = o_malloc(sizeof(struct certificate_config));
    if (*cls != NULL) {
      ((struct certificate_config *)*cls)->j_parameters = json_incref(j_parameters);
      ((struct certificate_config *)*cls)->mod_name = o_strdup(mod_name);
      j_return = json_pack("{si}", "result", G_OK);
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init certificate - Error allocating resources for *cls");
      j_return = json_pack("{si}", "result", G_ERROR_MEMORY);
    }
  } else if (check_result_value(j_result, G_ERROR_PARAM)) {
    j_return = json_pack("{sisO}", "result", G_ERROR_PARAM, "error", json_object_get(j_result, "error"));
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_init certificate - Error is_certificate_parameters_valid");
    j_return = json_pack("{si}", "result", G_ERROR);
  }
  json_decref(j_result);
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_close
 * 
 * Close an instance of this module declared in Glewlwyd service.
 * You must free the memory previously allocated in
 * the user_auth_scheme_module_init function as void * cls
 * 
 * @return value: G_OK on success, another value on error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_close(struct config_module * config, void * cls) {
  UNUSED(config);
  json_decref(((struct certificate_config *)cls)->j_parameters);
  o_free(((struct certificate_config *)cls)->mod_name);
  o_free(cls);
  return G_OK;
}

/**
 * 
 * user_auth_scheme_module_can_use
 * 
 * Validate if the user is allowed to use this scheme prior to the
 * authentication or registration
 * 
 * @return value: GLEWLWYD_IS_REGISTERED - User can use scheme and has registered
 *                GLEWLWYD_IS_AVAILABLE - User can use scheme but hasn't registered
 *                GLEWLWYD_IS_NOT_AVAILABLE - User can't use scheme
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_can_use(struct config_module * config, const char * username, void * cls) {
  UNUSED(config);
  json_t * j_user, * j_user_certificate = NULL;
  int ret;
  
  if (json_object_get(((struct certificate_config *)cls)->j_parameters, "store-certificate-user-backend") == json_true()) {
    j_user = config->glewlwyd_module_callback_get_user(config, username);
    if (check_result_value(j_user, G_OK)) {
      j_user_certificate = json_object_get(json_object_get(j_user, "user"), json_string_value(json_object_get(((struct certificate_config *)cls)->j_parameters, "user-certificate-property")));
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "user_auth_scheme_module_can_use certificate - Error glewlwyd_module_callback_get_user");
    }
    if (json_is_string(j_user_certificate) || json_array_size(j_user_certificate)) {
      ret = GLEWLWYD_IS_REGISTERED;
    } else {
      ret = GLEWLWYD_IS_AVAILABLE;
    }
  }
  if (json_object_get(((struct certificate_config *)cls)->j_parameters, "check-from-certificate-property") == json_true()) {
    ret = GLEWLWYD_IS_REGISTERED;
  }
  return ret;
}

/**
 * 
 * user_auth_scheme_module_register
 * 
 * Register the scheme for a user
 * Ex: add a certificate, add new TOTP values, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the HTTP API
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: additional data used to register the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(j_scheme_data);
  UNUSED(cls);
  json_t * j_return = json_pack("{si}", "result", G_ERROR);
  
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_register_get
 * 
 * Get the registration value(s) of the scheme for a user
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_register_get(struct config_module * config, const struct _u_request * http_request, const char * username, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(cls);
  json_t * j_return = json_pack("{si}", "result", G_ERROR);
  
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_trigger
 * 
 * Trigger the scheme for a user
 * Ex: send the code to a device, generate a challenge, etc.
 * 
 * @return value: a json_t * value with the following pattern:
 *                {
 *                  result: number (G_OK on success, another value on error)
 *                  response: JSON object, optional
 *                }
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter scheme_trigger: data sent to trigger the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
json_t * user_auth_scheme_module_trigger(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_trigger, void * cls) {
  UNUSED(config);
  UNUSED(http_request);
  UNUSED(username);
  UNUSED(j_scheme_trigger);
  UNUSED(cls);
  json_t * j_return = json_pack("{si}", "result", G_OK);
  
  return j_return;
}

/**
 * 
 * user_auth_scheme_module_validate
 * 
 * Validate the scheme for a user
 * Ex: check the code sent to a device, verify the challenge, etc.
 * 
 * @return value: G_OK on success
 *                G_ERROR_UNAUTHORIZED if validation fails
 *                G_ERROR_PARAM if error in parameters
 *                G_ERROR on another error
 * 
 * @parameter config: a struct config_module with acess to some Glewlwyd
 *                    service and data
 * @parameter http_request: the original struct _u_request from the API, must be casted to be available
 * @parameter username: username to identify the user
 * @parameter j_scheme_data: data sent to validate the scheme for the user
 *                           in JSON format
 * @parameter cls: pointer to the void * cls value allocated in user_auth_scheme_module_init
 * 
 */
int user_auth_scheme_module_validate(struct config_module * config, const struct _u_request * http_request, const char * username, json_t * j_scheme_data, void * cls) {
  UNUSED(config);
  UNUSED(username);
  UNUSED(j_scheme_data);
  UNUSED(cls);

  char * dn = NULL, * issuer_dn = NULL;
  size_t lbuf = 0, libuf = 0;
  int ret;

  if (http_request->client_cert != NULL) {
    gnutls_x509_crt_get_dn(http_request->client_cert, NULL, &lbuf);
    gnutls_x509_crt_get_issuer_dn(http_request->client_cert, NULL, &libuf);
    dn = o_malloc(lbuf + 1);
    issuer_dn = o_malloc(libuf + 1);
    if (dn != NULL && issuer_dn != NULL) {
      gnutls_x509_crt_get_dn(http_request->client_cert, dn, &lbuf);
      gnutls_x509_crt_get_issuer_dn(http_request->client_cert, issuer_dn, &libuf);
      dn[lbuf] = '\0';
      issuer_dn[libuf] = '\0';
      y_log_message(Y_LOG_LEVEL_DEBUG, "dn of the client: %s", dn);
      y_log_message(Y_LOG_LEVEL_DEBUG, "dn of the issuer: %s", issuer_dn);
      ret = G_OK;
    }
    o_free(dn);
    o_free(issuer_dn);
    ret = G_ERROR_MEMORY;
  } else {
    y_log_message(Y_LOG_LEVEL_DEBUG, "No certificate");
    ret = G_ERROR_UNAUTHORIZED;
  }

  return ret;
}
