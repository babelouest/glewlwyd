/**
 *
 * Glewlwyd OAuth2 Authorization Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * Provides Json Web Tokens (jwt)
 * 
 * Hash functions
 *
 * Copyright 2018 Nicolas Mora <mail@babelouest.org>
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
#include <gnutls/gnutls.h>
#include <crypt.h>

#include "glewlwyd.h"

/**
 * Generates a random string and store it in str
 */
char * rand_salt(char * str, size_t str_size) {
    size_t n;
    
    if (str_size > 0 && str != NULL) {
        for (n = 0; n < str_size; n++) {
            int key = rand()+1;
            str[n] = key;
        }
        str[str_size] = '\0';
        return str;
    } else {
      return NULL;
    }
}

/**
 * Generates a digest using the digest_algorithm specified from password and add a salt if specified, stores it in out_digest
 */
int generate_digest(digest_algorithm digest, const char * password, int use_salt, char * out_digest) {
  unsigned int res = 0;
  int alg, dig_res;
  gnutls_datum_t key_data;
  char * intermediate = NULL, salt[GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  unsigned char encoded_key[128 + GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  size_t encoded_key_size = (128 + GLEWLWYD_DEFAULT_SALT_LENGTH), encoded_key_size_base64;

  if (password != NULL && out_digest != NULL) {
    switch (digest) {
      case digest_SHA1:
        alg = GNUTLS_DIG_SHA1;
        break;
      case digest_SHA224:
        alg = GNUTLS_MAC_SHA224;
        break;
      case digest_SHA256:
        alg = GNUTLS_MAC_SHA256;
        break;
      case digest_SHA384:
        alg = GNUTLS_DIG_SHA384;
        break;
      case digest_SHA512:
        alg = GNUTLS_DIG_SHA512;
        break;
      case digest_MD5:
        alg = GNUTLS_MAC_MD5;
        break;
      default:
        alg = GNUTLS_MAC_UNKNOWN;
        break;
    }
    
    if(alg != GNUTLS_MAC_UNKNOWN) {
      if (o_strlen(password) > 0) {
        intermediate = o_malloc(o_strlen(password)+((GLEWLWYD_DEFAULT_SALT_LENGTH+1)*sizeof(char)));
        if (intermediate != NULL) {
          key_data.data = (unsigned char*)intermediate;
          sprintf(intermediate, "%s", password);
          if (use_salt) {
            rand_salt(salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
            strncat(intermediate, salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
          }
          
          key_data.size = o_strlen(intermediate);
          if (key_data.data != NULL && (dig_res = gnutls_fingerprint(alg, &key_data, encoded_key, &encoded_key_size)) == GNUTLS_E_SUCCESS) {
            if (use_salt) {
              memcpy(encoded_key+encoded_key_size, salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
              encoded_key_size += GLEWLWYD_DEFAULT_SALT_LENGTH;
            }
            if (o_base64_encode(encoded_key, encoded_key_size, (unsigned char *)out_digest, &encoded_key_size_base64)) {
              res = 1;
            } else{
              res = 0;
            }
          } else {
            res = 0;
          }
        } else {
          res = 0;
        }
        o_free(intermediate);
      } else {
        // No password, then out_digest becomes an empty string
        out_digest[0] = '\0';
        res = 1;
      }
    } else {
      res = 0;
    }
  } else {
    res = 0;
  }
  return res;
}

/**
 * Generates a hash from the specified password, using the digest method specified
 * returned value must be 'd after user
 */
char * generate_hash(struct config_elements * config, const char * digest, const char * password) {
  char * to_return = NULL, buffer[1024] = {0};
  //char salt[GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  
  if (digest != NULL && password != NULL) {
    if (!o_strcmp(digest, "SSHA")) {
      if (generate_digest(digest_SHA1, password, 1, buffer)) {
        to_return = msprintf("{SSHA}%s", buffer, o_strlen(buffer));
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
      }
    } else if (!o_strcmp(digest, "SHA1")) {
      if (generate_digest(digest_SHA1, password, 0, buffer)) {
        to_return = msprintf("{SHA}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
      }
    } else if (!o_strcmp(digest, "SHA224")) {
      if (generate_digest(digest_SHA224, password, 0, buffer)) {
        to_return = msprintf("{SHA224}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA224");
      }
    } else if (!o_strcmp(digest, "SSHA224")) {
      if (generate_digest(digest_SHA224, password, 1, buffer)) {
        to_return = msprintf("{SSHA224}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA224");
      }
    } else if (!o_strcmp(digest, "SHA256")) {
      if (generate_digest(digest_SHA256, password, 0, buffer)) {
        to_return = msprintf("{SHA256}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA256");
      }
    } else if (!o_strcmp(digest, "SSHA256")) {
      if (generate_digest(digest_SHA256, password, 1, buffer)) {
        to_return = msprintf("{SSHA256}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA256");
      }
    } else if (!o_strcmp(digest, "SHA384")) {
      if (generate_digest(digest_SHA384, password, 0, buffer)) {
        to_return = msprintf("{SHA384}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA384");
      }
    } else if (!o_strcmp(digest, "SSHA384")) {
      if (generate_digest(digest_SHA384, password, 1, buffer)) {
        to_return = msprintf("{SSHA384}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA384");
      }
    } else if (!o_strcmp(digest, "SHA512")) {
      if (generate_digest(digest_SHA512, password, 0, buffer)) {
        to_return = msprintf("{SHA512}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA512");
      }
    } else if (!o_strcmp(digest, "SSHA512")) {
      if (generate_digest(digest_SHA512, password, 1, buffer)) {
        to_return = msprintf("{SSHA512}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA512");
      }
    } else if (!o_strcmp(digest, "SMD5")) {
      if (generate_digest(digest_MD5, password, 1, buffer)) {
        to_return = msprintf("{SMD5}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SMD5");
      }
    } else if (!o_strcmp(digest, "MD5")) {
      if (generate_digest(digest_MD5, password, 0, buffer)) {
        to_return = msprintf("{MD5}%s", buffer);
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest MD5");
      }
    } else if (!o_strcmp(digest, "CRYPT")) {
      //rand_crypt_salt(salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
      //to_return = msprintf("{CRYPT}%s", crypt_r(password, salt, &config->auth_ldap->cur_crypt_data));
    } else {
      to_return = o_strdup(password);
    }
  }
  return to_return;
}
