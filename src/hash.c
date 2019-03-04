/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Hash functions
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
#include <gnutls/gnutls.h>
#include <crypt.h>

#include "glewlwyd.h"

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
            rand_string(salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
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
 * Generates a hash from the specified string data, using the digest method specified
 * returned value must be 'd after user
 */
char * generate_hash(digest_algorithm digest, const char * data) {
  char * to_return = NULL, buffer[1024] = {0};
  
  if (data != NULL) {
    switch (digest) {
      case digest_SSHA1:
        if (generate_digest(digest_SHA1, data, 1, buffer)) {
          to_return = msprintf("{SSHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA1:
        if (generate_digest(digest_SHA1, data, 0, buffer)) {
          to_return = msprintf("{SHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA224:
        if (generate_digest(digest_SHA224, data, 1, buffer)) {
          to_return = msprintf("{SSHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA224:
        if (generate_digest(digest_SHA224, data, 0, buffer)) {
          to_return = msprintf("{SHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA256:
        if (generate_digest(digest_SHA256, data, 1, buffer)) {
          to_return = msprintf("{SSHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA256:
        if (generate_digest(digest_SHA256, data, 0, buffer)) {
          to_return = msprintf("{SHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA384:
        if (generate_digest(digest_SHA384, data, 1, buffer)) {
          to_return = msprintf("{SSHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA384:
        if (generate_digest(digest_SHA384, data, 0, buffer)) {
          to_return = msprintf("{SHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA512:
        if (generate_digest(digest_SHA512, data, 1, buffer)) {
          to_return = msprintf("{SSHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA512:
        if (generate_digest(digest_SHA512, data, 0, buffer)) {
          to_return = msprintf("{SHA}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SMD5:
        if (generate_digest(digest_SMD5, data, 1, buffer)) {
          to_return = msprintf("{SMD5}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_MD5:
        if (generate_digest(digest_MD5, data, 0, buffer)) {
          to_return = msprintf("{MD5}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      default:
        y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error algorithm not found");
        to_return = NULL;
        break;
    }
  }
  return to_return;
}
