/**
 *
 * Glewlwyd SSO Server
 *
 * Authentiation server
 * Users are authenticated via various backend available: database, ldap
 * Using various authentication methods available: password, OTP, send code, etc.
 * 
 * Miscellaneous functions definitions
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/pkcs12.h>

#include "glewlwyd.h"

/**
 *
 * Read the content of a file and return it as a char *
 * returned value must be o_free'd after use
 *
 */
char * get_file_content(const char * file_path) {
  char * buffer = NULL;
  size_t length, res;
  FILE * f;

  f = fopen (file_path, "rb");
  if (f) {
    fseek (f, 0, SEEK_END);
    length = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = o_malloc((length+1)*sizeof(char));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        fprintf(stderr, "fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  }
  
  return buffer;
}

/**
 * Return the source ip address of the request
 * Based on the header value "X-Forwarded-For" if set, which means the request is forwarded by a proxy
 * otherwise the call is direct, return the client_address
 */
const char * get_ip_source(const struct _u_request * request) {
  const char * ip_source = u_map_get(request->map_header, "X-Forwarded-For");
  
  if (ip_source == NULL) {
    struct sockaddr_in * in_source = (struct sockaddr_in *)request->client_address;
    if (in_source != NULL) {
      ip_source = inet_ntoa(in_source->sin_addr);
    } else {
      ip_source = "NOT_FOUND";
    }
  }
  
  return ip_source;
};

char * get_client_hostname(const struct _u_request * request) {
  const char * ip_source = get_ip_source(request);
  char * hostname = NULL;
  struct hostent * lh;
  
  if (ip_source != NULL) {
    lh = gethostbyname(ip_source);
    if (lh) {
      hostname = msprintf("%s - %s", ip_source, lh->h_name);
    } else {
      hostname = o_strdup(ip_source);
    }
  }
  
  return hostname;
}

/**
 *
 * Generates a random long integer between 0 and max
 *
 */
unsigned char random_at_most(unsigned char max) {
  unsigned char
  num_bins = (unsigned char) max + 1,
  num_rand = (unsigned char) 0xff,
  bin_size = num_rand / num_bins,
  defect   = num_rand % num_bins;

  unsigned char x[1];
  do {
    gnutls_rnd(GNUTLS_RND_NONCE, x, sizeof(x));
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned char)x[0]);

  // Truncated division is intentional
  return x[0]/bin_size;
}

/**
 * Generates a random string and store it in str
 */
char * rand_string(char * str, size_t str_size) {
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t n;
  
  if (str_size && str != NULL) {
    for (n = 0; n < str_size; n++) {
      unsigned char key = random_at_most((sizeof(charset)) - 2);
      str[n] = charset[key];
    }
    str[str_size] = '\0';
    return str;
  } else {
    return NULL;
  }
}

int rand_code(char * str, size_t str_size) {
  const char charset[] = "0123456789";
  size_t n;
  
  if (str_size && str != NULL) {
    for (n = 0; n < str_size; n++) {
      unsigned char key = random_at_most((sizeof(charset)) - 2);
      str[n] = charset[key];
    }
    str[str_size] = '\0';
    return 1;
  } else {
    return 0;
  }
}

char * join_json_string_array(json_t * j_array, const char * separator) {
  char * str_result = NULL, * tmp;
  json_t * j_element;
  size_t index;
  
  if (j_array != NULL && json_is_array(j_array)) {
    json_array_foreach(j_array, index, j_element) {
      if (json_is_string(j_element) && json_string_length(j_element)) {
        if (str_result == NULL) {
          str_result = o_strdup(json_string_value(j_element));
        } else {
          tmp = msprintf("%s%s%s", str_result, separator, json_string_value(j_element));
          o_free(str_result);
          str_result = tmp;
        }
      }
    }
  }
  return str_result;
}

/**
 * Converts an integer value to its hex character
 */
char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/**
 * Returns a url-encoded version of str
 * IMPORTANT: be sure to o_free() the returned string after use 
 * Thanks Geek Hideout!
 * http://www.geekhideout.com/urlcode.shtml
 */
char * url_encode(const char * str) {
  char * pstr = (char *)str, * buf = o_malloc(strlen(str) * 3 + 1), * pbuf = buf;
  while (* pstr) {
    if (isalnum(* pstr) || * pstr == '-' || * pstr == '_' || * pstr == '.' || * pstr == '~') 
      * pbuf++ = * pstr;
    else if (* pstr == ' ') 
      * pbuf++ = '+';
    else 
      * pbuf++ = '%', * pbuf++ = to_hex(* pstr >> 4), * pbuf++ = to_hex(* pstr & 15);
    pstr++;
  }
  * pbuf = '\0';
  return buf;
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
        if (use_salt) {
          rand_string(salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
          intermediate = msprintf("%s%s", password, salt);
        } else {
          intermediate = o_strdup(password);
        }
        key_data.data = (unsigned char*)intermediate;
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

int generate_digest_pkcs5s2(const char * password, const char * salt, char * out_digest) {
  gnutls_pkcs12_bag_t bag;
  gnutls_pkcs12_bag_init(&bag);
  unsigned int schema = GNUTLS_PKCS_PKCS12_3DES, cipher = GNUTLS_CIPHER_3DES_CBC, salt_size = GLEWLWYD_DEFAULT_SALT_LENGTH, count = 1000;
  char * pbkdf2_key = NULL;
  char my_salt[GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  const char * cur_salt;
  unsigned char encoded_key[128 + GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  size_t encoded_key_size = (128 + GLEWLWYD_DEFAULT_SALT_LENGTH), encoded_key_size_base64;
  int res;
  
  if (!gnutls_pkcs12_bag_encrypt(bag, password, schema)) {
    if (salt != NULL) {
      cur_salt = salt;
    } else {
      rand_string(my_salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
      cur_salt = my_salt;
    }
    if (!gnutls_pkcs12_bag_enc_info(bag, &schema, &cipher, (void*)cur_salt, &salt_size, &count, &pbkdf2_key)) {
      memcpy(encoded_key, pbkdf2_key, o_strlen(pbkdf2_key));
      memcpy(encoded_key+o_strlen(pbkdf2_key), cur_salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
      encoded_key_size = o_strlen(pbkdf2_key) + GLEWLWYD_DEFAULT_SALT_LENGTH;
      if (o_base64_encode(encoded_key, encoded_key_size, (unsigned char *)out_digest, &encoded_key_size_base64)) {
        res = 1;
      } else {
        res = 0;
      }
    } else {
      res = 0;
    }
  } else {
    res = 0;
  }
  gnutls_free(pbkdf2_key);
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
          to_return = msprintf("{SSHA224}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA224:
        if (generate_digest(digest_SHA224, data, 0, buffer)) {
          to_return = msprintf("{SHA224}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA256:
        if (generate_digest(digest_SHA256, data, 1, buffer)) {
          to_return = msprintf("{SSHA256}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA256:
        if (generate_digest(digest_SHA256, data, 0, buffer)) {
          to_return = msprintf("{SHA256}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA384:
        if (generate_digest(digest_SHA384, data, 1, buffer)) {
          to_return = msprintf("{SSHA384}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA384:
        if (generate_digest(digest_SHA384, data, 0, buffer)) {
          to_return = msprintf("{SHA384}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA512:
        if (generate_digest(digest_SHA512, data, 1, buffer)) {
          to_return = msprintf("{SSHA512}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA512:
        if (generate_digest(digest_SHA512, data, 0, buffer)) {
          to_return = msprintf("{SHA512}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SMD5:
        if (generate_digest(digest_MD5, data, 1, buffer)) {
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
      case digest_PKCS5S2:
        if (generate_digest_pkcs5s2(data, NULL, buffer)) {
          to_return = msprintf("{PKCS5S2}%s", buffer, o_strlen(buffer));
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest PKCS5S2");
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

/**
 * Check if the result json object has a "result" element that is equal to value
 */
int check_result_value(json_t * result, const int value) {
  return (json_is_integer(json_object_get(result, "result")) && 
          json_integer_value(json_object_get(result, "result")) == value);
}
