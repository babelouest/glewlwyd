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
 * Copyright 2016-2021 Nicolas Mora <mail@babelouest.org>
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <ctype.h>
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <nettle/pbkdf2.h>

#include "glewlwyd-common.h"

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
    buffer = o_malloc((length+1));
    if (buffer) {
      res = fread (buffer, 1, length, f);
      if (res != length) {
        y_log_message(Y_LOG_LEVEL_ERROR, "get_file_content - fread warning, reading %zu while expecting %zu", res, length);
      }
      // Add null character at the end of buffer, just in case
      buffer[length] = '\0';
    }
    fclose (f);
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "get_file_content - error opening file %s\n", file_path);
  }
  
  return buffer;
}

/**
 * Return the source ip address of the request
 * Based on the header value "X-Forwarded-For" if set, which means the request is forwarded by a proxy
 * otherwise the call is direct, return the client_address
 */
const char * get_ip_source(const struct _u_request * request) {
  const char * ip_source = u_map_get_case(request->map_header, "X-Forwarded-For");
  
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
  struct addrinfo hints;
  struct addrinfo * lookup = NULL;
  char * hostname = NULL;
  
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_CANONNAME;
  hints.ai_canonname = NULL;
  if (ip_source != NULL) {
    hostname = o_strdup(ip_source);
    if (!getaddrinfo(ip_source, NULL, &hints, &lookup)) {
      if (!o_strnullempty(lookup->ai_canonname)) {
        hostname = mstrcatf(hostname, " - %s", lookup->ai_canonname);
      }
      freeaddrinfo(lookup);
      lookup = NULL;
    }
  }
  
  return hostname;
}

/**
 *
 * Generates a random long integer between 0 and max
 *
 */
unsigned char random_at_most(unsigned char max, int nonce, int * is_error) {
  unsigned char
  num_bins = (unsigned char) max + 1,
  num_rand = (unsigned char) 0xff,
  bin_size = num_rand / num_bins,
  defect   = num_rand % num_bins;

  unsigned char x[1];
  do {
    if (gnutls_rnd(nonce?GNUTLS_RND_NONCE:GNUTLS_RND_KEY, x, sizeof(x)) < 0) {
      *is_error = 1;
      break;
    }
  }
  // This is carefully written not to overflow
  while (num_rand - defect <= (unsigned char)x[0]);

  if (!(*is_error)) {
    // Truncated division is intentional
    return x[0]/bin_size;
  } else {
    return 0;
  }
}

/**
 * Generates a random string and store it in str
 */
char * rand_string(char * str, size_t str_size) {
  return rand_string_from_charset(str, str_size, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
}

/**
 * Generates a random string and store it in str
 */
char * rand_string_from_charset(char * str, size_t str_size, const char * charset) {
  size_t n;
  unsigned char rnd = 0;
  int is_error = 0;
  
  if (str_size && str != NULL) {
    for (n = 0; n < str_size; n++) {
      rnd = random_at_most((o_strlen(charset)) - 2, 0, &is_error);
      if (is_error) {
        return NULL;
      }
      str[n] = charset[rnd];
    }
    str[str_size] = '\0';
    return str;
  } else {
    return NULL;
  }
}

/**
 * Generates a random string used as nonce and store it in str
 */
char * rand_string_nonce(char * str, size_t str_size) {
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t n;
  unsigned char rnd = 0;
  int is_error = 0;
  
  if (str_size && str != NULL) {
    for (n = 0; n < str_size; n++) {
      rnd = random_at_most((o_strlen(charset)) - 2, 1, &is_error);
      if (is_error) {
        return NULL;
      }
      str[n] = charset[rnd];
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
  int is_error = 0;
  
  if (str_size && str != NULL) {
    for (n = 0; n < str_size; n++) {
      unsigned char key = random_at_most((sizeof(charset)) - 2, 0, &is_error);
      if (is_error) {
        return 0;
      }
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
      if (json_is_string(j_element) && !json_string_null_or_empty(j_element)) {
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
 * Generates a digest using the digest_algorithm specified from data and add a salt if specified, stores it in out_digest
 */
int generate_digest(digest_algorithm digest, const char * data, int use_salt, char * out_digest) {
  unsigned int res = 1;
  int alg, dig_res;
  gnutls_datum_t key_data;
  char * intermediate = NULL, salt[GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  unsigned char encoded_key[128 + GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  size_t encoded_key_size = (128 + GLEWLWYD_DEFAULT_SALT_LENGTH), encoded_key_size_base64;

  if (data != NULL && out_digest != NULL) {
    switch (digest) {
      case digest_SHA1:
        alg = GNUTLS_DIG_SHA1;
        break;
      case digest_SHA224:
        alg = GNUTLS_DIG_SHA224;
        break;
      case digest_SHA256:
        alg = GNUTLS_DIG_SHA256;
        break;
      case digest_SHA384:
        alg = GNUTLS_DIG_SHA384;
        break;
      case digest_SHA512:
        alg = GNUTLS_DIG_SHA512;
        break;
      case digest_MD5:
        alg = GNUTLS_DIG_MD5;
        break;
      default:
        alg = GNUTLS_DIG_UNKNOWN;
        break;
    }
    
    if(alg != GNUTLS_DIG_UNKNOWN) {
      if (o_strlen(data) > 0) {
        if (use_salt) {
          if (rand_string_nonce(salt, GLEWLWYD_DEFAULT_SALT_LENGTH) != NULL) {
            intermediate = msprintf("%s%s", data, salt);
          } else {
            res = 0;
          }
        } else {
          intermediate = o_strdup(data);
        }
        if (res) {
          key_data.data = (unsigned char*)intermediate;
          key_data.size = o_strlen(intermediate);
          if (key_data.data != NULL && (dig_res = gnutls_fingerprint(alg, &key_data, encoded_key, &encoded_key_size)) == GNUTLS_E_SUCCESS) {
            if (use_salt) {
              memcpy(encoded_key+encoded_key_size, salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
              encoded_key_size += GLEWLWYD_DEFAULT_SALT_LENGTH;
            }
            if (!o_base64_encode(encoded_key, encoded_key_size, (unsigned char *)out_digest, &encoded_key_size_base64)) {
              res = 0;
            }
          } else {
            res = 0;
          }
        }
        o_free(intermediate);
      } else {
        // No data, then out_digest becomes an empty string
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
 * Generates a digest using the digest_algorithm specified from data and add a salt if specified, stores it in out_digest as raw output
 */
int generate_digest_raw(digest_algorithm digest, const unsigned char * data, size_t data_len, unsigned char * out_digest, size_t * out_digest_len) {
  unsigned int res = 0;
  int alg, dig_res;
  gnutls_datum_t key_data;

  if (data != NULL && out_digest != NULL) {
    switch (digest) {
      case digest_SHA1:
        alg = GNUTLS_DIG_SHA1;
        break;
      case digest_SHA224:
        alg = GNUTLS_DIG_SHA224;
        break;
      case digest_SHA256:
        alg = GNUTLS_DIG_SHA256;
        break;
      case digest_SHA384:
        alg = GNUTLS_DIG_SHA384;
        break;
      case digest_SHA512:
        alg = GNUTLS_DIG_SHA512;
        break;
      case digest_MD5:
        alg = GNUTLS_DIG_MD5;
        break;
      default:
        alg = GNUTLS_DIG_UNKNOWN;
        break;
    }
    
    if(alg != GNUTLS_DIG_UNKNOWN) {
      if (data_len > 0) {
        key_data.data = (unsigned char *)data;
        key_data.size = data_len;
        if (key_data.data != NULL) {
          if ((dig_res = gnutls_fingerprint(alg, &key_data, out_digest, out_digest_len)) == GNUTLS_E_SUCCESS) {
            res = 1;
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "generate_digest_raw - Error gnutls_fingerprint: %d", dig_res);
            res = 0;
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_digest_raw - Error key_data.data");
          res = 0;
        }
      } else {
        // No data, then out_digest is empty
        *out_digest_len = 0;
        res = 1;
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "generate_digest_raw - Error alg");
      res = 0;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "generate_digest_raw - Error param");
    res = 0;
  }
  return res;
}

/**
 * Generates a digest using the PBKDF2 algorithm from data and a salt if specified, otherwise generates a salt, stores it in out_digest
 */
int generate_digest_pbkdf2(const char * data, unsigned int iterations, const char * salt, char * out_digest) {
  char my_salt[GLEWLWYD_DEFAULT_SALT_LENGTH + 1] = {0};
  uint8_t cur_salt[GLEWLWYD_DEFAULT_SALT_LENGTH], dst[32 + GLEWLWYD_DEFAULT_SALT_LENGTH] = {0};
  int res = 1;
  size_t encoded_key_size_base64;
  
  if (salt != NULL) {
    memcpy(cur_salt, salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
  } else {
    if (rand_string_nonce(my_salt, GLEWLWYD_DEFAULT_SALT_LENGTH) != NULL) {
      memcpy(cur_salt, my_salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
    } else {
      res = 0;
    }
  }
  if (res) {
    pbkdf2_hmac_sha256(o_strlen(data), (const uint8_t *)data, iterations, GLEWLWYD_DEFAULT_SALT_LENGTH, cur_salt, 32, dst);
    memcpy(dst+32, cur_salt, GLEWLWYD_DEFAULT_SALT_LENGTH);
    if (!o_base64_encode(dst, 32 + GLEWLWYD_DEFAULT_SALT_LENGTH, (unsigned char *)out_digest, &encoded_key_size_base64)) {
      res = 0;
    }
  }
  return res;
}

/**
 * Generates a digest using crypt library
 * uses a 16-bytes random salt
 */
int generate_digest_crypt(const char * data, const char * method, char * out_digest) {
  char salt[GLEWLWYD_DEFAULT_SALT_LENGTH+4] = {0},  * out_crypt;
  int res;
  
  if (method != NULL) {
    o_strcpy(salt, method);
  }
  if (rand_string_nonce(salt+o_strlen(method), GLEWLWYD_DEFAULT_SALT_LENGTH) != NULL) {
    if ((out_crypt = crypt(data, salt)) != NULL) {
      o_strcpy(out_digest, out_crypt);
      res = 1;
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
          to_return = msprintf("{SSHA}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA");
        }
        break;
      case digest_SHA1:
        if (generate_digest(digest_SHA1, data, 0, buffer)) {
          to_return = msprintf("{SHA}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA");
        }
        break;
      case digest_SSHA224:
        if (generate_digest(digest_SHA224, data, 1, buffer)) {
          to_return = msprintf("{SSHA224}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA224");
        }
        break;
      case digest_SHA224:
        if (generate_digest(digest_SHA224, data, 0, buffer)) {
          to_return = msprintf("{SHA224}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA224");
        }
        break;
      case digest_SSHA256:
        if (generate_digest(digest_SHA256, data, 1, buffer)) {
          to_return = msprintf("{SSHA256}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA256");
        }
        break;
      case digest_SHA256:
        if (generate_digest(digest_SHA256, data, 0, buffer)) {
          to_return = msprintf("{SHA256}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA256");
        }
        break;
      case digest_SSHA384:
        if (generate_digest(digest_SHA384, data, 1, buffer)) {
          to_return = msprintf("{SSHA384}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA384");
        }
        break;
      case digest_SHA384:
        if (generate_digest(digest_SHA384, data, 0, buffer)) {
          to_return = msprintf("{SHA384}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA384");
        }
        break;
      case digest_SSHA512:
        if (generate_digest(digest_SHA512, data, 1, buffer)) {
          to_return = msprintf("{SSHA512}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SSHA512");
        }
        break;
      case digest_SHA512:
        if (generate_digest(digest_SHA512, data, 0, buffer)) {
          to_return = msprintf("{SHA512}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SHA512");
        }
        break;
      case digest_SMD5:
        if (generate_digest(digest_MD5, data, 1, buffer)) {
          to_return = msprintf("{SMD5}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest SMD5");
        }
        break;
      case digest_MD5:
        if (generate_digest(digest_MD5, data, 0, buffer)) {
          to_return = msprintf("{MD5}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest MD5");
        }
        break;
      case digest_PBKDF2_SHA256:
        if (generate_digest_pbkdf2(data, G_PBKDF2_ITERATOR_DEFAULT, NULL, buffer)) {
          to_return = msprintf("{PBKDF2}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest PBKDF2");
        }
        break;
      case digest_CRYPT:
        if (generate_digest_crypt(data, NULL, buffer)) {
          to_return = msprintf("{CRYPT}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest CRYPT");
        }
        break;
      case digest_CRYPT_MD5:
        if (generate_digest_crypt(data, "$1$", buffer)) {
          to_return = msprintf("{CRYPT}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest CRYPT_MD5");
        }
        break;
      case digest_CRYPT_SHA256:
        if (generate_digest_crypt(data, "$5$", buffer)) {
          to_return = msprintf("{CRYPT}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest CRYPT_SHA256");
        }
        break;
      case digest_CRYPT_SHA512:
        if (generate_digest_crypt(data, "$6$", buffer)) {
          to_return = msprintf("{CRYPT}%s", buffer);
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "generate_hash - Error generating digest CRYPT_SHA512");
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

int json_string_null_or_empty(json_t * j_str) {
  return o_strnullempty(json_string_value(j_str));
}
