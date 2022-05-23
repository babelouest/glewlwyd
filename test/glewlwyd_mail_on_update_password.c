/* Public domain, no copyright. Use at your own risk. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <netinet/in.h>
#include <ctype.h>

#include <check.h>
#include <ulfius.h>
#include <orcania.h>
#include <yder.h>

#include "unit-tests.h"

#define SERVER_URI "http://localhost:4593/api"
#define ADMIN_USERNAME "admin"
#define ADMIN_PASSWORD "password"

#define USER1 "mail1"
#define MAIL1 "mail1@mail.tld"
#define USER2 "mail2"
#define MAIL2 "mail2@mail.tld"
#define USER3 "no-mail"
#define USER_PASSWORD "password"
#define USER_NEW_PASSWORD "new-password"

#define SCOPE1 "openid"
#define SCOPE2 "g_profile"
#define SCOPE3 "scope1"

#define CONFIG_TYPE "mail-on-connexion"
#define CONFIG_NAME "cur-mail-on-connection"
#define HOST "localhost"
#define PORT_2525 2525
#define PORT_2526 2526
#define PORT_2527 2527
#define PORT_2528 2528
#define PORT_2529 2529
#define CONTENT_TYPE "text/plain; charset=utf-8"
#define FROM "glewlwyd@mail.tld"
#define LANG_PROPERTY "lang"
#define SUBJECT "New registration"
#define BODY_PATTERN_USERNAME "New registration for "
#define BODY_PATTERN_IP "New registration at "
#define SUBJECT_FR "Nouvel enregistrement"
#define BODY_PATTERN_USERNAME_FR "Nouvel enregistrement pour "

struct _u_request admin_req;

static pthread_mutex_t smtp_lock;
static pthread_cond_t  smtp_cond;

#define BACKLOG_MAX  (10)
#define BUF_SIZE     4096
#define STREQU(a,b)  (strcmp(a, b) == 0)

struct smtp_manager {
  char       * mail_data;
  unsigned int port;
  int          sockfd;
  const char * body_pattern;
};

/**
 *
 * Function that emulates a very simple SMTP server
 * Taken from Kenneth Finnegan's ccsmtp program
 * https://gist.github.com/PhirePhly/2914635
 * This function is under the GPL2 license
 *
 */
static void handle_smtp (struct smtp_manager * manager) {
  int rc, i;
  char buffer[BUF_SIZE], bufferout[BUF_SIZE];
  int buffer_offset = 0;
  buffer[BUF_SIZE-1] = '\0';

  // Flag for being inside of DATA verb
  int inmessage = 0;

  sprintf(bufferout, "220 ulfius.tld SMTP CCSMTP\r\n");
  send(manager->sockfd, bufferout, strlen(bufferout), 0);

  while (1) {
    fd_set sockset;
    struct timeval tv;

    FD_ZERO(&sockset);
    FD_SET(manager->sockfd, &sockset);
    tv.tv_sec = 120; // Some SMTP servers pause for ~15s per message
    tv.tv_usec = 0;

    // Wait tv timeout for the server to send anything.
    select(manager->sockfd+1, &sockset, NULL, NULL, &tv);

    if (!FD_ISSET(manager->sockfd, &sockset)) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Socket timed out", manager->sockfd);
      break;
    }

    int buffer_left = BUF_SIZE - buffer_offset - 1;
    if (buffer_left == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Command line too long", manager->sockfd);
      sprintf(bufferout, "500 Too long\r\n");
      send(manager->sockfd, bufferout, strlen(bufferout), 0);
      buffer_offset = 0;
      continue;
    }

    rc = recv(manager->sockfd, buffer + buffer_offset, buffer_left, 0);
    if (rc == 0) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Remote host closed socket", manager->sockfd);
      break;
    }
    if (rc == -1) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Error on socket", manager->sockfd);
      break;
    }

    buffer_offset += rc;

    char *eol;

    // Only process one line of the received buffer at a time
    // If multiple lines were received in a single recv(), goto
    // back to here for each line
    //
processline:
    eol = strstr(buffer, "\r\n");
    if (eol == NULL) {
      y_log_message(Y_LOG_LEVEL_DEBUG, "%d: Haven't found EOL yet", manager->sockfd);
      continue;
    }

    // Null terminate each line to be processed individually
    eol[0] = '\0';

    if (!inmessage) { // Handle system verbs
      // Replace all lower case letters so verbs are all caps
      for (i=0; i<4; i++) {
        if (islower(buffer[i])) {
          buffer[i] += 'A' - 'a';
        }
      }
      // Null-terminate the verb for strcmp
      buffer[4] = '\0';

      // Respond to each verb accordingly.
      // You should replace these with more meaningful
      // actions than simply printing everything.
      //
      if (STREQU(buffer, "HELO")) { // Initial greeting
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "MAIL")) { // New mail from...
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "RCPT")) { // Mail addressed to...
        sprintf(bufferout, "250 Ok recipient\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "DATA")) { // Message contents...
        sprintf(bufferout, "354 Continue\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 1;
      } else if (STREQU(buffer, "RSET")) { // Reset the connection
        sprintf(bufferout, "250 Ok reset\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "NOOP")) { // Do nothing.
        sprintf(bufferout, "250 Ok noop\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      } else if (STREQU(buffer, "QUIT")) { // Close the connection
        sprintf(bufferout, "221 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        break;
      } else { // The verb used hasn't been implemented.
        sprintf(bufferout, "502 Command Not Implemented\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
      }
    } else { // We are inside the message after a DATA verb.
      if (0 == o_strncmp(manager->body_pattern, buffer, o_strlen(manager->body_pattern))) {
        manager->mail_data = o_strdup(buffer+o_strlen(manager->body_pattern));
      }
      if (STREQU(buffer, ".")) { // A single "." signifies the end
        sprintf(bufferout, "250 Ok\r\n");
        send(manager->sockfd, bufferout, strlen(bufferout), 0);
        inmessage = 0;
      }
    }

    // Shift the rest of the buffer to the front
    memmove(buffer, eol+2, BUF_SIZE - (eol + 2 - buffer));
    buffer_offset -= (eol - buffer) + 2;

    // Do we already have additional lines to process? If so,
    // commit a horrid sin and goto the line processing section again.
    if (strstr(buffer, "\r\n"))
      goto processline;
  }

  // All done. Clean up everything and exit.
  shutdown(manager->sockfd, SHUT_WR);
  close(manager->sockfd);
}

static void * simple_smtp(void * args) {
  struct smtp_manager * manager = (struct smtp_manager *)args;
  int server_fd;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);

  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) != 0) {
    if (!setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
      address.sin_family = AF_INET;
      address.sin_addr.s_addr = INADDR_ANY;
      address.sin_port = htons( manager->port );

      if (!bind(server_fd, (struct sockaddr *)&address, sizeof(address))) {
        if (listen(server_fd, 3) >= 0) {
          pthread_mutex_lock(&smtp_lock);
          pthread_cond_signal(&smtp_cond);
          pthread_mutex_unlock(&smtp_lock);
          if ((manager->sockfd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
            handle_smtp(manager);
          } else {
            y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error accept");
          }
        } else {
          y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error listen");
        }
      } else {
        y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error bind");
      }
    } else {
      y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error setsockopt");
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "simple_smtp - Error socket");
  }

  shutdown(server_fd, SHUT_RDWR);
  close(server_fd);

  pthread_exit(NULL);
}

START_TEST(test_glwd_mail_on_update_password_add_users)
{
  json_t * j_body;

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssss[sss]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssss[sss]so}", "username", USER2, "password", USER_PASSWORD, "email", MAIL2, "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssss[sss]so}", "username", USER3, "password", USER_PASSWORD, "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "POST", SERVER_URI "/user", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
}
END_TEST

START_TEST(test_glwd_mail_on_update_password_reset_users)
{
  json_t * j_body;

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssss[sss]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssss[sss]so}", "username", USER2, "password", USER_PASSWORD, "email", MAIL2, "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssss[sss]so}", "username", USER3, "password", USER_PASSWORD, "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
}
END_TEST

START_TEST(test_glwd_mail_on_update_password_remove_users)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER1, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER2, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/user/" USER3, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_mail_on_update_password_delete_misc_config)
{
  ck_assert_int_eq(run_simple_test(&admin_req, "DELETE", SERVER_URI "/misc/" CONFIG_NAME, NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL), 1);
}
END_TEST

START_TEST(test_glwd_mail_on_update_password_email_username_ok)
{
  struct smtp_manager manager;
  pthread_t thread;
  struct _u_request req;
  struct _u_response resp;

  json_t * j_body = json_pack("{sss{so ss si ss ss ss s{s{sossss}}}}",
                              "type", CONFIG_TYPE,
                              "value",
                                "enabled", json_true(),
                                "host", HOST,
                                "port", PORT_2525,
                                "content-type", CONTENT_TYPE,
                                "from", FROM,
                                "user-lang-property", LANG_PROPERTY,
                                "templatesUpdatePassword",
                                  "en",
                                    "defaultLang", json_true(),
                                    "subject", SUBJECT,
                                    "body-pattern", BODY_PATTERN_USERNAME "{USERNAME}");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  manager.mail_data = NULL;
  manager.port = PORT_2525;
  manager.sockfd = 0;
  manager.body_pattern = BODY_PATTERN_USERNAME;
  pthread_create(&thread, NULL, simple_smtp, &manager);

  pthread_mutex_lock(&smtp_lock);
  pthread_cond_wait(&smtp_cond, &smtp_lock);
  pthread_mutex_unlock(&smtp_lock);

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI,
                                                       U_OPT_HTTP_URL_APPEND, "/auth/",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_COOKIE_PARAMETER, resp.map_cookie[0].key, resp.map_cookie[0].value, U_OPT_NONE), U_OK);
  j_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "password", USER_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  pthread_join(thread, NULL);

  ck_assert_str_eq(manager.mail_data, USER1);

  o_free(manager.mail_data);
}
END_TEST

START_TEST(test_glwd_mail_on_update_password_no_email_ok)
{
  struct smtp_manager manager;
  pthread_t thread;
  struct _u_request req;
  struct _u_response resp;

  json_t * j_body = json_pack("{sss{so ss si ss ss ss s{s{sossss}}}}",
                              "type", CONFIG_TYPE,
                              "value",
                                "enabled", json_true(),
                                "host", HOST,
                                "port", PORT_2526,
                                "content-type", CONTENT_TYPE,
                                "from", FROM,
                                "user-lang-property", LANG_PROPERTY,
                                "templatesUpdatePassword",
                                  "en",
                                    "defaultLang", json_true(),
                                    "subject", SUBJECT,
                                    "body-pattern", BODY_PATTERN_USERNAME "{USERNAME}");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  manager.mail_data = NULL;
  manager.port = PORT_2526;
  manager.sockfd = 0;
  manager.body_pattern = BODY_PATTERN_USERNAME;
  pthread_create(&thread, NULL, simple_smtp, &manager);

  pthread_mutex_lock(&smtp_lock);
  pthread_cond_wait(&smtp_cond, &smtp_lock);
  pthread_mutex_unlock(&smtp_lock);

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", USER3, "password", USER_PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI,
                                                       U_OPT_HTTP_URL_APPEND, "/auth/",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_COOKIE_PARAMETER, resp.map_cookie[0].key, resp.map_cookie[0].value, U_OPT_NONE), U_OK);
  j_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "password", USER_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssss[sss]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI,
                                                       U_OPT_HTTP_URL_APPEND, "/auth/",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_COOKIE_PARAMETER, resp.map_cookie[0].key, resp.map_cookie[0].value, U_OPT_NONE), U_OK);
  j_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "password", USER_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  pthread_join(thread, NULL);

  ck_assert_str_eq(manager.mail_data, USER1);

  o_free(manager.mail_data);
}
END_TEST

START_TEST(test_glwd_mail_on_update_password_email_username_lang)
{
  struct smtp_manager manager;
  pthread_t thread;
  struct _u_request req;
  struct _u_response resp;

  // Test 1 - send e-mail in english
  json_t * j_body = json_pack("{sss{so ss si ss ss ss s{s{sossss}s{sossss}}}}",
                              "type", CONFIG_TYPE,
                              "value",
                                "enabled", json_true(),
                                "host", HOST,
                                "port", PORT_2527,
                                "content-type", CONTENT_TYPE,
                                "from", FROM,
                                "user-lang-property", LANG_PROPERTY,
                                "templatesUpdatePassword",
                                  "en",
                                    "defaultLang", json_true(),
                                    "subject", SUBJECT,
                                    "body-pattern", BODY_PATTERN_USERNAME "{USERNAME}",
                                  "fr",
                                    "defaultLang", json_false(),
                                    "subject", SUBJECT_FR,
                                    "body-pattern", BODY_PATTERN_USERNAME_FR "{USERNAME}");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssssss[sss]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, LANG_PROPERTY, "en", "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  manager.mail_data = NULL;
  manager.port = PORT_2527;
  manager.sockfd = 0;
  manager.body_pattern = BODY_PATTERN_USERNAME;
  pthread_create(&thread, NULL, simple_smtp, &manager);

  pthread_mutex_lock(&smtp_lock);
  pthread_cond_wait(&smtp_cond, &smtp_lock);
  pthread_mutex_unlock(&smtp_lock);

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI,
                                                       U_OPT_HTTP_URL_APPEND, "/auth/",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_COOKIE_PARAMETER, resp.map_cookie[0].key, resp.map_cookie[0].value, U_OPT_NONE), U_OK);
  j_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "password", USER_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  pthread_join(thread, NULL);

  ck_assert_str_eq(manager.mail_data, USER1);

  o_free(manager.mail_data);

  // Test 2 - send e-mail in french
  j_body = json_pack("{sss{so ss si ss ss ss s{s{sossss}s{sossss}}}}",
                      "type", CONFIG_TYPE,
                      "value",
                        "enabled", json_true(),
                        "host", HOST,
                        "port", PORT_2528,
                        "content-type", CONTENT_TYPE,
                        "from", FROM,
                        "user-lang-property", LANG_PROPERTY,
                        "templatesUpdatePassword",
                          "en",
                            "defaultLang", json_true(),
                            "subject", SUBJECT,
                            "body-pattern", BODY_PATTERN_USERNAME "{USERNAME}",
                          "fr",
                            "defaultLang", json_false(),
                            "subject", SUBJECT_FR,
                            "body-pattern", BODY_PATTERN_USERNAME_FR "{USERNAME}");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssssss[sss]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, LANG_PROPERTY, "fr", "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  manager.mail_data = NULL;
  manager.port = PORT_2528;
  manager.sockfd = 0;
  manager.body_pattern = BODY_PATTERN_USERNAME_FR;
  pthread_create(&thread, NULL, simple_smtp, &manager);

  pthread_mutex_lock(&smtp_lock);
  pthread_cond_wait(&smtp_cond, &smtp_lock);
  pthread_mutex_unlock(&smtp_lock);

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI,
                                                       U_OPT_HTTP_URL_APPEND, "/auth/",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_COOKIE_PARAMETER, resp.map_cookie[0].key, resp.map_cookie[0].value, U_OPT_NONE), U_OK);
  j_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "password", USER_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  pthread_join(thread, NULL);

  ck_assert_str_eq(manager.mail_data, USER1);

  o_free(manager.mail_data);

  // Test 3 - send e-mail in default lang
  j_body = json_pack("{sss{so ss si ss ss ss s{s{sossss}s{sossss}}}}",
                      "type", CONFIG_TYPE,
                      "value",
                        "enabled", json_true(),
                        "host", HOST,
                        "port", PORT_2529,
                        "content-type", CONTENT_TYPE,
                        "from", FROM,
                        "user-lang-property", LANG_PROPERTY,
                        "templatesUpdatePassword",
                          "en",
                            "defaultLang", json_true(),
                            "subject", SUBJECT,
                            "body-pattern", BODY_PATTERN_USERNAME "{USERNAME}",
                          "fr",
                            "defaultLang", json_false(),
                            "subject", SUBJECT_FR,
                            "body-pattern", BODY_PATTERN_USERNAME_FR "{USERNAME}");
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/misc/" CONFIG_NAME, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  
  ck_assert_ptr_ne(NULL, (j_body = json_pack("{sssssssss[sss]so}", "username", USER1, "password", USER_PASSWORD, "email", MAIL1, LANG_PROPERTY, "de", "scope", SCOPE1, SCOPE2, SCOPE3, "enabled", json_true())));
  ck_assert_int_eq(run_simple_test(&admin_req, "PUT", SERVER_URI "/user/" USER1, NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);

  manager.mail_data = NULL;
  manager.port = PORT_2529;
  manager.sockfd = 0;
  manager.body_pattern = BODY_PATTERN_USERNAME;
  pthread_create(&thread, NULL, simple_smtp, &manager);

  pthread_mutex_lock(&smtp_lock);
  pthread_cond_wait(&smtp_cond, &smtp_lock);
  pthread_mutex_unlock(&smtp_lock);

  ulfius_init_request(&req);
  ulfius_init_response(&resp);
  j_body = json_pack("{ssss}", "username", USER1, "password", USER_PASSWORD);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_HTTP_VERB, "POST",
                                                       U_OPT_HTTP_URL, SERVER_URI,
                                                       U_OPT_HTTP_URL_APPEND, "/auth/",
                                                       U_OPT_JSON_BODY, j_body,
                                                       U_OPT_NONE), U_OK);
  json_decref(j_body);
  ck_assert_int_eq(ulfius_send_http_request(&req, &resp), U_OK);
  ck_assert_int_eq(resp.status, 200);
  ck_assert_int_eq(resp.nb_cookies, 1);
  ulfius_clean_request(&req);
  
  ulfius_init_request(&req);
  ck_assert_int_eq(ulfius_set_request_properties(&req, U_OPT_COOKIE_PARAMETER, resp.map_cookie[0].key, resp.map_cookie[0].value, U_OPT_NONE), U_OK);
  j_body = json_pack("{ssss}", "old_password", USER_PASSWORD, "password", USER_NEW_PASSWORD);
  ck_assert_int_eq(run_simple_test(&req, "PUT", SERVER_URI "/profile/password/", NULL, NULL, j_body, NULL, 200, NULL, NULL, NULL), 1);
  json_decref(j_body);
  ulfius_clean_response(&resp);
  ulfius_clean_request(&req);

  pthread_join(thread, NULL);

  ck_assert_str_eq(manager.mail_data, USER1);

  o_free(manager.mail_data);
}
END_TEST

static Suite *glewlwyd_suite(void)
{
  Suite *s;
  TCase *tc_core;

  s = suite_create("Glewlwyd mail on connection");
  tc_core = tcase_create("test_glwd_mail_on_update_password");
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_add_users);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_email_username_ok);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_reset_users);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_no_email_ok);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_reset_users);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_email_username_lang);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_reset_users);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_delete_misc_config);
  tcase_add_test(tc_core, test_glwd_mail_on_update_password_remove_users);
  tcase_set_timeout(tc_core, 30);
  suite_add_tcase(s, tc_core);

  return s;
}

int main(int argc, char *argv[])
{
  int number_failed = 0;
  Suite *s;
  SRunner *sr;
  struct _u_request auth_req;
  struct _u_response auth_resp;
  int res, do_test = 0;
  json_t * j_body;
  char * cookie;

  y_init_logs("Glewlwyd test", Y_LOG_MODE_CONSOLE, Y_LOG_LEVEL_DEBUG, NULL, "Starting Glewlwyd test");

  pthread_mutex_init(&smtp_lock, NULL);
  pthread_cond_init(&smtp_cond, NULL);

  ulfius_init_request(&admin_req);
  // Getting a valid session id for authenticated http requests
  ulfius_init_request(&auth_req);
  ulfius_init_response(&auth_resp);
  auth_req.http_verb = strdup("POST");
  auth_req.http_url = msprintf("%s/auth/", SERVER_URI);
  j_body = json_pack("{ssss}", "username", ADMIN_USERNAME, "password", ADMIN_PASSWORD);
  ulfius_set_json_body_request(&auth_req, j_body);
  json_decref(j_body);
  res = ulfius_send_http_request(&auth_req, &auth_resp);
  if (res == U_OK && auth_resp.status == 200) {
    if (auth_resp.nb_cookies) {
      cookie = msprintf("%s=%s", auth_resp.map_cookie[0].key, auth_resp.map_cookie[0].value);
      u_map_put(admin_req.map_header, "Cookie", cookie);
      o_free(cookie);
      do_test = 1;
    }
  } else {
    y_log_message(Y_LOG_LEVEL_ERROR, "Error authentication");
  }
  ulfius_clean_response(&auth_resp);
  ulfius_clean_request(&auth_req);

  if (do_test) {
    s = glewlwyd_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
  }

  run_simple_test(&admin_req, "DELETE", SERVER_URI "/auth/", NULL, NULL, NULL, NULL, 200, NULL, NULL, NULL);

  pthread_mutex_destroy(&smtp_lock);
  pthread_cond_destroy(&smtp_cond);

  ulfius_clean_request(&admin_req);
  y_close_logs();

  return (do_test && number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
